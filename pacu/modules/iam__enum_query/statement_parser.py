from policyuniverse.statement import Statement


class ExtendedStatement(Statement):
    """
    Extends the Statement class to add the notresources and conditions properties
    """

    @property
    def notresources(self):
        # If the statement has NotResource, add a notresources attribute to the PU statement object
        if "NotResource" in self.statement:
            return set(self.statement.get("NotResource"))
        else:
            return set()

    @property
    def conditions(self):
        # Add a conditions attribute to the PU statement object
        return self.statement.get("Condition") or {}


def get_resources_for_query_actions(
    list_of_statements, query_actions, statement_grouping_id, all_or_none_actions=False
):
    """
    Gets the denied and allowed resources with conditions for a given actions query
    from a list of policy statements
    Args: list_of_statements (list): list of statement JSON objects from a policy
    Args: query_actions (list): list of actions to query for
    Args: all_or_none_actions (bool): if True, all actions in query_actions must be allowed
    returns: dict: a dictionary of actions with the following structure:

    {
     "someAction": {
          "Deny_resources": set(),
          "Deny_conditions": [],
          "Allow_resources": set(),
          "Allow_conditions": []
          },
     "someOtherAction": {
          "Deny_resources": set(),
          "Deny_conditions": [],
          "Allow_resources": set(),
          "Allow_conditions": []
          }
    }
    """
    results = {statement_grouping_id: {}}

    def new_action_dict():
        # returns a new action dictionary
        return {
            "Deny_resources": set(),
            "Deny_conditions": [],
            "Allow_resources": set(),
            "Allow_conditions": [],
        }

    actions_to_check = []
    for st in list_of_statements:
        try:
            statement = ExtendedStatement(st)
        except Exception as e:
            print(e)
            print(f"[!] Error parsing statement for {statement_grouping_id}:")
            continue

        # Expand the actions to check using policyuniverse
        actions_to_check = Statement({"Action": query_actions}).actions_expanded

        # Get all the query actions which are in the statement
        found_actions = [
            action
            for action in actions_to_check
            if action in statement.actions_expanded
        ]

        # iterate through the found query actions
        for found_action in found_actions:
            effect_key = statement.effect

            # Set the action dictionary to the results dictionary if it exists
            # otherwise create a new action dictionary
            action_dict = results[statement_grouping_id].get(
                found_action, new_action_dict()
            )

            # Add resources to the Deny_resources set if there is a notresources and effect is Allow
            if statement.notresources and statement.effect == "Allow":
                updated_resources = action_dict["Deny_resources"].union(
                    statement.notresources
                )
                action_dict.update({"Deny_resources": updated_resources})

            if statement.notresources and statement.effect == "Deny":
                # Add a condition in this case since it means access is denied
                # but does not mean any other access is allowed
                # TODO maybe a better way to do this but for now here we are.
                action_dict["Deny_conditions"].append(
                    {"IfResourcesNotIn": statement.notresources}
                )

            # Update the Allow or Deny resources
            updated_resources = action_dict[f"{effect_key}_resources"].union(
                statement.resources
            )
            action_dict.update({f"{effect_key}_resources": updated_resources})

            # Add conditions if any exist
            if statement.conditions:
                action_dict[f"{effect_key}_conditions"].append(statement.conditions)

            # Update the results for the actions
            results[statement_grouping_id][found_action] = action_dict

    if all_or_none_actions and not all(
        results[statement_grouping_id].get(action, {"Allow_resources": {}})[
            "Allow_resources"
        ]
        for action in actions_to_check
    ):
        # If all_or_none_actions is True, check if all the query actions are in the results
        # If not, return an empty dictionary
        results[statement_grouping_id] = {}

    return results
