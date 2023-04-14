#!/usr/bin/env python3
import argparse
import json
from colorama import Fore, Style
import os

from pacu.core.lib import strip_lines, downloads_dir

from . import statement_parser

module_info = {
    "name": "iam__recon_query",
    "author": "David Yesland (@daveysec)",
    "category": "ENUM",
    "one_liner": "Allows you to query enumerated user and role permissions.",
    "description": "This module allows you to query IAM permissions for users and roles and see what resources if any they have those permissions on. For example --query s3:get*,iam:create*.",  # noqa
    "services": ["IAM"],
    "prerequisite_modules": ["iam__enum_permissions"],
    "external_dependencies": [],
    "arguments_to_autocomplete": [],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info["description"])
parser.add_argument(
    "--query",
    required=True,
    help=strip_lines(
        """
    Permissions to query. One string like: s3:GetObject or s3:* or s3:GetObject,s3:PutObject.
"""
    ),
)
parser.add_argument(
    "--all-or-none",
    required=False,
    default=False,
    action="store_true",
    help=strip_lines(
        """
    This will check if all actions in the query are allowed, not just some of them, it will only print the principal and resources for those that allow all actions.
"""  # noqa
    ),
)
parser.add_argument(
    "--role",
    required=False,
    help=strip_lines(
        """
    Filter a to a specific role.
"""
    ),
)
parser.add_argument(
    "--user",
    required=False,
    help=strip_lines(
        """
    Filter a to a specific user.
"""
    ),
)


def main(args, pacu_main):
    args = parser.parse_args(args)
    print = pacu_main.print
    fetch_data = pacu_main.fetch_data

    class color:
        """
        Colorama color class
        Usage: print(color.red("This is red text"))
        Args: string (str): String to color
        """

        def red(string):
            return f"{Fore.RED}{string}{Style.RESET_ALL}"

        def green(string):
            return f"{Fore.GREEN}{string}{Style.RESET_ALL}"

        def yellow(string):
            return f"{Fore.YELLOW}{string}{Style.RESET_ALL}"

    iam_query_data_dir = f"{downloads_dir()}/iam_query_data/"
    if os.path.isdir(iam_query_data_dir) is False:
        print(
            f'{iam_query_data_dir} not found! Maybe you have not run {module_info["prerequisite_modules"][0]} yet...\n'
        )
        if (
            fetch_data(
                ["All users/roles permissions"],
                module_info["prerequisite_modules"][0],
                "--all-users --all-roles",
            )
            is False
        ):
            print("Pre-req module not run. Exiting...")
            return

    # List all the files in the iam_query_data directory
    # which is created by the iam__enum_permissions module
    files = os.listdir(iam_query_data_dir)

    # If the user has specified a role or user to filter by
    # then only use the files that match that role or user
    if args.role:
        files = [file for file in files if f"role-{args.role}.json" in file]
    elif args.user:
        files = [file for file in files if f"user-{args.user}.json" in file]

    # Loop through each file and parse the statements
    for file_name in files:
        statement_grouping_id = file_name.split(".")[0]

        with open(f"{iam_query_data_dir}{file_name}", "r") as statements_file:
            statements = json.load(statements_file)
            results_for_statements = statement_parser.get_resources_for_query_actions(
                statements,
                args.query.split(","),
                statement_grouping_id,
                args.all_or_none,
            )

            # Format results and print to the console
            for principal in results_for_statements:
                for action in results_for_statements[principal]:
                    action_object = results_for_statements[principal][action]
                    if action_object["Allow_resources"]:
                        print(f"{color.green(principal)} can perform {color.green(action)}")
                        print("on the following resources:")

                        for resource in action_object["Allow_resources"]:
                            print(resource)

                        if action_object["Allow_conditions"]:
                            print(color.yellow("- With the following conditions:"))
                            for condition in action_object["Allow_conditions"]:
                                print(condition)

                        if action_object["Deny_resources"]:
                            print(
                                color.red("- If the resources are not included in:")
                            )
                            for resource in action_object["Deny_resources"]:
                                print(resource)
                            if action_object["Deny_conditions"]:
                                print(
                                    "- These Deny rules only apply if the following conditions are met:"
                                )
                                for condition in action_object["Deny_conditions"]:
                                    print(condition)
                        print()
