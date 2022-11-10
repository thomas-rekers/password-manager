import argparse
from getpass import getpass


def get_args():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        "mode",
        action="store",
        type=str,
        choices=[
            "get",
            "set",
            "generate",
            "show",
            "init",
            "update",
            "regenerate",
            "delete",
        ],
    )
    arg_parser.add_argument(
        "-t",
        "--title",
        action="store",
        type=str,
        required=False,
        help="the title to identify the password",
    )
    arg_parser.add_argument(
        "-p",
        "--password",
        action="store",
        type=str,
        required=False,
        help="the set password (only required for positional argument 'set')",
    )

    args = arg_parser.parse_args()
    if args.mode == "set" and not args.password:
        arg_parser.error("argument -p/--password is required for setting a password")

    if args.mode not in ("show", "init") and not args.title:
        arg_parser.error(f"argument -r/--title is required for mode {args.mode}")
    return args


def get_main_password():
    return getpass("Your main password: ")
