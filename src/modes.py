import crypto
import file_handler
import utils
import pyperclip


def get(cli_args):
    try:
        main_password = utils.get_and_check_main_password()
        password_token = file_handler.get_password(cli_args.title).encode()
        password = crypto.decrypt_password(main_password, password_token)
        pyperclip.copy(password)
        print("password was copied to clipboard")
    except (ValueError):
        print("no password found for this title")


def set(cli_args):
    try:
        main_password = utils.get_and_check_main_password()
        password_token = crypto.encrypt_password(main_password, cli_args.password)
        file_handler.add_password(cli_args.title, password_token.decode())
        print("password was set successfully")
    except (ValueError):
        print("the provided title already exists")


def generate(cli_args):
    main_password = utils.get_and_check_main_password()
    utils.generate_password(main_password, cli_args.title)


def regenerate(cli_args):
    main_password = utils.get_and_check_main_password()
    file_handler.delete_password(cli_args.title)
    utils.generate_password(main_password, cli_args.title)


def update(cli_args):
    main_password = utils.get_and_check_main_password()
    file_handler.update_password(main_password, cli_args.title, cli_args.password)


def show(cli_args):
    for title in file_handler.list_titles():
        print(title)


def delete(cli_args):
    file_handler.delete_password(cli_args.title)


def init(cli_args):
    main_password = utils.define_main_password()
    file_handler.store_main_password(main_password)
    print("main password was stored successfully")
