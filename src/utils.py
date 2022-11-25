import random
import string
import pyperclip

import crypto
import file_handler
from cli import get_main_password

DEFAULT_STRING_LENGTH = 16
SPECIAL_CHARACTERS = "}{[]|,.;:/!*#?+-_=~^%()"


def get_random_string(length=DEFAULT_STRING_LENGTH):
    character_string = (
        string.ascii_lowercase
        + string.ascii_uppercase
        + string.digits
        + SPECIAL_CHARACTERS
    )
    return "".join(random.choice(character_string) for _ in range(length))


def define_main_password() -> str:
    print("You need to set a main password for initialization.")
    while True:
        main_password = get_main_password()
        print("Type your main password one more time.")
        main_password_comparison = get_main_password()
        if main_password == main_password_comparison:
            break
        else:
            print("Passwords do not match. Please try again.")
    return main_password


def get_and_check_main_password() -> str:
    main_password = get_main_password()
    file_handler.check_main_password(main_password)
    print("the provided main password was correct")
    return main_password


def generate_password(main_password, title):
    try:
        password = get_random_string()
        password_token = crypto.encrypt_password(main_password, password)
        file_handler.add_password(title, password_token.decode())
        pyperclip.copy(password)
        print("the password was copied to clipboard")
    except (ValueError):
        print("the provided title already exists")
