import os
import random
import string

from cryptography.fernet import Fernet

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from base64 import urlsafe_b64decode, urlsafe_b64encode

import csv

from cli import get_args, get_main_password

DEFAULT_ITERATIONS = 390000
ROUNDS = 12
DEFAULT_PASSWORD_LENGTH = 16
SPECIAL_CHARACTERS = "}{[]|,.;:/!*#?+-_=~^%()"

PASSWORD_TOKENS_FILE = "password_tokens.csv"
MAIN_PASSWORD_TOKEN_FILE = "main_password_token.csv"


def generate_password(length=DEFAULT_PASSWORD_LENGTH):
    character_string = (
        string.ascii_lowercase
        + string.ascii_uppercase
        + string.digits
        + SPECIAL_CHARACTERS
    )
    return "".join(random.choice(character_string) for _ in range(length))


def hash_main_password(
    main_password: str, iterations: int = DEFAULT_ITERATIONS
) -> bytes:
    salt = os.urandom(16)
    key = password_to_key(main_password, salt, iterations)
    return urlsafe_b64encode(salt + iterations.to_bytes(4, "big") + key)


def verify_main_password(main_password: str, hashed_main_password) -> bool:
    decoded_token = urlsafe_b64decode(hashed_main_password)
    salt = decoded_token[:16]
    iterations = int.from_bytes(decoded_token[16:20], "big")
    main_password_token = urlsafe_b64encode(decoded_token[20:])
    PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    ).verify(main_password.encode(), urlsafe_b64decode(main_password_token))


def password_to_key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode())


def encrypt_text(
    password: str, message: str, iterations: int = DEFAULT_ITERATIONS
) -> bytes:
    salt = os.urandom(16)
    key = password_to_key(password, salt, iterations)
    return urlsafe_b64encode(
        salt
        + iterations.to_bytes(4, "big")
        + urlsafe_b64decode(Fernet(urlsafe_b64encode(key)).encrypt(message.encode()))
    )


def decrypt_text(password: str, token: bytes) -> str:
    decoded_token = urlsafe_b64decode(token)
    salt = decoded_token[:16]
    iterations = int.from_bytes(decoded_token[16:20], "big")
    message_token = urlsafe_b64encode(decoded_token[20:])
    key = password_to_key(password, salt, iterations)
    return Fernet(urlsafe_b64encode(key)).decrypt(message_token).decode()


def is_duplicate(title: str) -> bool:
    with open(PASSWORD_TOKENS_FILE, "r") as f:
        for row in csv.reader(f):
            if row[0] == title:
                return True
    return False


def add_password(title: str, password: str):
    if is_duplicate(title):
        raise ValueError("title already exists")
    with open(PASSWORD_TOKENS_FILE, "a") as f:
        csv.writer(f).writerow([title, password])


def get_password(title: str) -> str:
    with open(PASSWORD_TOKENS_FILE, "r") as f:
        for row in csv.reader(f):
            if row[0] == title:
                return row[1]
    raise ValueError("no password found for this title")


def list_titles() -> list[str]:
    with open(PASSWORD_TOKENS_FILE, "r") as f:
        for row in csv.reader(f):
            yield row[0]


def store_main_password(main_password: str):
    hashed_main_password = hash_main_password(main_password)
    with open(MAIN_PASSWORD_TOKEN_FILE, "r") as f:
        if f.readline():
            print("main password was already defined")
            exit(1)
    with open(MAIN_PASSWORD_TOKEN_FILE, "w") as f:
        f.write(hashed_main_password.decode())


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


def main():
    cli_args = get_args()
    mode, title, password = [cli_args.mode, cli_args.title, cli_args.password]

    if mode == "get":
        try:
            main_password = get_main_password()
            password_token = get_password(title).encode()
            password = decrypt_text(main_password, password_token)
            print(password)
        except (ValueError):
            print("no password found for this title")

    if mode == "set":
        try:
            main_password = get_main_password()
            password_token = encrypt_text(main_password, password)
            add_password(title, password_token.decode())
            print("password was set successfully")
        except (ValueError):
            print("the provided title already exists")

    if mode == "generate":
        try:
            main_password = get_main_password()
            password = generate_password()
            password_token = encrypt_text(main_password, password)
            add_password(title, password_token.decode())
            print(f"your new password: {password}")
        except (ValueError):
            print("the provided title already exists")

    if mode == "update":
        pass

    if mode == "list":
        for title in list_titles():
            print(title)

    if mode == "delete":
        pass

    if mode == "init":
        main_password = define_main_password()
        store_main_password(main_password)
        print("main password was stored successfully")


if __name__ == "__main__":
    main()
