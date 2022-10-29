import os

from cryptography.fernet import Fernet

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from base64 import urlsafe_b64decode, urlsafe_b64encode

import csv

DEFAULT_ITERATIONS = 390000

PASSWORD_TOKENS_FILE = "password_tokens.csv"


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


def is_duplicate(title):
    with open(PASSWORD_TOKENS_FILE, "r") as f:
        for row in csv.reader(f):
            if row[0] == title:
                return True
    return False


def add_password(title, password):
    if is_duplicate(title):
        raise ValueError("title already exists")
    with open(PASSWORD_TOKENS_FILE, "a") as f:
        csv.writer(f).writerow([title, password])


def get_password(title):
    with open(PASSWORD_TOKENS_FILE, "r") as f:
        for row in csv.reader(f):
            if row[0] == title:
                return row[1]
    raise ValueError("no password found for this title")


def main():
    main_password = "main"
    title = "title"
    password = "password"

    # create new password
    password_token = encrypt_text(main_password, password)
    add_password(title, password_token.decode())

    # extract password
    password_token = get_password(title).encode()
    password = decrypt_text(main_password, password_token)
    print(password)


if __name__ == "__main__":
    main()
