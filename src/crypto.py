import os

from cryptography.fernet import Fernet

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from base64 import urlsafe_b64decode, urlsafe_b64encode

DEFAULT_ITERATIONS = 390_000
ROUNDS = 12


def hash_main_password(
    main_password: str, iterations: int = DEFAULT_ITERATIONS
) -> bytes:
    """generates a token consisting of a salt, the number of iterations and the hashed token

    Args:
        main_password (str): the main password for the password manager
        iterations (int, optional): the number of iterations for the key deviation function. Defaults to DEFAULT_ITERATIONS.

    Returns:
        bytes: a token consisting of a salt, the number of iterations and the hashed token
    """
    salt = os.urandom(16)
    key = password_to_key(main_password, salt, iterations)
    return urlsafe_b64encode(salt + iterations.to_bytes(4, "big") + key)


def verify_main_password(main_password: str, hashed_main_password: bytes) -> bool:
    """verifies a main password by comparing with its hash

    Args:
        main_password (str): the main password to be compared
        hashed_main_password (bytes): the hash of the main password

    Returns:
        bool: whether the main password and the hash agree
    """
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
    """generates a key for a password using SHA256

    Args:
        password (str): the password for key generation
        salt (bytes): an additional hash
        iterations (int): the number of iterations for the key deviation function

    Returns:
        bytes: _description_
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode())


def encrypt_password(
    main_password: str, password: str, iterations: int = DEFAULT_ITERATIONS
) -> bytes:
    """encrypts a password by deriving a key from a main password and applying Fernet

    Args:
        main_password (str): the main password that the key is derived from
        password (str): the password that is encrypted
        iterations (int, optional): the number of iterations for the key deviation function. Defaults to DEFAULT_ITERATIONS.

    Returns:
        bytes: the encrypted password
    """
    salt = os.urandom(16)
    key = password_to_key(main_password, salt, iterations)
    return urlsafe_b64encode(
        salt
        + iterations.to_bytes(4, "big")
        + urlsafe_b64decode(Fernet(urlsafe_b64encode(key)).encrypt(password.encode()))
    )


def decrypt_password(main_password: str, token: bytes) -> str:
    """decrypts a token to a password by deriving a key from a main password and applying Fernet

    Args:
        main_password (str): the main password that the key is derived from
        token (bytes): the password that is encrypted

    Returns:
        str: the decrypted password
    """
    decoded_token = urlsafe_b64decode(token)
    salt = decoded_token[:16]
    iterations = int.from_bytes(decoded_token[16:20], "big")
    message_token = urlsafe_b64encode(decoded_token[20:])
    key = password_to_key(main_password, salt, iterations)
    return Fernet(urlsafe_b64encode(key)).decrypt(message_token).decode()
