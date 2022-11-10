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
    salt = os.urandom(16)
    key = password_to_key(main_password, salt, iterations)
    return urlsafe_b64encode(salt + iterations.to_bytes(4, "big") + key)


def verify_main_password(main_password: str, hashed_main_password: bytes) -> bool:
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
