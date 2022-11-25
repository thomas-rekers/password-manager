import os
import csv

import crypto


PASSWORD_TOKENS_FILE = os.getenv("PASSWORD_TOKENS_FILE")
MAIN_PASSWORD_TOKEN_FILE = os.getenv("MAIN_PASSWORD_TOKEN_FILE")


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
    hashed_main_password = crypto.hash_main_password(main_password)
    with open(MAIN_PASSWORD_TOKEN_FILE, "r") as f:
        if f.readline():
            print("main password was already defined")
            exit(1)
    with open(MAIN_PASSWORD_TOKEN_FILE, "w") as f:
        f.write(hashed_main_password.decode())


def check_main_password(main_password: str):
    with open(MAIN_PASSWORD_TOKEN_FILE, "r") as f:
        main_password_token = f.readline()
        if not main_password_token:
            print("no main password defined yet")
            exit(1)
        try:
            crypto.verify_main_password(main_password, main_password_token.encode())
        except:
            print("invalid main password")
            exit(1)


def update_password(main_password: str, title: str, password: str):
    rows = []
    title_exists = False
    with open(PASSWORD_TOKENS_FILE, "r") as f:
        for row in csv.reader(f):
            if row[0] == title:
                row[1] = crypto.encrypt_password(main_password, password).decode()
                title_exists = True
            rows.append(row)
        if not title_exists:
            print("no matching title found")
            exit(1)
    with open(PASSWORD_TOKENS_FILE, "w") as f:
        csv.writer(f).writerows(rows)
    print("update was successful")


def delete_password(title: str):
    rows = []
    title_exists = False
    with open(PASSWORD_TOKENS_FILE, "r") as f:
        for row in csv.reader(f):
            if row[0] == title:
                title_exists = True
                continue
            else:
                rows.append(row)
        if not title_exists:
            print("no matching title found")
            exit(1)
    with open(PASSWORD_TOKENS_FILE, "w") as f:
        csv.writer(f).writerows(rows)
    print("deletion was successful")
