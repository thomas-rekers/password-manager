# Password Manager

## Demo

![demo](./docs/demo.gif)

## Requirements and Setup

[cryptography](https://pypi.org/project/cryptography/) and [pyperclip](https://pypi.org/project/pyperclip/) are the only dependencies for this project. You need to define the environment variables `PASSWORD_TOKENS_FILE` and `MAIN_PASSWORD_TOKEN_FILE` that specify the path to the file with the hashed passwords and the file with the hashed main password. Execute `src/main.py` to run the application.
