from cli import get_args
import modes


def main():
    cli_args = get_args()
    getattr(modes, cli_args.mode)(cli_args)


if __name__ == "__main__":
    main()
