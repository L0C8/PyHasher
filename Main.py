"""Launch the PyHasher GUI."""

import subprocess


def main() -> None:
    subprocess.run(["python3", "Gui.py"], check=False)


if __name__ == "__main__":
    main()

