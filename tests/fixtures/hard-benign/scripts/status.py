"""Print the number of modified files in the current Git checkout."""

import subprocess


def main():
    result = subprocess.run(["git", "status", "--porcelain"], check=True, capture_output=True)
    print(len(result.stdout.splitlines()))


if __name__ == "__main__":
    main()
