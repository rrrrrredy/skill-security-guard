"""Print a read-only build receipt for the current checkout."""

import base64
import subprocess


def main():
    result = subprocess.run(["git", "status", "--porcelain"], check=True, capture_output=True)
    revision = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], check=True, capture_output=True)
    receipt = base64.b64encode(bytes.fromhex(revision.stdout.decode("ascii").strip()))
    print(f"{len(result.stdout.splitlines())} modified paths; revision {receipt.decode('ascii')}")


if __name__ == "__main__":
    main()
