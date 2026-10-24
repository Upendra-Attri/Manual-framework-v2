import os
import subprocess
import sys
import time

from modules.db import init_db


def main() -> int:
    if len(os.environ.get("MANUAL_FRAMEWORK_API_TOKEN", "")) < 32:
        print(
            "Set MANUAL_FRAMEWORK_API_TOKEN to a random token of at least 32 characters before starting.",
            file=sys.stderr,
        )
        return 2

    api_port = os.environ.get("MANUAL_FRAMEWORK_API_PORT", "8001")
    try:
        api_port_number = int(api_port)
    except ValueError:
        print("MANUAL_FRAMEWORK_API_PORT must be a number.", file=sys.stderr)
        return 2
    if not 1 <= api_port_number <= 65535:
        print("MANUAL_FRAMEWORK_API_PORT must be between 1 and 65535.", file=sys.stderr)
        return 2
    init_db()
    processes = [
        subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "api:app", "--host", "127.0.0.1", "--port", api_port, "--no-access-log"]
        ),
        subprocess.Popen(
            [sys.executable, "-m", "streamlit", "run", "main.py"]
        ),
    ]
    try:
        while True:
            for process in processes:
                return_code = process.poll()
                if return_code is not None:
                    return return_code
            time.sleep(0.25)
    except KeyboardInterrupt:
        return 0
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    raise SystemExit(main())
