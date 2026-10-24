import os

import uvicorn

from modules.db import init_db


def main() -> None:
    if len(os.environ.get("MANUAL_FRAMEWORK_API_TOKEN", "")) < 32:
        raise SystemExit(
            "Set MANUAL_FRAMEWORK_API_TOKEN to a random token of at least 32 characters before starting the API."
        )
    port = int(os.environ.get("MANUAL_FRAMEWORK_API_PORT", "8001"))
    if not 1 <= port <= 65535:
        raise SystemExit("MANUAL_FRAMEWORK_API_PORT must be between 1 and 65535.")
    init_db()
    uvicorn.run("api:app", host="127.0.0.1", port=port, access_log=False)


if __name__ == "__main__":
    main()
