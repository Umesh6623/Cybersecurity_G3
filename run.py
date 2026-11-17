"""Localhost-only launcher for the IIIT Allahabad Cyber Security (IT-30001) Lab."""

import uvicorn
from app.config import LAB_HOST, LAB_PORT
from app.db import init_db


def main() -> None:
    init_db()
    print(f"[IIITA IT-30001 Lab] Starting on http://{LAB_HOST}:{LAB_PORT} (localhost-only)")
    uvicorn.run("app.main:app", host=LAB_HOST, port=LAB_PORT, reload=False)


if __name__ == "__main__":
    main()
