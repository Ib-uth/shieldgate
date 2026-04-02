#!/usr/bin/env python3
"""Create or update a ShieldGate dashboard user in PostgreSQL (e.g. Neon).

Requires DATABASE_URL. Run from repo root::

    DATABASE_URL=postgresql://... .venv/bin/python scripts/seed_admin_user.py \\
        --email you@example.com --password 'your-secret' --role admin
"""

from __future__ import annotations

import argparse
import os
import sys


def main() -> None:
    import bcrypt

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, os.path.join(repo_root, "apps"))

    from gateway.models.database import Base, SessionLocal, User, engine

    parser = argparse.ArgumentParser(
        description="Create or update a bcrypt user row for /auth/login."
    )
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--role", default="admin")
    args = parser.parse_args()

    if engine is None:
        print("DATABASE_URL is not set", file=sys.stderr)
        sys.exit(1)

    Base.metadata.create_all(bind=engine)

    email_key = args.email.strip().lower()
    pwd_hash = bcrypt.hashpw(args.password.encode("utf-8"), bcrypt.gensalt()).decode(
        "utf-8"
    )

    db = SessionLocal()
    try:
        u = db.query(User).filter(User.email == email_key).first()
        if u:
            u.password_hash = pwd_hash
            u.role = args.role
        else:
            u = User(email=email_key, password_hash=pwd_hash, role=args.role)
            db.add(u)
        db.commit()
        print(f"OK: user {u.email!r} role={u.role!r}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
