#!/usr/bin/env python3
"""One-time first-owner bootstrap for locked-down production.

Registration is closed by default (ALLOW_OPEN_REGISTRATION=False) and the
demo seed correctly refuses production. Use this script once to create the
initial owner + organization + project, then sign in via the dashboard.

Usage (on the prod host, after `migrations` has completed):
  docker compose -f compose.yaml -f compose.prod.yaml run --rm web \
    python scripts/bootstrap_admin.py --email admin@example.com --password 'StrongPass123!'

Local dev:
  python scripts/bootstrap_admin.py --email admin@example.com --password 'StrongPass123!'

Safety:
  - Refuses to run when any users already exist unless --force is given
    (prevents accidental second bootstrap overwriting audit history).
  - Never logs or prints the password.
"""

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.session import SessionLocal
from app.models import Organization, OrganizationMember, Project, User
from app.services.security import hash_password


def _valid_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email or ""))


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap the first production owner.")
    parser.add_argument("--email", required=True, help="Owner email (e.g. admin@example.com)")
    parser.add_argument("--password", required=True, help="Owner password (min 8 chars)")
    parser.add_argument("--org-name", default="", help="Organization name (default: '<local-part>'s Org')")
    parser.add_argument("--project-name", default="Default Project", help="Initial project name")
    parser.add_argument("--force", action="store_true", help="Allow bootstrap even if users already exist")
    args = parser.parse_args()

    email = (args.email or "").strip().lower()
    password = args.password or ""
    if not _valid_email(email):
        print("ERROR: --email must be a valid email address.", file=sys.stderr)
        return 1
    if len(password) < 8:
        print("ERROR: --password must be at least 8 characters.", file=sys.stderr)
        return 1
    if len(args.project_name) > 100:
        print("ERROR: --project-name must be <=100 characters.", file=sys.stderr)
        return 1

    db = SessionLocal()
    try:
        existing_count = db.query(User).count()
        if existing_count > 0 and not args.force:
            print(
                f"ERROR: {existing_count} user(s) already exist. Refusing bootstrap "
                "(use --force to create an additional owner).",
                file=sys.stderr,
            )
            return 1
        if db.query(User).filter(User.email == email).first():
            print(f"ERROR: user {email} already exists.", file=sys.stderr)
            return 1

        user = User(email=email, password_hash=hash_password(password))
        db.add(user)
        db.flush()

        org_name = (args.org_name or "").strip() or (email.split("@")[0].capitalize() + "'s Org")
        org = Organization(name=org_name[:255])
        db.add(org)
        db.flush()

        db.add(OrganizationMember(organization_id=org.id, user_id=user.id, role="owner"))
        project = Project(organization_id=org.id, name=(args.project_name.strip() or "Default Project")[:255])
        db.add(project)
        db.commit()
        print(f"Bootstrap complete. Owner {email} created in org '{org.name}' (project '{project.name}').")
        print("Sign in via the dashboard. If ALLOW_OPEN_REGISTRATION was opened, close it now.")
        return 0
    except Exception as e:
        db.rollback()
        print(f"ERROR: bootstrap failed: {e}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
