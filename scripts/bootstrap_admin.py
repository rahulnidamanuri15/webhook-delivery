#!/usr/bin/env python3
"""One-time first-owner bootstrap for locked-down production.

Registration is closed by default (ALLOW_OPEN_REGISTRATION=False) and the
demo seed correctly refuses production. Use this script once to create the
initial owner + organization + project, then sign in via the dashboard.

Usage (on the prod host, after `migrations` has completed):
  docker compose -f compose.yaml -f compose.prod.yaml run --rm web \
    python scripts/bootstrap_admin.py --email admin@example.com --password-file /run/secrets/bootstrap_pw
  # or (interactive, no ps exposure):
  #   python scripts/bootstrap_admin.py --email admin@example.com
  # or via env: BOOTSTRAP_PASSWORD='...' python scripts/bootstrap_admin.py --email ...

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


def _resolve_password(args) -> str:
    # Prefer secure sources over --password (visible in ps/history/CI logs).
    import getpass as _getpass

    if args.password_file:
        try:
            with open(args.password_file, "r", encoding="utf-8") as f:
                val = f.read().strip().splitlines()[0].strip() if f else ""
                if val:
                    return val
        except Exception as e:
            print(f"ERROR: cannot read --password-file: {e}", file=sys.stderr)
            sys.exit(1)
    env_pw = (os.getenv("BOOTSTRAP_PASSWORD", "") or "").strip()
    if env_pw:
        return env_pw
    if args.password:
        print("WARNING: --password is visible in ps/history; prefer --password-file or BOOTSTRAP_PASSWORD.", file=sys.stderr)
        return args.password
    try:
        return _getpass.getpass("Owner password: ").strip()
    except Exception:
        return ""


def _validate_password_policy(password: str) -> str | None:
    # Same policy as dashboard (3-of-4 classes) + reset flow.
    try:
        from app.services.password_reset import validate_new_password as _v

        return _v(password)
    except Exception:
        if len(password) < 8:
            return "Password must be at least 8 characters."
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap the first production owner.")
    parser.add_argument("--email", required=True, help="Owner email (e.g. admin@example.com)")
    parser.add_argument("--password", required=False, default=None, help="Owner password (prefer --password-file)")
    parser.add_argument("--password-file", required=False, default=None, help="File containing owner password")
    parser.add_argument("--org-name", default="", help="Organization name (default: '<local-part>'s Org')")
    parser.add_argument("--project-name", default="Default Project", help="Initial project name")
    parser.add_argument("--force", action="store_true", help="Allow bootstrap even if users already exist")
    args = parser.parse_args()

    email = (args.email or "").strip().lower()
    password = _resolve_password(args) or ""
    if not _valid_email(email):
        print("ERROR: --email must be a valid email address.", file=sys.stderr)
        return 1
    _pw_err = _validate_password_policy(password)
    if _pw_err:
        print(f"ERROR: --password invalid: {_pw_err}", file=sys.stderr)
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
