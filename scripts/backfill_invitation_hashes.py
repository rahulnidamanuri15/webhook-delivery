#!/usr/bin/env python3
"""One-time backfill: hash legacy raw invitation tokens at rest.

Before hash-only lookup, OrganizationInvitation.token could hold raw
token_urlsafe values (via old model default). After the fix, lookup is
hash-only, so raw rows would be orphaned. This script hashes any non-hex
token in place.

Usage:
  python scripts/backfill_invitation_hashes.py [--dry-run]

Safe to re-run (idempotent: skips 64-char hex digests).
"""
import os
import re
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def main() -> int:
    dry = "--dry-run" in sys.argv
    from app.db.session import SessionLocal
    from app.models.invitation import OrganizationInvitation
    from app.services.security import hash_invitation_token

    db = SessionLocal()
    try:
        rows = db.query(OrganizationInvitation).all()
        to_fix = [r for r in rows if not (r.token and _HEX64.match(r.token.strip()))]
        print(f"Found {len(rows)} invitations, {len(to_fix)} need hashing.")
        if dry:
            for r in to_fix:
                print(f"  would hash {r.id} email={r.email}")
            return 0
        for r in to_fix:
            try:
                r.token = hash_invitation_token(r.token)
            except Exception as e:
                print(f"  skip {r.id}: {e}", file=sys.stderr)
        db.commit()
        print(f"Backfilled {len(to_fix)} invitation token(s).")
        return 0
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        print(f"ERROR: backfill failed: {e}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
