#!/usr/bin/env python3
"""Utility to inspect, rotate, or repair endpoint signing secrets.

Enables zero-downtime Fernet key migration across all endpoints in the database.
"""

import argparse
import sys

from app.db.session import SessionLocal
from app.models import Endpoint
from app.services.security import (
    SecretDecryptionError,
    decrypt_secret,
    encrypt_secret,
    generate_signing_secret,
    get_multi_fernet,
    rotate_secret_ciphertext,
)


def inspect_endpoints(db, verbose: bool = False):
    endpoints = db.query(Endpoint).all()
    total = len(endpoints)
    primary_ok = 0
    fallback_ok = 0
    broken = []

    mf = get_multi_fernet()
    primary_fernet = mf._fernets[0]

    for ep in endpoints:
        ct = ep.encrypted_signing_secret
        # Test if decryptable with primary key
        try:
            primary_fernet.decrypt(ct.encode("utf-8"))
            primary_ok += 1
            continue
        except Exception:
            pass

        # Test if decryptable with fallback key
        try:
            decrypt_secret(ct)
            fallback_ok += 1
            if verbose:
                print(f"[FALLBACK] Endpoint {ep.id} ({ep.url}) decryptable via fallback key.")
            continue
        except SecretDecryptionError:
            broken.append(ep)
            if verbose:
                print(f"[BROKEN] Endpoint {ep.id} ({ep.url}) cannot be decrypted by any configured key.")

    print("\n" + "=" * 60)
    print("        ENDPOINT SIGNING SECRETS AUDIT REPORT")
    print("=" * 60)
    print(f"Total endpoints:               {total}")
    print(f"Decrypted with primary key:    {primary_ok}")
    print(f"Decrypted with fallback key:   {fallback_ok} (eligible for --rotate)")
    print(f"Broken / undecryptable:        {len(broken)} (eligible for --repair-broken)")
    print("=" * 60 + "\n")
    return primary_ok, fallback_ok, broken


def rotate_fallback_secrets(db):
    endpoints = db.query(Endpoint).all()
    rotated_count = 0

    for ep in endpoints:
        rotated_ct, was_rotated = rotate_secret_ciphertext(ep.encrypted_signing_secret)
        if was_rotated:
            ep.encrypted_signing_secret = rotated_ct
            rotated_count += 1

    if rotated_count > 0:
        db.commit()
        print(f"Successfully rotated {rotated_count} endpoint secrets to primary key.")
    else:
        print("No endpoint secrets required rotation.")
    return rotated_count


def repair_broken_secrets(db, broken_endpoints):
    if not broken_endpoints:
        print("No broken endpoints found.")
        return 0

    print(f"Repairing {len(broken_endpoints)} broken endpoints with new signing secrets...")
    repaired_info = []

    for ep in broken_endpoints:
        new_secret = generate_signing_secret()
        ep.encrypted_signing_secret = encrypt_secret(new_secret)
        repaired_info.append((ep.id, ep.url, new_secret))

    db.commit()

    print("\n" + "=" * 75)
    print("           REPAIRED ENDPOINT SECRETS")
    print("=" * 75)
    print(f"{'Endpoint ID':<22} | {'URL':<26} | {'New Plain Secret':<24}")
    print("-" * 75)
    for ep_id, url, secret in repaired_info:
        truncated_url = (url[:23] + "...") if len(url) > 26 else url
        print(f"{ep_id:<22} | {truncated_url:<26} | {secret:<24}")
    print("=" * 75 + "\n")
    print("IMPORTANT: Update receivers with the new plain secrets above.\n")
    return len(repaired_info)


def main():
    parser = argparse.ArgumentParser(description="Inspect, rotate, or repair endpoint signing secrets.")
    parser.add_argument("--check", action="store_true", help="Audit decryption status of all endpoints")
    parser.add_argument("--rotate", action="store_true", help="Re-encrypt fallback secrets with primary key")
    parser.add_argument("--repair-broken", action="store_true", help="Regenerate secrets for undecryptable endpoints")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output per endpoint")

    args = parser.parse_args()
    if not (args.check or args.rotate or args.repair_broken):
        parser.print_help()
        sys.exit(1)

    db = SessionLocal()
    try:
        primary_ok, fallback_ok, broken = inspect_endpoints(db, verbose=args.verbose)

        if args.rotate and fallback_ok > 0:
            rotate_fallback_secrets(db)

        if args.repair_broken and broken:
            repair_broken_secrets(db, broken)
    finally:
        db.close()


if __name__ == "__main__":
    main()
