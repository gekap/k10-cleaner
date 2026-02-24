#!/usr/bin/env python3
# k10-cleaner — Ed25519 license key generator (developer-only)
# Copyright (c) 2026 Georgios Kapellakis
# Licensed under AGPL-3.0 — see LICENSE for details.
#
# Requires: pip install cryptography
#
# Usage:
#   python generate_license.py --generate-keypair   # create new keypair
#   python generate_license.py <fingerprint>         # sign a fingerprint

from __future__ import annotations

import argparse
import base64
import os
import sys


def generate_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    key_path = os.path.expanduser("~/.k10cleaner-signing-key.pem")

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    old_umask = os.umask(0o177)
    try:
        with open(key_path, "wb") as f:
            f.write(pem)
    finally:
        os.umask(old_umask)

    pub_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    print(f"Private key saved to: {key_path}")
    print(f"Public key (hex):     {pub_bytes.hex()}")
    print()
    print("Embed this in k10_cleaner/compliance.py:")
    print(f'_LICENSE_PUBLIC_KEY_HEX = "{pub_bytes.hex()}"')


def sign_fingerprint(fingerprint: str):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key_path = os.path.expanduser("~/.k10cleaner-signing-key.pem")
    if not os.path.exists(key_path):
        print(f"Error: private key not found at {key_path}", file=sys.stderr)
        print("Run: python generate_license.py --generate-keypair", file=sys.stderr)
        sys.exit(1)

    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)

    signature = key.sign(fingerprint.encode())
    encoded = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    license_key = f"k10-{encoded}"

    print(f"Fingerprint: {fingerprint}")
    print(f"License key: {license_key}")
    print()
    print("To activate:")
    print(f"  k10-cleaner --license-key {license_key}")
    print("  # or")
    print(f"  export K10CLEANER_LICENSE_KEY={license_key}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate Ed25519 license keys for k10-cleaner",
    )
    parser.add_argument(
        "--generate-keypair",
        action="store_true",
        help="Generate a new Ed25519 signing keypair",
    )
    parser.add_argument(
        "fingerprint",
        nargs="?",
        help="Cluster fingerprint to sign (from k10-cleaner --show-fingerprint)",
    )

    args = parser.parse_args()

    if args.generate_keypair:
        generate_keypair()
    elif args.fingerprint:
        sign_fingerprint(args.fingerprint)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
