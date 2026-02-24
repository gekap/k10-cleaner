# k10-cleaner — Pure-Python Ed25519 signature verification (RFC 8032 §5.1)
# Copyright (c) 2026 Georgios Kapellakis
# Licensed under AGPL-3.0 — see LICENSE for details.
#
# Verify-only: no key generation or signing.  Zero external dependencies.
# Used as fallback when the ``cryptography`` package is unavailable.

from __future__ import annotations

import hashlib

# ---------------------------------------------------------------------------
# Field and curve constants
# ---------------------------------------------------------------------------

_P = 2**255 - 19  # field prime
_D = -121665 * pow(121666, _P - 2, _P) % _P  # curve parameter d
_L = 2**252 + 27742317777372353535851937790883648493  # base-point order
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)  # sqrt(-1) mod p

# ---------------------------------------------------------------------------
# Extended-coordinate point arithmetic on  -x² + y² = 1 + d·x²·y²
#
# Representation: (X, Y, Z, T) with  x = X/Z,  y = Y/Z,  x·y = T/Z
# ---------------------------------------------------------------------------

_ZERO = (0, 1, 1, 0)  # identity element


def _point_add(P, Q):
    """Unified addition (a = -1 twisted Edwards, extended coords)."""
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = X1 * X2 % _P
    B = Y1 * Y2 % _P
    C = T1 * _D % _P * T2 % _P
    D_ = Z1 * Z2 % _P
    E = ((X1 + Y1) * (X2 + Y2) - A - B) % _P
    F = (D_ - C) % _P
    G = (D_ + C) % _P
    H = (B + A) % _P  # -a·A = A  since a = -1
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _point_double(P):
    """Dedicated doubling (a = -1 twisted Edwards, extended coords)."""
    X1, Y1, Z1, _ = P
    A = X1 * X1 % _P
    B = Y1 * Y1 % _P
    C = 2 * Z1 * Z1 % _P
    D_ = (_P - A) % _P  # a·X² = -X²
    E = ((X1 + Y1) * (X1 + Y1) - A - B) % _P
    G = (D_ + B) % _P
    F = (G - C) % _P
    H = (D_ - B) % _P
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _scalar_mult(s: int, P):
    """Double-and-add scalar multiplication."""
    Q = _ZERO
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_double(P)
        s >>= 1
    return Q


# ---------------------------------------------------------------------------
# Encoding / decoding (RFC 8032 §5.1.2 – §5.1.3)
# ---------------------------------------------------------------------------

def _point_decode(bs: bytes):
    """Decode 32-byte compressed Edwards point → extended coords."""
    if len(bs) != 32:
        raise ValueError("point must be 32 bytes")
    y = int.from_bytes(bs, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        raise ValueError("y >= p")

    # x² = (y² - 1) / (d·y² + 1)
    y2 = y * y % _P
    u = (y2 - 1) % _P
    v = (y2 * _D + 1) % _P

    # x = u·v³ · (u·v⁷)^((p-5)/8)
    v3 = v * v % _P * v % _P
    v7 = v3 * v3 % _P * v % _P
    x = u * v3 % _P * pow(u * v7 % _P, (_P - 5) // 8, _P) % _P

    if (v * x * x - u) % _P != 0:
        if (v * x * x + u) % _P != 0:
            raise ValueError("not on curve")
        x = x * _SQRT_M1 % _P

    if x == 0 and sign:
        raise ValueError("x is zero but sign bit is set")
    if x & 1 != sign:
        x = _P - x

    return (x, y, 1, x * y % _P)


def _point_encode(P) -> bytes:
    """Encode extended-coords point → 32 bytes."""
    X, Y, Z, _ = P
    zi = pow(Z, _P - 2, _P)
    x = X * zi % _P
    y = Y * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


# ---------------------------------------------------------------------------
# Base point  B = (x, 4/5)  where x is even ("positive")
# ---------------------------------------------------------------------------

def _compute_base_point():
    By = 4 * pow(5, _P - 2, _P) % _P
    # By < 2^255, so top bit is 0 → sign bit = 0 → x will be even
    return _point_decode(By.to_bytes(32, "little"))


_B = _compute_base_point()

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify an Ed25519 signature (RFC 8032 §5.1.7).

    Args:
        public_key: 32-byte public key
        signature:  64-byte signature  (R ‖ S)
        message:    arbitrary-length message

    Returns:
        True if the signature is valid, False otherwise.
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False

    try:
        A = _point_decode(public_key)
    except ValueError:
        return False

    R_bytes = signature[:32]
    S_bytes = signature[32:]

    try:
        R = _point_decode(R_bytes)
    except ValueError:
        return False

    S = int.from_bytes(S_bytes, "little")
    if S >= _L:
        return False

    # k = SHA-512(R ‖ A ‖ M) mod l
    k = int.from_bytes(
        hashlib.sha512(R_bytes + public_key + message).digest(), "little"
    ) % _L

    # Verify: [S]B == R + [k]A
    SB = _scalar_mult(S, _B)
    kA = _scalar_mult(k, A)
    RkA = _point_add(R, kA)

    return _point_encode(SB) == _point_encode(RkA)


# ---------------------------------------------------------------------------
# Self-test against RFC 8032 §7.1 test vectors (runs once at import time)
# ---------------------------------------------------------------------------

def _self_test():
    # Test vector 1: empty message
    pk = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a"
        "0ee172f3daa62325af021a68f707511a"
    )
    sig = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b"
    )
    assert verify(pk, sig, b""), "Ed25519 self-test FAILED: RFC 8032 test vector 1"

    # Negative test: flipped bit must fail
    bad_sig = bytearray(sig)
    bad_sig[0] ^= 0x01
    assert not verify(pk, bytes(bad_sig), b""), "Ed25519 self-test FAILED: bad signature accepted"


_self_test()
