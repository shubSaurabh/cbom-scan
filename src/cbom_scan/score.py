"""PQC readiness score: a transparent 0-100 number so teams can track migration progress over time.

    start at 100
    -15 per distinct broken algorithm family        (MD5, SHA-1, DES, RC4, RSA-1024, ECB...)  max -45
    -10 per distinct quantum-vulnerable family      (RSA, ECDSA, ECDH, EdDSA, DH)             max -40
     -3 per distinct quantum-weakened family        (AES-128, HMAC-SHA1)                      max  -9
    -10 per security issue of severity "error"      (legacy TLS, verification off, keys)      max -20
     +10 if post-quantum or hybrid algorithms are already in use (never above 100)
"""
from __future__ import annotations

from dataclasses import dataclass

from . import algorithms as A
from .scanner import Inventory

GRADES = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]


@dataclass
class Score:
    value: int
    grade: str
    broken: list[str]
    vulnerable: list[str]
    weakened: list[str]
    pqc: list[str]
    errors: int
    breakdown: list[tuple[str, int]]


def _family(a: A.Algorithm) -> str:
    if a.family in ("EC", "ECDSA", "ECDH", "EdDSA"):
        return a.family if a.family != "EC" else "ECC"
    return a.family


def compute(inv: Inventory) -> Score:
    fams: dict[str, set[str]] = {A.BROKEN: set(), A.VULNERABLE: set(), A.WEAKENED: set()}
    pqc = set()
    for asset in inv.algorithms():
        a = asset.algorithm
        if a.status in fams:
            fams[a.status].add(a.name if a.status == A.BROKEN else _family(a))
        if a.is_pqc or a.hybrid:
            pqc.add(a.name)
    # a family counted as broken (e.g. RSA-1024) still counts as quantum-vulnerable too, that is intentional
    errors = sum(1 for i in inv.issues if i.severity == "error")
    breakdown = [
        ("broken algorithms", -min(45, 15 * len(fams[A.BROKEN]))),
        ("quantum-vulnerable families", -min(40, 10 * len(fams[A.VULNERABLE]))),
        ("quantum-weakened families", -min(9, 3 * len(fams[A.WEAKENED]))),
        ("security issues", -min(20, 10 * errors)),
    ]
    if pqc:
        breakdown.append(("post-quantum in use", 10))
    value = max(0, min(100, 100 + sum(v for _, v in breakdown)))
    grade = next(g for t, g in GRADES if value >= t)
    return Score(value, grade, sorted(fams[A.BROKEN]), sorted(fams[A.VULNERABLE]), sorted(fams[A.WEAKENED]),
                 sorted(pqc), errors, breakdown)
