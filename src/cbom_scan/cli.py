"""cbom-scan command line."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .output import to_cbom, to_markdown, to_sarif, to_text, write_json
from .scanner import Inventory, scan_path
from .score import compute


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cbom-scan",
        description="Find the cryptography in code, configs, certificates and TLS endpoints; produce a CycloneDX "
                    "CBOM and a post-quantum readiness score.")
    p.add_argument("paths", nargs="*", help="directories or files to scan (default: current directory)")
    p.add_argument("--tls", action="append", default=[], metavar="HOST[:PORT]", help="also probe a live TLS endpoint (repeatable)")
    p.add_argument("--cbom", metavar="FILE", help="write a CycloneDX 1.6 CBOM (JSON)")
    p.add_argument("--sarif", metavar="FILE", help="write SARIF 2.1.0 for GitHub code scanning")
    p.add_argument("--markdown", metavar="FILE", help="write a Markdown report")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths matching this glob (repeatable)")
    p.add_argument("--name", help="project name for the reports (default: directory name)")
    p.add_argument("--fail-under", type=int, metavar="SCORE", help="exit 1 if the readiness score is below SCORE (for CI)")
    p.add_argument("--fail-on-broken", action="store_true", help="exit 1 if any broken algorithm or error-level issue is found")
    p.add_argument("-q", "--quiet", action="store_true", help="do not print the summary")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=__version__)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    paths = a.paths or ([] if a.tls else ["."])
    inv = Inventory()
    for path in paths:
        if not Path(path).exists():
            print(f"cbom-scan: {path}: no such file or directory", file=sys.stderr)
            return 2
        scan_path(path, inv, a.exclude)
    if a.tls:
        from .tls import probe
        for endpoint in a.tls:
            probe(inv, endpoint)
    score = compute(inv)
    name = a.name or (Path(paths[0]).resolve().name if paths else a.tls[0])

    if a.cbom:
        write_json(to_cbom(inv, score, name), a.cbom)
    if a.sarif:
        write_json(to_sarif(inv), a.sarif)
    if a.markdown:
        Path(a.markdown).write_text(to_markdown(inv, score, name))
    if not a.quiet:
        print(to_text(inv, score, color=False if a.no_color else None))
        written = [f for f in (a.cbom, a.sarif, a.markdown) if f]
        if written:
            print("\nWrote " + ", ".join(written))

    if a.fail_under is not None and score.value < a.fail_under:
        print(f"cbom-scan: readiness {score.value} is below --fail-under {a.fail_under}", file=sys.stderr)
        return 1
    if a.fail_on_broken and (score.broken or score.errors):
        print("cbom-scan: broken cryptography or error-level issues found", file=sys.stderr)
        return 1
    return 0
