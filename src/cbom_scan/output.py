"""Renders an inventory as a CycloneDX 1.6 CBOM, SARIF 2.1.0 (GitHub code scanning), Markdown or terminal text."""
from __future__ import annotations

import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from . import algorithms as A
from .scanner import Asset, Inventory
from .score import Score

TOOL_URL = "https://github.com/shubSaurabh/cbom-scan"
FUNCTIONS = {"keygen": "keygen", "encrypt": "encrypt", "digest": "digest", "sign": "sign", "mac": "tag",
             "keyagree": "keyderive", "keyderive": "keyderive"}
MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"}
STATUS_LABEL = {A.BROKEN: "Broken", A.VULNERABLE: "Quantum-vulnerable", A.WEAKENED: "Quantum-weakened", A.SAFE: "OK"}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9.+-]+", "-", text.lower()).strip("-")[:80]


def bom_ref(asset: Asset) -> str:
    return f"crypto/{asset.kind}/{_slug(asset.name)}"


def _alg_ref(inv: Inventory, name: str) -> str | None:
    a = inv.assets.get(f"algorithm:{name}")
    return bom_ref(a) if a else None


def _recommendation(a: A.Algorithm) -> str:
    return a.note if a.status == A.BROKEN and a.note else A.RECOMMENDATIONS.get(a.family, a.note)


# ---- CycloneDX ----------------------------------------------------------------------------------
def to_cbom(inv: Inventory, score: Score, project: str) -> dict:
    components = []
    for asset in sorted(inv.assets.values(), key=lambda x: (x.kind, x.name)):
        comp: dict = {"type": "cryptographic-asset", "bom-ref": bom_ref(asset), "name": asset.name}
        props = [{"name": "cbom-scan:status", "value": asset.status}]
        if asset.kind == "algorithm":
            a = asset.algorithm
            ap: dict = {"primitive": a.primitive}
            if a.parameter_set or a.key_size:
                ap["parameterSetIdentifier"] = str(a.parameter_set or a.key_size)
            if a.curve:
                ap["curve"] = a.curve
            if a.mode:
                ap["mode"] = a.mode if a.mode in MODES else "other"
            funcs = sorted({FUNCTIONS.get(f, "other") for f in a.functions if f})
            if funcs:
                ap["cryptoFunctions"] = funcs
            if a.classical_bits:
                ap["classicalSecurityLevel"] = a.classical_bits
            if a.nist_level is not None:
                ap["nistQuantumSecurityLevel"] = a.nist_level
            comp["cryptoProperties"] = {"assetType": "algorithm", "algorithmProperties": ap}
            if a.oid:
                comp["cryptoProperties"]["oid"] = a.oid
            rec = _recommendation(a)
            if rec and a.status != A.SAFE:
                props.append({"name": "cbom-scan:recommendation", "value": rec})
        elif asset.kind == "certificate":
            p = asset.properties
            cp = {"subjectName": p["subject"], "issuerName": p["issuer"], "notValidBefore": p["not_before"],
                  "notValidAfter": p["not_after"], "certificateFormat": p["format"]}
            refs = [r for r in (_alg_ref(inv, n) for n in asset.refs) if r]
            if refs:
                cp["subjectPublicKeyRef"] = refs[0]
            if len(refs) > 1:
                cp["signatureAlgorithmRef"] = refs[1]
            comp["cryptoProperties"] = {"assetType": "certificate", "certificateProperties": cp}
        elif asset.kind == "related-crypto-material":
            p = asset.properties
            rp = {"type": p["type"], "format": p["format"]}
            if p.get("size"):
                rp["size"] = p["size"]
            ref = _alg_ref(inv, asset.refs[0]) if asset.refs else None
            if ref:
                rp["algorithmRef"] = ref
            comp["cryptoProperties"] = {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": rp}
        elif asset.kind == "protocol":
            p = asset.properties
            pp: dict = {"type": "tls", "version": p.get("version", "")}
            if p.get("cipher_suite"):
                refs = [r for r in (_alg_ref(inv, n) for n in asset.refs) if r]
                pp["cipherSuites"] = [{"name": p["cipher_suite"], "algorithms": refs}]
            comp["cryptoProperties"] = {"assetType": "protocol", "protocolProperties": pp}
            props += [{"name": f"cbom-scan:{k}", "value": str(v)} for k, v in p.items()
                      if k in ("endpoint", "group", "pq_key_exchange", "legacy_protocols")]
        if asset.occurrences:
            comp["evidence"] = {"occurrences": [
                {"location": o.path, **({"line": o.line} if o.line > 0 else {}), "additionalContext": o.snippet}
                for o in asset.occurrences[:200]]}
        comp["properties"] = props
        components.append(comp)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "cbom-scan", "version": __version__,
                                      "externalReferences": [{"type": "website", "url": TOOL_URL}]}]},
            "component": {"type": "application", "bom-ref": "target", "name": project},
            "properties": [{"name": "cbom-scan:pqc-readiness-score", "value": str(score.value)},
                           {"name": "cbom-scan:pqc-readiness-grade", "value": score.grade}],
        },
        "components": components,
        "dependencies": [{"ref": "target", "dependsOn": [c["bom-ref"] for c in components]}],
    }


# ---- SARIF --------------------------------------------------------------------------------------
SARIF_RULES = {
    "broken-algorithm": ("error", "Broken or deprecated cryptography", "Replace this algorithm now; it is weak even without a quantum computer."),
    "quantum-vulnerable-algorithm": ("warning", "Quantum-vulnerable cryptography", "Shor's algorithm breaks this. Add it to your PQC migration plan (ML-KEM, ML-DSA, hybrids)."),
    "quantum-weakened-algorithm": ("note", "Quantum-weakened cryptography", "Grover's algorithm halves its strength. Prefer 256-bit symmetric keys for long-lived data."),
}


def to_sarif(inv: Inventory) -> dict:
    results, rule_ids = [], {}
    for asset in inv.algorithms():
        a = asset.algorithm
        rid = {A.BROKEN: "broken-algorithm", A.VULNERABLE: "quantum-vulnerable-algorithm",
               A.WEAKENED: "quantum-weakened-algorithm"}.get(a.status)
        if not rid:
            continue
        rule_ids[rid] = SARIF_RULES[rid]
        msg = f"{a.name} ({STATUS_LABEL[a.status].lower()}). {_recommendation(a) or ''}".strip()
        for o in asset.occurrences:
            results.append(_sarif_result(rid, SARIF_RULES[rid][0], msg, o.path, o.line))
    for i in inv.issues:
        rule_ids.setdefault(i.rule, (i.severity, i.rule.replace("-", " ").capitalize(), i.message))
        results.append(_sarif_result(i.rule, i.severity, i.message, i.path, i.line))
    rules = [{"id": rid, "name": rid, "shortDescription": {"text": title}, "fullDescription": {"text": desc},
              "defaultConfiguration": {"level": level}, "helpUri": TOOL_URL}
             for rid, (level, title, desc) in sorted(rule_ids.items())]
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "cbom-scan", "version": __version__, "informationUri": TOOL_URL,
                                          "rules": rules}}, "results": results}]}


def _sarif_result(rule: str, level: str, msg: str, path: str, line: int) -> dict:
    if path.startswith("tls://"):
        loc = {"physicalLocation": {"artifactLocation": {"uri": path}}}
    else:
        loc = {"physicalLocation": {"artifactLocation": {"uri": path}, "region": {"startLine": max(1, line)}}}
    return {"ruleId": rule, "level": level, "message": {"text": msg}, "locations": [loc]}


# ---- Markdown ---------------------------------------------------------------------------------
def _loc(path: str, line: int) -> str:
    return path if line <= 0 else f"{path}:{line}"


def _first(asset: Asset) -> str:
    if not asset.occurrences:
        return ""
    o = asset.occurrences[0]
    more = f" (+{len(asset.occurrences) - 1})" if len(asset.occurrences) > 1 else ""
    return f"`{_loc(o.path, o.line)}`{more}"


def to_markdown(inv: Inventory, score: Score, project: str) -> str:
    algs = sorted(inv.algorithms(), key=lambda x: (A.STATUS_ORDER[x.status], x.name))
    out = [f"# Cryptography inventory: {project}", "",
           f"**PQC readiness: {score.value}/100 (grade {score.grade})** · {inv.files_scanned} files scanned · "
           f"{len(algs)} algorithms · {sum(1 for a in inv.assets.values() if a.kind == 'certificate')} certificates · "
           f"{len(inv.issues)} issues", ""]
    out += ["| Score component | Points |", "|---|---:|"] + [f"| {k} | {v:+d} |" for k, v in score.breakdown] + [""]

    fix_now = [a for a in algs if a.status == A.BROKEN]
    errors = [i for i in inv.issues if i.severity == "error"]
    if fix_now or errors:
        out += ["## Fix now", ""]
        out += [f"- **{a.name}**: {_recommendation(a.algorithm)} {_first(a)}" for a in fix_now]
        out += [f"- **{i.rule}**: {i.message} `{_loc(i.path, i.line)}`" for i in errors]
        out.append("")
    plan = [a for a in algs if a.status == A.VULNERABLE]
    if plan:
        out += ["## Plan the post-quantum migration", ""]
        by_family: dict[str, list[Asset]] = {}
        for a in plan:
            by_family.setdefault(a.algorithm.family, []).append(a)
        for fam, items in by_family.items():
            names = ", ".join(sorted({x.name for x in items}))
            count = sum(len(x.occurrences) for x in items)
            out.append(f"- **{fam}** ({names}; {count} places): {A.RECOMMENDATIONS.get(fam, '')}")
        out.append("")
    if score.pqc:
        out += ["## Post-quantum already in use", "", ", ".join(f"**{p}**" for p in score.pqc), ""]
    others = [i for i in inv.issues if i.severity != "error"]
    if others:
        out += ["## Other findings", ""] + [f"- {i.severity}: {i.message} `{_loc(i.path, i.line)}`" for i in others] + [""]
    out += ["## Algorithm inventory", "", "| Algorithm | Primitive | Status | NIST PQ level | Where |", "|---|---|---|---|---|"]
    for a in algs:
        lvl = "" if a.algorithm.nist_level is None else str(a.algorithm.nist_level)
        out.append(f"| {a.name} | {a.algorithm.primitive} | {STATUS_LABEL[a.status]} | {lvl} | {_first(a)} |")
    certs = [a for a in inv.assets.values() if a.kind == "certificate"]
    if certs:
        out += ["", "## Certificates", "", "| Subject | Key | Signature | Expires | Status |", "|---|---|---|---|---|"]
        for c in certs:
            p = c.properties
            out.append(f"| {p['subject']} | {p['public_key']} | {p['signature_algorithm']} | {p['not_after'][:10]} | "
                       f"{STATUS_LABEL[c.status]} |")
    protos = [a for a in inv.assets.values() if a.kind == "protocol"]
    if protos:
        out += ["", "## TLS endpoints", "", "| Endpoint | Version | Cipher suite | Key exchange | Post-quantum KEX |", "|---|---|---|---|---|"]
        for p in protos:
            q = p.properties
            out.append(f"| {q['endpoint']} | {q.get('version', '')} | {q.get('cipher_suite', '')} | {q.get('group', '')} | "
                       f"{q.get('pq_key_exchange', '')} |")
    out += ["", f"_Generated by [cbom-scan]({TOOL_URL}) {__version__}. Static analysis finds what is visible in "
                 "code and config; review results, and treat the score as a trend indicator._", ""]
    return "\n".join(out)


# ---- terminal ---------------------------------------------------------------------------------
def to_text(inv: Inventory, score: Score, color: bool | None = None) -> str:
    color = sys.stdout.isatty() if color is None else color
    c = (lambda code, s: f"\033[{code}m{s}\033[0m") if color else (lambda code, s: s)
    tint = {A.BROKEN: "31", A.VULNERABLE: "33", A.WEAKENED: "36", A.SAFE: "32"}
    grade_tint = {"A": "32", "B": "32", "C": "33", "D": "31", "F": "31"}[score.grade]
    lines = [c("1", f"PQC readiness {c(grade_tint, f'{score.value}/100 ({score.grade})')}") +
             f"   {inv.files_scanned} files, {len(inv.algorithms())} algorithms, {len(inv.issues)} issues", ""]
    for status in (A.BROKEN, A.VULNERABLE, A.WEAKENED, A.SAFE):
        items = sorted((a for a in inv.algorithms() if a.status == status), key=lambda x: x.name)
        if items:
            lines.append(c(tint[status], f"{STATUS_LABEL[status]} ({len(items)})"))
            for a in items:
                lines.append(f"  {a.name:<28} {_first(a).replace('`', '')}")
    protos = [a for a in inv.assets.values() if a.kind == "protocol"]
    if protos:
        lines += ["", c("1", "TLS endpoints")]
        for p in protos:
            q = p.properties
            pq = {"yes": c("32", "post-quantum KEX"), "no": c("33", "no post-quantum KEX")}.get(q["pq_key_exchange"], "PQ KEX unknown")
            lines.append(f"  {q['endpoint']:<28} TLS {q['version']}  {q['cipher_suite']}  {q.get('group', '')}  {pq}")
    if inv.issues:
        lines += ["", c("1", "Issues")]
        for i in inv.issues:
            lines.append(f"  {c({'error': '31', 'warning': '33'}.get(i.severity, '36'), i.severity):<7} "
                         f"{_loc(i.path, i.line)}  {i.message}")
    return "\n".join(lines)


def write_json(data: dict, path: str) -> None:
    Path(path).write_text(json.dumps(data, indent=2) + "\n")
