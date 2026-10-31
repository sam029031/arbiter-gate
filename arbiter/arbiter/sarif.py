"""gate.json -> SARIF 2.1.0, for GitHub code scanning.

    python3 -m arbiter.sarif gate.json > report.sarif

The mapping (plan 7.4) keeps the gate's four verdicts apart:

  * proven_exploitable   one result per proven finding, level "error", located at the
                         definition of the vulnerable function;
  * static_hint_unproven one result per static-tool hint, level "warning", rule ids
                         prefixed "slither/" (P2 fills `static_hints`; the mapping is here);
  * no_provable_attack   NO result. "We found nothing provable" is not a finding, and a
                         code-scanning tab with no alert must not be read as a clean bill;
                         the file is listed under run.properties.coverage instead;
  * not_executed         NO result. invocations[0].executionSuccessful is false and the
                         reason is a toolExecutionNotification, so CI shows "the audit did
                         not finish", never a pass.

Uncovered changes (diffscan's unscanned_reasons, P5) go to run.properties.unscanned.
Paths are relative (`uriBaseId` %SRCROOT%); the report is built from gate.json alone.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from .verdict import LABELS, NO_PROVABLE, NOT_EXECUTED, PROVEN, STATIC_HINT

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = ("https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
                "sarif-schema-2.1.0.json")
TOOL_NAME = "ARBITER Gate"
TOOL_URI = "https://github.com/sam029031/arbiter-gate"
# GitHub reads `security-severity` (0.0-10.0) to rank alerts.
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}


def _slug(text: str) -> str:
    ascii_ = re.sub(r"[‐-―]", "-", text or "")
    return re.sub(r"[^a-z0-9]+", "-", ascii_.lower()).strip("-") or "exploit"


def proven_count(report: dict[str, Any]) -> int:
    """How many error-level results to_sarif() must produce: one per proven finding."""
    return sum(max(1, len(e.get("findings") or []))
               for e in report.get("files") or [] if e.get("verdict") == PROVEN)


def _location(entry: dict[str, Any], region: dict[str, Any] | None) -> dict[str, Any]:
    loc: dict[str, Any] = {"physicalLocation": {"artifactLocation": {
        "uri": (entry.get("artifact") or {}).get("uri") or "Target.sol",
        "uriBaseId": "%SRCROOT%"}}}
    if region and region.get("startLine"):
        loc["physicalLocation"]["region"] = {
            k: region[k] for k in ("startLine", "endLine") if region.get(k)}
    return loc


def _proven_result(entry: dict[str, Any], f: dict[str, Any],
                   rules: dict[str, dict[str, Any]]) -> dict[str, Any]:
    rule_id = f"arbiter/proven/{_slug(f.get('vuln_class') or 'exploit')}"
    severity = str(f.get("severity") or "").lower()
    rules.setdefault(rule_id, {
        "id": rule_id,
        "name": "ProvenExploit",
        "shortDescription": {"text": f"已證實可攻擊：{f.get('vuln_class') or '漏洞'}"},
        "fullDescription": {"text": "攻擊程式已在 EVM 上執行，並滿足由 harness 持有的成功條件；"
                                    "這不是靜態推測。"},
        "help": {"text": "下載回歸測試與修補（若有），審閱後套用並重新稽核。"},
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "proven-exploit"],
                       "security-severity": _SECURITY_SEVERITY.get(severity, "8.0")},
    })
    abg = f.get("abg") or {}
    patch = f.get("patch") or {}
    fn = f.get("vulnerable_function") or "?"
    text = (f"{LABELS[PROVEN]}：{f.get('title') or '(未記錄)'}。函式 {fn}；"
            f"以 {f.get('predicate')} 在 EVM 上證實（攻擊證明 {f.get('poc_name')}）。")
    if not f.get("predicate_strict"):
        text += f" {f.get('predicate_note') or ''}"
    region = f.get("region") or {}
    uri = (entry.get("artifact") or {}).get("uri") or ""
    fingerprint = hashlib.sha256(
        f"{uri}|{fn}|{f.get('vuln_class')}".encode("utf-8")).hexdigest()
    return {
        "ruleId": rule_id,
        "level": "error",
        "message": {"text": text.strip()},
        "locations": [_location(entry, region)],
        "partialFingerprints": {"arbiterFinding/v1": fingerprint},
        "properties": {
            "verdict": PROVEN,
            "severity": f.get("severity"),
            "vulnerable_function": fn,
            "predicate": f.get("predicate"),
            "predicate_strict": f.get("predicate_strict"),
            "poc_name": f.get("poc_name"),
            "location_basis": region.get("basis"),
            "abg_status": abg.get("status"),
            "abg_wei": [{k: r.get(k) for k in ("env", "A", "B", "G")}
                        for r in abg.get("environments") or []],
            "patch_status": patch.get("status"),
            "regression_status": (f.get("regression") or {}).get("status"),
        },
    }


def _hint_result(entry: dict[str, Any], h: dict[str, Any],
                 rules: dict[str, dict[str, Any]]) -> dict[str, Any]:
    rule_id = f"slither/{h.get('check') or 'hint'}"
    rules.setdefault(rule_id, {
        "id": rule_id,
        "name": "StaticHint",
        "shortDescription": {"text": f"靜態工具提示：{h.get('check')}"},
        "fullDescription": {"text": "靜態分析工具的提示，沒有執行證據，不是已證實的漏洞。"},
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "static-hint"]},
    })
    region = {"startLine": h.get("line"), "endLine": h.get("end_line") or h.get("line")}
    return {
        "ruleId": rule_id,
        "level": "warning",
        "message": {"text": f"{LABELS[STATIC_HINT]}：{h.get('message') or h.get('check')}"},
        "locations": [_location(entry, region)],
        "properties": {"verdict": STATIC_HINT, "impact": h.get("impact"),
                       "confidence": h.get("confidence")},
    }


def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    notifications: list[dict[str, Any]] = []
    for e in report.get("files") or []:
        verdict = e.get("verdict")
        uri = (e.get("artifact") or {}).get("uri") or "Target.sol"
        sa = e.get("static_analysis") or {}
        coverage.append({"uri": uri, "verdict": verdict, "label": LABELS.get(verdict, verdict),
                         "reason": e.get("reason"),
                         "static_analysis": {"status": sa.get("status"), "tool": sa.get("tool"),
                                             "reason": sa.get("reason")} if sa else None})
        if verdict == PROVEN:
            findings = e.get("findings") or [{}]
            results += [_proven_result(e, f, rules) for f in findings]
        elif verdict == STATIC_HINT:
            results += [_hint_result(e, h, rules) for h in e.get("static_hints") or []]
        elif verdict == NOT_EXECUTED:
            detail = e.get("detail") or ""
            notifications.append({
                "level": "error",
                "message": {"text": f"{uri}：{LABELS[NOT_EXECUTED]}。原因：{e.get('reason')}"
                                    + (f"；{detail}" if detail and detail != e.get("reason") else "")},
                "locations": [_location(e, None)],
            })
        # NO_PROVABLE: deliberately no result; it is in coverage.
    invocation: dict[str, Any] = {
        "executionSuccessful": not notifications,
        "exitCode": report.get("exit_code"),
    }
    if notifications:
        invocation["toolExecutionNotifications"] = notifications
    inp = report.get("input") or {}
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "informationUri": TOOL_URI,
                                "semanticVersion": "0.1.0",
                                "rules": list(rules.values())}},
            "originalUriBaseIds": {"%SRCROOT%": {"description": {
                "text": "The repository (or upload) root the gate audited."}}},
            "invocations": [invocation],
            "results": results,
            "properties": {
                "gate_schema": report.get("schema"),
                "run_id": inp.get("run_id"),
                "models": report.get("models"),
                "generated_at": report.get("generated_at"),
                "coverage": coverage,
                "unscanned": report.get("unscanned_reasons") or [],
                "no_provable_attack_note": f"{LABELS[NO_PROVABLE]}：不產生 alert；"
                                           "沒有 alert 不代表合約沒有漏洞。",
            },
        }],
    }


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python3 -m arbiter.sarif gate.json > report.sarif", file=sys.stderr)
        return 64
    report = json.loads(Path(args[0]).read_text(encoding="utf-8"))
    json.dump(to_sarif(report), sys.stdout, ensure_ascii=False, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
