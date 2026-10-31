#!/usr/bin/env python3
"""P8 reliability runs (plan 12.4): upload StakingVault to the running web page, one run
at a time, and read the five 12.4 quantities from the job's own event log.

    python3 scripts/reliability_p8.py --label main [--n 10] [--file examples/StakingVault.sol]
        [--base http://127.0.0.1:8765] [--out runs/p8/runs.jsonl]
    python3 scripts/reliability_p8.py --label turns10 --direct --max-turns 10

--direct (user decision 10/30, the fewer-turns arm): no page in between -- the exact
command a web job runs (gate --file <copy> --mode repo --repair --run-id ... --out
--events, ARBITER_SANDBOX=1, cwd arbiter/, the page's 3300 s limit) plus the extra
gate flags, with the job directory under runs/p8/direct/ and t0 = just before gate
starts. The upload's ~1 s of request handling is the only part not measured.

Each run is the browser's multipart upload (the finals path: gate --file --mode repo
--repair in the per-job sandbox, the page's defaults), sent only when the page has no
job running, so no time is spent in its queue. Times are seconds from the job's
`created` (the moment the page accepted the upload) to the event that marks:

  proof     the audit row with proven=true                         (12.4 item 2.1-2.2)
  replay    evidence ladder rung 3 (live_replay on a local anvil)  (item 2.3)
            on_chain = the replay showed the loss (rung 3 pass);
            replayed = a translation worked and the chain ran at all
  patch     repair_result accepted (the final verdict on the patch, after check 5
            when it is on, as it is by default)                    (items 2.4-2.5)
            patch04_s = the first patch passing checks 0-4, for reference
  done      the result page exists (job finished)

Every upload counts, including failed, timed-out and interrupted ones; nothing is
replaced. A run is not started while a pre-registered evaluation (gptoss-v3-) runs.
One JSON line per run, appended and fsynced; --n counts the label's lines already there.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ARB = HERE.parent
JOBS = ARB / "runs" / "gate" / "jobs"


def evaluation_running() -> bool:
    r = subprocess.run(["pgrep", "-f", r"cli\.py run .*--run-id gptoss-v3-"],
                       capture_output=True, text=True)
    return bool(r.stdout.strip())


def get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as resp:
        return json.loads(resp.read())


def upload(base: str, path: Path) -> str:
    """The browser's multipart POST; returns the job id from the redirect."""
    boundary = uuid.uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"contract\"; "
            f"filename=\"{path.name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            ).encode() + path.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(f"{base}/upload", data=body, method="POST", headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}"})

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):  # noqa: ANN002, ANN003
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open(req, timeout=60)
    except urllib.error.HTTPError as exc:
        loc = exc.headers.get("Location") or ""
        if exc.code in (302, 303) and "/job/" in loc:
            return loc.rsplit("/", 1)[-1]
        raise
    raise RuntimeError("the upload did not redirect to a job page")


def page_busy(base: str) -> bool:
    """True while any job of the page is queued or running."""
    for d in sorted(JOBS.iterdir())[-20:] if JOBS.exists() else []:
        try:
            if json.loads((d / "job.json").read_text(encoding="utf-8")).get("status") in ("queued", "running"):
                return True
        except (OSError, json.JSONDecodeError):
            continue
    return False


def measure(jid: str, d: Path | None = None) -> dict:
    d = d or JOBS / jid
    job = json.loads((d / "job.json").read_text(encoding="utf-8"))
    t0 = job["created"]
    evs = [json.loads(l) for l in (d / "events.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]

    def first(pred) -> dict | None:  # noqa: ANN001
        return next((e for e in evs if pred(e)), None)

    def secs(e: dict | None) -> float | None:
        return round(e["t"] - t0, 1) if e else None

    row = first(lambda e: e.get("kind") == "row")
    proof = first(lambda e: e.get("kind") == "row" and e.get("proven"))
    rung3 = first(lambda e: e.get("kind") == "ladder" and e.get("rung") == 3)
    p04 = first(lambda e: e.get("kind") == "repair_round_done" and e.get("first_failure") is None)
    rres = first(lambda e: e.get("kind") == "repair_result")
    done = first(lambda e: e.get("kind") == "stage" and e.get("step") == "done")
    rec = {"job": jid, "status": job.get("status"), "error": job.get("error") or "",
           "rid": job.get("rid"), "row_s": secs(row), "proven": bool(proof),
           "proof_s": secs(proof), "replay_s": secs(rung3),
           "rung3_event": (rung3 or {}).get("status"), "patch04_s": secs(p04),
           "patch_accepted": bool(rres and rres.get("accepted")),
           "patch_s": secs(rres) if rres and rres.get("accepted") else None,
           "patch_event_s": secs(rres), "done_s": secs(done),
           "exit_code": (done or {}).get("exit_code"), "verdicts": (done or {}).get("verdicts"),
           "reattacks": [{"round": e.get("round"), "status": e.get("status"), "turns": e.get("turns"),
                          "s": secs(e)} for e in evs if e.get("kind") == "reattack_done"],
           "turn_events": sum(1 for e in evs if e.get("kind") == "stage" and e.get("step") == "execute")}
    gate_path = d / "gate.json"
    if gate_path.exists():
        g = json.loads(gate_path.read_text(encoding="utf-8"))
        inp = g.get("input") or {}
        fds = [fd for f in g.get("files") or [] for fd in f.get("findings") or []]
        fd = fds[0] if fds else {}
        ev = fd.get("evidence") or {}
        r3 = ev.get("rung3") or {}
        p = fd.get("patch") or {}
        rec.update(
            requests=inp.get("llm_requests_this_invocation"),
            requests_audit=inp.get("llm_requests_audit"), requests_repair=inp.get("llm_requests_repair"),
            predicate=fd.get("predicate"), predicate_strict=fd.get("predicate_strict"),
            abg=[(e.get("A"), e.get("B"), e.get("G")) for e in (fd.get("abg") or {}).get("environments") or []],
            on_chain=r3.get("status") == "pass",
            replayed=bool(r3.get("worlds")), rung3_status=r3.get("status"),
            rung3_summary=r3.get("summary"), rung3_reason=(r3.get("reason") or "")[:300],
            patch_status=p.get("status"), patch_label=p.get("label"),
            verdict=[f.get("verdict") for f in g.get("files") or []])
    return rec


def run_direct(label: str, i: int, src: Path, extra: list[str], timeout: int) -> dict:
    """One web-job-equivalent gate run outside the page (see --direct)."""
    jid = time.strftime("%Y%m%d-%H%M%S") + f"-{label}{i}"
    d = ARB / "runs" / "p8" / "direct" / jid
    (d / "upload").mkdir(parents=True)
    path = d / "upload" / src.name
    path.write_bytes(src.read_bytes())
    job = {"id": jid, "kind": "direct", "label": label, "argv_extra": extra,
           "created": time.time(), "status": "running"}
    (d / "job.json").write_text(json.dumps(job), encoding="utf-8")
    env = {**os.environ, "ARBITER_SANDBOX": "1"}
    run_id = f"p8-{jid}"
    try:
        r = subprocess.run([sys.executable, "-m", "arbiter.gate", "--file", str(path),
                            "--mode", "repo", "--repair", "--run-id", run_id, *extra,
                            "--out", str(d / "gate.json"), "--events", str(d / "events.jsonl")],
                           cwd=ARB, capture_output=True, text=True, timeout=timeout, env=env)
        job.update(status="done", rc=r.returncode, stderr_tail=r.stderr[-400:])
    except subprocess.TimeoutExpired:
        from arbiter import sandbox  # noqa: PLC0415
        sandbox.remove(sandbox.container_name(run_id))
        job.update(status="timeout")
    job["finished"] = time.time()
    (d / "job.json").write_text(json.dumps(job), encoding="utf-8")
    if not (d / "events.jsonl").exists():
        (d / "events.jsonl").write_text("", encoding="utf-8")
    return measure(jid, d)


THRESHOLDS = {"proven": 9, "proof_s": 95.0, "on_chain": 9, "replay_s": 140.0, "patch_s": 190.0}


def ninth(values: list[float | None], n: int) -> float | None:
    """The 9th fastest of n runs; a run without the event counts as infinitely slow."""
    xs = sorted(v for v in values if v is not None) + [float("inf")] * (n - sum(v is not None for v in values))
    return xs[8] if len(xs) >= 9 and xs[8] != float("inf") else None


def summarise(rows: list[dict], n: int = 10) -> dict:
    """The five 12.4 quantities and the decision, for one label's runs."""
    proven = [r for r in rows if r.get("proven")]
    on_chain = [r for r in rows if r.get("on_chain")]
    patched = [r for r in rows if r.get("patch_accepted")]
    t_proof = ninth([r.get("proof_s") for r in proven], n)
    t_replay = ninth([r.get("replay_s") for r in on_chain], n)
    t_patch = ninth([r.get("patch_s") for r in patched], n)
    cond = {
        "proven>=9": len(proven) >= THRESHOLDS["proven"],
        "9th proof<=95s": t_proof is not None and t_proof <= THRESHOLDS["proof_s"],
        "on_chain>=9": len(on_chain) >= THRESHOLDS["on_chain"],
        "9th replay<=140s": t_replay is not None and t_replay <= THRESHOLDS["replay_s"],
        "9th patch<=190s": t_patch is not None and t_patch <= THRESHOLDS["patch_s"],
    }
    preds: dict[str, int] = {}
    for r in proven:
        preds[str(r.get("predicate"))] = preds.get(str(r.get("predicate")), 0) + 1
    return {"runs": len(rows), "proven": len(proven), "predicates": preds,
            "proof_s": sorted(r["proof_s"] for r in proven), "ninth_proof_s": t_proof,
            "replayed": sum(1 for r in rows if r.get("replayed")), "on_chain": len(on_chain),
            "replay_s_on_chain": sorted(r["replay_s"] for r in on_chain), "ninth_replay_s": t_replay,
            "replay_s_all": sorted(r["replay_s"] for r in rows if r.get("replay_s") is not None),
            "patch_accepted": len(patched), "patch_s": sorted(r["patch_s"] for r in patched),
            "ninth_patch_s": t_patch,
            "patch04_s": sorted(r["patch04_s"] for r in rows if r.get("patch04_s") is not None),
            "done_s": sorted(r["done_s"] for r in rows if r.get("done_s") is not None),
            "reattacks": [x for r in rows for x in r.get("reattacks") or []],
            "requests": sum(r.get("requests") or 0 for r in rows),
            "conditions": cond, "live": all(cond.values())}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--n", type=int, default=10)
    ap.add_argument("--file", type=Path, default=ARB / "examples" / "StakingVault.sol")
    ap.add_argument("--base", default="http://127.0.0.1:8765")
    ap.add_argument("--out", type=Path, default=ARB / "runs" / "p8" / "runs.jsonl")
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--direct", action="store_true", help="run gate directly (see above)")
    ap.add_argument("--max-turns", type=int, default=None, help="--direct: gate --max-turns")
    ap.add_argument("--summary", action="store_true", help="print the 12.4 summary per label")
    a = ap.parse_args()
    if a.summary:
        rows = [json.loads(l) for l in a.out.read_text(encoding="utf-8").splitlines() if l.strip()]
        for label in dict.fromkeys(r["label"] for r in rows):
            print(label, json.dumps(summarise([r for r in rows if r["label"] == label], a.n),
                                    ensure_ascii=False))
        return 0
    extra = ["--max-turns", str(a.max_turns)] if a.max_turns else []
    if extra and not a.direct:
        ap.error("--max-turns needs --direct (the page's upload has no such setting)")
    a.out.parent.mkdir(parents=True, exist_ok=True)
    have = [json.loads(l) for l in a.out.read_text(encoding="utf-8").splitlines()
            if l.strip()] if a.out.exists() else []
    done = sum(1 for r in have if r.get("label") == a.label)
    for i in range(done + 1, a.n + 1):
        if evaluation_running():
            print("stop: a pre-registered evaluation is running", flush=True)
            return 3
        while page_busy(a.base):
            time.sleep(5)
        started = time.strftime("%Y-%m-%d %H:%M:%S")
        if a.direct:
            print(f"[{started}] {a.label} {i}/{a.n} direct gate {' '.join(extra)}", flush=True)
            rec = {"label": a.label, "n": i, "started_at": started, "mode": "direct",
                   "gate_extra": extra, **run_direct(a.label, i, a.file, extra, 3300)}
            rec["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            with a.out.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            print(f"    -> {rec.get('status')} proven={rec.get('proven')} {rec.get('predicate')} "
                  f"proof={rec.get('proof_s')} replay={rec.get('replay_s')} on_chain={rec.get('on_chain')} "
                  f"patch={rec.get('patch_status')} patch_s={rec.get('patch_s')} done={rec.get('done_s')} "
                  f"req={rec.get('requests')}", flush=True)
            continue
        try:
            jid = upload(a.base, a.file)
        except Exception as exc:  # noqa: BLE001
            rec = {"label": a.label, "n": i, "started_at": started, "status": "upload_failed",
                   "error": f"{type(exc).__name__}: {exc}"[:300]}
        else:
            print(f"[{started}] {a.label} {i}/{a.n} job {jid}", flush=True)
            t_end = time.time() + a.timeout
            status = ""
            while time.time() < t_end:
                try:
                    status = get(f"{a.base}/api/job/{jid}")["job"].get("status", "")
                except Exception:  # noqa: BLE001
                    status = ""
                if status in ("done", "error", "interrupted"):
                    break
                time.sleep(3)
            rec = {"label": a.label, "n": i, "started_at": started, **measure(jid)}
            if status not in ("done", "error", "interrupted"):
                rec["status"] = f"driver_timeout ({status or 'unknown'})"
        rec["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        with a.out.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        print(f"    -> {rec.get('status')} proven={rec.get('proven')} {rec.get('predicate')} "
              f"proof={rec.get('proof_s')} replay={rec.get('replay_s')} on_chain={rec.get('on_chain')} "
              f"patch={rec.get('patch_status')} patch_s={rec.get('patch_s')} done={rec.get('done_s')} "
              f"req={rec.get('requests')}", flush=True)
    print("all runs done", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
