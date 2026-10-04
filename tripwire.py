#!/usr/bin/env python3
"""Tripwire: tamper-evident log, policy guard and kill switch for coding agents.

Runs as a Claude Code PreToolUse hook. Standard library only.
Usage: tripwire.py {init,hook,verify,tail,pause,resume,status}
"""
import argparse, fnmatch, hashlib, json, os, re, sys, time
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows: no file locking in this MVP
    fcntl = None

HOME = Path(os.environ.get("TRIPWIRE_HOME", Path.home() / ".tripwire"))
LOG, POLICY, PAUSE = HOME / "log.jsonl", HOME / "policy.json", HOME / "PAUSED"
GENESIS = "0" * 64

DEFAULT_POLICY = {
    "mode": "enforce",  # "audit" logs would-be blocks without blocking
    "deny_paths": [
        "*/.aws", "*/.aws/*", "*/.ssh", "*/.ssh/*", "*/.env", "*/.env.*",
        "*/.npmrc", "*/.netrc", "*/.git-credentials", "*/.config/gcloud/*",
    ],
    "deny_command_patterns": [
        r"\.aws/credentials", r"\.ssh/", r"\.git-credentials", r"\.netrc",
        r"(^|[\s/'\"])\.env(\.[\w-]+)?($|[\s'\"])",
        r"rm\s+-rf\s+(/|~)", r"curl[^|]*\|\s*(ba)?sh", r"wget[^|]*\|\s*(ba)?sh",
        r"\bsudo\b", r"git\s+push\s+.*--force",
    ],
    "block_unlisted_hosts": True,
    "allow_hosts": ["github.com", "pypi.org", "files.pythonhosted.org", "registry.npmjs.org"],
}


def canon(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":"))


def digest(prev, rec):
    return hashlib.sha256((prev + canon(rec)).encode()).hexdigest()


def trunc(v, n=1000):
    if isinstance(v, str):
        return v if len(v) <= n else v[:n] + "...[truncated]"
    if isinstance(v, dict):
        return {k: trunc(x, n) for k, x in v.items()}
    if isinstance(v, list):
        return [trunc(x, n) for x in v[:50]]
    return v


def load_policy():
    try:
        return {**DEFAULT_POLICY, **json.loads(POLICY.read_text())}
    except Exception:
        return DEFAULT_POLICY


def append(rec):
    HOME.mkdir(parents=True, exist_ok=True)
    with open(LOG, "a+b") as f:
        if fcntl:
            fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - 65536))
        lines = [l for l in f.read().splitlines() if l.strip()]
        last = json.loads(lines[-1]) if lines else None
        prev = last["hash"] if last else GENESIS
        rec = {"seq": (last["seq"] + 1) if last else 1, **rec, "prev": prev}
        rec["hash"] = digest(prev, rec)
        f.write((canon(rec) + "\n").encode())
        if fcntl:
            fcntl.flock(f, fcntl.LOCK_UN)


def evaluate(inp, pol):
    if PAUSE.exists():
        return "deny", "session paused by operator (tripwire resume to continue)"
    for k in ("file_path", "path", "notebook_path"):
        p = inp.get(k)
        if isinstance(p, str):
            ap = os.path.abspath(os.path.expanduser(p))
            for g in pol["deny_paths"]:
                if fnmatch.fnmatch(ap, g):
                    return "deny", f"path {ap} matches deny rule {g}"
    cmd = inp.get("command") if isinstance(inp.get("command"), str) else ""
    for pat in pol["deny_command_patterns"]:
        if re.search(pat, cmd):
            return "deny", f"command matches deny rule {pat}"
    if pol["block_unlisted_hosts"]:
        text = cmd + " " + (inp.get("url") if isinstance(inp.get("url"), str) else "")
        for h in re.findall(r"https?://([^/\s:'\"]+)", text):
            h = h.lower()
            if not any(h == a or h.endswith("." + a) for a in pol["allow_hosts"]):
                return "deny", f"host {h} is not in allow_hosts"
    return "allow", ""


def cmd_hook(_):
    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0  # fail open on malformed input; never break the agent
    pol = load_policy()
    inp = data.get("tool_input") or {}
    decision, why = evaluate(inp, pol)
    audit = pol.get("mode") == "audit"
    logged = "would_deny" if decision == "deny" and audit else decision
    try:
        append({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "session": data.get("session_id", "?"), "tool": data.get("tool_name", "?"),
                "input": trunc(inp), "decision": logged, "reason": why})
    except Exception as e:
        print(f"tripwire: could not write log: {e}", file=sys.stderr)
    if decision == "deny" and not audit:
        print(f"Tripwire blocked this action: {why}. Do not retry it; ask the user.", file=sys.stderr)
        return 2
    return 0


def cmd_verify(_):
    if not LOG.exists():
        print("no log yet")
        return 0
    prev, n = GENESIS, 0
    for i, line in enumerate(open(LOG), 1):
        if not line.strip():
            continue
        rec = json.loads(line)
        h = rec.pop("hash", None)
        if rec.get("prev") != prev or digest(prev, rec) != h:
            print(f"TAMPERED: chain breaks at line {i} (seq {rec.get('seq')})")
            return 1
        prev, n = h, n + 1
    print(f"OK: {n} records. Head hash (save this somewhere safe): {prev}")
    return 0


def cmd_tail(a):
    if not LOG.exists():
        return 0
    for line in open(LOG).read().splitlines()[-a.n:]:
        r = json.loads(line)
        detail = r["input"].get("command") or r["input"].get("file_path") or r["input"].get("url") or ""
        print(f'{r["seq"]:>5} {r["ts"]} {r["decision"]:<10} {r["tool"]:<10} {str(detail)[:70]} {r["reason"]}')
    return 0


def cmd_init(_):
    HOME.mkdir(parents=True, exist_ok=True)
    if not POLICY.exists():
        POLICY.write_text(json.dumps(DEFAULT_POLICY, indent=2))
    me = os.path.abspath(__file__)
    snippet = {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
        {"type": "command", "command": f"{sys.executable} {me} hook"}]}]}}
    print(f"Policy: {POLICY}\nAdd this to .claude/settings.json (project) or ~/.claude/settings.json:\n")
    print(json.dumps(snippet, indent=2))
    return 0


def cmd_pause(_):
    HOME.mkdir(parents=True, exist_ok=True)
    PAUSE.write_text(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    print("PAUSED: all tool calls will be blocked until `tripwire resume`")
    return 0


def cmd_resume(_):
    PAUSE.unlink(missing_ok=True)
    print("resumed")
    return 0


def cmd_status(_):
    print("PAUSED" if PAUSE.exists() else "running", "| mode:", load_policy()["mode"], "| log:", LOG)
    return 0


def main():
    ap = argparse.ArgumentParser(prog="tripwire")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in [("init", cmd_init), ("hook", cmd_hook), ("verify", cmd_verify),
                     ("pause", cmd_pause), ("resume", cmd_resume), ("status", cmd_status)]:
        sub.add_parser(name).set_defaults(fn=fn)
    t = sub.add_parser("tail")
    t.add_argument("-n", type=int, default=20)
    t.set_defaults(fn=cmd_tail)
    a = ap.parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
