# Brakelog

[![test](https://github.com/sydanishraza/brakelog/actions/workflows/test.yml/badge.svg)](https://github.com/sydanishraza/brakelog/actions/workflows/test.yml)

An audit log, policy guard and kill switch for coding agents. Works today as a Claude Code `PreToolUse` hook. Python 3.8+ on macOS and Linux, no dependencies.

**Using it, or want to?** [Get updates and tell me what it should catch](https://docs.google.com/forms/d/e/1FAIpQLSep5V2V3w56EfKKrhICh3hnQUZYMSOwD5GVqfGMy59JSxKZUg/viewform). It takes a minute.

## What it does
- **Records** every tool call the agent makes (command, file path, URL) to `~/.brakelog/log.jsonl`. Each record includes the hash of the previous one, so a hand-edited or deleted line shows up in `verify` unless the whole chain after it is recomputed (see the limits below).
- **Protects itself.** The agent's tools can't read or change Brakelog's folder, edit the hook script, or edit Claude Code settings files (where the hook lives and hooks can be disabled). These rules are locked: they can't be turned off in the policy and they apply even in audit mode. The agent may still run `brakelog.py` with `tail`, `verify`, `status` or `pause`.
- **Blocks** calls that break your policy: credential files (`~/.aws`, `~/.ssh`, `.env`), dangerous commands (`curl | sh`, `rm -rf /`, `sudo`, force-push), and network hosts not on your allowlist (`localhost` and `127.0.0.1` are allowed by default, so local dev servers work). File rules follow symlinks and ignore case, so a link to `~/.aws/credentials` or a path like `~/.AWS/credentials` is still blocked.
- **Kill switch:** `brakelog pause` blocks every tool call immediately, mid-run, even in audit mode. `brakelog resume` lifts it. Run `resume` from your own terminal: while paused, the agent's commands are blocked too.

## Quick start
```bash
python3 brakelog.py init     # writes a default policy, prints the hook config
```
Paste the printed JSON into `.claude/settings.json` (one project) or `~/.claude/settings.json` (all projects). Then:

```bash
python3 brakelog.py tail         # recent actions and decisions
python3 brakelog.py verify       # check the chain; prints the head hash
python3 brakelog.py pause        # kill switch
python3 brakelog.py resume
```
Edit `~/.brakelog/policy.json` yourself to change rules (the agent can't). Set `"mode": "audit"` to log what *would* be blocked without blocking, which is a good first week. Lists in `policy.json` replace the built-in defaults, so after upgrading Brakelog, delete or update your `policy.json` to pick up new default rules.

## Tests
```bash
python3 -m unittest -v     # standard library only; uses a temporary BRAKELOG_HOME
```

## Honest limits
- **Not a sandbox.** It inspects tool calls Claude Code routes through hooks. A determined or obfuscated shell command can slip past regex rules. Treat it as a guardrail and flight recorder, not a security boundary.
- **The hash chain is not proof on its own.** It uses no secret key, so anyone who can write `~/.brakelog` can edit a record, recompute every hash after it, and `verify` will still pass. Brakelog stops the agent's tools from touching that folder, but other programs and people on the machine can. To make past entries provable, save the head hash from `verify` somewhere off the machine (your notes, a ticket, a CI job). Later, check that the saved hash still appears in the log and `verify` passes: if any earlier record was changed, that hash would no longer exist. Signed records are on the roadmap.
- **Self-protection matches text too.** Like the other command rules, a sufficiently obfuscated command could get past it.
- **Logs may contain secrets** that appear in commands. Brakelog creates `~/.brakelog` owner-only (`init` also tightens older installs); keep it that way.
- **Command rules match text,** so they can also block harmless commands that merely mention a pattern, such as a script whose source contains a credential path.
- The hook fails open on malformed input so it never breaks your agent.
- **Don't move or delete `brakelog.py` while the hook points at it.** Python exits with code 2 when the file is missing, and Claude Code treats that as "block", so every tool call would be blocked. Update the hook path first.
- **Windows is untested:** it has no log file locking there, so parallel tool calls could fork the chain.
- Tested live as a Claude Code `PreToolUse` hook on macOS with Python 3.9; confirm against your Claude Code version before relying on it.

License: MIT.
