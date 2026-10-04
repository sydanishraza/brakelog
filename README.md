# Tripwire

[![test](https://github.com/sydanishraza/tripwire/actions/workflows/test.yml/badge.svg)](https://github.com/sydanishraza/tripwire/actions/workflows/test.yml)

A tamper-evident log, policy guard and kill switch for coding agents. Works today as a Claude Code `PreToolUse` hook. Python 3.8+ on macOS and Linux, no dependencies.

## What it does
- **Records** every tool call the agent makes (command, file path, URL) to `~/.tripwire/log.jsonl`. Each record includes the hash of the previous one, so editing or deleting an entry in the middle is detectable.
- **Blocks** calls that break your policy: credential files (`~/.aws`, `~/.ssh`, `.env`), dangerous commands (`curl | sh`, `rm -rf /`, `sudo`, force-push), and network hosts not on your allowlist. File rules follow symlinks and ignore case, so a link to `~/.aws/credentials` or a path like `~/.AWS/credentials` is still blocked.
- **Kill switch:** `tripwire pause` blocks every tool call immediately, mid-run, even in audit mode. `tripwire resume` lifts it. Run `resume` from your own terminal: while paused, the agent's commands are blocked too.

## Quick start
```bash
python3 tripwire.py init     # writes a default policy, prints the hook config
```
Paste the printed JSON into `.claude/settings.json` (one project) or `~/.claude/settings.json` (all projects). Then:

```bash
python3 tripwire.py tail         # recent actions and decisions
python3 tripwire.py verify       # check the chain; prints the head hash
python3 tripwire.py pause        # kill switch
python3 tripwire.py resume
```
Edit `~/.tripwire/policy.json` to change rules. Set `"mode": "audit"` to log what *would* be blocked without blocking, which is a good first week. Lists in `policy.json` replace the built-in defaults, so after upgrading Tripwire, delete or update your `policy.json` to pick up new default rules.

## Tests
```bash
python3 -m unittest -v     # standard library only; uses a temporary TRIPWIRE_HOME
```

## Honest limits
- **Not a sandbox.** It inspects tool calls Claude Code routes through hooks. A determined or obfuscated shell command can slip past regex rules. Treat it as a guardrail and flight recorder, not a security boundary.
- **Tail deletion is not detectable from the log alone.** Save the head hash from `verify` somewhere the agent can't write (your notes, a ticket, a CI job).
- **Logs may contain secrets** that appear in commands. Tripwire creates `~/.tripwire` owner-only (`init` also tightens older installs); keep it that way.
- **Command rules match text,** so they can also block harmless commands that merely mention a pattern, such as a script whose source contains a credential path.
- The hook fails open on malformed input so it never breaks your agent.
- **Windows is untested:** it has no log file locking there, so parallel tool calls could fork the chain.
- Tested live as a Claude Code `PreToolUse` hook on macOS with Python 3.9; confirm against your Claude Code version before relying on it.

License: MIT.
