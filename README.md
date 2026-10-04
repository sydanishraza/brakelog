# Tripwire

A tamper-evident log, policy guard and kill switch for coding agents. Works today as a Claude Code `PreToolUse` hook. Python 3.8+, no dependencies.

## What it does
- **Records** every tool call the agent makes (command, file path, URL) to `~/.tripwire/log.jsonl`. Each record includes the hash of the previous one, so editing or deleting an entry in the middle is detectable.
- **Blocks** calls that break your policy: credential files (`~/.aws`, `~/.ssh`, `.env`), dangerous commands (`curl | sh`, `rm -rf /`, `sudo`, force-push), and network hosts not on your allowlist.
- **Kill switch:** `tripwire pause` blocks every tool call immediately, mid-run. `tripwire resume` lifts it.

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
Edit `~/.tripwire/policy.json` to change rules. Set `"mode": "audit"` to log what *would* be blocked without blocking, which is a good first week.

## Honest limits
- **Not a sandbox.** It inspects tool calls Claude Code routes through hooks. A determined or obfuscated shell command can slip past regex rules. Treat it as a guardrail and flight recorder, not a security boundary.
- **Tail deletion is not detectable from the log alone.** Save the head hash from `verify` somewhere the agent can't write (your notes, a ticket, a CI job).
- **Logs may contain secrets** that appear in commands. Keep `~/.tripwire` private.
- The hook fails open on malformed input so it never breaks your agent.
- Tested with simulated hook input; confirm against your Claude Code version before relying on it.

License: MIT.
