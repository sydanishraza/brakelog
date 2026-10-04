# Tripwire technical spec (v0.1)

## Goal
Give developers who run coding agents unattended three things: a trustworthy record of what the agent did, automatic blocking of out-of-scope actions, and a stop button that works mid-run.

## Non-goals (v0.1)
OS-level isolation, prompt-injection detection, multi-agent orchestration, hosted dashboards.

## Architecture
```
Claude Code -> PreToolUse hook (JSON on stdin)
            -> evaluate(policy, PAUSED flag) -> allow | deny
            -> append hash-chained record to log.jsonl
            -> exit 0 (allow) or exit 2 + reason on stderr (block; fed back to the agent)
```
CLI commands read the same log and flag files. No daemon, no network.

## Record format (one JSON object per line)
`seq, ts, session, tool, input (truncated), decision {allow|deny|would_deny}, reason, prev, hash`
`hash = sha256(prev + canonical_json(record_without_hash))`; first `prev` is 64 zeros.

## Policy
`deny_paths` (globs on absolute paths for file tools), `deny_command_patterns` (regex on Bash commands), `allow_hosts` + `block_unlisted_hosts` (hosts found in commands and URL inputs), `mode` (enforce|audit).

## Threat model
Defends against: an agent drifting out of scope, accidental credential reads, silent edits to the middle of the log.
Does not defend against: an attacker with write access to `~/.tripwire` (can truncate the log or edit policy), shell obfuscation, actions outside hooked tools.

## Roadmap
1. v0.2: remote anchoring of head hashes (hosted, the first paid feature), Slack/email alerts on denies.
2. v0.3: egress proxy and OS sandbox profiles (bubblewrap on Linux, sandbox-exec on macOS) to enforce policy below the hook layer.
3. v0.4: adapters for other agents (Cursor, Codex CLI, MCP gateway), team dashboard, policy templates.
