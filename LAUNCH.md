# Launch checklist

## You must do these (I can't)
1. Put your email or a Tally/Google Form link in the landing page signup button.
2. Create a public GitHub repo, add `tripwire.py`, `README.md`, `SPEC.md`, an MIT `LICENSE`, and push.
3. Post the launch posts below. Reply to every comment for the first 48 hours.
4. Record every signup and conversation in a sheet: who, what agent they run, would they pay.
5. Test the hook on your own Claude Code before announcing it.

## Show HN draft
**Title:** Show HN: Tripwire, an open-source flight recorder and kill switch for coding agents
**Body:** I run coding agents with real credentials and wanted two things: a log I can trust and a stop button that works mid-run. Tripwire is a Claude Code hook (about 200 lines of stdlib Python) that hash-chains every tool call, blocks credential reads, `curl | sh` and unlisted network hosts, and has a `pause` command. It is not a sandbox and I list the limits in the README. I'd like to know what you would want it to catch, and which other agents to support.

## Reddit / X variant
"What did your coding agent actually do while you were away? I built a small open-source hook that logs every action tamper-evidently and lets you hit pause. Feedback welcome, especially on what it should block."

## Where to post
Hacker News (Show HN), r/ClaudeAI, r/LocalLLaMA, r/programming, X, Indian dev communities and Discords. Space them out; don't post everywhere in one hour.

## Money path
- Weeks 1-4: free tool, build the signup list, interview users.
- Pay trigger: when 3+ people ask for alerts, shared policies or hosted anchoring, build that and charge for it.
- Meanwhile, sell your technical writing as a fixed-price offer so income doesn't depend on this.

## Stop rule
After 30 days: under 50 signups and no one willing to pay means change the wedge or move on.
