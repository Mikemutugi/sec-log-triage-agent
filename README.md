# Linux Security Log Triage Agent (`sec-log-triage-agent`)

An AI-powered security triage agent written in Python that ingests raw Linux authentication and system logs, correlates multi-step attack patterns, maps findings to MITRE ATT&CK techniques, and outputs structured incident response recommendations.

## Repository Structure
- `agent.py` — Core triage agent logic, log parser, and severity classification pipeline.
- `requirements.txt` — Python dependencies.
- `traces/test_trace.json` — Recorded end-to-end agent execution trace and structured triage verdict.

## Setup & Usage
```bash
git clone https://github.com
cd sec-log-triage-agent
pip install -r requirements.txt
python agent.py
```

## Testing & Verification Write-Up

### Methodology
The agent was tested against synthetic and real-world `/var/log/auth.log` attack scenarios covering:
1. **SSH Brute-Force -> Compromise -> Privilege Escalation:** Verifying that the agent correlates failed login bursts with a subsequent accepted login and `sudo` root shell execution.
2. **Benign Admin Activity (False-Positive Check):** Verifying that routine scheduled cron jobs and standard key-based logins from trusted internal IPs are classified as `LOW` / informational without triggering false alerts.

### Sample Execution Trace Summary
Full trace available in [`traces/test_trace.json`](traces/test_trace.json):
- **Input:** 5 log lines showing rapid SSH password failures from `185.220.101.42`, followed by successful login as `deploy` and `sudo /usr/bin/bash`.
- **Reasoning Steps:** `parse_syslog_entries` -> `correlate_attack_pattern` -> `check_threat_intel`
- **Verdict:** `CRITICAL` (`T1110.001`, `T1548.003`) with immediate containment commands.
