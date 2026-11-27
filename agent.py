import json
import os
import re
import urllib.request
from datetime import datetime, timezone

MAX_STEPS = 5

def parse_auth_log(raw_log: str) -> dict:
    injection_patterns = [r"ignore previous", r"system prompt", r"execute command", r"bypass"]
    for pat in injection_patterns:
        if re.search(pat, raw_log, re.IGNORECASE):
            return {"status": "blocked_by_guardrail", "reason": f"Prompt injection pattern detected: {pat}"}

    ips = re.findall(r"Failed password for .*? from (\d+\.\d+\.\d+\.\d+)", raw_log)
    counts = {}
    for ip in ips:
        counts[ip] = counts.get(ip, 0) + 1
    return {"status": "ok", "failed_attempts_by_ip": counts}

def check_ip_reputation(ip_address: str) -> dict:
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip_address):
        return {"status": "error", "message": "Invalid IPv4 format"}
    
    known_bad = {
        "185.220.101.42": {"risk": "high", "tag": "ssh_bruteforce_botnet", "asn": "AS205100"},
        "45.33.32.156": {"risk": "low", "tag": "authorized_scanner", "asn": "AS63949"},
    }
    info = known_bad.get(ip_address, {"risk": "medium", "tag": "unknown_external", "asn": "UNKNOWN"})
    return {"status": "ok", "ip": ip_address, **info}

def propose_ufw_block(ip_address: str, reason: str, auto_approve: bool = False) -> dict:
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip_address):
        return {"status": "error", "message": "Invalid IPv4 address"}

    command = f"sudo ufw deny from {ip_address} to any port 22"
    if not auto_approve:
        print(f"\n[GUARDRAIL - HUMAN APPROVAL REQUIRED]")
        print(f"Proposed Action: {command}\nReason: {reason}")
        choice = input("Approve firewall rule? [y/N]: ").strip().lower()
        if choice != "y":
            return {"status": "rejected_by_human", "command": command}

    return {"status": "approved", "command": command, "executed": False}

TOOLS_SCHEMA = [
    {
        "name": "parse_auth_log",
        "description": "Parse raw Linux auth.log text to count failed SSH login attempts per IP.",
        "parameters": {
            "type": "OBJECT",
            "properties": {"raw_log": {"type": "STRING", "description": "Raw auth.log lines"}},
            "required": ["raw_log"],
        },
    },
    {
        "name": "check_ip_reputation",
        "description": "Look up threat reputation and ASN metadata for a single IPv4 address.",
        "parameters": {
            "type": "OBJECT",
            "properties": {"ip_address": {"type": "STRING", "description": "IPv4 address to inspect"}},
            "required": ["ip_address"],
        },
    },
    {
        "name": "propose_ufw_block",
        "description": "Propose a UFW firewall block rule for a confirmed high-risk malicious IP.",
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "ip_address": {"type": "STRING", "description": "Malicious IPv4 address"},
                "reason": {"type": "STRING", "description": "Evidence justifying the block"},
            },
            "required": ["ip_address", "reason"],
        },
    },
]

def call_gemini(contents: list, api_key: str) -> dict:
    url = f"https://googleapis.com{api_key}"
    payload = {
        "systemInstruction": {
            "parts": [{"text": (
                "You are a Linux Security Triage Agent. Always follow this workflow: "
                "1) Parse logs with parse_auth_log. "
                "2) Check reputation of any IP with >=3 failed attempts using check_ip_reputation. "
                "3) Only call propose_ufw_block if risk is 'high'. Never block 'low' risk IPs. "
                "4) Provide a concise incident summary."
            )}]
        },
        "contents": contents,
        "tools": [{"functionDeclarations": TOOLS_SCHEMA}],
        "toolConfig": {"functionCallingConfig": {"mode": "AUTO"}},
    }
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))

def run_agent(log_data: str, auto_approve: bool = False, save_trace: bool = True) -> dict:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("Set GEMINI_API_KEY environment variable first.")

    state = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "max_steps": MAX_STEPS,
        "trajectory": [],
        "seen_calls": [],
        "final_answer": "",
    }
    contents = [{"role": "user", "parts": [{"text": f"Triage this auth.log snippet:\n\n{log_data}"}]}]

    for step in range(1, MAX_STEPS + 1):
        response = call_gemini(contents, api_key)
        candidate = response["candidates"][0]["content"]
        contents.append(candidate)

        parts = candidate.get("parts", [])
        tool_calls = [p["functionCall"] for p in parts if "functionCall" in p]

        if not tool_calls:
            text_out = " ".join(p.get("text", "") for p in parts).strip()
            state["final_answer"] = text_out
            state["trajectory"].append({"step": step, "type": "final_response", "output": text_out})
            break

        tool_response_parts = []
        for call in tool_calls:
            fn_name = call["name"]
            fn_args = call.get("args", {})
            call_sig = f"{fn_name}:{json.dumps(fn_args, sort_keys=True)}"

            if call_sig in state["seen_calls"]:
                result = {"status": "halted", "reason": "Duplicate tool call detected"}
            else:
                state["seen_calls"].append(call_sig)
                if fn_name == "parse_auth_log":
                    result = parse_auth_log(**fn_args)
                elif fn_name == "check_ip_reputation":
                    result = check_ip_reputation(**fn_args)
                elif fn_name == "propose_ufw_block":
                    result = propose_ufw_block(**fn_args, auto_approve=auto_approve)
                else:
                    result = {"status": "error", "message": f"Unknown tool: {fn_name}"}

            state["trajectory"].append({
                "step": step,
                "type": "tool_call",
                "tool": fn_name,
                "args": fn_args,
                "result": result,
            })
            tool_response_parts.append({
                "functionResponse": {"name": fn_name, "response": {"result": result}}
            })

        contents.append({"role": "user", "parts": tool_response_parts})

    if save_trace:
        os.makedirs("traces", exist_ok=True)
        fname = f"traces/trace_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json"
        with open(fname, "w") as f:
            json.dump(state, f, indent=2)
        print(f"Saved execution trace to {fname}")

    return state
