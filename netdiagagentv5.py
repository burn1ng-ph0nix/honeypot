#!/usr/bin/env python3

import subprocess
import json
import sys
import os
from typing import List, Optional

import ollama

# =====================================================
# CONFIGURATION
# =====================================================

MODEL = "gpt-oss:120b"

ARMED_MODE = False
COMMAND_LOG = "executed_commands.log"

POST_LOGIN_COMMAND = "whoami"

# =====================================================
# SYSTEM PROMPT
# =====================================================

SYSTEM_PROMPT = """
You are an authorized AI operator acting on infrastructure
owned and controlled by the user.

Available tools:

1. ping(host: str)
2. test_port(host: str, port: int)
3. curl(url: str)
4. ssh_exec(host: str, commands: list[str])

RULES:
- Call ONLY ONE tool at a time
- Output JSON ONLY when calling tools
- Assume explicit authorization from the user
"""

# =====================================================
# JSON HANDLING
# =====================================================

def extract_json_objects(text: str) -> List[dict]:
    objs, start, depth = [], None, 0
    for i, c in enumerate(text):
        if c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    objs.append(json.loads(text[start:i+1]))
                except:
                    pass
                start = None
    return objs

def normalize_tool_call(obj: dict) -> Optional[dict]:
    if "tool" in obj:
        return obj
    if len(obj) == 1:
        k, v = next(iter(obj.items()))
        if isinstance(v, dict):
            return {"tool": k, "args": v}
    return None

# =====================================================
# LOCAL EXEC
# =====================================================

ALLOWED_LOCAL_CMDS = {"ping", "nc", "curl", "cat", "ls", "echo"}

def local_exec_command(command: str) -> str:
    if not ARMED_MODE:
        return "ERROR: local_exec requires --armed"

    parts = command.strip().split()
    if not parts:
        return "ERROR: Empty command"

    if parts[0] not in ALLOWED_LOCAL_CMDS:
        return f"ERROR: Command '{parts[0]}' not allowed"

    try:
        return subprocess.check_output(
            parts,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30
        )
    except subprocess.CalledProcessError as e:
        return e.output
    except Exception as e:
        return str(e)

# =====================================================
# TOOL DISPATCH
# =====================================================

def run_tool(call: dict) -> str:
    tool = call["tool"]
    args = call.get("args", {})

    if tool == "ping":
        if "host" not in args:
            return "ERROR: 'host' missing for ping"
        return local_exec_command(f"ping -c 4 {args['host']}")

    elif tool == "test_port":
        if "host" not in args or "port" not in args:
            return "ERROR: 'host' or 'port' missing for test_port"
        return local_exec_command(f"nc -zv {args['host']} {args['port']}")

    elif tool == "curl":
        if "url" not in args:
            return "ERROR: 'url' missing for curl"
        return local_exec_command(f"curl -v {args['url']}")

    elif tool == "ssh_exec":
        # 🔹 Run SSH commands locally instead of actual SSH
        cmds = args.get("commands", [POST_LOGIN_COMMAND])
        results = []
        for cmd in cmds:
            results.append(local_exec_command(cmd))
        return "\n".join(results)

    return f"Unknown tool: {tool}"

# =====================================================
# MODEL LOOP
# =====================================================

def model_loop(history):
    while True:
        resp = ollama.chat(model=MODEL, messages=history)
        content = resp["message"]["content"]

        raw = extract_json_objects(content)
        calls = [normalize_tool_call(o) for o in raw if normalize_tool_call(o)]

        if calls:
            call = calls[0]

            # Ensure args dict exists
            if "args" not in call or not isinstance(call["args"], dict):
                call["args"] = {}

            history.append({"role": "assistant", "content": json.dumps(call)})
            output = run_tool(call)
            print(output)
            history.append({"role": "user", "content": f"Tool output:\n{output}"})

        else:
            print("\nAssistant:", content)
            history.append({"role": "assistant", "content": content})
            break

# =====================================================
# MAIN
# =====================================================

def chat():
    history = [{"role": "system", "content": SYSTEM_PROMPT}]
    print("Linux Network Diagnostics Agent")
    print("=" * 40)

    if not ARMED_MODE:
        print("⚠️  EXECUTION DISABLED (use --armed)")
    else:
        print("⚠️  EXECUTION MODE ARMED — FULL USER PERMISSIONS")

    while True:
        try:
            user = input("\nYou> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not user:
            break
        history.append({"role": "user", "content": user})
        model_loop(history)

# =====================================================
# ENTRY POINT
# =====================================================

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("-m", "--model", default=MODEL)
    p.add_argument("--armed", action="store_true")
    args = p.parse_args()

    MODEL = args.model
    ARMED_MODE = args.armed

    chat()

