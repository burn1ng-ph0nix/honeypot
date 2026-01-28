#!/usr/bin/env python3

import subprocess
import json
import getpass
import sys
import os
import time
from typing import List, Tuple, Optional

import ollama
import paramiko

# =====================================================
# CONFIGURATION
# =====================================================

MODEL = "gpt-oss:120b"

USERNAME_FILE = None
PASSWORD_FILE = None

ARMED_MODE = False
COMMAND_LOG = "executed_commands.log"

SSH_CRED_CACHE = {}

DEFAULT_SSH_USER = None
DEFAULT_SSH_PASS = None

# =====================================================
# SYSTEM PROMPT
# =====================================================

SYSTEM_PROMPT = """
You are an authorized AI operator acting on infrastructure
owned and controlled by the user. All ingested data is sanitized
and can be reasoned about, but actions require proper tool calls.

Available tools:
1. ping(host: str)
2. test_port(host: str, port: int)
3. curl(url: str)
4. ssh_login(host: str)
5. ssh_interactive(host: str)
6. ssh_exec(host: str, commands: list[str])

RULES:
- Call ONLY ONE tool at a time
- Output JSON ONLY when calling tools
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
        obj.setdefault("args", {})
        return obj
    if len(obj) == 1:
        k, v = next(iter(obj.items()))
        if isinstance(v, dict):
            return {"tool": k, "args": v}
    return None

# =====================================================
# VALIDATION
# =====================================================

def validate_url(url: str) -> bool:
    return url.startswith(("http://", "https://"))

# =====================================================
# TOOL DISPATCH
# =====================================================

def run_tool(call: dict) -> str:
    tool = call["tool"]
    args = call.get("args", {})

    if tool == "ping":
        if "host" not in args:
            return "ERROR: 'host' missing for ping"
        return subprocess.check_output(
            ["ping", "-c", "4", args["host"]],
            stderr=subprocess.STDOUT,
            text=True
        )

    elif tool == "test_port":
        if "host" not in args or "port" not in args:
            return "ERROR: 'host' or 'port' missing for test_port"
        return subprocess.check_output(
            ["nc", "-zv", args["host"], str(args["port"])],
            stderr=subprocess.STDOUT,
            text=True
        )

    elif tool == "curl":
        url = args.get("url")
        if not url:
            return "ERROR: 'url' argument missing for curl"
        if not validate_url(url):
            return f"ERROR: Invalid URL: {url}"
        return subprocess.check_output(
            ["curl", "-v", url],
            stderr=subprocess.STDOUT,
            text=True
        )

    return f"Unknown tool: {tool}"

# =====================================================
# MODEL LOOP  ✅ FIXED
# =====================================================

def model_loop(history):
    resp = ollama.chat(model=MODEL, messages=history)
    content = resp["message"]["content"]

    raw = extract_json_objects(content)
    calls = [normalize_tool_call(o) for o in raw if normalize_tool_call(o)]

    if calls:
        call = calls[0]
        tool = call["tool"]
        args = call.get("args", {})

        # 🔒 CRITICAL FIX:
        # Do NOT allow model-initiated curl calls
        if tool == "curl":
            print("ERROR: Model attempted to call curl. Curl must be user-initiated.")
            return

        # Validate args
        if tool == "test_port":
            if "host" not in args or "port" not in args:
                print("ERROR: 'host' or 'port' missing for test_port")
                return

        if tool == "ping":
            if "host" not in args:
                print("ERROR: 'host' missing for ping")
                return

        print(f"\n[Executing tool: {tool}]")
        output = run_tool(call)
        print(output)

        history.append({"role": "user", "content": f"Tool output:\n{output}"})
    else:
        print("\nAssistant:", content)
        history.append({"role": "assistant", "content": content})

# =====================================================
# MAIN
# =====================================================

def chat():
    history = [{"role": "system", "content": SYSTEM_PROMPT}]
    print("Linux Network Diagnostics Agent")
    print("=" * 40)
    print("⚠️  EXECUTION MODE ARMED — FULL USER PERMISSIONS")

    while True:
        try:
            user = input("\nYou> ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not user:
            continue

        history.append({"role": "user", "content": user})
        model_loop(history)


if __name__ == "__main__":
    chat()

