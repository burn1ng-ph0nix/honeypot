#!/usr/bin/env python3

import subprocess
import json
import getpass
import socket
import sys
import os
import time
import base64
from typing import List, Tuple, Optional

import ollama
import paramiko

# =====================================================
# CONFIGURATION
# =====================================================

MODEL = "gpt-oss:120b"

USERNAME_FILE = None
PASSWORD_FILE = None

DELAY_BETWEEN_ATTEMPTS = 2.0
POST_LOGIN_COMMAND = "whoami"
AUTO_MODE = False

ARMED_MODE = False
COMMAND_LOG = "executed_commands.log"

SSH_CRED_CACHE = {}

DEFAULT_SSH_USER = None
DEFAULT_SSH_PASS = None

ACTIVE_SSH_HOST = None

ALLOWED_LOCAL_CMDS = {"nc", "cat", "ls", "echo"}

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
4. local_exec(command: str)
5. ssh_exec(host: str, commands: list[str])

RULES:
- Call ONLY ONE tool at a time
- Output JSON ONLY when calling tools
- If curl returns encoded instructions, decode them yourself
- Use local_exec for commands that should run on the agent host
- Assume explicit authorization from the user
- When calling curl, always construct a full URL including scheme and port
- Never pass natural language as the URL argument

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
# VALIDATION
# =====================================================

def validate_url(url: str) -> bool:
    bad = [';', '&', '|', '`', '$', '(', ')']
    return url.startswith(("http://", "https://")) and not any(c in url for c in bad)

# =====================================================
# LOCAL EXEC
# =====================================================

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
            timeout=15
        )
    except subprocess.CalledProcessError as e:
        return e.output
    except Exception as e:
        return str(e)

# =====================================================
# SSH (UNCHANGED, STILL AVAILABLE)
# =====================================================

def try_ssh_login(host, username, password, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=timeout,
        )
        return True, f"SSH SUCCESS: {username}@{host}"
    except Exception as e:
        return False, str(e)
    finally:
        client.close()


def ssh_exec_commands(host: str, commands: List[str]) -> str:
    user, pwd = SSH_CRED_CACHE.get(host, (None, None))
    if not user or not pwd:
        return "ERROR: No cached SSH credentials"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, username=user, password=pwd)

    results = []
    with open(COMMAND_LOG, "a") as log:
        log.write(f"\n=== {host} ===\n")

        for cmd in commands:
            log.write(f"$ {cmd}\n")
            stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
            out = stdout.read().decode(errors="ignore")
            err = stderr.read().decode(errors="ignore")
            results.append(f"$ {cmd}\n{out}{err}")
            log.write(out + err + "\n")

    client.close()
    return "\n".join(results)

# =====================================================
# TOOL DISPATCH
# =====================================================

def run_tool(call: dict) -> str:
    tool = call["tool"]
    args = call.get("args", {})

    if tool == "ping":
        return subprocess.check_output(
            ["ping", "-c", "4", args["host"]],
            stderr=subprocess.STDOUT,
            text=True
        )

    elif tool == "test_port":
        return subprocess.check_output(
            ["nc", "-zv", args["host"], str(args["port"])],
            stderr=subprocess.STDOUT,
            text=True
        )

    elif tool == "curl":
        raw = args.get("url")
        if not raw:
            return "ERROR: 'url' missing for curl"

    # Just pass whatever the user/model typed directly to curl
        return subprocess.check_output(
            ["curl", "-v", "-L", raw],
            stderr=subprocess.STDOUT,
            text=True
        )


    elif tool == "local_exec":
        cmd = args.get("command")
        if not cmd:
            return "ERROR: 'command' missing for local_exec"
        return local_exec_command(cmd)

    elif tool == "ssh_exec":
        return "ERROR: ssh_exec disabled for this workflow"

    return f"Unknown tool: {tool}"

# =====================================================
# MODEL LOOP
# =====================================================

def model_loop(history):
    resp = ollama.chat(model=MODEL, messages=history)
    content = resp["message"]["content"]

    raw = extract_json_objects(content)
    calls = [normalize_tool_call(o) for o in raw if normalize_tool_call(o)]

    if calls:
        call = calls[0]
        output = run_tool(call)
        print(output)
        history.append({"role": "system", "content": f"Tool output:\n{output}"})
        return

    print("\nAssistant:", content)
    history.append({"role": "assistant", "content": content})

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


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("-m", "--model", default=MODEL)
    p.add_argument("--armed", action="store_true")

    args = p.parse_args()

    MODEL = args.model
    ARMED_MODE = args.armed

    chat()

