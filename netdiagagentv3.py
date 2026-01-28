#!/usr/bin/env python3

import subprocess
import json
import getpass
import socket
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

DELAY_BETWEEN_ATTEMPTS = 2.0
POST_LOGIN_COMMAND = "whoami"
AUTO_MODE = False

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
# VALIDATION
# =====================================================

def validate_host(host: str) -> bool:
    bad = [';', '&', '|', '`', '$', '(', ')', '<', '>']
    return bool(host) and not any(c in host for c in bad)


def validate_url(url: str) -> bool:
    bad = [';', '&', '|', '`', '$', '(', ')']
    return url.startswith(("http://", "https://")) and not any(c in url for c in bad)

# =====================================================
# CREDENTIAL HANDLING
# =====================================================

def read_credentials_from_files() -> Tuple[List[str], List[str]]:
    users, pwds = [], []

    if USERNAME_FILE and os.path.exists(USERNAME_FILE):
        with open(USERNAME_FILE) as f:
            users = [l.strip() for l in f if l.strip()]

    if PASSWORD_FILE and os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE) as f:
            pwds = [l.strip() for l in f if l.strip()]

    return users, pwds


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


def get_valid_ssh_credentials(host: str) -> Tuple[str, str]:
    if host in SSH_CRED_CACHE:
        return SSH_CRED_CACHE[host]

    if DEFAULT_SSH_USER and DEFAULT_SSH_PASS:
        ok, _ = try_ssh_login(host, DEFAULT_SSH_USER, DEFAULT_SSH_PASS)
        if ok:
            SSH_CRED_CACHE[host] = (DEFAULT_SSH_USER, DEFAULT_SSH_PASS)
            return DEFAULT_SSH_USER, DEFAULT_SSH_PASS

    users, pwds = read_credentials_from_files()
    if users and pwds:
        for u in users:
            for p in pwds:
                ok, _ = try_ssh_login(host, u, p)
                if ok:
                    SSH_CRED_CACHE[host] = (u, p)
                    return u, p

    MAX_ATTEMPTS = 3

    for attempt in range(MAX_ATTEMPTS):
        user = input(f"SSH username for {host}: ")
        pwd = getpass.getpass("SSH password: ")

        ok, err = try_ssh_login(host, user, pwd)
        if ok:
            SSH_CRED_CACHE[host] = (user, pwd)
            return user, pwd

        print(f"❌ Authentication failed ({attempt + 1}/{MAX_ATTEMPTS})")

    raise RuntimeError("SSH authentication failed after multiple attempts")


# =====================================================
# SSH EXEC
# =====================================================

def ssh_exec_commands(host: str, commands: List[str]) -> str:
    user, pwd = get_valid_ssh_credentials(host)

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
        if "url" not in args:
            return "ERROR: 'url' missing for curl"
        return subprocess.check_output(
            ["curl", "-v", args["url"]],
            stderr=subprocess.STDOUT,
            text=True
        )

    elif tool == "ssh_exec":
        if not ARMED_MODE:
            return "ERROR: ssh_exec requires --armed"

        # 🔹 Auto-fill for legacy "ssh into <host>" style input
        host = args.get("host")
        cmds = args.get("commands", [POST_LOGIN_COMMAND])

        if not host:
            return "ERROR: 'host' missing for ssh_exec"

        return ssh_exec_commands(host, cmds)

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

            # 🔹 Ensure args dict exists
            if "args" not in call or not isinstance(call["args"], dict):
                call["args"] = {}

            # 🔹 BEST FIX: deterministic host recovery
            if call["tool"] == "ssh_exec":
                args = call["args"]

                if "host" not in args:
                    # Pull host from the user's last message
                    last_user_msg = history[-1]["content"]
                    for token in last_user_msg.split():
                        if token.count(".") == 3:  # simple IPv4 detection
                            args["host"] = token
                            break

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
        print("⚠️  ssh_exec DISABLED (use --armed)")
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
    p.add_argument("-u", "--usernames")
    p.add_argument("-p", "--passwords")
    p.add_argument("-m", "--model", default=MODEL)
    p.add_argument("--armed", action="store_true")
    p.add_argument("--ssh-user")
    p.add_argument("--ssh-pass")

    args = p.parse_args()

    USERNAME_FILE = args.usernames
    PASSWORD_FILE = args.passwords
    MODEL = args.model
    ARMED_MODE = args.armed

    DEFAULT_SSH_USER = args.ssh_user
    DEFAULT_SSH_PASS = args.ssh_pass

    chat()

