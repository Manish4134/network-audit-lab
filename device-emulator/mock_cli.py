#!/usr/bin/env python3
import json
import os
import sys

try:
    with open("/etc/mock_env.json", "r", encoding="utf-8") as f:
        ENV = json.load(f)
except FileNotFoundError:
    ENV = {}

VENDOR = ENV.get("VENDOR_STYLE", os.environ.get("VENDOR_STYLE", "huawei")).lower()
HOSTNAME = ENV.get("DEVICE_HOSTNAME", os.environ.get("DEVICE_HOSTNAME", "mock-device"))
CONFIG_PATH = ENV.get("CONFIG_FILE", os.environ.get("CONFIG_FILE", "/etc/mock/config.txt"))

PROMPTS = {
    "huawei": f"<{HOSTNAME}>",
    "sros": f"A:{HOSTNAME}# ",
    "nxos": f"{HOSTNAME}# ",
    "junos": f"audit@{HOSTNAME}> ",
}

def read_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return f"! No config mounted at {CONFIG_PATH}\n"

def handle_cmd(cmd):
    c = " ".join(cmd.strip().lower().split())
    if c in ("quit", "exit", "logout"):
        return None
    if c in ("", "screen-length 0 temporary", "terminal length 0",
             "environment no more", "set cli screen-length 0"):
        return ""
    if any(k in c for k in (
        "display cur", "show run", "admin display-config", "admin display config",
        "show configuration", "show config"
    )):
        return read_config()
    if "version" in c:
        return f"Emulated {VENDOR.upper()} Device ({HOSTNAME}) - Config Audit Target\n"
    return f"% Simulated response for: {cmd.strip()}\n"

ssh_orig = os.environ.get("SSH_ORIGINAL_COMMAND")
if ssh_orig:
    out = handle_cmd(ssh_orig)
    if out:
        sys.stdout.write(out)
    sys.exit(0)

prompt = PROMPTS.get(VENDOR, f"{HOSTNAME}# ")
while True:
    try:
        sys.stdout.write(prompt)
        sys.stdout.flush()
        line = sys.stdin.readline()
        if not line:
            break
        out = handle_cmd(line)
        if out is None:
            break
        if out:
            sys.stdout.write(out if out.endswith("\n") else out + "\n")
            sys.stdout.flush()
    except (EOFError, KeyboardInterrupt):
        break
