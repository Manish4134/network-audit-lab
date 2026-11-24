#!/usr/bin/env python3
import json
import os
import re
import time
import paramiko

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\r")

def collect_exec(client, commands):
    outputs = []
    for cmd in commands:
        _, stdout, stderr = client.exec_command(cmd, timeout=15)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        outputs.append(out + err)
    return "\n".join(outputs)

def collect_shell(client, commands, exit_cmd="exit"):
    chan = client.invoke_shell(width=200, height=50)
    time.sleep(1.5)
    while chan.recv_ready():
        chan.recv(65535)

    for cmd in commands:
        chan.send(cmd + "\n")
        time.sleep(1.2)

    chan.send(exit_cmd + "\n")
    chunks = []
    deadline = time.time() + 10
    last_data = time.time()
    while time.time() < deadline:
        if chan.recv_ready():
            chunks.append(chan.recv(65535).decode("utf-8", errors="replace"))
            last_data = time.time()
        elif time.time() - last_data > 1.5:
            break
        else:
            time.sleep(0.2)
    chan.close()
    return ANSI_RE.sub("", "".join(chunks))

def audit_config(vendor, text):
    low = text.lower()
    findings = []

    if any(k in low for k in ("feature telnet", "telnet-server", "telnet;")) or re.search(
        r"transport input\s+.*\b(telnet|all)\b", low
    ):
        findings.append("FAIL: Telnet enabled")

    if re.search(r"community\s+[\"']?public[\"']?", low):
        findings.append("FAIL: Weak SNMP 'public'")

    has_ssh = any(k in low for k in ("ssh", "stelnet server enable", "ssh-server"))
    if not has_ssh:
        findings.append("WARN: SSH config not explicit")

    return findings if findings else ["PASS"]

def main():
    with open("inventory.json", "r", encoding="utf-8") as f:
        devices = json.load(f)

    os.makedirs("collected_configs", exist_ok=True)
    print(f"{'DEVICE':<16} {'VENDOR':<15} {'STATUS':<10} {'LINES':<7} {'AUDIT FINDINGS'}")
    print("-" * 85)

    for dev in devices:
        name = dev["name"]
        vendor = dev["vendor"]
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=dev["host"],
                username=dev["username"],
                password=dev["password"],
                timeout=10,
                look_for_keys=False,
                allow_agent=False,
            )
            if dev.get("mode") == "exec":
                cfg = collect_exec(client, dev["commands"])
            else:
                cfg = collect_shell(client, dev["commands"], dev.get("exit_cmd", "exit"))
            client.close()

            out_path = os.path.join("collected_configs", f"{name}.txt")
            with open(out_path, "w", encoding="utf-8") as out_f:
                out_f.write(cfg)

            findings = audit_config(vendor, cfg)
            lines = len(cfg.splitlines())
            print(f"{name:<16} {vendor:<15} {'OK':<10} {lines:<7} {', '.join(findings)}")
        except Exception as e:
            print(f"{name:<16} {vendor:<15} {'ERROR':<10} {0:<7} {type(e).__name__}: {e}")

if __name__ == "__main__":
    main()
