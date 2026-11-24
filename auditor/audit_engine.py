#!/usr/bin/env python3
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import html
import json
import os
import re
import time
import paramiko

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\r")

REMEDIATIONS = {
    "cisco_ios": {
        "SEC-TELNET-OFF": "line vty 0 4 -> transport input ssh",
        "SEC-SNMP-WEAK": "no snmp-server community public",
        "SEC-EXEC-TIMEOUT": "line vty 0 4 -> exec-timeout 10 0",
    },
    "cisco_ios_l2": {
        "SEC-TELNET-OFF": "line vty 0 4 -> transport input ssh",
        "SEC-SNMP-WEAK": "no snmp-server community public",
        "SEC-EXEC-TIMEOUT": "line vty 0 4 -> exec-timeout 10 0",
    },
    "huawei_vrp": {
        "SEC-TELNET-OFF": "undo telnet server enable",
        "SEC-SNMP-WEAK": "undo snmp-agent community public",
    },
    "nokia_sros": {
        "SEC-TELNET-OFF": "configure system security no telnet-server",
        "SEC-SNMP-WEAK": "configure system snmp no community \"public\"",
    },
    "cisco_nxos": {
        "SEC-TELNET-OFF": "no feature telnet",
        "SEC-SNMP-WEAK": "no snmp-server community public",
        "SEC-EXEC-TIMEOUT": "line vty -> exec-timeout 10",
    },
    "juniper_junos": {
        "SEC-TELNET-OFF": "delete system services telnet",
        "SEC-SNMP-WEAK": "delete snmp community public",
    },
}

def infer_layer(dev):
    if "layer" in dev:
        return dev["layer"]
    v = dev.get("vendor", "")
    if v in ("nokia_srlinux", "cisco_ios", "cisco_ios_l2"):
        return "Real NOS (Layer 2)"
    if v == "frr":
        return "Infra (Layer 1)"
    return "Emulated Farm (Layer 3)"

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
    time.sleep(1.2)
    while chan.recv_ready():
        chan.recv(65535)
    for cmd in commands:
        chan.send(cmd + "\n")
        time.sleep(1.0)
    chan.send(exit_cmd + "\n")
    chunks = []
    deadline = time.time() + 10
    last_data = time.time()
    while time.time() < deadline:
        if chan.recv_ready():
            chunks.append(chan.recv(65535).decode("utf-8", errors="replace"))
            last_data = time.time()
        elif time.time() - last_data > 1.2:
            break
        else:
            time.sleep(0.15)
    chan.close()
    return ANSI_RE.sub("", "".join(chunks))

def audit_config(vendor, text):
    low = text.lower()
    findings = []

    if any(k in low for k in ("feature telnet", "telnet-server", "telnet;")) or re.search(
        r"transport input\s+.*\b(telnet|all)\b", low
    ):
        findings.append(("SEC-TELNET-OFF", "HIGH", "Telnet service enabled"))

    if re.search(r"community\s+[\"']?(public|private)[\"']?", low):
        findings.append(("SEC-SNMP-WEAK", "HIGH", "Weak SNMP community (public/private)"))

    if not any(k in low for k in ("ssh", "stelnet server enable", "ssh-server")):
        findings.append(("SEC-SSH-ON", "MEDIUM", "SSH configuration not explicit"))

    if re.search(r"exec-timeout\s+0(\s+0)?\b", low):
        findings.append(("SEC-EXEC-TIMEOUT", "LOW", "Infinite VTY exec-timeout 0"))

    return findings

def audit_device(dev, out_dir):
    name = dev["name"]
    vendor = dev["vendor"]
    layer = infer_layer(dev)
    t0 = time.perf_counter()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=dev["host"],
            username=dev["username"],
            password=dev["password"],
            timeout=12,
            look_for_keys=False,
            allow_agent=False,
        )
        if dev.get("mode") == "exec":
            cfg = collect_exec(client, dev["commands"])
        else:
            cfg = collect_shell(client, dev["commands"], dev.get("exit_cmd", "exit"))
        client.close()

        with open(os.path.join(out_dir, f"{name}.txt"), "w", encoding="utf-8") as f:
            f.write(cfg)

        raw_findings = audit_config(vendor, cfg)
        findings = []
        for rule_id, sev, msg in raw_findings:
            fix = REMEDIATIONS.get(vendor, {}).get(rule_id, "Review vendor hardening guide")
            findings.append({"rule": rule_id, "severity": sev, "message": msg, "fix": fix})

        status = "PASS" if not findings else ("FAIL" if any(f["severity"] == "HIGH" for f in findings) else "WARN")
        return {
            "name": name,
            "host": dev["host"],
            "vendor": vendor,
            "layer": layer,
            "collect_status": "OK",
            "audit_status": status,
            "lines": len(cfg.splitlines()),
            "duration_s": round(time.perf_counter() - t0, 2),
            "findings": findings,
        }
    except Exception as e:
        return {
            "name": name,
            "host": dev["host"],
            "vendor": vendor,
            "layer": layer,
            "collect_status": "ERROR",
            "audit_status": "ERROR",
            "lines": 0,
            "duration_s": round(time.perf_counter() - t0, 2),
            "findings": [{"rule": "CONN-ERR", "severity": "HIGH", "message": f"{type(e).__name__}: {e}", "fix": "Check SSH reachability"}],
        }

def render_html(results, elapsed, out_file):
    total = len(results)
    passed = sum(1 for r in results if r["audit_status"] == "PASS")
    failed = sum(1 for r in results if r["audit_status"] in ("FAIL", "ERROR"))
    warned = sum(1 for r in results if r["audit_status"] == "WARN")
    score = round((passed / total) * 100, 1) if total else 0.0

    rows = []
    for r in results:
        badge_cls = {
            "PASS": "bg-pass",
            "FAIL": "bg-fail",
            "WARN": "bg-warn",
            "ERROR": "bg-fail",
        }.get(r["audit_status"], "bg-warn")

        if r["findings"]:
            f_html = "<ul class='flist'>" + "".join(
                f"<li><span class='sev sev-{html.escape(f['severity'])}'>{html.escape(f['severity'])}</span> "
                f"<strong>{html.escape(f['rule'])}</strong>: {html.escape(f['message'])}"
                f"<br><span class='fix'>Suggested fix: <code>{html.escape(f['fix'])}</code></span></li>"
                for f in r["findings"]
            ) + "</ul>"
        else:
            f_html = "<span class='ok-txt'>All security checks passed</span>"

        rows.append(
            f"<tr>"
            f"<td><strong>{html.escape(r['name'])}</strong><br><small>{html.escape(r['host'])}</small></td>"
            f"<td>{html.escape(r['vendor'])}</td>"
            f"<td><span class='layer'>{html.escape(r['layer'])}</span></td>"
            f"<td>{r['lines']}</td>"
            f"<td><span class='badge {badge_cls}'>{html.escape(r['audit_status'])}</span></td>"
            f"<td>{f_html}</td>"
            f"</tr>"
        )

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Network Configuration Audit Dashboard</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }}
  .wrap {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ margin: 0 0 6px 0; font-size: 24px; }}
  .sub {{ color: #94a3b8; margin-bottom: 20px; font-size: 14px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 22px; }}
  .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 16px; }}
  .card .lbl {{ color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }}
  .card .val {{ font-size: 28px; font-weight: 700; margin-top: 6px; }}
  .pass-c {{ color: #4ade80; }} .fail-c {{ color: #f87171; }} .warn-c {{ color: #fbbf24; }} .blue-c {{ color: #38bdf8; }}
  table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 10px; overflow: hidden; border: 1px solid #334155; }}
  th, td {{ padding: 12px 14px; text-align: left; border-bottom: 1px solid #334155; vertical-align: top; font-size: 14px; }}
  th {{ background: #0b1220; color: #cbd5e1; font-size: 12px; text-transform: uppercase; }}
  small {{ color: #94a3b8; }}
  .badge {{ padding: 3px 9px; border-radius: 999px; font-size: 12px; font-weight: 700; display: inline-block; }}
  .bg-pass {{ background: #14532d; color: #86efac; }}
  .bg-fail {{ background: #7f1d1d; color: #fca5a5; }}
  .bg-warn {{ background: #78350f; color: #fde68a; }}
  .layer {{ background: #334155; color: #e2e8f0; padding: 2px 8px; border-radius: 6px; font-size: 12px; }}
  .flist {{ margin: 0; padding-left: 16px; }}
  .flist li {{ margin-bottom: 6px; }}
  .sev {{ font-size: 10px; padding: 1px 6px; border-radius: 4px; font-weight: 700; }}
  .sev-HIGH {{ background: #991b1b; color: #fecaca; }}
  .sev-MEDIUM {{ background: #92400e; color: #fde68a; }}
  .sev-LOW {{ background: #1e3a8a; color: #bfdbfe; }}
  .fix {{ color: #94a3b8; font-size: 12px; }}
  code {{ background: #0f172a; padding: 1px 5px; border-radius: 4px; color: #7dd3fc; }}
  .ok-txt {{ color: #4ade80; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Multi-Vendor Network Configuration Audit Dashboard</h1>
  <div class="sub">Generated: {html.escape(now)} | Total audit runtime: <strong>{elapsed:.2f}s</strong></div>
  <div class="cards">
    <div class="card"><div class="lbl">Total Devices</div><div class="val blue-c">{total}</div></div>
    <div class="card"><div class="lbl">Compliant (PASS)</div><div class="val pass-c">{passed}</div></div>
    <div class="card"><div class="lbl">Non-Compliant (FAIL)</div><div class="val fail-c">{failed}</div></div>
    <div class="card"><div class="lbl">Warnings</div><div class="val warn-c">{warned}</div></div>
    <div class="card"><div class="lbl">Compliance Score</div><div class="val">{score}%</div></div>
  </div>
  <table>
    <thead>
      <tr><th>Device</th><th>Vendor</th><th>Platform Layer</th><th>Lines</th><th>Status</th><th>Findings &amp; Suggested Remediation</th></tr>
    </thead>
    <tbody>
      {"".join(rows)}
    </tbody>
  </table>
</div>
</body>
</html>"""
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(page)

def main():
    parser = argparse.ArgumentParser(description="Concurrent Multi-Vendor Config Auditor & Dashboard Generator")
    parser.add_argument("--inventory", default="inventory.json", help="Path to JSON inventory")
    parser.add_argument("--workers", type=int, default=20, help="Concurrent SSH workers")
    parser.add_argument("--html", default="report.html", help="Output HTML dashboard path")
    parser.add_argument("--json", default="audit_report.json", help="Output JSON report path")
    args = parser.parse_args()

    with open(args.inventory, "r", encoding="utf-8") as f:
        devices = json.load(f)

    out_dir = "collected_configs"
    os.makedirs(out_dir, exist_ok=True)

    t_start = time.perf_counter()
    results = [None] * len(devices)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        fut_to_idx = {pool.submit(audit_device, dev, out_dir): idx for idx, dev in enumerate(devices)}
        for fut in as_completed(fut_to_idx):
            results[fut_to_idx[fut]] = fut.result()
    elapsed = time.perf_counter() - t_start

    print(f"{'DEVICE':<16} {'VENDOR':<15} {'STATUS':<7} {'LINES':<6} {'TIME':<6} {'FINDINGS'}")
    print("-" * 92)
    for r in results:
        summary = ", ".join(f["message"] for f in r["findings"]) if r["findings"] else "All checks passed"
        print(f"{r['name']:<16} {r['vendor']:<15} {r['audit_status']:<7} {r['lines']:<6} {r['duration_s']:<6} {summary}")
    print("-" * 92)
    print(f"Audited {len(results)} devices concurrently in {elapsed:.2f}s -> {args.html}")

    with open(args.json, "w", encoding="utf-8") as f:
        json.dump({"generated_at": datetime.now().isoformat(), "elapsed_s": round(elapsed, 2), "devices": results}, f, indent=2)
    render_html(results, elapsed, args.html)

if __name__ == "__main__":
    main()
