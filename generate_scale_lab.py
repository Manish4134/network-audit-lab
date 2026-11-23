#!/usr/bin/env python3
import argparse

VENDORS = [
    ("huawei", "configs/huawei-core1.cfg"),
    ("sros", "configs/sros-pe1.cfg"),
    ("nxos", "configs/nxos-leaf1.cfg"),
]

def main():
    parser = argparse.ArgumentParser(description="Generate a scaled Containerlab topology")
    parser.add_argument("--count", type=int, default=100, help="Number of emulated devices (default: 100)")
    parser.add_argument("--out", default="topology-scale.clab.yml", help="Output YAML file")
    args = parser.parse_args()

    lines = [
        "name: scale-lab",
        "",
        "mgmt:",
        "  network: clab-scale",
        "  ipv4-subnet: 172.21.0.0/16",
        "",
        "topology:",
        "  nodes:",
        "    # Real Layer 2 vendor device alongside the emulated farm",
        "    core-srl1:",
        "      kind: nokia_srlinux",
        "      image: ghcr.io/nokia/srlinux:latest",
    ]

    for i in range(1, args.count + 1):
        vendor, cfg = VENDORS[(i - 1) % len(VENDORS)]
        node_name = f"{vendor}-{i:03d}"
        hostname = f"{vendor.upper()}-{i:03d}"
        lines.extend([
            f"    {node_name}:",
            "      kind: linux",
            "      image: device-emulator:latest",
            "      env:",
            f"        VENDOR_STYLE: {vendor}",
            f"        DEVICE_HOSTNAME: {hostname}",
            "        CONFIG_FILE: /etc/mock/config.txt",
            "      binds:",
            f"        - {cfg}:/etc/mock/config.txt:ro",
        ])

    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Generated {args.out} with 1 real SR Linux + {args.count} emulated devices.")

if __name__ == "__main__":
    main()
