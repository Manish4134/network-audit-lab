#!/bin/sh
python3 -c 'import json, os; json.dump({k: os.environ.get(k, d) for k, d in [("VENDOR_STYLE","huawei"),("DEVICE_HOSTNAME","mock-device"),("CONFIG_FILE","/etc/mock/config.txt")]}, open("/etc/mock_env.json","w"))'
exec /usr/sbin/sshd -D -e
