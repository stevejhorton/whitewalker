#!/usr/bin/env python3

import socket
import subprocess

hostname = subprocess.check_output(
    ["hostname"],
    text=True
).strip()

user = subprocess.check_output(
    ["whoami"],
    text=True
).strip()

msg = (
    f'<133>{subprocess.check_output(["date","+%b %e %H:%M:%S"], text=True).strip()} '
    f'testhost '
    f'CPR-test: '
    f'action=test_shot '
    f'machine="{hostname}" '
    f'user="{user}" '
    f'msg="hello from python"'
)

print(msg)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(
    msg.encode(),
    ("10.175.38.75", 514)
)
sock.close()
