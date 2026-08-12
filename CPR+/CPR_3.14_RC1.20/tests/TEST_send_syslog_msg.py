#!/usr/bin/env python3

import socket
import datetime
import getpass
import argparse

parser = argparse.ArgumentParser(description="Send CPR test syslog")
parser.add_argument(
    "-m", "--message",
    default="hello from WhiteWalker",
    help="Message text"
)
parser.add_argument(
    "-s", "--server",
    default="cpr-syslog.uhc.com",
    help="Syslog server"
)

args = parser.parse_args()

hostname = socket.gethostname()
user = getpass.getuser()

msg = (
    f'<133>{datetime.datetime.now():%b %e %H:%M:%S} '
    f'{hostname} CPR-test: '
    f'action=test_shot '
    f'machine="{hostname}" '
    f'user="{user}" '
    f'msg="{args.message}"'
)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(msg.encode("ascii", "replace"), (args.server, 514))
sock.close()

print(f"Sent to {args.server}:")
print(msg)
