"""A loopback DNS sink for `detonate`: logs each query name and answers NXDOMAIN, so nothing resolves.

Runs inside the sandbox on 127.0.0.1:53 (the run sets net.ipv4.ip_unprivileged_port_start=0). stdlib only.
"""
import socket
import sys


def main(log_path: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 53))
    with open(log_path, "a", buffering=1) as log:
        while True:
            data, addr = sock.recvfrom(512)
            labels, i = [], 12
            while i < len(data) and data[i] and len(labels) < 64:
                n = data[i]
                labels.append(data[i + 1:i + 1 + n].decode("ascii", "replace"))
                i += 1 + n
            log.write(".".join(labels)[:253] + "\n")
            if len(data) >= i + 5:
                sock.sendto(data[:2] + b"\x81\x83" + data[4:6] + b"\x00" * 6 + data[12:i + 5], addr)


if __name__ == "__main__":
    main(sys.argv[1])
