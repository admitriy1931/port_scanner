import argparse
from scapy.all import *
from scapy.layers.inet import IP, TCP
result = []

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('host', type=str, nargs=1)
    parser.add_argument('p1', type=int, nargs=1)
    parser.add_argument('p2', type=int, nargs=1)
    args = parser.parse_args()
    return args.host, args.p1, args.p2


def tcp_scan(ip, port):
    global result
    try:
        package = IP(dst=ip) / TCP(dport=port, flags="S")
    except socket.gaierror:
        raise ValueError()

    answer, unanswer = sr(package, timeout=2, retry=1)
    if not answer:
        result +=[f'port {port} on host {ip} is offline']
    else:
        for sent, received in answer:
            if received[TCP].flags == "SA":
                result +=[f'port {port} on {ip} is open']
            else:
                result +=[f'port {port} on {ip} is closed']


if __name__ == '__main__':
    parse_args = parse_args()
    host = parse_args[0]
    p1 = parse_args[1]
    p2 = parse_args[2]
    ports = []
    for e in range(p1[0], p2[0]):
        tcp_scan(host, e)
    for e in range(0, len(result)):
        print(result[e])
