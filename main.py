import argparse
import socket
from scapy.all import *
from scapy.layers.inet import IP, TCP
result = []
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('host', type=str, nargs=1)
    parser.add_argument('p1', type=int, nargs=1)
    parser.add_argument('p2', type=int, nargs=1)
    args = parser.parse_args()
    return (args.host,args.p1,args.p2)

def tcp_scan(ip, ports):
    try:
        syn = IP(dst=ip) / TCP(dport=ports, flags="S")
    except socket.gaierror:
        raise ValueError()

    answer, unanswer = sr(syn, timeout=2, retry=1)
    for sent, received in answer:
        if received[TCP].flags == "SA":
            result.append(received[TCP].sport)

if __name__ == '__main__':
    parse_args = parse_args()
    host = parse_args[0]
    p1 = parse_args[1]
    p2 = parse_args[2]
    ports = []
    for e in range(p1[0], p2[0]):
        try:
            result = tcp_scan(host, e)
        except ValueError as error:
            print(error)
            exit(1)

    print(result)
    if result.count()!=0:
        for port in result:
            print(f'Port {port} is open.')
    else:
        print("Нет открытых портов")


