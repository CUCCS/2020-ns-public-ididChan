#! /usr/bin/python

from scapy.all import *
import argparse


"""
    function: print the status of the target port
    params:
        target_port: the scanned port
        status: the status of the port
"""
def print_stat(target_port, status):

    print("PORT-%s:===============>%s " % (target_port, status))


"""
    function: TCP-connect scan
    params: 
        target_ip: the ip address of the remote host
        target_ports: the ports you want to scan
"""
def tcp_connect_scan(target_ip, target_ports):

    print("starting TCP-connect scan...")

    for port in target_ports:

        recved = sr1(IP(dst=target_ip) / TCP(dport=port, flags="S"), timeout=1)
        
        if recved is None:
            status = "Filtered"
        else:
            if recved.haslayer(TCP):
                if recved[TCP].flags == 18:
                    status = "Open"
                elif recved[TCP].flags == 20:
                    status = "Closed"


        print_stat(port, status)


"""
    function: TCP-syn scan
    params:
        target_ip: the ip address of the remote host
        target_ports: the ports you want to scan
"""
def tcp_syn_scan(target_ip, target_ports):

    print("starting TCP-syn scan...")

    for port in target_ports:

        recved = sr1(IP(dst=target_ip) / TCP(dport=port, flags="S"), timeout=1)

        if recved is None:
            status = "Unanswered"
        else:
            if recved.haslayer(TCP):
                if recved[TCP].flags == 18:
                    status = "Open"
                    pkt_rst = sr(IP(dst=target_ip) / TCP(dport=port, flags="R"), timeout=1)
                elif recved[TCP].flags == 20:
                    status = "Closed"
                else:
                    status = "[TCP]Resp/Filtered"
            elif recved.haslayer(ICMP):
                if (int(recved.getlayer(ICMP).type) == 3) and (int(recved.getlayer(ICMP).code in [1,2,3,9,10,13])):
                    status = "[ICMP]Filtered"
                else:
                    status = "[ICMP]Resp"
            else:
                status = "[Unknown]Resp"

        print_stat(port, status)

"""
    function: TCP-Xmas scan
    params:
        target_ip: the ip address of the remote host
        target_ports: the ports you wan to scan
"""
def tcp_xmas_scan(target_ip, target_ports):

    print("starting TCP-Xmas scan...")

    for port in target_ports:

        recved = sr1(IP(dst=target_ip) / TCP(dport=port, flags="UPF"), timeout=1)

        if recved is None:
            status = "Open/Filtered"
        else:
            if recved.haslayer(TCP):
                if recved[TCP].flags == 20:
                    status = "Closed"
            elif recved.haslayer(ICMP):
                if (int(recved.getlayer(ICMP).type) == 3) and (int(recved.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    status = "[ICMP]Filtered"
                else:
                    status = "[ICMP]Resp"
            else:
                status = "[Unknown]Resp"

        print_stat(port, status)

"""
    function: TCP-FIN scan
    params:
        target_ip: the ip address of the remote host
        target_ports: the ports you want to scan
"""
def tcp_fin_scan(target_ip, target_ports):

    print("starting TCP-FIN scan...")

    for port in target_ports:

        recved = sr1(IP(dst=target_ip) / TCP(dport=port, flags="F"), timeout=1)

        if recved is None:
            status = "Open/Filtered"
        else:
            if recved.haslayer(TCP):
                if recved[TCP].flags == 20:
                    status = "Closed"
            elif recved.haslayer(ICMP):
                if (int(recved.getlayer(ICMP).type) == 3) and (int(recved.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    status = "[ICMP]Filtered"
                else:
                    status = "[ICMP]Resp"
            else:
                status = "[Unknown]Resp"

        print_stat(port, status)

"""
    function: TCP-NULL scan
    params:
        target_ip: the ip address of the remote host
        target_ports: the ports you want to scan
"""
def tcp_null_scan(target_ip, target_ports):

    print("starting TCP-NULL scan...")

    for port in target_ports:

        recved = sr1(IP(dst=target_ip) / TCP(dport=port, flags=""), timeout=1)

        if recved is None:
            status = "Open/Filtered"
        else:
            if recved.haslayer(TCP):
                if recved[TCP].flags == 20:
                    status = "Closed"
            elif recved.haslayer(TCP):
                if (int(recved.getlayer(ICMP).type == 3)) and (int(recved.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    status = "[ICMP]Filtered"
                else:
                    status = "[ICMP]Resp"
            else:
                status = "[Unknown]Resp"

        print_stat(port, status)

"""
    function: UDP scan
    params:
        target_ip: the ip address of the remote host
        target_posts: the ports you want to scan
"""
def udp_scan(target_ip, target_ports):

    print("starting UDP scan...")

    for port in target_ports:

        recved = sr1(IP(dst=target_ip) / UDP(dport=port), timeout=5)

        if recved is None:
            status = "Open/Closed/Filtered"
        else:
            if recved.haslayer(UDP):
                status = "Open"
            elif recved.haslayer(ICMP):
                status = "Closed"
            else:
                status = "Unknown"

        print_stat(port, status)



parser = argparse.ArgumentParser(description='Port scanner based on scapy:)')
parser.add_argument("-t", "--target", help="IP address of the remote host", required=True)
parser.add_argument("-p", "--ports", type=int, nargs="+", help="Specify the ports for the scanner")
parser.add_argument("-s", "--scantype", help="Scan type, TCP-connect/TCP-SYN/TCP-Xmas/TCP-FIN/TCP-NULL/UDP", required=True)

args = parser.parse_args()

target = args.target
scantype = args.scantype.lower()

if args.ports:
    ports = args.ports
else:
    ports = range(0, 65535)

if scantype == "connect" or scantype == "c":
    tcp_connect_scan(target, ports)
elif scantype == "syn" or scantype == "s":
    tcp_syn_scan(target, ports)
elif scantype == "xmas" or scantype == "x":
    tcp_xmas_scan(target, ports)
elif scantype == "fin" or scantype == "f":
    tcp_fin_scan(target, ports)
elif scantype == "null" or scantype == "n":
    tcp_null_scan(target, ports)
elif scantype == "udp" or scantype == "u":
    udp_scan(target, ports)
else:
    print("Scan type ERROR:(")
    print("Please try another instead...")



