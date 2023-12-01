from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import ICMP
from scapy.layers.inet import TCP
import sys

ip = input('What is your target IP address/website?\n')

def scanner(ip_addr):
    ans, unans = sr(IP(dst=ip_addr)/ICMP(), timeout = 3)
    returned = "No"
    if(len(unans) == 0):
        returned = "Yes"
    print("Device with this IP address responds to ICMP-ping request pkts [yes/no]: " + returned)
    if(returned == "Yes"):
        ans1, unans1 = sr(IP(dst=ip_addr)/ICMP())
        ans2, unans2 = sr(IP(dst=ip_addr)/ICMP())
        ans3, unans3 = sr(IP(dst=ip_addr)/ICMP())
        ans4, unans4 = sr(IP(dst=ip_addr)/ICMP())
        ans5, unans5 = sr(IP(dst=ip_addr)/ICMP())
        receivedPkts = [unans1, unans2, unans3, unans4, unans5]
        maybeSafePackets = [ans1, ans2, ans3, ans4, ans5]
        safePackets = [ans1, ans2, ans3, ans4, ans5]
        notReceivedCount = 0
        increasingCount = 0
        zeroCount = 0
        for x in range(5):
            if((len(receivedPkts[x])) != 0):
                notReceivedCount = notReceivedCount + 1
                safePackets.remove(maybeSafePackets[x])
        if(notReceivedCount >= 3):
                print("did not get enough ICMP packets to calculate")
        else:
            for x in range(5 - notReceivedCount):
                if(safePackets[x][0][1].id == 0):
                    zeroCount = zeroCount + 1
                elif(x != 0 and safePackets[x-1][0][1].id < safePackets[x][0][1].id):
                    increasingCount = increasingCount + 1
            if (zeroCount == (5 - notReceivedCount)):
                print("IP-ID counter observed in ICMP-reply pkts [zero/incremental/random]: zero")
            elif (increasingCount == (5 - notReceivedCount) - 1):
                print("IP-ID counter observed in ICMP-reply pkts [zero/incremental/random]: incremental")
            else:
                print("IP-ID counter observed in ICMP-reply pkts [zero/incremental/random]: random")
    ans6, unans6 = sr(IP(dst=ip_addr)/TCP(dport=80,flags="S"), timeout = 10)
    portOpen = "No"
    if(len(unans6) == 0 and ans6[0][1].sprintf("%TCP.flags%") == "SA"):
        portOpen = "Yes"
        print("TCP port 80 on this device is open [yes/no]: yes")
        ans9, unans9 = sr(IP(dst=ip_addr)/TCP(dport=80,flags="S"), timeout = 10)
        ans10, unans10 = sr(IP(dst=ip_addr)/TCP(dport=80,flags="S"), timeout = 10)
        ans11, unans11 = sr(IP(dst=ip_addr)/TCP(dport=80,flags="S"), timeout = 10)
        ans12, unans12 = sr(IP(dst=ip_addr)/TCP(dport=80,flags="S"), timeout = 10)
        ans13, unans13 = sr(IP(dst=ip_addr)/TCP(dport=80,flags="S"), timeout = 10)
        receivedPkts = [unans9, unans10, unans11, unans12, unans13]
        maybeSafePackets = [ans9, ans10, ans11, ans12, ans13]
        safePackets = [ans9, ans10, ans11, ans12, ans13]
        notReceivedCount = 0
        increasingCount = 0
        zeroCount = 0
        for x in range(5):
            if((len(receivedPkts[x])) != 0):
                notReceivedCount = notReceivedCount + 1
                safePackets.remove(maybeSafePackets[x])
        if(notReceivedCount >= 3):
            print("did not get enough TCP packets to calculate")
        else:
            for x in range(5 - notReceivedCount):
                if(safePackets[x][0][1].id == 0):
                    zeroCount = zeroCount + 1
                elif(x != 0 and safePackets[x-1][0][1].id < safePackets[x][0][1].id):
                    increasingCount = increasingCount + 1
            if (zeroCount == (5 - notReceivedCount)):
                print("IP-ID counter observed in TCP replies [zero/incremental/random]: zero")
            elif (increasingCount == (5 - notReceivedCount) - 1):
                print("IP-ID counter observed in TCP replies [zero/incremental/random]: incremental")
            else:
                print("IP-ID counter observed in TCP replies [zero/incremental/random]: random")
        sr(IP(dst=ip_addr)/TCP(dport=80,flags="S"), timeout = 0.1)
        captured = sniff(filter="tcp and src host " + ip_addr, count=10, timeout = 120)
        if(len(captured) == 1):
            print("SYN cookies deployed by service running on TCP port 80 [yes/no]: Yes")
            print("max # of SYN-ACK pkts retransmitted by service on TCP port 80: " + str(len(captured)))
        else:
            print("SYN cookies deployed by service running on TCP port 80 [yes/no]: No")
    if(portOpen == "Yes"):
        ans7, unans7 = sr(IP(dst=ip_addr)/TCP(dport=80,flags="S"), timeout = 30)
        ans8, unans8 = sr(IP(dst=ip_addr)/ICMP(), timeout = 30)
        if(len(unans7) != 0 and len(unans8) != 0):
            print("not enough data to determine OS system")
        elif(len(unans7) == 0 and len(unans8) != 0):
            if(ans7[0][1].ttl > 64 and ans7[0][1].ttl <= 128):
                print("Likely OS system deployed on this device [Linux/Windows]: Windows")
            else:
                print("Likely OS system deployed on this device [Linux/Windows]: Linux")
        elif(len(unans7) != 0 and len(unans8) == 0):
            if(ans8[0][1].ttl > 64 and ans8[0][1].ttl <= 128):
                print("Likely OS system deployed on this device [Linux/Windows]: Windows")
            else:
                print("Likely OS system deployed on this device [Linux/Windows]: Linux")
        elif(ans7[0][1].ttl > 64 and ans7[0][1].ttl <= 128 and ans8[0][1].ttl > 64 and ans8[0][1].ttl <= 128):
            print("Likely OS system deployed on this device [Linux/Windows]: Windows")
        else:
            print("Likely OS system deployed on this device [Linux/Windows]: Linux")
    else:
        print("TCP port 80 on this device is open [yes/no]: no")
        ans7, unans7 = sr(IP(dst=ip_addr)/ICMP(), timeout = 30)
        if(len(unans7) != 0):
            print("Not enough data to determine OS syetm")
        elif(ans7[0][1].ttl > 64 and ans7[0][1].ttl <= 128):
            print("Likely OS system deployed on this device [Linux/Windows]: Windows")
        else:
            print("Likely OS system deployed on this device [Linux/Windows]: Linux")

scanner(ip)