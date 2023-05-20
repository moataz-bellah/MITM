from scapy.all import *
from scapy.layers.l2 import Ether, ARP, arping
from scapy.layers.inet import IP, TCP,Packet
import time


def capturePackets(interface):
	sniff(iface=interface,store=False,prn = doSomething)

def doSomething(packet):
	packet.show()
capturePackets('eth0')
