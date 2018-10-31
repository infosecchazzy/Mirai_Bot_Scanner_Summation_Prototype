from scapy.all import *
from scapy.config import conf
from scapy.utils import RawPcapReader,RawPcapWriter,hexdiff
from scapy.layers import all


# rdpcap comes from scapy and loads in our pcap file
packets = RawPcapReader('2016-10-22.pcap')

print packets[0]

### Let's iterate through every packet
##for packet in packets:
##    # We're only interested packets with a DNS Round Robin layer
##    if packet.haslayer(DNSRR):
##        # If the an(swer) is a DNSRR, print the name it replied with.
##        if isinstance(packet.an, DNSRR):
##            print(packet.an.rrname)
##

print "Finished reading packets"
