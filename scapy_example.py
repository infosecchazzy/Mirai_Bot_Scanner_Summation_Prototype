from scapy.all import *
## Datetime
import datetime
import time

d1 = datetime.datetime.now()
time.sleep(35)
d2 = datetime.datetime.now()
d3 = d2 - d1

print d3


# rdpcap comes from scapy and loads in our pcap file
##packets = rdpcap('C:/Mirai2016PCAPS/2016-11-24.pcap/2016-11-24.pcap')
##
##num_packets = 0
##
##
### Let's iterate through every packet
##for packet in packets:
##    print packet["IP"].src
##    print packet["IP"].dst
  
