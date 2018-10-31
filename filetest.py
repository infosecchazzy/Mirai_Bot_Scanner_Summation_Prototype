import os

PCAP_DIR_2016 = "C:/Mirai2016PCAPS"

Slash = '/'

for root, dirs, files in os.walk(PCAP_DIR_2016):

    for filename in files:

        pcap_file = PCAP_DIR_2016  +  Slash + filename  + Slash + filename

        print(pcap_file)
