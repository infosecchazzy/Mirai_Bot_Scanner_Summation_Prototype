## Charles Frank
## Utility to read a PCAP Bot scanning file with Wireshark
## Bot Scanning dataset from:
##       https://www.impactcybertrust.org/dataset_view?idDataset=740
## Part of experimentation for Dissertation


## Wireshark
import pyshark

## Initialize the total number of packets
total_packets = 0

## initialize the total time delta from previous packet
total_time_delta = 0


## Read the PCAP file using Wireshark.
packets = pyshark.FileCapture("C:/aaadiss/Chapt4/2016-10-22.pcap")


## Go thru each packet
for each_packet in packets:

    ## if not the first packet
    if total_packets > 0:

        ## Add to the total time delta
        total_time_delta = total_time_delta + each_packet.frame-frame.time_delta

        

##    print each_packet.ip.src
##    print each_packet.ip.dst
    total_packets = total_packets + 1
    


print "Total number of packets: ", total_packets
print "Average Delta Time for a packet: ", (total_time_delta / ( total_packets - 1 ))
