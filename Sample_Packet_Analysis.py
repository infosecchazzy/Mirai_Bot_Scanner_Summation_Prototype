## Charles Frank
## Utility to read a PCAP Bot scanning file with Wireshark
## Bot Scanning dataset from:
##       https://www.impactcybertrust.org/dataset_view?idDataset=740
## Part of experimentation for Dissertation

## Wireshark
import pyshark

## Pandas dataframe
import pandas as pd

## Initialize the total number of packets
total_packets = 0

## Initialize the total time delta from previous packet
total_time_delta = 0

## Initialize total number of distinct source IP
total_source_ip = 0

## Initialize total number of distict destination IP
total_dest_ip = 0

## Initialize total number of unique packets
total_unique_packets = 0

## Initialize total number of non-unique packets
total_non_unique_packets = 0

## Initialize total number of potential new bot victims
total_potential_new_bot_victims = 0

## Initialize total number of non potential bot victims
total_non_vuln_bot_victims = 0

## Initialize needed lists
packet_date_list = []
ip_src_list = []
ip_dst_list = []
delta_time_list = []

## PCAP File
pcap_file = 'C:/aaadiss/Chapt4/2016-10-22.pcap'

## Read the PCAP file using Wireshark.
packets = pyshark.FileCapture(pcap_file)


## Go thru each packet
for each_packet in packets:
    
    ## increment total packtes read
    total_packets = total_packets + 1

    ## split the packet information
    split_packet_info = str(each_packet.frame_info)
    split_packet_info = split_packet_info.split(" ")

    ## set packet delta time
    delta_time = split_packet_info[9]

    ## total up the delta time
    total_time_delta = total_time_delta + float(delta_time)

    ## get the date of the packet
    packet_date = split_packet_info[25] + " " + split_packet_info[26] + " " + split_packet_info[27]
       
    ## Build the needed lists
    packet_date_list.append(packet_date)
    ip_src_list.append(each_packet.ip.src)
    ip_dst_list.append(each_packet.ip.src)
    delta_time_list.append(delta_time)


## Put lists into a dictionary
packets_dict = {'Date':packet_date_list, 'Source':ip_src_list, 'Destination':ip_dst_list, 'Delta':delta_time_list}

## Build the dataframe
packets_df = pd.DataFrame(packets_dict)

## Total number of distinct source IP
criteria = packets_df.Source.unique()
total_source_ip = len(criteria)

## Total number of distict destination IP
criteria = packets_df.Destination.unique()
total_dest_ip = len(criteria)

## Calcualte the frequency for the packet based upon source and destination
packets_df1 = packets_df.groupby(['Source', 'Destination']).size().reset_index(name='Freq')

## Calculate total of unique packets
criteria = packets_df1.loc[packets_df1['Freq'] == 1]
total_unique_packets = criteria['Freq'].sum()

## Calculate total of potential new bot victims
criteria1 = criteria.Destination.unique()
total_potential_new_bot_victims = len(criteria1)

## Calculate the total for non vulnerable bot victims
## and non unique packets
criteria = packets_df1.loc[packets_df1['Freq'] != 1]
total_non_vuln_bot_victims = len(criteria)
total_non_unique_packets = criteria['Freq'].sum()


## Summary
print "Summary for PCAP: ", pcap_file
print "-------------------------------------------------------------------------"
print "Total number of packets: %d" % total_packets
print "Total number of successful SYN packets: %d" % total_unique_packets
print "Total number of re-transmission packets: %d" % total_non_unique_packets
print "-------------------------------------------------------------------------"
print "Total number of Bots: %d" % total_source_ip
print "Total number of potential new Bot Victims: %d" % total_potential_new_bot_victims 
print "Total number of non-vulnerable Bot Victims: %d" % total_non_vuln_bot_victims
print "-------------------------------------------------------------------------"
print "Average packet delta time (seconds): %4.2f" % ( total_time_delta / ( total_packets - 1 ) )
