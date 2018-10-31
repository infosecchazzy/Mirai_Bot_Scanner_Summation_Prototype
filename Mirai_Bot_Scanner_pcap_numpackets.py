## Charles Frank
## Program:
## Utility to read a Mirai Bot Scanning dataset 
## Bot Scanning dataset from:
##       https://www.impactcybertrust.org/dataset_view?idDataset=740
## Experimentation for Dissertation

## OS
import os

## Wireshark
import pyshark

## Pandas dataframe
import pandas as pd

##
## This function analyzes the PCAP file from the dataset
## Parameters:
##  pcap_file - PCAP file
##  provide_summary - determines if the summary should be provided for the pcap file
## Returns:
##  packet_date - date of the packets
##  total_packets - total number of packets
##  total_unique_packets - total number of unique packtes
##  total_non_unique_packets - total number of non-unique packets
##  total_bots - total number of Bots
##  total_potential_new_bot_victims - total number of potential new Bot victims
##  total_non_vuln_bot_victims - total number of non-vulnerable Bot victims
##  avg_delta_time - average Bot scanning time
##
def analyze_pcap_file( pcap_file, provide_summary ): 

    ## Initialize the total number of packets
    total_packets = 0

    ## Initialize the total time delta from previous packet
    total_time_delta = 0

    ## Initialize total number of distinct source IP
    total_bots = 0

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

    ## Initialize average delta time packets of the PCAP file
    avg_delta_time = 0

    ## Initialize needed lists
    packet_date_list = []
    ip_src_list = []
    ip_dst_list = []
    delta_time_list = []

    ## Read the PCAP file using Wireshark.
    packets = pyshark.FileCapture(pcap_file)

    for exch_packet in packets:
        total_packets = total_packets + 1

    print "Number of Packets: " , total_packets



##
def analyze_bot_scanning_dataset():

    pcap_file ="C:/aaadiss/Chapt4/2016-10-22.pcap"

##    analyze_pcap_file( pcap_file, 1 )

    pcap_file = "C:/Mirai2016PCAPS/2016-11-24.pcap/2016-11-24.pcap"

    analyze_pcap_file( pcap_file, 1 )

#if in main part of python script
if __name__ == "__main__":

    #analyze the Mirai Scanning dataset
    analyze_bot_scanning_dataset() 
    
    
