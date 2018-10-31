## Student:
##		Charles V. Frank Jr.
##		charles.frank@trojans.dsu.edu
## 
## University:
##		Dakota State University
## 
## Date:
##		August 1, 2018
## -------------------------------------------------------------------------------------------	
## Module:
##      BotScanner.py
## -------------------------------------------------------------------------------------------
## Purpose:
##      Functions to perform experimentation with Mirai Bot Scanning dataset 
##
## Bot Scanning dataset from:
##      https://www.impactcybertrust.org/dataset_view?idDataset=740
## -------------------------------------------------------------------------------------------
##
## Functions included:
##
## -------------------------------------------------------------------------------------------
## This function analyzes the PCAP file from the dataset
##
## Parameters:
##    pcap_file - PCAP file
##
## analyze_pcap_file(pcap_file):
## -------------------------------------------------------------------------------------------
## This function returns the PCAP file date
##
## Parameter:
##    pcap_file - pcap file
##
## pcap_file_date( pcap_file ):
## -------------------------------------------------------------------------------------------
## This function returns the destination subnet
##
## Parameter:
##    ip_dst - ip address
##
## dest_subnet( ip_dst ):
##

## OS
import os

## Scapy
from scapy.all import *

## Pandas dataframe
import pandas as pd

## Mongo DB
from pymongo import MongoClient

## Datetime
import datetime

##
## This function analyzes the PCAP file from the dataset
## Parameters:
##  pcap_file - PCAP file
##

def analyze_pcap_file(pcap_file): 
    print "========================================================================="
    
    ## get the current date/time
    startDT = datetime.datetime.now()
    
    print "Starting PCAP Analysis:", startDT

    ## Initialize the total number of packets
    total_packets = 0

    ## Initialize total number of distinct source IP
    total_bots = 0

    ## Initialize total number of unique syn packets
    total_syn_packets = 0

    ## Initialize total number of retransmission packets
    total_retransmission_packets = 0

    ## Initialize total number of potential new bot victims
    total_potential_new_bot_victims = 0

    ## Initialize destination subnet
    dst_subnet = []

    ## Initialize needed lists
    ip_src_list = []
    ip_dst_list = []

    ## Initilaize minutes for the day
    minutes = 1440

    ## Initialize destination IP
    dest_ip = ""

    ## initialize subnet list
    subnet_list = []

    ## display message
    print "Reading PCAP File:", pcap_file

    ## Read the PCAP file 
    packets = rdpcap(pcap_file)
    
    ## Go thru each packet
    for each_packet in packets:
    
        ## increment total packets read
        total_packets = total_packets + 1
       
        ## Build the needed lists
        ip_src_list.append(each_packet["IP"].src)
        ip_dst_list.append(each_packet["IP"].dst)

        ## assign destination ip
        dest_ip = each_packet["IP"].dst

        ## Get the destination subnets in the PCAP file
        dst_subnet = dest_subnet(dest_ip)

        ## put subnet in list
        if dst_subnet not in subnet_list:
            subnet_list.append(dst_subnet)

    print ".... Completed reading PCAP file"

    print ".... Performing Analysis"

    ## Put lists into a dictionary
    packets_dict = {'Source':ip_src_list, 'Destination':ip_dst_list}
    
    ## Build the dataframe
    packets_df = pd.DataFrame(packets_dict)

    ## Total number of distinct source IP
    total_bots = len(packets_df.Source.unique())
        
    ## Calcualte the frequency for the packet based upon source and destination
    packets_df1 = packets_df.groupby(['Source', 'Destination']).size().reset_index(name='Freq')
  
    ## Calculate total of unique packets
    criteria = packets_df1.loc[packets_df1['Freq'] == 1]

    ## determine number of unique packets
    if ( len(criteria) > 0 ):
        total_syn_packets = criteria['Freq'].sum()
    else:
        total_syn_packets = 0

    ## Calculate total of potential new bot victims
    df_pot_new_bot_victims = criteria.Destination.unique()
    total_potential_new_bot_victims = len(df_pot_new_bot_victims)
        
    ## determine the number of total retransmission packets
    total_retransmission_packets = total_packets - total_syn_packets

    ## Calculate PCAP date
    packet_date = pcap_file_date(pcap_file)

    print ".... Completed Performing Analysis"

    print ".... Updating Database"

    ## Assign Mondo DB Client
    client = MongoClient('localhost:27017')

    ## Assign DB
    db = client.Bot_Scanning_Dataset
    
    ## Add the record to the DB
    db.Daily_PCAP.insert_one(
    {
        ## packet date
	"packet_date" : str(packet_date),

        ## destination subnet(s)
	"dest_subnet" : subnet_list,

        ## total number of packets
        "total_packets" : int(total_packets),

        ## total numner of unique syn packets
        "total_syn_packets" : int(total_syn_packets),

        ## total number of retransmission packtes
        "total_retransmission_packets" : int(total_retransmission_packets),

        ## total number of bots
        "total_bots" : int(total_bots),

        ## total number of potential new bot victims
        "total_potential_new_bot_victims" : int(total_potential_new_bot_victims),
     })

    ## Get ending time 
    endDT = datetime.datetime.now()
    print "Ending PCAP Analysis: ", endDT

    print ".... Updating PCAP Runtime Database"

    ## Add the record to the DB
    db.Daily_PCAP_Runtime.insert_one(
    {
        ## packet date
	"packet_date" : str(packet_date),

        ## starting date
	"start_date" : str(startDT),

        ## ending date
        "end_date" : str(endDT)
     })

    ## close client
    client.close()

    print ".... Completed Updating PCAP Runtime Database"
    print "========================================================================="
    
    return 0

##
## This function returns the PCAP file date
## Parameter:
##    pcap_file - pcap file
##

def pcap_file_date( pcap_file ):
    ## Initialize
    packet_date = ""

    ## split the file name that includes the complete path
    packet_date = pcap_file.split("/")

    ## Split to get the file name without the extension, which is the date
    packet_date = packet_date[(len(packet_date) - 1)].split(".")
    
    ## return the date
    return packet_date[0]

##
## This function returns the destination subnet
## Parameter:
##    ip_dst - ip address
##

def dest_subnet( ip_dst ):

    ## Subnet
    dst_sub = ""
    
    ## Get octets
    ip_dst = ip_dst.split(".")

    ## if it is a subnet
    if len( ip_dst ) == 4 :

            ## Assign /24 subnet
            dst_sub = ip_dst[0] + "." + ip_dst[1] + "." + ip_dst[2] + ".0/24"

    ## Return the /24 subnet
    return dst_sub


    
