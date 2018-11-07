## Student:

##		Charles V. Frank Jr.

##		charles.frank@trojans.dsu.edu

## 

## University:

##		Dakota State University

## 

## Date:

##		Nov. 6, 2018

## -------------------------------------------------------------------------------------------	

## Module:

##      Alert_Pcaps.py

## -------------------------------------------------------------------------------------------

## Purpose:

##      This module will process Pcap files for alerts in Suricata.

##      

##

## Bot Scanning dataset from:

##      https://www.impactcybertrust.org/dataset_view?idDataset=740

## -------------------------------------------------------------------------------------------

##

## Functions:

##


import os

import time

import datetime


## Directory for converted PcapNG to Pcap

PCAP_CONV_DIR = "C:/MiraiCONVPCAPS"


##

## This function converts PcapNG files to Pcap format

##

## Parmeters:

##      pcapng_dir - directory containing pcapng files from Bot scanning dataset

##



def alert_pcaps(pcap_dir):

    ## Directory separator

    Slash = '/'

    ## Analyze the PCAP files

    for root, dirs, files in os.walk(pcap_dir):

        ## for each file in the directory

        for filename in files:

            pcap_file = pcap_dir + Slash + filename

            ## create the suricata command 

            suricata_command = "C:/\"Program Files (x86)\"/Suricata/suricata -c suricata.yaml -s mira-bot-scanning.rules "
            suricata_command = suricata_command + " -r " + pcap_file
        

            print "Suricata Command: ", suricata_command

            os.system(suricata_command)

    return 0

##

## Main

##


if __name__ == "__main__":

    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

    print st

    ## produce alerts

    alert_pcaps(PCAP_CONV_DIR)

    ts = time.time()
    et = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

    print et
