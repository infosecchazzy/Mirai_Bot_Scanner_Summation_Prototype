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

##      Convert_Pcap.py

## -------------------------------------------------------------------------------------------

## Purpose:

##      This module will convert PcapNG tp Pcap.

##      

##

## Bot Scanning dataset from:

##      https://www.impactcybertrust.org/dataset_view?idDataset=740
 
## -------------------------------------------------------------------------------------------

##

## Functions:

##

## -------------------------------------------------------------------------------------------

## This function analyzes the PCAP files contained in a directory

##

## Parmeters:

##      pcap_dir - directory containing pcap files from Bot scanning dataset

##

## enumerate_analyze_pcaps(pcap_dir):

## -------------------------------------------------------------------------------------------

##

import os

import time

import datetime


## Directory for the 2016 PCAPNG Files

PCAPNG_DIR_2016 = "C:/Mirai2016PCAPS"

## Directory for the 2017 PCAPNG Files

PCAPNG_DIR_2017 = "C:/Mirai2017PCAPS"

## Directory for converted PcapNG to Pcap

PCAP_CONV_DIR = "C:/MiraiCONVPCAPS"


##

## This function converts PcapNG files to Pcap format

##

## Parmeters:

##      pcapng_dir - directory containing pcapng files from Bot scanning dataset

##



def convert_pcaps(pcapng_dir):

    ## Directory separator

    Slash = '/'

    ## Analyze the PCAP files

    for root, dirs, files in os.walk(pcapng_dir):

        ## for each file in the directory

        for filename in files:

            ## calculate the pcap file including its path

            pcapng_file = pcapng_dir  +  Slash + filename + Slash + filename

            pcap_file = PCAP_CONV_DIR + Slash + filename 

            tiger_shark = "C:/\"Program Files\"/Wireshark/tshark -F pcap -r " + pcapng_file + " -w " + pcap_file

            print "Tiger Shark Command: ", tiger_shark

            os.system(tiger_shark)

    return 0

##

## Main

##


if __name__ == "__main__":

    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

    print st

    ## Convert the 2016 PCAPNG files

    convert_pcaps(PCAPNG_DIR_2016)


    ## Analyze the 2017 PCAPNG files

    convert_pcaps(PCAPNG_DIR_2017)

    ts = time.time()
    et = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

    print et
