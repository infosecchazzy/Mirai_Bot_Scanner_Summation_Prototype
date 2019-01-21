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
##      Analyze_PCAP_Files.py
## -------------------------------------------------------------------------------------------
## Purpose:
##      This module will analyze the pcap files that are part of the Bot scanning dataset.
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
## BotScanner module:
##
##      The BotScanner module creates a MongoDB with the results for each PCAP file analyzed.
##

import BotScanner as bs
import os

## Directory for the 2016 PCAP Files
PCAP_DIR_2016 = "C:/Mirai2016PCAPS"

## Directory for the 2017 PCAP Files
PCAP_DIR_2017 = "C:/Mirai2017PCAPS"

##
## This function analyzes the PCAP files contained in a directory
##
## Parmeters:
##      pcap_dir - directory containing pcap files from Bot scanning dataset
##

def analyze_pcaps(pcap_dir):
    ## Directory separator
    Slash = '/'
    
    ## Analyze the PCAP files
    for root, dirs, files in os.walk(pcap_dir):
        
        ## for each file in the directory
        for filename in files:

            ## calculate the pcap file including its path
            pcap_file = pcap_dir  +  Slash + filename  + Slash + filename

            ## analyze the pcap file
            bs.analyze_pcap_file(pcap_file)

    return 0

##
## Main
##

if __name__ == "__main__":

    ## Analyze the 2016 PCAP files
    analyze_pcaps(PCAP_DIR_2016)

    ## Analyze the 2017 PCAP files
    analyze_pcaps(PCAP_DIR_2017)

 
  
    
    
        

        
