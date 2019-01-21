## Student:
##		Charles V. Frank Jr.
##		charles.frank@trojans.dsu.edu
## 
## University:
##		Dakota State University
## 
## Date:
##		August 5, 2018
## -------------------------------------------------------------------------------------------	
## Module:
##      Answer_Research_Questions.py
## -------------------------------------------------------------------------------------------
## Purpose:
##      This module will answer the dissertation research questions.
##      
##
## Bot Scanning dataset from:
##      https://www.impactcybertrust.org/dataset_view?idDataset=740
## -------------------------------------------------------------------------------------------
##
## Functions:
##
## can_the_bots_and_potential_new_bot_victims_be_idenitied - answer research questions one and two
##
## is_it_possible_to_monitor_bot_scanning_over_time - answer research question three
##

import BotScannerResults as bsr

##
## First and second Research Questions
##

def can_the_bots_and_potential_new_bot_victims_be_idenitied():

    ## details for each PCAP in the dataset
    bsr.dataset_details("2016-06-01", "2017-03-31")
 
    ## summary for all of the PCAP files
    bsr.dataset_summary("2016-06-01", "2017-03-31")

    
##
## Third research question
##

def is_it_possible_to_monitor_bot_scanning_over_time():

    ## summary for all of the PCAP files
    bsr.dataset_summary("2016-12-20", "2016-12-24")

    ## packet totls graph
    bsr.packet_total_graph("2016-12-20", "2016-12-24")


    ## Bot and potential new Bot Victim graph
    bsr.bot_totals_graph("2016-12-20", "2016-12-24")


##
## Main
##

if __name__ == "__main__":

    ## Answer research questions one and two
    can_the_bots_and_potential_new_bot_victims_be_idenitied()

    ## Answer reserach question three
    is_it_possible_to_monitor_bot_scanning_over_time()   
 
