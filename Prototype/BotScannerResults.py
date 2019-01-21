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
##      BotScannerResults.py
## -------------------------------------------------------------------------------------------
## Purpose:
##      Functions to provide results with Mirai Bot Scanning dataset 
##
## Bot Scanning dataset from:
##      https://www.impactcybertrust.org/dataset_view?idDataset=740
## -------------------------------------------------------------------------------------------
##
## Functions included:
##
## -------------------------------------------------------------------------------------------
## This function prints out the details for the PCAP runtime
##
## Parameters:
##	start_date - start date
##      end_date - end date
## 
## pcapruntime_details(start_date, end_date):
## -------------------------------------------------------------------------------------------
## This function summarizes the PCAP runtime
##
## Parameters:
##	start_date - start date
##      end_date - end date
##
## pcapruntime_summary(start_date, end_date):
## -------------------------------------------------------------------------------------------
## This function summarizes the dataset 
##
## Parameters:
##	start_date - start date
##      end_date - end date
## 
## dataset_summary(start_date, end_date):
## -------------------------------------------------------------------------------------------
## This function prints out the details for the dataset 
##
## Parameters:
##      start_date - start date
##      end_date - end date
##
## dataset_details(start_date, end_date):
## -------------------------------------------------------------------------------------------
## This function produces two line graphs
##		Line 1: Number of Bots
##		Line 2: Number of potential new Bot Victims
##
##	Parameters:
##		start_date - start date for the PCAP file
##		end_date - end date for the PCAP file
##
## bot_totals_graph(start_date, end_date):
## -------------------------------------------------------------------------------------------
## This function produces two line graphs
##		Line 1: Average Number of Bots 
##		Line 2: Average Number of potential new Bot Victims
##
##	Parameters:
##		start_date - start date for the PCAP file
##		end_date - end date for the PCAP file
##
## bot_average_graph(start_date, end_date):
## -------------------------------------------------------------------------------------------
## This function produces a three line graph
##		Line 1: Total Packets 
##		Line 2: Total Syn Packtes
##              Line 3: Total Retransmission Packets
##
##	Parameters:
##		start_date - start date for the PCAP file
##		end_date - end date for the PCAP file
##
## packet_total_graph(start_date, end_date):
##

## import division
from __future__ import division

## OS
import os

## Pandas dataframe
import pandas as pd

## Mongo DB
from pymongo import MongoClient

## Bokeh
from bokeh.plotting import figure, output_file, show

## Datetime
import datetime as dt

## A python code with pprint
from pprint import pprint

##
## This function prints out the details for the PCAP runtime
##
## Parameters:
##	start_date - start date
##      end_date - end date
##

def pcapruntime_details(start_date, end_date):
 
    ## Assign Mondo DB Client
    client = MongoClient('localhost:27017')
    db = client.Bot_Scanning_Dataset

    ## find the the records in the db from start_date until the end_date
    all_pfiles = db.Daily_PCAP_Runtime.find({"packet_date": {"$gte": start_date, "$lte": end_date}})

    ## Close client
    client.close()

    ## Print Header
    print "--------------------------------------------------------------------------------------------"
    print "PCAP Runtime Details"
    print "Starting PCAP File: ", start_date
    print "Ending PCAP File: ", end_date
   
    ## loop thru all of the records 
    for p_file in all_pfiles:
        ## print a blank line
        print

    	## print out the record
        print "Packet Date: ", p_file['packet_date']
        print "Start Date/Time: ", p_file['start_date']
        print "End Date/Time: ", p_file['end_date']

    print "--------------------------------------------------------------------------------------------"

    return 0

##
## This function summarizes the PCAP runtime
##
## Parameters:
##	start_date - start date
##      end_date - end date
##

def pcapruntime_summary(start_date, end_date):
    ## Initialization
    total_pcaps = 0
    total_run_time = 0
 
    ## Assign Mondo DB Client
    client = MongoClient('localhost:27017')
    db = client.Bot_Scanning_Dataset

    ## find the the records in the db from start_date until the end_date
    all_pfiles = db.Daily_PCAP_Runtime.find({"packet_date": {"$gte": start_date, "$lte": end_date}})

    ## close the client
    client.close()

    ## loop thru all of the records
    first_time = 0
    for p_file in all_pfiles:

        ## Total Packets
        total_pcaps = total_pcaps + 1

        ## Calculate the delta runtime
        s_date = dt.datetime.strptime(str(p_file['start_date']), "%Y-%m-%d %H:%M:%S.%f")
        e_date = dt.datetime.strptime(str(p_file['end_date']), "%Y-%m-%d %H:%M:%S.%f")
        
        delta = e_date - s_date
        
        ## Assign the delta to the total runtime
        if first_time == 0:
            first_time = 1
            total_run_time = delta
        else:
            total_run_time = total_run_time + delta

    ## Set the average runtime
    s_total_run_time = int(total_run_time.total_seconds())
    avg_run_time = float( ( int(s_total_run_time) / 60 ) / int(total_pcaps) ) 

    print "*************************************************************************************"
    print "Summary for PCAP Runtime"
    print "Starting PCAP File: ", start_date
    print "Ending PCAP File: ", end_date
    print "-------------------------------------------------------------------------"
    print "Total Number of PCAP files: " ,total_pcaps
    print("Total Runtime of PCAP files: {}".format(total_run_time))
    print "Average Runtime Per PCAP (minutes): %4.2f" % avg_run_time
    print "*************************************************************************************"

    return 0

##
## This function summarizes the dataset 
##
## Parameters:
##	start_date - start date
##      end_date - end date
##

def dataset_summary(start_date, end_date):
    
    ## Initialization
    total_packets = 0
    total_syn_packets = 0
    total_retransmission_packets = 0
    total_bots = 0
    total_potential_new_bot_victims = 0
    
    avg_packet_time = 0
    avg_bot_scan = 0
    avg_pot_new_bot_victims = 0
 
    ## initialize total subnets
    total_subnets = []

    ## initialize number of pcap files
    num_pfiles = 0

    ## Initilaize minutes for the day of the pcap file
    minutes = 1440
 
    ## Assign Mondo DB Client
    client = MongoClient('localhost:27017')
    db = client.Bot_Scanning_Dataset

    ## find the the records in the db from start_date until the end_date
    all_pfiles = db.Daily_PCAP.find({"packet_date": {"$gte": start_date, "$lte": end_date}})
    
    ## close the client
    client.close()

    ## loop thru all of the records 
    for p_file in all_pfiles:

        ## Sum up attributes
        num_pfiles = num_pfiles + 1
        
        total_packets = total_packets + int(p_file['total_packets'])
        total_syn_packets = total_syn_packets + int(p_file['total_syn_packets'])
        total_retransmission_packets = total_retransmission_packets + int(p_file['total_retransmission_packets'])
        total_bots = total_bots + int(p_file['total_bots'])
        total_potential_new_bot_victims = total_potential_new_bot_victims + int(p_file['total_potential_new_bot_victims'])

        ## add destination subnet
        for dst_subnet in p_file['dest_subnet'] :
            if str(dst_subnet) not in total_subnets:
                total_subnets.append(str(dst_subnet))

    ## Set the averages
            
    avg_packet_time =  float( float( total_packets / num_pfiles ) / minutes ) 
    avg_bot_scan = float ( float( total_bots /  num_pfiles )  / minutes )
    avg_pot_new_bot_victims = float( float( total_potential_new_bot_victims / num_pfiles ) / minutes )

    avg_num_bots = float( total_bots / num_pfiles )
    avg_num_new_pot_bot_victims = float( total_potential_new_bot_victims / num_pfiles )

    ## Display the summary

    print "*************************************************************************************"
    print "Summary for Bot Scanning Dataset"
    print "Start Date: ", start_date
    print "End Date: ", end_date
    print "Destination Subnets: ", total_subnets
    print "-------------------------------------------------------------------------"
    print "Total number of packets: %d" % total_packets
    print "Total number of successful SYN packets: %d" % total_syn_packets
    print "Total number of re-transmission packets: %d" % total_retransmission_packets
    print "-------------------------------------------------------------------------"
    print "Avgerage number of Bots scanning (per PCAP): %6.2f" % avg_num_bots
    print "Avgerage number of potential new Bot Victims (per PCAP): %6.2f" % avg_num_new_pot_bot_victims
    print "-------------------------------------------------------------------------"
    print "Average Number of Packets (per minute): %6.2f" % avg_packet_time
    print "Average Number of Bots Scanning (per minute): %6.2f" % avg_bot_scan
    print "Average Potential New Bot Victims (per minute): %6.2f" % avg_pot_new_bot_victims
    print "Average Potential New Bot Victims (per hour): %6.2f" % ( avg_pot_new_bot_victims * 60 )
    print "*************************************************************************************"

    return 0

##
## This function prints out the details for the dataset 
##
## Parameters:
##      start_date - start date
##      end_date - end date
##

def dataset_details(start_date, end_date):
 
    ## Assign Mondo DB Client
    client = MongoClient('localhost:27017')
    db = client.Bot_Scanning_Dataset

    ## find the the records in the db from start_date until the end_date
    all_pfiles = db.Daily_PCAP.find({"packet_date": {"$gte": start_date, "$lte": end_date}})

    ## Close client
    client.close()

    ## Print Header
    print "--------------------------------------------------------------------------------------------"
    print "Dataset Details"
    print "Starting PCAP File: ", start_date
    print "Ending PCAP File: ", end_date
   
    ## loop thru all of the records 
    for p_file in all_pfiles:

    	## print out the record
        print
        print "Packet Date: ", p_file['packet_date']
        print "Destination Subnets: ", p_file['dest_subnet']
        print "Number of Packets: ", p_file['total_packets']
        print "Number of SYN Packets: ", p_file['total_syn_packets']
        print "Number of Retransmission Packets: ", p_file['total_retransmission_packets']
        print "Number of Bots: ", p_file['total_bots']
        print "Number of Potential New Bot Victims: ", p_file['total_potential_new_bot_victims']

    print "--------------------------------------------------------------------------------------------"

    return 0

##
## This function produces line graphs for
##		Line 1: Number of Bots
##		Line 2: Number of potential new Bot Victims
##
##	Parameters:
##		start_date - start date for the PCAP file
##		end_date - end date for the PCAP file
##

def bot_totals_graph(start_date, end_date):
    ## Initialization
    pcaps = []
    bots = []
    pot_new_bot_victims = []

    ## Assign Mondo DB Client
    client = MongoClient('localhost:27017')
    db = client.Bot_Scanning_Dataset

    ## find the the records in the db from start_date until the end_date
    all_pfiles = db.Daily_PCAP.find({"packet_date": {"$gte": start_date, "$lte": end_date}})

    ## Close client
    client.close()
    
    ## loop thru all of the records 
    for p_file in all_pfiles:

        ## PCAP files
        pcaps.append( dt.datetime.strptime( str(p_file['packet_date'] ), "%Y-%m-%d") )

        ## Bots
        bots.append(int(p_file['total_bots']))

        ## potenital new Bot victims
        pot_new_bot_victims.append(int(p_file['total_potential_new_bot_victims']))

    ## output to static HTML file
    output_file("bot_totals_graph.html")

    ## define the title and x-axis
    p1 = figure(title="Bot Totals", x_axis_type='datetime')

    ## Bots Line
    p1.line(pcaps, bots, legend="Bots", line_width=5, line_color="red")

    ## show the line
    show(p1)

    ## Assign HTML file
    ## output to static HTML file
    output_file("pot_bot_totals_graph.html")

    ## define the title and x-axis
    p2 = figure(title="Potential New Bot Victim Totals", x_axis_type='datetime')

    ## potential new Bot Victims Line
    p2.line(pcaps, pot_new_bot_victims, legend="Pot New Bot Victims", line_width=5, line_color="yellow")

    ## show the line
    show(p2)

    return 0

##
## This function produces two line graphs
##		Line 1: Average Number of Bots 
##		Line 2: Average Number of potential new Bot Victims
##
##	Parameters:
##		start_date - start date for the PCAP file
##		end_date - end date for the PCAP file
##

def bot_average_graph(start_date, end_date):
    ## Initialization
    pcaps = []
    bots = []
    pot_new_bot_victims = []
 
    ## Assign Mondo DB Client
    client = MongoClient('localhost:27017')
    db = client.Bot_Scanning_Dataset

    ## find the the records in the db from start_date until the end_date
    all_pfiles = db.Daily_PCAP.find({"packet_date": {"$gte": start_date, "$lte": end_date}})

    ## Close client
    client.close()

    ## Minutes in a day
    minutes = 1440
   
    ## loop thru all of the records 
    for p_file in all_pfiles:

        ## Set the averages
        avg_bots = float( p_file['total_bots'] / minutes )
        avg_potential_new_bot_victims = float( p_file['total_potential_new_bot_victims'] / minutes ) 

        ## PCAP files
        pcaps.append( dt.datetime.strptime( str(p_file['packet_date'] ), "%Y-%m-%d") )

        ## Average number of Bots per minute
        bots.append(float(avg_bots))

        ## Average number of potenital new Bot victims per minute
        pot_new_bot_victims.append(float(avg_potential_new_bot_victims))

    ## output to static HTML file
    output_file("bot_average_graph.html")

    ## define the title and x-axis
    p1 = figure(title="Bots Per Minute", x_axis_type='datetime')

    ## Bots Line
    p1.line(pcaps, bots, legend="Bots Per Minute", line_width=5, line_color="red")

    ## show the line
    show(p1)

    ## Assign HTML file
    ## output to static HTML file
    output_file("pot_bot_totals_average_graph.html")

    ## define the title and x-axis
    p2 = figure(title="Potential Bot Victims Per Minute", x_axis_type='datetime')

    ## potential new Bot Victims Line
    p2.line(pcaps, pot_new_bot_victims, legend="Pot Bot Victims Per Minute", line_width=5, line_color="yellow")

    ## show the line
    show(p2)

    return 0

##
## This function produces a two line graph
##		Line 1: Number of Packets
##		Line 2: Number of syn packets
##              Line 3: Number of retransmission packets
##
##	Parameters:
##		start_date - start date for the PCAP file
##		end_date - end date for the PCAP file
##

def packet_total_graph(start_date, end_date):
    ## Initialization
    pcaps = []
    packets = []
    syn_packets = []
    retransmission_packets = []

    ## Assign Mondo DB Client
    client = MongoClient('localhost:27017')
    db = client.Bot_Scanning_Dataset

    ## find the the records in the db from start_date until the end_date
    all_pfiles = db.Daily_PCAP.find({"packet_date": {"$gte": start_date, "$lte": end_date}})

    ## Close client
    client.close()
   
    ## loop thru all of the records 
    for p_file in all_pfiles:

        ## PCAP files
        pcaps.append( dt.datetime.strptime( str(p_file['packet_date'] ), "%Y-%m-%d") )

        ## Packets
        packets.append(int(p_file['total_packets']))

        ## Syn packets
        syn_packets.append(int(p_file['total_syn_packets']))

        ## Retransmission packets
        retransmission_packets.append(int(p_file['total_retransmission_packets']))

    ## output to static HTML file
    output_file("packet_total_graph.html")

    ## define the title and x-axis
    p = figure(title="Packet Totals", x_axis_type='datetime')

    ## Packets Line
    p.line(pcaps, packets, legend="Total Packets", line_width=3, line_color="blue")

    ## Syn packets Line
    p.line(pcaps, syn_packets, legend="SYN Packets", line_width=3, line_color="red")

    ## Retransmission packets
    p.line(pcaps, retransmission_packets, legend="Retransmission Packets", line_width=3, line_color="green")

    ## show the results
    show(p)

    return 0
 
    
