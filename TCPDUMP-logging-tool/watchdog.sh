#!/bin/bash

export SSLKEYLOGFILE=/home/ruwa/Documents/My_GITHUB_projects/Network_Analysis/TCPDUMP-logging-tool/sslkeys
/usr/bin/google-chrome-stable &
sudo tcpdump host apod.nasa.gov -w capture.pcap -G 600 -C 1
