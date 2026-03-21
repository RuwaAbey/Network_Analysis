#!/bin/bash

sudo tcpdump  port 22 -i any -w proof.pcap -C 2 -G 600