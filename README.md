Improved script for second IDOL task

#TODO: add description
Sort packets with regexp and transmit them over network using UDP.
Written and tested on Python 2.7

    Required external modules:
        scapy
        argparse


USAGE: sudo python udp_idol.py [-h] [-t timeout] path servers

    -h   -- display help
    -t   -- ping timeout in seconds
    path -- path to input file
    servers -- path to servers .json file
