**Improved script for second IDOL task**

Reads file line by line using C shared object library and '\n' as line 
separator. C library is wrapped using SWIG. Packets are checked against 
rules. Then packets that pass are transited to network hosts using UDP 
protocol. 
After transmission of every packet host address is pinged with ICMP packet. 
If host doesnt respond during 'ping timeout' period it will be considered offline. 
Datagram will not be sent and proper warning will be displayed. Every outgoing datagram is checked to assure 
that it was sent to the network.
Program displays total count of successfully sent packets or IDs of packets 
missed by scanner. Script requires _root privileges_ to perform scanning.

Written and tested on Python 2.7

    Required external modules:
        scapy
        argparse


USAGE: sudo python udp_idol.py [-h] [-t timeout] path servers

    -h   -- display help
    -t   -- ping timeout in seconds (1 sec by default)
    path -- path to input file
    servers -- path to servers .json file
