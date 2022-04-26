from scapy.all import *
from scapy import *
from scapy.utils import rdpcap
from scapy.utils import wrpcap

packets = rdpcap("./testing.pcap", 1000)

for pkt in packets:
    if pkt.haslayer('IP') == 1:
        ##pass
        pkt['IP'].src = "10.0.1.2"
        pkt['IP'].dst = "10.0.1.1"
        del pkt['IP'].chksum

##for pkt in packets:
##   pkt.display()

wrpcap("./testing_edit_check.pcap", packets)
sendpfast(packets)