#!/usr/bin/env python

__author__ = "Stuart 'XsCode' Woodcock"
__license__ = "GPL"
__version__ = "0.0.1"
__email__ = "stu.woodcock@gmail.com"
__status__ = "alpha"

from struct import *
import sys
import os
import argparse
import subprocess

"""
 4s  u32 signature; 
 I     u32 version;
 B    u8  message_pair;
 B    u8  essid_len;
 32s u8  essid[32];
 B     u8  keyver;
 16s u8  keymic[16];
 6s   u8  mac_ap[6];
 32s u8  nonce_ap[32];
 6s   u8  mac_sta[6];
 32s u8  nonce_sta[32];
 H    u16 eapol_len;
 256s u8  eapol[256];
"""
def read_in_chunks(file_object, chunk_size=393):
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data

def decode_message_pair(message):
    if message == 0:
        return "M1+M2, Eapol source M2, Replay counter maching."
    elif message == 1:
        return "M1+M4, Eapol source M4, Replay counter maching."
    elif message == 2:
        return "M2+M3, Eapol source M2, Replay counter maching."
    elif message == 3:
        return "M2+M3, Eapol source M3, Replay counter maching."
    elif message == 4:
        return "M3+M4, Eapol source M3, Replay counter maching."
    elif message == 5:
        return "M3+M4, Eapol source M4, Replay counter maching."
    elif message == 128:
        return "M1+M2, Eapol source M2, Replay counter not maching."
    elif message == 129:
        return "M1+M4, Eapol source M4, Replay counter not maching."
    elif message == 130:
        return "M2+M3, Eapol source M2, Replay counter not maching."
    elif message == 131:
        return "M1+M3, Eapol source M3, Replay counter not maching."
    elif message == 132:
        return "M3+M4, Eapol source M3, Replay counter not maching."
    elif message == 133:
        return "M3+M4, Eapol source M4, Replay counter not maching."
        
def decode_MAC(keymic):
    return format(ord(keymic[0]), '02X') + ":" + format(ord(keymic[1]), '02X') + ":" + format(ord(keymic[2]), '02X') + ":" +format(ord(keymic[3]), '02X') + ":" + format(ord(keymic[4]), '02X') + ":" + format(ord(keymic[5]), '02X')

def string_to_hex(string):
    tmp = ''
    for x in range(0,  len(string) - 1):
        tmp +=  format(ord(string[x]), '02X')
    return tmp

def format_EAPOL(eapol,  eapol_len):
    tmp = ''
    for x in range(0,  eapol_len - 1):
        if x > 0 and not x % 16: tmp += "\n                "
        tmp += format(ord(eapol[x]), "02X") + " "
    return tmp
    
#def get_oui(mac):
#   search_string = format(ord(keymic[0]), '02X') + format(ord(keymic[1]), '02X') + format(ord(keymic[2]), '02X')
#   proc = subprocess.Popen('grep ' + search_string + " oui.txt" , stdout=subprocess.PIPE)
#   tmp = split(proc.stdout, 
    
parser = argparse.ArgumentParser(description='Get info contained in Hashcat hccapx files')
parser.add_argument('hccapx')
#parser.add_argument('-x',  help='Add extended info such as APs possible type')

args = parser.parse_args()


with open(sys.argv[1], 'r') as f:
    infile = f.read
    packet_total = os.fstat(f.fileno()).st_size / 393
    if not os.fstat(f.fileno()).st_size % 393:
        packet_count = 0
        for cap in read_in_chunks(f):
            packet_count += 1
            signature,  version, message_pair, essid_len, essid, keyver, keymic, mac_ap, nonce_ap, \
            mac_sta, nonce_sta,  eapol_len, eapol = unpack('4s I B B 32s B 16s 6s 32s 6s 32s 2s 256s', cap)
            print "--------------------------"
            print "Packet " + str(packet_count) + " / " + str(packet_total)
            print "--------------------------"
            print "     Signature: " + signature
            print "       Version: " + str(int(version))
            print "  Message Pair: " + decode_message_pair(int(message_pair))
            print "  ESSID length: " + str(essid_len)
            print "         ESSID: " + essid[0:int(essid_len)]
            print "   Key Version: " + str(int(keyver))
            print "       Key Mic: " + string_to_hex(keymic)
            print "        AP MAC: " + decode_MAC(mac_ap)
            print "      AP Nonce: " + string_to_hex(nonce_ap)
            print "   Station MAC: " + decode_MAC(mac_sta)
            print " Station Nonce: " + string_to_hex(nonce_sta)
            _eapol_len = (ord(eapol_len[1]) * 256) + (ord(eapol_len[0]))
            print "  EAPOL Length: " + str(_eapol_len)
            print "         EAPOL: " + format_EAPOL(eapol, _eapol_len)
            print "\n"
            
    else:
        print "Invalid HCCAPX file - size not a multiple of 393 bytes."
    
    
