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
import urllib.request

"""
hccapx packet format
u32 signature; 
u32 version;
u8  message_pair;
u8  essid_len;
u8  essid[32];
u8  keyver;
u8  keymic[16];
u8  mac_ap[6];
u8  nonce_ap[32];
u8  mac_sta[6];
u8  nonce_sta[32];
u16 eapol_len;
u8  eapol[256];
"""
# Each hccapx frame is 393 bytes long, therefore just load each frame one at a time.
def read_in_chunks(file_object, chunk_size=393):
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data


# Simple function to map message pair value to text.
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
        

# Map chars to hex codes for MAC address format 00:00:00:00:00:00
def decode_MAC(keymic):
    return format(keymic[0], '02X') + ":" + format(keymic[1], '02X') + ":" + format(keymic[2], '02X') + ":" +format(keymic[3], '02X') + ":" + format(keymic[4], '02X') + ":" + format(keymic[5], '02X')


# Simple char string to hex string function
def string_to_hex(string):
    tmp = ''
    for x in range(0,  len(string) - 1):
        tmp +=  format(string[x],  '02X')
    return tmp



# Format char string to something nice to display
def format_EAPOL(eapol,  eapol_len):
    tmp = ''
    for x in range(0,  eapol_len - 1):
        if x > 0 and not x % 16: tmp += "\n                "
        tmp += format(eapol[x], "02X") + " "
    return tmp
    
#def get_oui(mac):
#   search_string = format(ord(keymic[0]), '02X') + format(ord(keymic[1]), '02X') + format(ord(keymic[2]), '02X')
#   proc = subprocess.Popen('grep ' + search_string + " oui.txt" , stdout=subprocess.PIPE)
#   tmp = split(proc.stdout, 
    

# Read oui.txt for hardware info
def oui(mac):
#    print('***In OUI')
    inputfile = open("oui.txt", 'r')
    data = inputfile.read()
    entries = data.split("\n\n")[1:-1] #ignore first and last entries, they're not real entries
    d = {}
    for entry in entries:
        parts = entry.split("\n")[1].split("\t")
        company_id = parts[0].split()[0]
        company_name = parts[-1]
        d[company_id] = company_name
 #   print('***Sending back ' + d[string_to_hex(mac)[0:6]])
    return d[string_to_hex(mac)[0:6]]
    

## Main program start
parser = argparse.ArgumentParser(description='Get info contained in Hashcat hccapx files')
parser.add_argument('hccapx')
parser.add_argument("--oui", "-o",   help='Add OUI lookup information',  action="store_true")
parser.add_argument("-d",  help="Download oui file for manufacturer information",  action="store_true")
args = parser.parse_args()

if not os.path.isfile("oui.txt") and args.oui: 
    sys.exit("Please download by using the -d option.")

if args.d:
    print("Downloading oui file, please wait...")
    urllib.request.urlretrieve("http://standards-oui.ieee.org/oui.txt", filename="oui.txt")

try:
    f = open(args.hccapx, 'rb') 
except OSError:
        print("File " + args.hccapx + " not found!")
else:
    infile = f.read
    packet_total = int(os.fstat(f.fileno()).st_size / 393)
    if not os.fstat(f.fileno()).st_size % 393:
        packet_count = 0
        for cap in read_in_chunks(f):
            packet_count += 1
            signature,  version, message_pair, essid_len, essid, keyver, keymic, mac_ap, nonce_ap, \
            mac_sta, nonce_sta,  eapol_len, eapol = unpack('4s I B B 32s B 16s 6s 32s 6s 32s 2s 256s', cap)
            print ("--------------------------")
            print ("Packet " + str(packet_count) + " / " + str(packet_total))
            print ("--------------------------")
            print ("     Signature: " + signature.decode("utf-8"))
            print ("       Version: " + str(int(version)))
            print ("  Message Pair: " + decode_message_pair(int(message_pair)))
            print ("  ESSID length: " + str(essid_len))
            print ("         ESSID: " + essid[0:int(essid_len)].decode("utf-8"))
            print ("   Key Version: " + str(int(keyver)))
            print ("       Key Mic: " + string_to_hex(keymic))
            print ("        AP MAC: " + decode_MAC(mac_ap))
            if args.oui or args.d:
                print ("       AP Manf: " + oui(mac_ap))
            print ("      AP Nonce: " + string_to_hex(nonce_ap)) 
            print ("   Station MAC: " + decode_MAC(mac_sta)) 
            if args.oui or args.d: 
                print ("      STA Manf: " + oui(mac_sta))
            print (" Station Nonce: " + string_to_hex(nonce_sta))
            _eapol_len = (eapol_len[1] * 256) + (eapol_len[0])
            print ("  EAPOL Length: " + str(_eapol_len) + " bytes")
            print ("         EAPOL: " + format_EAPOL(eapol, _eapol_len))
            print ("\n")
    else:
            print ("Invalid HCCAPX file - size not a multiple of 393 bytes.")
    
    
