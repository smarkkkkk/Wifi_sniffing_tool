import radiotap as r
import pcap
from scapy.all import *

pc = pcap.pcap(name='variable_rate_attack02_mon_VP')

pkt = pc[0]

off, radiotap = r.radiotap_parse(pkt)

print(radiotap)

off, mac = r.ieee80211_parse(pkt, off)

print(mac)
