import numpy as np
import pyshark
import radiotap as r
from scapy.all import *


def live_capture():

    capture = pyshark.LiveCapture(interface='wlan0mon', display_filter='(wlan.sa==00:25:9c:cf:8a:73 || '
                                                                       'wlan.sa==00:25:9c:cf:8a:71)'
                                                                       '&&(wlan.da==40:c3:36:07:d4:bf||'
                                                                       'wlan.da==ff:ff:ff:ff:ff:ff)'
                                                                       '&&!(wlan.fc.type==0)&&tcp')

    for pkt in capture.sniff_continuously(packet_count=200):
        print(pkt.radiotap.dbm_antsignal, pkt.radiotap.datarate, pkt.wlan.duration, pkt.wlan.seq, pkt.ip.ttl)


if __name__=="__main__":
    live_capture()