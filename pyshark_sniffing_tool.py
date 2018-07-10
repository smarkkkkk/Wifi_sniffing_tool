import numpy as np
import pyshark
from scapy.all import *


def pyshark_filtering():
    pcap = pyshark.FileCapture('variable_rate_attack01_mon_VP', display_filter='(wlan.sa==00:25:9c:cf:8a:73 || wlan.sa=='
                                                                               '00:25:9c:cf:8a:71)&&(wlan.da==40:c3:36:07:d4:bf||'
                                                                               'wlan.da==ff:ff:ff:ff:ff:ff)&&!(wlan.fc.type==0)'
                                                                               '&&tcp')
    i = 1
    data = np.zeros((256, 3))
    for pkt in pcap:
        data[i][0] = pkt.radiotap.datarate
        data[i][1] = pkt.radiotap.dbm_antsignal
        data[i][2] = pkt.wlan.duration
        print(pkt.radiotap.datarate,  pkt.radiotap.dbm_antsignal, pkt.wlan.duration)
        i += 1


if __name__ == "__main__":
    pyshark_filtering()