import numpy as np
import pyshark

# Initialise empty lists for packet features
dbm_antsignal = []  # Received Signal Strength Indication RSSI
datarate = []
duration = []
seq = []
ttl = []
inter_time = []

disp_filter = '(wlan.sa==00:25:9c:cf:8a:73 ||'  \
                     'wlan.sa==00:25:9c:cf:8a:71) &&'  \
                     '(wlan.da==40:c3:36:07:d4:bf ||'  \
                     'wlan.da==ff:ff:ff:ff:ff:ff) '    \
                     '&&!(wlan.fc.type==0)&&tcp'

pcap_fn = '/pcap_files/variable_rate_normal_mon_VP'

pkt_list = pyshark.FileCapture(input_file='pcap_files/variable_rate_attack01_mon_VP', display_filter=disp_filter)

for pkt in pkt_list:
    dbm_antsignal.append(float(pkt.radiotap.dbm_antsignal))
    datarate.append(float(pkt.radiotap.datarate))
    duration.append(float(pkt.wlan.duration))
    seq.append(float(pkt.wlan.seq))
    ttl.append(float(pkt.ip.ttl))
    print(pkt[10])

# Convert all packet feature lists to numpy arrays
dbm_antsignal = np.asarray(dbm_antsignal)
datarate = np.asarray(datarate)
duration = np.asarray(duration)
seq = np.asarray(seq)
ttl = np.asarray(ttl)

# Write all packet feature data to .csv file
pkt_incr = 0
pkt_data = np.zeros((len(dbm_antsignal), 5))

while pkt_incr < len(dbm_antsignal):
    pkt_data[pkt_incr][0] = dbm_antsignal[pkt_incr]
    pkt_data[pkt_incr][1] = datarate[pkt_incr]
    pkt_data[pkt_incr][2] = duration[pkt_incr]
    pkt_data[pkt_incr][3] = seq[pkt_incr]
    pkt_data[pkt_incr][4] = ttl[pkt_incr]
    # print(dbm_antsignal[pkt_incr], datarate[pkt_incr], duration[pkt_incr], seq[pkt_incr], ttl[pkt_incr])
    pkt_incr += 1


# RSSI, Rate, TTL, NAV, sequence number (MAC Layer - Not TCP seq number),
# and finally inter arrival time. I attach the txt file for attack02