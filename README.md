# Wifi_sniffing_tool

This repository contains an Intrusion Detection System (IDS) developed from the work of the Signal Processing and Networks Research group at Loughborough University http://www.lboro.ac.uk/departments/meme/research/research-groups/signal-processing-networks/. The IDS is designed to detect and respond, by closing the victims web browser, to attacks launched by the Airpwn-ng tool. 

The tool works by applying Dempster-Shafer data fusion techniques to analyse packet metrics and produce statistical results that determine if an attack has been launched. In order to further improve the statistical analysis an automatic Basic Probability Assignment (BPA) method is employed that continually adapts to suit the current 'normal' of the metrics. 

The IDS is based on the following journals: 

KYRIAKOPOULOS, K.G., APARICIO-NAVARRO, F.J. and PARISH, D.J., 2014. "Manual and automatic assigned thresholds in multi-layer data fusion
intrusion detection system for 802.11 attacks". IET Information Security, 8 (1), pp. 42 - 50.

APARICIO-NAVARRO, F.J., KYRIAKOPOULOS, K.G., Gong, Y., PARISH, D.J., CHAMBERS, J.A., 2017. "Using Pattern-of-Life as Contextual Information for Anomaly-Based Intrusion Detection Systems". IEEE Access, 5, pp. 22177 - 22193.

The research in these journals comes from a wider joint research programme between Loughborough University in the UK and King Saud University of Saudi Arabia. The research has been supported by the Gulf Science, Innovation and Knowledge Economy Programme of the U.K. Government under UK-Gulf Institutional Link Grant IL 279339985. Further information can be found at: http://www.lboro.ac.uk/departments/meme/research/research-groups/signal-processing-networks/int-collaboration/

Please feel free to use and experiment with this open source IDS. 
