# WireSharkTools
An assortment of wireshark tools 

## pcap stripper 
remove the first N bytes of header for each packet in the wireshark pcap file 
```
#./pcapStriper.py --help
usage: pcapStriper.py [-h] -n NUMBYTES -f FILE

Strip first N bytes of packet/frames in the pcap file

optional arguments:
  -h, --help            show this help message and exit
  -n NUMBYTES, --numBytes NUMBYTES
                        Number of bytes to remove (between 1 and 1000) from the start of the packet
  -f FILE, --file FILE  Path to the pcap file that needs to be stipped.


Example: Remove first 36 bytes from each packet in the pcap file

#./pcapStriper.py -n 36 -f log.pcap
 Reading the file log.pcap
Read 3 packets
Generated striped pcap file modified-log.pcap
```
