#!/usr/bin/env python3
import struct 
import sys
import os
import pdb
import argparse


pcapHeaderStruct = struct.Struct('I H H i I I I')
pktHeaderStruct = struct.Struct('I I I I')

parser = argparse.ArgumentParser(description="Strip first N bytes of packet/frames in the pcap file")

# Add argument for number of bytes
parser.add_argument("-n", "--numBytes", type=lambda x: int(x) if 1 <= int(x) <= 1000 else argparse.ArgumentTypeError("Number of bytes must be between 1 and 1000"), required=True, help="Number of bytes to remove (between 1 and 1000) from the start of the packet")

# Add argument for stored file (made compulsory)
parser.add_argument("-f", "--file", type=str, required=True, help="Path to the pcap file that needs to be stipped.")
# Parse the command-line arguments
args = parser.parse_args()

fileName = os.path.basename( args.file ) 
dirName = os.path.dirname ( args.file )


byteLenToChop = args.numBytes  
 

fh = open( args.file, "rb" )
# set the position to the last byte of the file
fh.seek(0,2)
inputFSize = fSize = fh.tell()
fh.seek(0)
minPcapSize = 24+16+64
assert  fSize > minPcapSize, "Invalid pcap file" 

pcapHeader = fh.read(24)
headerSignature = pcapHeaderStruct.unpack( pcapHeader )[0]
assert headerSignature == 0xa1b2c3d4, "Invalid Pcap Header" 
newFile = pcapHeader 
numPkt = 0 
#print( " file is %d  bytes " % (  fSize ) )
# move beyond Pcap header
fSize -= 24
totalHeaderSize = 0 
print(" Reading the file {}".format( fileName ), end="" )
filename = "modified-" + fileName
filename =  os.path.join( dirName, filename ) 
nf =  open(filename, 'wb')
assert nf != None, "Unable to create file {}".format( filename )
nf.write( pcapHeader ) 
while( fSize > 0 ):
    # read packet header 
    if (fSize < 16 ):
        print( " truncated packet header {}".format(numPkt+1) )
        fSize = 0
        break
    before = fh.read(16)
    ts ,uts, incLen, origLen = pktHeaderStruct.unpack ( before )  
    if ( fSize -16 < incLen ):
         fSize = 0
         print( " truncated packet {}".format(numPkt+1) )
         break
    assert incLen > byteLenToChop , " incLen {} chopping#{} ".format( incLen, byteLenToChop)  
    if ( numPkt and numPkt%1000==0 ):
        print(".",end="",flush=True)
    pkt = fh.read( incLen ) 
    modPack =  pktHeaderStruct.pack( ts , uts, incLen - byteLenToChop, origLen )
    modPack += pkt[ byteLenToChop : incLen ]
    nf.write( modPack ) 
    fSize = fSize - 16 - incLen
    numPkt += 1 
print( "\nRead {} packets ".format( numPkt ) )
fh.close()
assert fSize == 0 , " Pcap file size is non-zero after read"
nf.close()
print ( "Generated striped pcap file %s " % (  filename ) )
