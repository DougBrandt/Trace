
README
------
Trace implements a program that will output protocol header information for a
number of header types.  The pcap library API will be used to sniff packets.


AUTHORS
-------
* Douglas Brandt


INSTALL
-------
To build and run this program do the following steps from the main
directory (networks-packet-trace):

Steps are tested on Ubuntu 12.04

Install Dependencies:

* sudo apt-get install flex
* sudo apt-get install bison
* sudo apt-get install libpcap-dev

Ensure that the pcap library is installed: http://www.tcpdump.org/

Then build:
* make

Then run:

* ./trace [filename]
