#!/bin/bash

echo ArpTest Test
./trace ArpTest.pcap > myOutput.out.txt
diff -B --ignore-all-space myOutput.out.txt ArpTest.out.txt

echo IP_bad_checksum Test
./trace IP_bad_checksum.pcap > myOutput.out.txt
diff -B --ignore-all-space myOutput.out.txt IP_bad_checksum.out.txt

echo PingTest Test
./trace PingTest.pcap > myOutput.out.txt
diff -B --ignore-all-space myOutput.out.txt PingTest.out.txt

echo UDPfile Test
./trace UDPfile.pcap > myOutput.out.txt
diff -B --ignore-all-space myOutput.out.txt UDPfile.out.txt

echo smallTCP Test
./trace smallTCP.pcap > myOutput.out.txt
diff -B --ignore-all-space myOutput.out.txt smallTCP.out.txt

echo largeMix Test
./trace largeMix.pcap > myOutput.out.txt
diff -B --ignore-all-space myOutput.out.txt largeMix.out.txt

echo largeMix2 Test
./trace largeMix2.pcap > myOutput.out.txt
diff -B --ignore-all-space myOutput.out.txt largeMix2.out.txt

echo clean up
rm -f myOutput.out.txt

