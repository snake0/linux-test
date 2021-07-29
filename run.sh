#!/bin/bash
make clean
make debug

sudo dmesg --clear
sudo rmmod lkm.ko

sudo insmod lkm.ko

sleep 4

clear
dmesg --notime
