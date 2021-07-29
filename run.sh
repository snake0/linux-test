#!/bin/bash

make clean
make debug

sudo dmesg --clear
sudo rmmod clique

clear

sudo insmod clique.ko

sleep 3

dmesg