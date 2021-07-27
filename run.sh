#!/bin/bash
make clean
make debug
sudo insmod clique.ko

sudo rmmod clique.ko
