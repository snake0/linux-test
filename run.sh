#!/bin/bash
make clean
make debug
sudo rmmod clique.ko

sudo insmod clique.ko

