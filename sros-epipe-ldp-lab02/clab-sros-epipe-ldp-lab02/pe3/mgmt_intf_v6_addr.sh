#!/bin/bash

source /pkg/bin/ztp_helper.sh

xrapply_string "interface MgmtEth0/RP0/CPU0/0\n no ipv6 address\n"
