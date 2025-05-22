#!/bin/sh
# Join multicast groups on eth1.85

ip addr add 239.10.10.6/32 dev eth1.85 autojoin
ip addr add 239.10.10.5/32 dev eth1.85 autojoin
