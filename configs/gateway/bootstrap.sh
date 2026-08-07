#!/bin/sh
set -eu

for attempt in 1 2 3; do
  if apk add --no-cache nftables iproute2 iproute2-tc tcpdump; then
    break
  fi
  echo "apk add failed (attempt $attempt), retrying in 5s..."
  sleep 5
done

ip address add 10.61.254.2/30 dev eth1

ip address add 10.61.10.1/27 dev eth2
ip address add 10.61.20.1/26 dev eth3
ip address add 10.61.30.1/25 dev eth4
ip address add 10.61.40.1/24 dev eth5
ip address add 10.61.50.1/27 dev eth6
ip address add 10.61.60.1/28 dev eth7
ip address add 10.61.70.1/24 dev eth8

ip route replace default via 10.61.254.1 dev eth1

ip link set eth9 promisc on
for interface in eth1 eth2 eth3 eth4 eth5 eth6 eth7 eth8; do
  tc qdisc add dev "$interface" clsact
  tc filter add dev "$interface" ingress matchall action mirred egress mirror dev eth9
done

sysctl -w net.ipv4.ip_forward=1
nft -f /etc/nftables.conf
