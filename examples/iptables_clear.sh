#!/usr/bin/env bash
ENO_INTERFACE="enp5s0" # Replace here your interface name
sudo iptables -t nat -D PREROUTING -i "$ENO_INTERFACE" -j PHANTOMGATE 2>/dev/null
sudo iptables -t nat -F PHANTOMGATE 2>/dev/null
sudo iptables -t nat -X PHANTOMGATE 2>/dev/null
echo "PhantomGate iptables rules have been removed!"