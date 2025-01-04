#!/usr/bin/env bash
ENO_INTERFACE="enp5s0" # Replace here your interface name
PHANTOMGATE_PORT="8888" # Replace here your PhantomGate port
sudo iptables -t nat -N PHANTOMGATE 2>/dev/null
sudo iptables -t nat -C PREROUTING -i "$ENO_INTERFACE" -j PHANTOMGATE 2>/dev/null \
  || sudo iptables -t nat -A PREROUTING -i "$ENO_INTERFACE" -j PHANTOMGATE

# Keep original ports open
# SSH
sudo iptables -t nat -A PHANTOMGATE -p tcp --dport 22 -j RETURN
# HTTP
sudo iptables -t nat -A PHANTOMGATE -p tcp --dport 80 -j RETURN
# HTTPS
sudo iptables -t nat -A PHANTOMGATE -p tcp --dport 443 -j RETURN
# PhantomGate
sudo iptables -t nat -A PHANTOMGATE -p tcp --dport "$PHANTOMGATE_PORT" -j RETURN

# All others redirect to PhantomGate
sudo iptables -t nat -A PHANTOMGATE -p tcp --dport 1:65535 -j REDIRECT --to-ports "$PHANTOMGATE_PORT"

echo "PhantomGate iptables rules have been applied!"