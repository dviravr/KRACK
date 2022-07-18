########### Enable NAT ############
iptables -t nat -A POSTROUTING -o wlp2s0 -j MASQUERADE
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i wlxc4e9841e1a74 -o wlp2s0 -j ACCEPT

sysctl -w net.ipv4.ip_forward=1 #ENable ip forwarding