#!/system/bin/sh
magiskpolicy --live "allow magisk magisk capability net_admin"
iptables -t nat -A OUTPUT -d 3.33.245.139 -p tcp --dport 30101 -j DNAT --to-destination 192.168.0.66:30101
iptables -t nat -S OUTPUT | grep 30101 && echo DNAT-OK
