#!/system/bin/sh
# dnat_usb.sh — qualquer :30101 -> 127.0.0.1:30101 (tunel adb reverse USB -> PC -> mock)
magiskpolicy --live "allow magisk magisk capability net_admin"
sysctl -w net.ipv4.conf.all.route_localnet=1
iptables -t nat -D OUTPUT -p tcp --dport 30101 -j DNAT --to-destination 127.0.0.1:30101 2>/dev/null
iptables -t nat -A OUTPUT -p tcp --dport 30101 -j DNAT --to-destination 127.0.0.1:30101
iptables -t nat -S OUTPUT | grep 30101 && echo DNAT-USB-OK
