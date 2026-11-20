#!/system/bin/sh
# dnat_all.sh — redireciona TODA saida tcp:30101 (qualquer IP de gateway) pro nosso mock
magiskpolicy --live "allow magisk magisk capability net_admin"
iptables -t nat -D OUTPUT -p tcp --dport 30101 -j DNAT --to-destination 192.168.0.66:30101 2>/dev/null
iptables -t nat -A OUTPUT -p tcp --dport 30101 -j DNAT --to-destination 192.168.0.66:30101
iptables -t nat -S OUTPUT | grep 30101 | head -2 && echo DNAT-ALL-OK
