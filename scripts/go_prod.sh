#!/system/bin/sh
# go_prod.sh — CLIENT -> SERVIDOR DE PRODUCAO (remove redirecionamento)
magiskpolicy --live "allow magisk magisk capability net_admin"
iptables -t nat -D OUTPUT -p tcp --dport 30101 -j DNAT --to-destination 127.0.0.1:30101 2>/dev/null
iptables -t nat -F OUTPUT 2>/dev/null
N=$(iptables -t nat -S OUTPUT 2>/dev/null | grep -c 30101)
echo "regras 30101 restantes: $N (0 = limpo, cliente vai pra PRODUCAO)"
