#!/bin/bash
#Autoscript-Lite By Vinstechmy
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
clear
trgo=$(cat /usr/local/etc/xray/port/port-trgo)
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\\E[0;41;36m   Change Port XRAY Trojan GO WS   \E[0m"
echo -e "\033[0;34m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
echo -e "      Change Port XRAY Trojan GO WS [ ${green}$trgo${NC} ]"
echo ""
read -p "New Port XRAY Trojan GO WS : " tr2

if [ -z $tr2 ]; then
echo "Please Insert Port !"
exit 0
fi

cek=$(netstat -nutlp | grep -w $tr2)
if [[ -z $cek ]]; then

sed -i "s/$trgo/$tr2/g" /usr/local/etc/xray/trgo.json
echo "$tr2" >> /usr/local/etc/xray/port/port-trgo

iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport $trgo -j ACCEPT
iptables -D INPUT -m state --state NEW -m udp -p udp --dport $trgo -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport $tr2 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport $tr2 -j ACCEPT
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save > /dev/null
netfilter-persistent reload > /dev/null
systemctl restart trojan-go.service > /dev/null
echo ""
echo -e "\e[032;1mPort $tr2 modified successfully\e[0m"
else
echo ""
echo -e "\e[1;31mPort $tr2 already used by other services !\e[0m"
fi
