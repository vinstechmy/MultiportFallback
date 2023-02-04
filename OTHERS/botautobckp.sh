#!/bin/bash

MYIP=$(wget -qO- ipinfo.io/ip);
IP=$MYIP

date=$(date +"%Y-%m-%d")
token=$(cat /etc/token_bott | awk '{print $2}')
admin=$(cat /etc/admin_id | awk '{print $2}')
Name=$(curl -sS https://raw.githubusercontent.com/vinstechmy/MultiportFallback/main/ACCESS/access | grep $MYIP | awk '{print $4}')
InputPass=123
rm -rf /root/backup
mkdir -p /root/backup
cp -r /usr/local/etc/xray/*.json /root/backup/ >/dev/null 2>&1
cp -r /usr/local/etc/xray/configlogs /root/backup/ >/dev/null 2>&1
cp -r /home/vps/public_html /root/backup/public_html
cp -r /etc/cron.d /root/backup/cron.d &> /dev/null
cp -r /etc/crontab /root/backup/crontab &> /dev/null
cd /root
zip -rP $InputPass $IP-$Name-$date.zip backup >/dev/null 2>&1
curl --request POST \
  --url https://api.telegram.org/bot$token/sendDocument?chat_id=$admin \
  --header 'content-type: multipart/form-data' \
  --form document=@/root/$IP-$Name-$date.zip \
  --form 'caption=Here Is Your Backup Files'
clear
rm -rf backup
rm -f /root/$IP-$Name-$date.zip

