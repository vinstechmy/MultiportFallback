## MUTLIPORT USING FALLBACK ONLY (NOT USING NGINX FOR MULTIPORT)

## SUPPORT AUTOBACKUP & BACKUP VIA TELEGRAM BOT (THANKS TO VPNLEGASI)
<b>
[  HTTP  ] <br>
<br>
-VMESS WEBSOCKET TLS (443) <br>
-VLESS WEBSOCKET TLS (443) <br>
-TROJAN WEBSOCKET TLS (443) <br>
-VLESS TCP XTLS (443) <br>
-TROJAN TCP TLS (443) <br>
<br>
[  HTTPS  ] <br>
<br>
-VMESS WEBSOCKET NONE TLS (80) <br>
-VLESS WEBSOCKET NONE TLS (80) <br>
-TROJAN WEBSOCKET NONE TLS (80) <br>
<br>
♦️ For Debian 10 Only For First Time Installation (Update Repo) <br>

  ```html
 apt update -y && apt upgrade -y && apt dist-upgrade -y && reboot
  ```
  ♦️ For Ubuntu 18.04 Only For First Time Installation (Update Repo) <br>
  
  ```html
 apt-get update && apt-get upgrade -y && apt dist-upgrade -y && update-grub && reboot
 ```
♦️ Please do below step before proceed installing autoscript to avoid menu error <br>

1.Install resolvconf service
  ```html
 apt install resolvconf -y
  ```
2.Enable & start the service
  ```html
 systemctl enable resolvconf.service
 systemctl start resolvconf.service
 ```
3.Insert dns into resolvconf
  ```html
 echo "nameserver 8.8.8.8" >> /etc/resolv.conf
 echo "nameserver 8.8.8.8" >> /etc/resolvconf/resolv.conf.d/head
 systemctl restart resolvconf.service
  ```
♦️ Installation Link<br>

  ```html
sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update && apt install -y bzip2 gzip coreutils screen curl && wget https://raw.githubusercontent.com/vinstechmy/MultiportFallback/main/INSTALL/setup.sh && chmod +x setup.sh && ./setup.sh
  ```

## MULTIPORT FALLBACK AUTOSCRIPT EXAMPLE
<b>
</b>
<br>

</b>
<p align="center">
<img src="https://user-images.githubusercontent.com/82468311/216796094-5e7f5f72-1844-4d53-be50-32421f7920f2.png" width="350" title="Autoscript-Lite">
</p>
