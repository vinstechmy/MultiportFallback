#!/bin/bash
clear
MYIP2=$(wget -qO- ipv4.icanhazip.com);
domain=$(cat /usr/local/etc/xray/domain)
user=TRIAL-`echo $RANDOM | head -c4`
uuid=$(cat /proc/sys/kernel/random/uuid)
trgo=$(cat /usr/local/etc/xray/port/port-trgo)
masaaktif=1
echo ""
echo ""
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
hariini=`date -d "0 days" +"%Y-%m-%d"`

echo -e "### $user $exp" >> /usr/local/etc/xray/akauntrgo.conf
sed -i '/"'""$uuid""'"$/a\,"'""$user""'"' /usr/local/etc/xray/trgo.json

trojanlink="trojan-go://${user}@${sts}${domain}:${trgo}?sni=${sni}#TROJAN_GO_${user}"
trojanlinkws="trojan-go://${user}@${sts}${domain}:${trgo}?sni=${sni}&type=ws&host=${domain}&path=/trojan-go#TROJAN_GO_${user}"

cat > /home/vps/public_html/$user-TRGO.yaml <<EOF
port: 7890
socks-port: 7891
redir-port: 7892
mixed-port: 7893
tproxy-port: 7895
ipv6: false
mode: rule
log-level: silent
allow-lan: true
external-controller: 0.0.0.0:9090
secret: ""
bind-address: "*"
unified-delay: true
profile:
  store-selected: true
  store-fake-ip: true
dns:
  enable: true
  ipv6: false
  use-host: true
  enhanced-mode: fake-ip
  listen: 0.0.0.0:7874
  nameserver:
    - 8.8.8.8
    - 1.0.0.1
    - https://dns.google/dns-query
  fallback:
    - 1.1.1.1
    - 8.8.4.4
    - https://cloudflare-dns.com/dns-query
    - 112.215.203.254
  default-nameserver:
    - 8.8.8.8
    - 1.1.1.1
    - 112.215.203.254
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "*.localdomain"
    - "*.example"
    - "*.invalid"
    - "*.localhost"
    - "*.test"
    - "*.local"
    - "*.home.arpa"
    - time.*.com
    - time.*.gov
    - time.*.edu.cn
    - time.*.apple.com
    - time1.*.com
    - time2.*.com
    - time3.*.com
    - time4.*.com
    - time5.*.com
    - time6.*.com
    - time7.*.com
    - ntp.*.com
    - ntp1.*.com
    - ntp2.*.com
    - ntp3.*.com
    - ntp4.*.com
    - ntp5.*.com
    - ntp6.*.com
    - ntp7.*.com
    - "*.time.edu.cn"
    - "*.ntp.org.cn"
    - +.pool.ntp.org
    - time1.cloud.tencent.com
    - music.163.com
    - "*.music.163.com"
    - "*.126.net"
    - musicapi.taihe.com
    - music.taihe.com
    - songsearch.kugou.com
    - trackercdn.kugou.com
    - "*.kuwo.cn"
    - api-jooxtt.sanook.com
    - api.joox.com
    - joox.com
    - y.qq.com
    - "*.y.qq.com"
    - streamoc.music.tc.qq.com
    - mobileoc.music.tc.qq.com
    - isure.stream.qqmusic.qq.com
    - dl.stream.qqmusic.qq.com
    - aqqmusic.tc.qq.com
    - amobile.music.tc.qq.com
    - "*.xiami.com"
    - "*.music.migu.cn"
    - music.migu.cn
    - "*.msftconnecttest.com"
    - "*.msftncsi.com"
    - msftconnecttest.com
    - msftncsi.com
    - localhost.ptlogin2.qq.com
    - localhost.sec.qq.com
    - +.srv.nintendo.net
    - +.stun.playstation.net
    - xbox.*.microsoft.com
    - xnotify.xboxlive.com
    - +.battlenet.com.cn
    - +.wotgame.cn
    - +.wggames.cn
    - +.wowsgame.cn
    - +.wargaming.net
    - proxy.golang.org
    - stun.*.*
    - stun.*.*.*
    - +.stun.*.*
    - +.stun.*.*.*
    - +.stun.*.*.*.*
    - heartbeat.belkin.com
    - "*.linksys.com"
    - "*.linksyssmartwifi.com"
    - "*.router.asus.com"
    - mesu.apple.com
    - swscan.apple.com
    - swquery.apple.com
    - swdownload.apple.com
    - swcdn.apple.com
    - swdist.apple.com
    - lens.l.google.com
    - stun.l.google.com
    - +.nflxvideo.net
    - "*.square-enix.com"
    - "*.finalfantasyxiv.com"
    - "*.ffxiv.com"
    - "*.mcdn.bilivideo.cn"
    - +.media.dssott.com
proxies:
  - name: TROJAN_GO_${user}
    server: ${sts}${domain}
    port: ${trgo}
    type: trojan
    password: ${user}
    skip-cert-verify: true
    sni: ${sni}
    udp: true
proxy-groups:
  - name: VINSTECHMY-AUTOSCRIPT
    type: select
    proxies:
      - TROJAN_GO_${user}
      - DIRECT
rules:
  - MATCH,VINSTECHMY-AUTOSCRIPT
EOF

cat > /home/vps/public_html/$user-TRGOWS.yaml <<EOF
port: 7890
socks-port: 7891
redir-port: 7892
mixed-port: 7893
tproxy-port: 7895
ipv6: false
mode: rule
log-level: silent
allow-lan: true
external-controller: 0.0.0.0:9090
secret: ""
bind-address: "*"
unified-delay: true
profile:
  store-selected: true
  store-fake-ip: true
dns:
  enable: true
  ipv6: false
  use-host: true
  enhanced-mode: fake-ip
  listen: 0.0.0.0:7874
  nameserver:
    - 8.8.8.8
    - 1.0.0.1
    - https://dns.google/dns-query
  fallback:
    - 1.1.1.1
    - 8.8.4.4
    - https://cloudflare-dns.com/dns-query
    - 112.215.203.254
  default-nameserver:
    - 8.8.8.8
    - 1.1.1.1
    - 112.215.203.254
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "*.localdomain"
    - "*.example"
    - "*.invalid"
    - "*.localhost"
    - "*.test"
    - "*.local"
    - "*.home.arpa"
    - time.*.com
    - time.*.gov
    - time.*.edu.cn
    - time.*.apple.com
    - time1.*.com
    - time2.*.com
    - time3.*.com
    - time4.*.com
    - time5.*.com
    - time6.*.com
    - time7.*.com
    - ntp.*.com
    - ntp1.*.com
    - ntp2.*.com
    - ntp3.*.com
    - ntp4.*.com
    - ntp5.*.com
    - ntp6.*.com
    - ntp7.*.com
    - "*.time.edu.cn"
    - "*.ntp.org.cn"
    - +.pool.ntp.org
    - time1.cloud.tencent.com
    - music.163.com
    - "*.music.163.com"
    - "*.126.net"
    - musicapi.taihe.com
    - music.taihe.com
    - songsearch.kugou.com
    - trackercdn.kugou.com
    - "*.kuwo.cn"
    - api-jooxtt.sanook.com
    - api.joox.com
    - joox.com
    - y.qq.com
    - "*.y.qq.com"
    - streamoc.music.tc.qq.com
    - mobileoc.music.tc.qq.com
    - isure.stream.qqmusic.qq.com
    - dl.stream.qqmusic.qq.com
    - aqqmusic.tc.qq.com
    - amobile.music.tc.qq.com
    - "*.xiami.com"
    - "*.music.migu.cn"
    - music.migu.cn
    - "*.msftconnecttest.com"
    - "*.msftncsi.com"
    - msftconnecttest.com
    - msftncsi.com
    - localhost.ptlogin2.qq.com
    - localhost.sec.qq.com
    - +.srv.nintendo.net
    - +.stun.playstation.net
    - xbox.*.microsoft.com
    - xnotify.xboxlive.com
    - +.battlenet.com.cn
    - +.wotgame.cn
    - +.wggames.cn
    - +.wowsgame.cn
    - +.wargaming.net
    - proxy.golang.org
    - stun.*.*
    - stun.*.*.*
    - +.stun.*.*
    - +.stun.*.*.*
    - +.stun.*.*.*.*
    - heartbeat.belkin.com
    - "*.linksys.com"
    - "*.linksyssmartwifi.com"
    - "*.router.asus.com"
    - mesu.apple.com
    - swscan.apple.com
    - swquery.apple.com
    - swdownload.apple.com
    - swcdn.apple.com
    - swdist.apple.com
    - lens.l.google.com
    - stun.l.google.com
    - +.nflxvideo.net
    - "*.square-enix.com"
    - "*.finalfantasyxiv.com"
    - "*.ffxiv.com"
    - "*.mcdn.bilivideo.cn"
    - +.media.dssott.com
proxies:
  - name: TROJAN_GO_${user}
    server: ${sts}${domain}
    port: ${trgo}
    type: trojan
    password: ${user}
    skip-cert-verify: true
    sni: ${sni}
    network: ws
    ws-opts:
      path: /trojan-go
      headers:
        Host: ${domain}
    udp: true
proxy-groups:
  - name: VINSTECHMY-AUTOSCRIPT
    type: select
    proxies:
      - TROJAN_GO_${user}
      - DIRECT
rules:
  - MATCH,VINSTECHMY-AUTOSCRIPT
EOF

systemctl restart trojan-go.service
service cron restart

clear
echo -e "" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "═════════════[TROJAN GO WS]═════════════" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "Remarks           : ${user}" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "Domain            : ${domain}" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "Port              : ${trgo}" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "Password          : ${user}" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "Security          : TLS" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "Encryption        : None" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "Network           : Standard & Websocket" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "Path              : /trojan-go" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "════════════════════════════════════════" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "Link Trojan Go    : ${trojanlink}" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "════════════════════════════════════════" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "Link Trojan Go WS : ${trojanlinkws}" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "════════════════════════════════════════" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "YAML TROJAN GO    : http://${MYIP2}:81/$user-TRGO.yaml" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "════════════════════════════════════════" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "YAML TROJAN GO WS : http://${MYIP2}:81/$user-TRGOWS.yaml" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "════════════════════════════════════════" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "Created On        : $hariini" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "Expired On        : $exp" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "════════════════════════════════════════" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "Autoscript By Vinstechmy" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt
echo -e "" | tee -a /usr/local/etc/xray/configlogs/trojango-$user.txt