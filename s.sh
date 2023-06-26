#!/bin/bash
# =========================================
# Fallbacks Multiport By Vinstechmy
# Version    : V1.0 Multiport Fallbacks
# Script By  : Vinstechmy
# (C) Copyright 2022 By Vinstechmy
# =========================================
clear
#Color
RED="\033[31m"
export NC='\e[0m'
export DEFBOLD='\e[39;1m'
export RB='\e[31;1m'
export GB='\e[32;1m'
export YB='\e[33;1m'
export BB='\e[34;1m'
export MB='\e[35;1m'
export CB='\e[35;1m'
export WB='\e[37;1m'

if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
fi

echo -e ""
echo -e "\e[94m              .-----------------------------------------------.    "
echo -e "\e[94m              |          Installing Autoscript Begin          |    "
echo -e "\e[94m              '-----------------------------------------------'    "
echo -e "\e[0m"
echo ""
sleep 3
clear

if [ -f "/usr/local/etc/xray/domain" ]; then
echo "Script Already Installed"
exit 0
fi

secs_to_human() {
    echo "Installation time : $(( ${1} / 3600 )) hours $(( (${1} / 60) % 60 )) minute's $(( ${1} % 60 )) seconds"
}
start=$(date +%s)

#update
apt update -y
apt full-upgrade -y
apt dist-upgrade -y
apt install socat curl screen cron neofetch screenfetch netfilter-persistent vnstat fail2ban -y
apt-get --reinstall --fix-missing install -y bzip2 gzip coreutils wget screen rsyslog iftop htop net-tools zip unzip wget net-tools curl nano sed screen gnupg gnupg1 bc apt-transport-https build-essential dirmngr libxml-parser-perl neofetch git lsof
apt-get remove --purge ufw firewalld -y
apt-get remove --purge exim4 -y
mkdir /backup
mkdir /user
clear

# install resolvconf service
apt install resolvconf -y

#start resolvconf service
systemctl enable resolvconf.service
systemctl start resolvconf.service

# Make Folder Log XRAY
mkdir -p /var/log/xray
chmod +x /var/log/xray

# Make Folder XRAY
mkdir -p /usr/local/etc/xray

# Make Folder Config Logs
mkdir -p /usr/local/etc/xray/configlogs

# Download XRAY Core Latest Link Official
latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"

# Installation Xray Core Official
xraycore_link="https://github.com/XTLS/Xray-core/releases/download/v$latest_version/xray-linux-64.zip"

# Unzip Xray Linux 64
cd `mktemp -d`
curl -sL "$xraycore_link" -o xray.zip
unzip -q xray.zip && rm -rf xray.zip
mv xray /usr/local/bin/xray
chmod +x /usr/local/bin/xray

#Server Info
curl -s ipinfo.io/city >> /usr/local/etc/xray/city
curl -s ipinfo.io/org | cut -d " " -f 2-10 >> /usr/local/etc/xray/org
curl -s ipinfo.io/timezone >> /usr/local/etc/xray/timezone
clear

cd
clear

# Install Speedtest
#wget -O /usr/bin/speedtest "https://raw.githubusercontent.com/vinstechmy/MultiportFallback/main/OTHERS/speedtest_cli.py"
#chmod +x /usr/bin/speedtest
curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | sudo bash
sudo apt-get install speedtest
clear

# set time GMT +8
ln -fs /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime

# banner /etc/issue.net
wget -q -O /etc/issue.net "https://raw.githubusercontent.com/vinstechmy/MultiportFallback/main/OTHERS/issues.net" && chmod +x /etc/issue.net
echo "Banner /etc/issue.net" >>/etc/ssh/sshd_config

# Install Nginx
apt install nginx -y
rm /var/www/html/*.html
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
systemctl restart nginx
clear

# Insert Domain Features
touch /usr/local/etc/xray/domain
echo -e "${RED}♦️${NC} ${green}Established By Vinstechmy 2022${NC} ${RED}♦️${NC}"
echo ""
echo "Please Insert Your Domain Before Proceed Installing"
echo " "
read -rp "Insert Domain : " -e dns
if [ -z $dns ]; then
echo -e "Please Insert Domain!"
else
echo "$dns" > /usr/local/etc/xray/domain
echo "DNS=$dns" > /var/lib/dnsvps.conf
fi
clear

# Install Cert Domain For XRAY 
systemctl stop nginx
domain=$(cat /usr/local/etc/xray/domain)
curl https://get.acme.sh | sh
source ~/.bashrc
cd .acme.sh
bash acme.sh --issue -d $domain --server letsencrypt --keylength ec-256 --fullchain-file /usr/local/etc/xray/xray.crt --key-file /usr/local/etc/xray/xray.key --standalone --force

# Nginx directory file download
mkdir -p /home/vps/public_html
cd
chown -R www-data:www-data /home/vps/public_html

# Random UUID For XRAY
uuid=$(cat /proc/sys/kernel/random/uuid)

#INSTALLING WEBSOCKET TLS
cat> /usr/local/etc/xray/config.json << END
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
    {
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}",
                        "flow": "xtls-rprx-direct",
                        "level": 0,
                        "email": ""
#xtls
                    }
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": 1310,
                        "xver": 1
                    },
                    {
                        "path": "/vmess-ws",
                        "dest": 1311,
                        "xver": 1
                    },
                    {
                        "path": "/vless-ws",
                        "dest": 1312,
                        "xver": 1
                    },
                    {
                        "path": "/trojan-ws",
                        "dest": 1313,
                        "xver": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "xtls",
                "xtlsSettings": {
                "alpn": ["http/1.1"],
                "certificates": [
                 {
                 "certificateFile": "/usr/local/etc/xray/xray.crt",
                  "keyFile": "/usr/local/etc/xray/xray.key"
                  }
                ],
                "minVersion": "1.2",
                 "cipherSuites": "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
                }
            }
        },
    {
      "port": 1311,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 0,
            "level": 0,
            "email": ""
#vmtls
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings":
            {
              "acceptProxyProtocol": true,
              "path": "/vmess-ws"
            }
      }
    },
    {
      "port": 1312,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "level": 0,
            "email": ""
#vltls
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings":
            {
              "acceptProxyProtocol": true,
              "path": "/vless-ws"
            }
        }
     },
    {
      "port": 1313,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "${uuid}",
            "level": 0,
            "email": ""
#trtls
          }
        ],
        "decryption":"none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings":
            {
              "acceptProxyProtocol": true,
              "path": "/trojan-ws"
            }
        }
    },
        {
            "port": 1310,
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "id": "${uuid}",
                        "password": "xxxxx"
#tr
                    }
                ],
                "fallbacks": [
                    {
                        "dest": 80
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none",
                "tcpSettings": {
                    "acceptProxyProtocol": true
                }
            }
        }
  ],
    "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true
    }
  }
}
END

# // INSTALLING WEBSOCKET NONE-TLS
cat> /usr/local/etc/xray/none.json << END
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 10086,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
      {
      "port": 80,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}"
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "dest": 1314,
            "xver": 1
          },
          {
              "path": "/vmess-ws",
              "dest": 1311,
              "xver": 1
          },
          {
              "path": "/vless-ws",
              "dest": 1312,
              "xver": 1
          },
          {
              "path": "/trojan-ws",
              "dest": 1313,
              "xver": 1
          }
        ]
      },
      "streamSettings": {
       "network": "tcp",
        "security": "none",
         "tlsSettings": {
          "alpn": ["http/1.1"]
             }
          }
       }
    ],
"outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink" : true,
      "statsOutboundDownlink" : true
    }
  }
}
END

#Remove Old Service
rm -rf /etc/systemd/system/xray.service.d
rm -rf /etc/systemd/system/xray@.service.d

#XRAY Service
cat> /etc/systemd/system/xray.service << END
[Unit]
Description=XRAY-MULTIPORT SERVICE
Documentation=https://t.me/Vinstechmy https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=3s
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

END

#XRAY Service
cat> /etc/systemd/system/xray@.service << END
[Unit]
Description=XRAY-MULTIPORT SERVICE
Documentation=https://t.me/Vinstechmy https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/%i.json
Restart=on-failure
RestartSec=3s
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

END

# Set Nginx Conf
cat > /etc/nginx/nginx.conf << EOF
user www-data;
worker_processes 1;
pid /var/run/nginx.pid;
events {
	multi_accept on;
	worker_connections 1024;
}
http {
	gzip on;
	gzip_vary on;
	gzip_comp_level 5;
	gzip_types text/plain application/x-javascript text/xml text/css;
	autoindex on;
	sendfile on;
	tcp_nopush on;
	tcp_nodelay on;
	keepalive_timeout 65;
	types_hash_max_size 2048;
	server_tokens off;
	include /etc/nginx/mime.types;
	default_type application/octet-stream;
	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;
	client_max_body_size 32M;
	client_header_buffer_size 8m;
	large_client_header_buffers 8 8m;
	fastcgi_buffer_size 8m;
	fastcgi_buffers 8 8m;
	fastcgi_read_timeout 600;
	#CloudFlare IPv4
	set_real_ip_from 199.27.128.0/21;
	set_real_ip_from 173.245.48.0/20;
	set_real_ip_from 103.21.244.0/22;
	set_real_ip_from 103.22.200.0/22;
	set_real_ip_from 103.31.4.0/22;
	set_real_ip_from 141.101.64.0/18;
	set_real_ip_from 108.162.192.0/18;
	set_real_ip_from 190.93.240.0/20;
	set_real_ip_from 188.114.96.0/20;
	set_real_ip_from 197.234.240.0/22;
	set_real_ip_from 198.41.128.0/17;
	set_real_ip_from 162.158.0.0/15;
	set_real_ip_from 104.16.0.0/12;
	#Incapsula
	set_real_ip_from 199.83.128.0/21;
	set_real_ip_from 198.143.32.0/19;
	set_real_ip_from 149.126.72.0/21;
	set_real_ip_from 103.28.248.0/22;
	set_real_ip_from 45.64.64.0/22;
	set_real_ip_from 185.11.124.0/22;
	set_real_ip_from 192.230.64.0/18;
	real_ip_header CF-Connecting-IP;
	include /etc/nginx/conf.d/*.conf;
}
EOF

#Nginx Webserver
wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/vinstechmy/MultiportFallback/main/OTHERS/vps.conf"

echo -e "[ ${YB}INFO${NC} ] Restart Daemon Service"
echo ""
systemctl daemon-reload
sleep 1

# enable xray ws tls
echo -e "[ ${GB}OK${NC} ] Restarting XRAY Core Service"
systemctl daemon-reload
systemctl enable xray.service
systemctl start xray.service
systemctl restart xray.service

# enable xray ws ntls
systemctl daemon-reload
systemctl enable xray@none.service
systemctl start xray@none.service
systemctl restart xray@none.service

# enable nginx
echo -e "[ ${GB}OK${NC} ] Restarting Nginx Service"
systemctl restart nginx

sleep 1

# Blokir TORRENT
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

# Enable BBR
clear
echo -e "[ ${GB}INFO${NC} ] Installing TCP BBR Please Wait . . ."
echo ""
sleep 2
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sed -i '/fs.file-max/d' /etc/sysctl.conf
sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
echo "fs.file-max = 1000000
fs.inotify.max_user_instances = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.route.gc_timeout = 100
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_synack_retries = 1
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_orphans = 32768
# forward ipv4
net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
echo -e "[ ${GB}INFO${NC} ] TCP BBR Successfully Installed !"
echo ""
sleep 2
clear

# Github Profile Repo
Git_Profile="https://raw.githubusercontent.com/vinstechmy/MultiportFallback/main"
echo -e "[ ${GB}INFO${NC} ] Download Autoscript Files Into VPS"
echo ""
sleep 1
#MENU
wget -O /usr/bin/menu "${Git_Profile}/MENU/menu.sh" && chmod +x /usr/bin/menu
wget -O /usr/bin/menu-ws "${Git_Profile}/MENU/menu-ws.sh" && chmod +x /usr/bin/menu-ws
wget -O /usr/bin/menu-vless "${Git_Profile}/MENU/menu-vless.sh" && chmod +x /usr/bin/menu-vless
wget -O /usr/bin/menu-tr "${Git_Profile}/MENU/menu-tr.sh" && chmod +x /usr/bin/menu-tr
wget -O /usr/bin/menu-xray "${Git_Profile}/MENU/menu-xray.sh" && chmod +x /usr/bin/menu-xray
wget -O /usr/bin/menu-xtr "${Git_Profile}/MENU/menu-xtr.sh" && chmod +x /usr/bin/menu-xtr
wget -O /usr/bin/backupmenu "${Git_Profile}/MENU/backupmenu.sh" && chmod +x /usr/bin/backupmenu

#XRAY
wget -O /usr/bin/add-ws "${Git_Profile}/XRAY/add-ws.sh" && chmod +x /usr/bin/add-ws
wget -O /usr/bin/add-vless "${Git_Profile}/XRAY/add-vless.sh" && chmod +x /usr/bin/add-vless
wget -O /usr/bin/add-tr "${Git_Profile}/XRAY/add-tr.sh" && chmod +x /usr/bin/add-tr
wget -O /usr/bin/add-xray "${Git_Profile}/XRAY/add-xray.sh" && chmod +x /usr/bin/add-xray
wget -O /usr/bin/add-xtr "${Git_Profile}/XRAY/add-xtr.sh" && chmod +x /usr/bin/add-xtr
wget -O /usr/bin/del-ws "${Git_Profile}/XRAY/del-ws.sh" && chmod +x /usr/bin/del-ws
wget -O /usr/bin/del-vless "${Git_Profile}/XRAY/del-vless.sh" && chmod +x /usr/bin/del-vless
wget -O /usr/bin/del-tr "${Git_Profile}/XRAY/del-tr.sh" && chmod +x /usr/bin/del-tr
wget -O /usr/bin/del-xray "${Git_Profile}/XRAY/del-xray.sh" && chmod +x /usr/bin/del-xray
wget -O /usr/bin/del-xtr "${Git_Profile}/XRAY/del-xtr.sh" && chmod +x /usr/bin/del-xtr
wget -O /usr/bin/cek-ws "${Git_Profile}/XRAY/cek-ws.sh" && chmod +x /usr/bin/cek-ws
wget -O /usr/bin/cek-vless "${Git_Profile}/XRAY/cek-vless.sh" && chmod +x /usr/bin/cek-vless
wget -O /usr/bin/cek-tr "${Git_Profile}/XRAY/cek-tr.sh" && chmod +x /usr/bin/cek-tr
wget -O /usr/bin/cek-xray "${Git_Profile}/XRAY/cek-xray.sh" && chmod +x /usr/bin/cek-xray
wget -O /usr/bin/cek-xtr "${Git_Profile}/XRAY/cek-xtr.sh" && chmod +x /usr/bin/cek-xtr
wget -O /usr/bin/renew-ws "${Git_Profile}/XRAY/renew-ws.sh" && chmod +x /usr/bin/renew-ws
wget -O /usr/bin/renew-vless "${Git_Profile}/XRAY/renew-vless.sh" && chmod +x /usr/bin/renew-vless
wget -O /usr/bin/renew-tr "${Git_Profile}/XRAY/renew-tr.sh" && chmod +x /usr/bin/renew-tr
wget -O /usr/bin/renew-xray "${Git_Profile}/XRAY/renew-xray.sh" && chmod +x /usr/bin/renew-xray
wget -O /usr/bin/renew-xtr "${Git_Profile}/XRAY/renew-xtr.sh" && chmod +x /usr/bin/renew-xtr
wget -O /usr/bin/user-ws "${Git_Profile}/XRAY/user-ws.sh" && chmod +x /usr/bin/user-ws
wget -O /usr/bin/user-vless "${Git_Profile}/XRAY/user-vless.sh" && chmod +x /usr/bin/user-vless
wget -O /usr/bin/user-tr "${Git_Profile}/XRAY/user-tr.sh" && chmod +x /usr/bin/user-tr
wget -O /usr/bin/user-xray "${Git_Profile}/XRAY/user-xray.sh" && chmod +x /usr/bin/user-xray
wget -O /usr/bin/user-xtr "${Git_Profile}/XRAY/user-xtr.sh" && chmod +x /usr/bin/user-xtr
wget -O /usr/bin/trial-ws "${Git_Profile}/XRAY/trial-ws.sh" && chmod +x /usr/bin/trial-ws
wget -O /usr/bin/trial-vless "${Git_Profile}/XRAY/trial-vless.sh" && chmod +x /usr/bin/trial-vless
wget -O /usr/bin/trial-tr "${Git_Profile}/XRAY/trial-tr.sh" && chmod +x /usr/bin/trial-tr
wget -O /usr/bin/trial-xray "${Git_Profile}/XRAY/trial-xray.sh" && chmod +x /usr/bin/trial-xray
wget -O /usr/bin/trial-xtr "${Git_Profile}/XRAY/trial-xtr.sh" && chmod +x /usr/bin/trial-xtr

#OTHERS
wget -O /usr/bin/limit "${Git_Profile}/OTHERS/limit-speed.sh" && chmod +x /usr/bin/limit
wget -O /usr/bin/add-host "${Git_Profile}/OTHERS/add-host.sh" && chmod +x /usr/bin/add-host
wget -O /usr/bin/cekport "${Git_Profile}/OTHERS/cekport.sh" && chmod +x /usr/bin/cekport
wget -O /usr/bin/certxray "${Git_Profile}/OTHERS/certxray.sh" && chmod +x /usr/bin/certxray
wget -O /usr/bin/dns "${Git_Profile}/OTHERS/dns.sh" && chmod +x /usr/bin/dns
wget -O /usr/bin/get-backres "${Git_Profile}/OTHERS/get-backres.sh" && chmod +x /usr/bin/get-backres
wget -O /usr/bin/restart "${Git_Profile}/OTHERS/restart.sh" && chmod +x /usr/bin/restart
wget -O /usr/bin/status "${Git_Profile}/OTHERS/status.sh" && chmod +x /usr/bin/status
wget -O /usr/bin/cleaner "${Git_Profile}/OTHERS/logcleaner.sh" && chmod +x /usr/bin/cleaner
wget -O /usr/bin/xp "${Git_Profile}/OTHERS/xp.sh" && chmod +x /usr/bin/xp
wget -O /usr/bin/nf "https://raw.githubusercontent.com/vinstechmy/MediaUnlockerTest/main/media.sh" && chmod +x /usr/bin/nf

# Installing RAM & CPU Monitor
curl https://raw.githubusercontent.com/xxxserxxx/gotop/master/scripts/download.sh | bash && chmod +x gotop && sudo mv gotop /usr/local/bin/
echo -e "[ ${GB}INFO${NC} ] Autoscript Files Successfully Download !"
echo ""
sleep 2
clear

echo "0 6 * * * root reboot" >> /etc/crontab
echo "0 0 * * * root /usr/bin/xp" >> /etc/crontab
echo "*/2 * * * * root /usr/bin/cleaner" >> /etc/crontab

#Set Log Cleaner
if [ ! -f "/etc/cron.d/cleaner" ]; then
cat> /etc/cron.d/cleaner << END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root /usr/bin/cleaner
END
fi

systemctl restart cron
systemctl restart sshd

#Install Rclone
apt install rclone
printf "q\n" | rclone config
wget -O /root/.config/rclone/rclone.conf "${Git_Profile}/OTHERS/rclone.conf" >/dev/null 2>&1

#Install Wondershape for limit bandwith
git clone  https://github.com/MrMan21/wondershaper.git
cd wondershaper
make install
cd
rm -rf wondershaper

cat > /root/.profile << END
# ~/.profile: executed by Bourne-compatible login shells.

if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n || true
clear
menu
END

# remove unnecessary files
cd
apt autoclean -y
apt -y remove --purge unscd
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove bind9*;
apt-get -y remove sendmail*
apt autoremove -y

#Autoscript Version
echo "1.0" > /home/ver

clear
echo ""
echo -e "${RB}      .-------------------------------------------.${NC}"
echo -e "${RB}      |${NC}      ${CB}Installation Has Been Completed${NC}      ${RB}|${NC}"
echo -e "${RB}      '-------------------------------------------'${NC}"
echo -e "${BB}————————————————————————————————————————————————————————${NC}"
echo -e "      ${WB}Multiport Websocket Autoscript By Vinstechmy${NC}"
echo -e "${BB}————————————————————————————————————————————————————————${NC}"
echo -e "  ${WB}»»» Protocol Service «««  |  »»» Network Protocol «««${NC}  "
echo -e "${BB}————————————————————————————————————————————————————————${NC}"
echo -e "  ${RB}♦️${NC} ${YB}Vmess Websocket${NC}         ${WB}|${NC}  ${RB}♦️${NC}${YB} Websocket (CDN) TLS${NC}"
echo -e "  ${RB}♦️${NC} ${YB}Vless Websocket${NC}         ${WB}|${NC}  ${RB}♦️${NC}${YB} Websocket (CDN) NTLS${NC}"
echo -e "  ${RB}♦️${NC} ${YB}Trojan Websocket${NC}        ${WB}|${NC}  ${RB}♦️${NC}${YB} TCP XTLS${NC}"
echo -e "  ${RB}♦️${NC} ${YB}Vless TCP XTLS${NC}          ${WB}|${NC}  ${RB}♦️${NC}${YB} TCP TLS${NC}"
echo -e "  ${RB}♦️${NC} ${YB}Trojan TCP TLS${NC}          ${WB}|${NC}"
echo -e "${BB}————————————————————————————————————————————————————————${NC}"
echo -e "           ${WB}»»» YAML Service Information «««${NC}          "
echo -e "${BB}————————————————————————————————————————————————————————${NC}"
echo -e "  ${RB}♦️${NC} ${YB}YAML XRAY VMESS WS${NC}"
echo -e "  ${RB}♦️${NC} ${YB}YAML XRAY VLESS WS${NC}"
echo -e "  ${RB}♦️${NC} ${YB}YAML XRAY TROJAN WS${NC}"
echo -e "  ${RB}♦️${NC} ${YB}YAML XRAY VLESS TCP XTLS${NC}"
echo -e "  ${RB}♦️${NC} ${YB}YAML XRAY TROJAN TCP TLS${NC}"
echo -e "${BB}————————————————————————————————————————————————————————${NC}"
echo -e "             ${WB}»»» Server Information «««${NC}                 "
echo -e "${BB}————————————————————————————————————————————————————————${NC}"
echo -e "  ${RB}♦️${NC} ${YB}Timezone                : Asia/Kuala_Lumpur (GMT +8)${NC}"
echo -e "  ${RB}♦️${NC} ${YB}Fail2Ban                : [ON]${NC}"
echo -e "  ${RB}♦️${NC} ${YB}Deflate                 : [ON]${NC}"
echo -e "  ${RB}♦️${NC} ${YB}IPtables                : [ON]${NC}"
echo -e "  ${RB}♦️${NC} ${YB}Auto-Reboot             : [ON]${NC}"
echo -e "  ${RB}♦️${NC} ${YB}IPV6                    : [OFF]${NC}"
echo -e ""
echo -e "  ${RB}♦️${NC} ${YB}Autoreboot On 06.00 GMT +8${NC}"
echo -e "  ${RB}♦️${NC} ${YB}Autobackup On 12:05 GMT +8${NC}"
echo -e "  ${RB}♦️${NC} ${YB}Backup VPS Data Via Telegram Bot${NC}"
echo -e "  ${RB}♦️${NC} ${YB}Backup & Restore VPS Data${NC}"
echo -e "  ${RB}♦️${NC} ${YB}Automatic Delete Expired Account${NC}"
echo -e "  ${RB}♦️${NC} ${YB}Bandwith Monitor${NC}"
echo -e "  ${RB}♦️${NC} ${YB}RAM & CPU Monitor${NC}"
echo -e "  ${RB}♦️${NC} ${YB}Check Login User${NC}"
echo -e "  ${RB}♦️${NC} ${YB}Check Created Config${NC}"
echo -e "  ${RB}♦️${NC} ${YB}Automatic Clear Log${NC}"
echo -e "  ${RB}♦️${NC} ${YB}Media Checker${NC}"
echo -e "  ${RB}♦️${NC} ${YB}DNS Changer${NC}"
echo -e "${BB}————————————————————————————————————————————————————————${NC}"
echo -e "              ${WB}»»» Network Port Service «««${NC}             "
echo -e "${BB}————————————————————————————————————————————————————————${NC}"
echo -e "  ${RB}♦️${NC} ${YB}HTTP                    : 443${NC}"
echo -e "  ${RB}♦️${NC} ${YB}HTTPS                   : 80${NC}"
echo -e "${BB}————————————————————————————————————————————————————————${NC}"
echo ""
secs_to_human "$(($(date +%s) - ${start}))"
echo ""
echo -ne "${YB}[ WARNING ] Reboot now ? (Y/N)${NC} : "
read REDDIR
if [ "$REDDIR" == "${REDDIR#[Yy]}" ]; then
    rm -r setup.sh
	clear
    menu
else
    rm -r setup.sh
    reboot
fi
