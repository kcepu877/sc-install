#!/bin/bash
# ============================================================
# SCRIPT INSTALLER TUNNEL + ZIVPN - SUPPORT DEBIAN & UBUNTU
# MODDED BY [NAMA LO] - 2024
# ============================================================

apt install -y
apt upgrade -y
apt update -y
apt install curl -y
apt install wondershaper -y
apt install lolcat -y
gem install lolcat

# ============================================================
# COLOR SETUP
# ============================================================
Green="\e[92;1m"
RED="\033[1;31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'
BIBlue='\e[1;94m'
BGCOLOR='\e[41;37m'

TIME=$(date '+%d %b %Y')
ipsaya=$(wget -qO- ipinfo.io/ip)
TIMES="10"
CHATID="7114686701"  # GANTI DENGAN CHATID LO
KEY="7747621243:AAH2nkriS_uohnMnj30Gwj5Zsmuv0dfDHiA"  # GANTI DENGAN KEY LO
URL="https://api.telegram.org/bot$KEY/sendMessage"
clear

export IP=$( curl -sS icanhazip.com )
clear

# ============================================================
# DETECT OS & VERSION - FIXED
# ============================================================
detect_os() {
    OS_ID=$(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g')
    OS_NAME=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')
    
    if [[ $OS_ID == "ubuntu" ]]; then
        OS_VERSION=$(lsb_release -rs 2>/dev/null || echo "20.04")
        echo -e "${OK} Detected: Ubuntu $OS_VERSION"
        echo "ubuntu" > /tmp/os_type
        echo "$OS_VERSION" > /tmp/os_version
    elif [[ $OS_ID == "debian" ]]; then
        DEBIAN_VERSION=$(cat /etc/debian_version | cut -d. -f1)
        echo -e "${OK} Detected: Debian $DEBIAN_VERSION"
        echo "debian" > /tmp/os_type
        echo "$DEBIAN_VERSION" > /tmp/os_version
        
        if [[ $DEBIAN_VERSION -ge 11 ]]; then
            echo -e "${YELLOW}[INFO] Debian $DEBIAN_VERSION detected - Using compatible configuration${NC}"
        fi
    else
        echo -e "${ERROR} OS not supported: $OS_NAME"
        exit 1
    fi
}

# ============================================================
# WELCOME MESSAGE
# ============================================================
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo -e "\033[96;1m          WELCOME TO SCRIPT BY [NAMA LO]            \033[0m"
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo ""
sleep 3

# ============================================================
# ARCHITECTURE CHECK
# ============================================================
if [[ $( uname -m | awk '{print $1}' ) == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}$( uname -m )${NC} )"
else
    echo -e "${EROR} Your Architecture Is Not Supported ( ${YELLOW}$( uname -m )${NC} )"
    exit 1
fi

# ============================================================
# OS CHECK
# ============================================================
detect_os

if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${NC} )"
elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${NC} )"
else
    echo -e "${EROR} Your OS Is Not Supported ( ${YELLOW}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${NC} )"
    exit 1
fi

# ============================================================
# IP CHECK
# ============================================================
if [[ $ipsaya == "" ]]; then
    echo -e "${EROR} IP Address ( ${RED}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

# ============================================================
# ROOT CHECK
# ============================================================
if [ "${EUID}" -ne 0 ]; then
    echo "You need to run this script as root"
    exit 1
fi

# ============================================================
# OPENVZ CHECK
# ============================================================
if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ is not supported"
    exit 1
fi

# ============================================================
# HOSTNAME SETUP
# ============================================================
localip=$(hostname -I | cut -d\  -f1)
hst=( `hostname` )
dart=$(cat /etc/hosts | grep -w `hostname` | awk '{print $2}')
if [[ "$hst" != "$dart" ]]; then
    echo "$localip $(hostname)" >> /etc/hosts
fi

# ============================================================
# TIMER FUNCTION
# ============================================================
secs_to_human() {
    echo "Installation time : $(( ${1} / 3600 )) hours $(( (${1} / 60) % 60 )) minute's $(( ${1} % 60 )) seconds"
}

# ============================================================
# DIRECTORY SETUP
# ============================================================
rm -rf /etc/rmbl
mkdir -p /etc/rmbl
mkdir -p /etc/rmbl/theme
mkdir -p /var/lib/ >/dev/null 2>&1
echo "IP=" >> /var/lib/ipvps.conf
clear

# ============================================================
# INPUT NAME
# ============================================================
echo -e "${BIBlue}╭══════════════════════════════════════════╮${NC}"
echo -e "${BIBlue}│ ${BGCOLOR}             MASUKKAN NAMA KAMU         ${NC}${BIBlue} │${NC}"
echo -e "${BIBlue}╰══════════════════════════════════════════╯${NC}"
echo " "
read -p "   Nama Lu: " nama_kamu
name="$nama_kamu"
rm -rf /etc/profil
echo "$name" > /etc/profil
echo ""
clear

# ============================================================
# IP & AUTHOR SETUP
# ============================================================
author=$(cat /etc/profil)
echo ""
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "\e[32mloading...\e[0m"
clear

# ============================================================
# REPO & VARIABLES
# ============================================================
REPO="https://raw.githubusercontent.com/kcepu877/zero-tunneling/main/"
start=$(date +%s)

function print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
}

function print_install() {
    echo -e "${green} =============================== ${FONT}"
    echo -e "${YELLOW} # $1 ${FONT}"
    echo -e "${green} =============================== ${FONT}"
    sleep 1
}

function print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}

function print_success() {
    if [[ 0 -eq $? ]]; then
        echo -e "${green} =============================== ${FONT}"
        echo -e "${Green} # $1 berhasil dipasang"
        echo -e "${green} =============================== ${FONT}"
        sleep 2
    fi
}

# ============================================================
# FIRST SETUP - HAPROXY FIXED
# ============================================================
function first_setup(){
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Directory Xray"
    
    OS_TYPE=$(cat /tmp/os_type)
    OS_VER=$(cat /tmp/os_version)
    
    if [[ $OS_TYPE == "ubuntu" ]]; then
        echo "Setup Dependencies $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        sudo apt update -y
        apt-get install --no-install-recommends software-properties-common -y
        add-apt-repository ppa:vbernat/haproxy-2.0 -y
        apt-get update -y
        apt-get -y install haproxy=2.0.*
        
    elif [[ $OS_TYPE == "debian" ]]; then
        echo "Setup Dependencies For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        
        if [[ $OS_VER == "10" ]]; then
            curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
            echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" http://haproxy.debian.net buster-backports-1.8 main >/etc/apt/sources.list.d/haproxy.list
            apt-get update -y
            apt-get -y install haproxy=1.8.*
        else
            apt-get update -y
            apt-get -y install haproxy
        fi
    fi
}

# ============================================================
# NGINX INSTALL
# ============================================================
function nginx_install() {
    OS_TYPE=$(cat /tmp/os_type)
    
    if [[ $OS_TYPE == "ubuntu" ]]; then
        print_install "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        sudo apt-get update -y
        sudo apt-get install nginx -y
        
    elif [[ $OS_TYPE == "debian" ]]; then
        print_success "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        apt update -y
        apt install nginx -y
    fi
    
    service enable nginx
    service start nginx
}

# ============================================================
# BASE PACKAGE INSTALL
# ============================================================
function base_package() {
    clear
    print_install "Menginstall Packet Yang Dibutuhkan"
    
    apt update -y
    apt upgrade -y
    
    apt install at -y
    apt install zip pwgen openssl netcat socat cron bash-completion -y
    apt install figlet -y
    apt dist-upgrade -y
    
    service enable chronyd 2>/dev/null || true
    service restart chronyd 2>/dev/null || true
    service enable chrony 2>/dev/null || true
    service restart chrony 2>/dev/null || true
    
    apt install ntpdate -y
    ntpdate pool.ntp.org
    
    apt install sudo -y
    sudo apt-get clean all
    sudo apt-get autoremove -y
    sudo apt-get install -y debconf-utils
    sudo apt-get remove --purge exim4 -y 2>/dev/null || true
    sudo apt-get remove --purge ufw firewalld -y 2>/dev/null || true
    sudo apt-get install -y --no-install-recommends software-properties-common
    
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    
    sudo apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
    libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools \
    libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr \
    libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip \
    p7zip-full python3-pip libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx \
    iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg \
    gnupg2 lsb-release gcc shc make cmake git screen socat xz-utils apt-transport-https \
    gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa -y
    
    print_success "Packet Yang Dibutuhkan"
}

# ============================================================
# XRAY DIRECTORY SETUP
# ============================================================
print_install "Membuat direktori xray"
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
mkdir -p /var/log/xray
chown www-data.www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
mkdir -p /var/lib/kyt >/dev/null 2>&1

# ============================================================
# MAKE FOLDER XRAY
# ============================================================
function make_folder_xray() {
    rm -rf /etc/vmess/.vmess.db
    rm -rf /etc/vless/.vless.db
    rm -rf /etc/trojan/.trojan.db
    rm -rf /etc/shadowsocks/.shadowsocks.db
    rm -rf /etc/ssh/.ssh.db
    rm -rf /etc/bot/.bot.db
    mkdir -p /etc/bot
    mkdir -p /etc/xray
    mkdir -p /etc/vmess
    mkdir -p /etc/vless
    mkdir -p /etc/trojan
    mkdir -p /etc/shadowsocks
    mkdir -p /etc/ssh
    mkdir -p /usr/bin/xray/
    mkdir -p /var/log/xray/
    mkdir -p /var/www/html
    mkdir -p /etc/kyt/limit/vmess/ip
    mkdir -p /etc/kyt/limit/vless/ip
    mkdir -p /etc/kyt/limit/trojan/ip
    mkdir -p /etc/kyt/limit/ssh/ip
    chmod +x /var/log/xray
    touch /etc/xray/domain
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    touch /etc/vmess/.vmess.db
    touch /etc/vless/.vless.db
    touch /etc/trojan/.trojan.db
    touch /etc/shadowsocks/.shadowsocks.db
    touch /etc/ssh/.ssh.db
    touch /etc/bot/.bot.db
}

# ============================================================
# DOMAIN SETUP
# ============================================================
function pasang_domain() {
    echo -e ""
    clear
    echo -e "    ----------------------------------"
    echo -e "   |\e[1;32mPlease Select a Domain Type Below \e[0m|"
    echo -e "    ----------------------------------"
    echo -e "     \e[1;32m1)\e[0m Your Domain"
    echo -e "     \e[1;32m2)\e[0m Random Domain "
    echo -e "   ------------------------------------"
    read -p "   Pilih [1-2]: " host
    
    if [[ $host == "1" ]]; then
        clear
        echo ""
        echo ""
        echo -e "   \e[1;36m_______________________________$NC"
        echo -e "   \e[1;32m      INPUT YOUR DOMAIN $NC"
        echo -e "   \e[1;36m_______________________________$NC"
        echo -e ""
        read -p "   Domain: " host1
        echo "IP=${host1}" >> /var/lib/kyt/ipvps.conf
        echo $host1 > /etc/xray/domain
        echo $host1 > /root/domain
        echo ""
    elif [[ $host == "2" ]]; then
        wget ${REPO}Fls/cf.sh && chmod +x cf.sh && ./cf.sh
        rm -f /root/cf.sh
        clear
    fi
}

# ============================================================
# SSL INSTALL
# ============================================================
function pasang_ssl() {
    clear
    print_install "Memasang SSL Pada Domain"
    rm -rf /etc/xray/xray.key
    rm -rf /etc/xray/xray.crt
    domain=$(cat /root/domain)
    STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}' 2>/dev/null)
    rm -rf /root/.acme.sh
    mkdir /root/.acme.sh
    service stop $STOPWEBSERVER 2>/dev/null || true
    service stop nginx 2>/dev/null || true
    
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    chmod 777 /etc/xray/xray.key
    print_success "SSL Certificate"
}

# ============================================================
# INSTALL XRAY
# ============================================================
function install_xray() {
    clear
    print_install "Core Xray 1.8.1 Latest Version"
    domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir $domainSock_dir
    chown www-data.www-data $domainSock_dir
    
    latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version
    
    wget -O /etc/xray/config.json "${REPO}Cfg/config.json" >/dev/null 2>&1
    wget -O /etc/systemd/system/runn.service "${REPO}Fls/runn.service" >/dev/null 2>&1
    domain=$(cat /etc/xray/domain)
    print_success "Core Xray 1.8.1 Latest Version"
    
    print_install "Memasang Konfigurasi Packet"
    wget -O /etc/haproxy/haproxy.cfg "${REPO}Cfg/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}Cfg/xray.conf" >/dev/null 2>&1
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl ${REPO}Cfg/nginx.conf > /etc/nginx/nginx.conf 2>/dev/null
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem
    chmod +x /etc/systemd/system/runn.service
    
    cat >/etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target nss-lookup.target
[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
[Install]
WantedBy=multi-user.target
EOF
    print_success "Konfigurasi Packet"
}

# ============================================================
# SSH SETUP
# ============================================================
function ssh(){
    clear
    print_install "Memasang Password SSH"
    wget -O /etc/pam.d/common-password "${REPO}Fls/password"
    chmod +x /etc/pam.d/common-password
    
    cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

    cat > /etc/rc.local <<-END
exit 0
END
    chmod +x /etc/rc.local
    service enable rc-local
    service start rc-local.service
    
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
    sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
    sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
    
    print_success "Password SSH"
}

# ============================================================
# API TUNNEL
# ============================================================
function api_tunnel() { 
    apt install dos2unix -y
    wget -q ${REPO}api.sh && chmod +x api.sh && dos2unix api.sh && bash api.sh
    clear
}

# ============================================================
# UDP MINI
# ============================================================
function udp_mini(){
    clear
    print_install "Memasang Service Limit IP & Quota"
    wget -q https://raw.githubusercontent.com/kcepu877/V1/main/config/fv-tunnel && chmod +x fv-tunnel && ./fv-tunnel
    
    mkdir -p /usr/local/
    wget -q -O /usr/local/udp-mini "${REPO}Fls/udp-mini"
    chmod +x /usr/local/udp-mini
    wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}Fls/udp-mini-1.service"
    wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}Fls/udp-mini-2.service"
    wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}Fls/udp-mini-3.service"
    
    service enable udp-mini-1
    service start udp-mini-1
    service enable udp-mini-2
    service start udp-mini-2
    service enable udp-mini-3
    service start udp-mini-3
    
    print_success "Limit IP Service"
}

# ============================================================
# SLOWDNS
# ============================================================
function ssh_slow(){
    clear
    print_install "Memasang modul SlowDNS Server"
    wget -q -O /tmp/nameserver "${REPO}Fls/nameserver" >/dev/null 2>&1
    chmod +x /tmp/nameserver
    bash /tmp/nameserver | tee /root/install.log
    clear
    print_success "SlowDNS"
}

# ============================================================
# SSHD
# ============================================================
function ins_SSHD(){
    clear
    print_install "Memasang SSHD"
    wget -q -O /etc/ssh/sshd_config "${REPO}Fls/sshd" >/dev/null 2>&1
    chmod 700 /etc/ssh/sshd_config
    /etc/init.d/ssh restart
    service restart ssh
    print_success "SSHD"
}

# ============================================================
# DROPBEAR
# ============================================================
function ins_dropbear(){
    clear
    print_install "Menginstall Dropbear"
    apt-get install dropbear -y > /dev/null 2>&1
    wget -q -O /etc/default/dropbear "${REPO}Cfg/dropbear.conf"
    chmod +x /etc/default/dropbear
    /etc/init.d/dropbear restart
    print_success "Dropbear"
}

# ============================================================
# VNSTAT
# ============================================================
function ins_vnstat(){
    clear
    print_install "Menginstall Vnstat"
    apt -y install vnstat > /dev/null 2>&1
    /etc/init.d/vnstat restart
    service enable vnstat
    print_success "Vnstat"
}

# ============================================================
# OPENVPN
# ============================================================
function ins_openvpn(){
    clear
    print_install "Menginstall OpenVPN"
    wget ${REPO}Fls/openvpn && chmod +x openvpn && ./openvpn
    /etc/init.d/openvpn restart
    print_success "OpenVPN"
}

# ============================================================
# BACKUP
# ============================================================
function ins_backup(){
    clear
    print_install "Memasang Backup Server"
    apt install rclone -y
    printf "q\n" | rclone config
    wget -O /root/.config/rclone/rclone.conf "${REPO}Cfg/rclone.conf"
    
    cd /bin
    git clone https://github.com/LunaticBackend/wondershaper.git
    cd wondershaper
    sudo make install
    cd
    rm -rf wondershaper
    echo > /home/files
    
    print_success "Backup Server"
}

# ============================================================
# SWAP & GOTOP
# ============================================================
function ins_swab(){
    clear
    print_install "Memasang Swap 1 G"
    
    gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    if [[ -z "$gotop_latest" ]]; then
        gotop_latest="4.2.0"
    fi
    
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb || {
        echo -e "${YELLOW}Failed to download gotop, skipping...${NC}"
    }
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1 || true
    
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile >/dev/null 2>&1
    swapon /swapfile >/dev/null 2>&1
    sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab
    
    wget ${REPO}Fls/bbr.sh && chmod +x bbr.sh && ./bbr.sh
    print_success "Swap 1 G"
}

# ============================================================
# FAIL2BAN
# ============================================================
function ins_Fail2ban(){
    clear
    print_install "Menginstall Fail2ban"
    mkdir -p /usr/local/ddos
    echo "Banner /etc/banner.txt" >>/etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.txt"@g' /etc/default/dropbear
    wget -O /etc/banner.txt "${REPO}banner.txt"
    print_success "Fail2ban"
}

# ============================================================
# EPRO WEBSOCKET
# ============================================================
function ins_epro(){
    clear
    print_install "Menginstall ePro WebSocket Proxy"
    wget -O /usr/bin/ws "${REPO}Fls/ws" >/dev/null 2>&1
    wget -O /usr/bin/tun.conf "${REPO}Cfg/tun.conf" >/dev/null 2>&1
    wget -O /etc/systemd/system/ws.service "${REPO}Fls/ws.service" >/dev/null 2>&1
    chmod +x /etc/systemd/system/ws.service
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf
    service enable ws
    service start ws
    
    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
    
    iptables-save > /etc/iptables.up.rules
    iptables-restore -t < /etc/iptables.up.rules
    netfilter-persistent save
    netfilter-persistent reload
    
    apt autoclean -y >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1
    print_success "ePro WebSocket Proxy"
    
    clear
    print_install "MEMASANG NOOBZVPNS"
    cd
    apt install git -y
    git clone https://github.com/rifstore/noobzvpn.git
    cd noobzvpn/
    chmod +x install.sh
    ./install.sh
    service enable noobzvpns
    service start noobzvpns
    print_success "NOOBZVPNS"
}

# ============================================================
# 🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀
#   ZIVPN INSTALLER - UDH DIGABUNG LANGSUNG!
#   MODE: STANDALONE FUNCTION - SAMA PERSIS DENGAN SCRIPT LO
# 🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀
# ============================================================
function ins_zivpn() {
    clear
    print_install "Memasang ZiVPN UDP Protocol"
    
    # ==================================================
    # ZiVPN UDP Installer — MOD by ${author}
    # ==================================================
    
    set -e
    
    # Colors (reuse dari atas)
    echo -e "${BOLD}ZiVPN UDP Installer${RESET}"
    echo -e "${GRAY}MOD by ${author} Edition${RESET}"
    echo ""
    
    # CEK OS
    if [[ "$(uname -s)" != "Linux" ]] || [[ "$(uname -m)" != "x86_64" ]]; then
        print_fail "System not supported (Linux x86_64 only)"
    fi
    
    # CEK INSTALASI
    if [[ -f /usr/local/bin/zivpn ]]; then
        echo -e "${YELLOW}ZiVPN already installed, skipping...${NC}"
        return 0
    fi
    
    # UPDATE & DEPENDENCY
    print_task "Updating system"
    apt-get update -y &>/tmp/zivpn_install.log
    print_done "Updating system"
    
    if ! command -v go &>/dev/null; then
        print_task "Installing dependencies"
        apt-get install -y golang git wget curl ufw openssl &>>/tmp/zivpn_install.log
        print_done "Installing dependencies"
    else
        print_done "Dependencies ready"
    fi
    
    # ============================================================
    # DOMAIN - SAMA PERSIS DENGAN SCRIPT UTAMA!
    # ============================================================
    echo -e "${BOLD}Domain Configuration${RESET}"
    echo -e "    ----------------------------------"
    echo -e "   |\e[1;32mPlease Select a Domain Type Below \e[0m|"
    echo -e "    ----------------------------------"
    echo -e "     \e[1;32m1)\e[0m Your Domain (Recommended)"
    echo -e "     \e[1;32m2)\e[0m Random Domain "
    echo -e "   ------------------------------------"
    read -p "   Pilih [1-2]: " host_zivpn
    
    if [[ $host_zivpn == "1" ]]; then
        clear
        echo ""
        echo ""
        echo -e "   \e[1;36m_______________________________"
        echo -e "   \e[1;32m      INPUT YOUR DOMAIN"
        echo -e "   \e[1;36m_______________________________"
        echo -e ""
        read -p "   Domain: " domain_zivpn
        
    elif [[ $host_zivpn == "2" ]]; then
        echo -e "${YELLOW}   Getting random domain...${NC}"
        # Ambil random domain dari script sebelumnya
        domain_zivpn=$(curl -s https://raw.githubusercontent.com/kcepu877/zero-tunneling/main/Fls/cf.sh | grep -oE 'subdomain.*' | head -1 | cut -d' ' -f2 | sed 's/"//g' 2>/dev/null)
        
        # Fallback kalo gagal
        if [[ -z "$domain_zivpn" ]]; then
            domain_zivpn="vpn-$(openssl rand -hex 4).trycloudflare.com"
        fi
        echo -e "   ${GREEN}Domain: $domain_zivpn${NC}"
    else
        echo -e "   Using default domain..."
        domain_zivpn="vpn-$(openssl rand -hex 4).trycloudflare.com"
        echo -e "   ${GREEN}Domain: $domain_zivpn${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}✓ Domain set to: $domain_zivpn${RESET}"
    echo ""
    
    # =========================
    # API KEY
    # =========================
    echo -e "${BOLD}API Key Configuration${RESET}"
    generated_key=$(openssl rand -hex 16)
    echo -e "Generated Key: ${CYAN}$generated_key${RESET}"
    read -rp "Enter API Key (Enter = use generated): " input_key
    api_key="${input_key:-$generated_key}"
    echo -e "Using Key: ${GREEN}$api_key${RESET}"
    echo ""
    
    service stop zivpn.service &>/dev/null || true
    
    # =========================
    # DOWNLOAD CORE
    # =========================
    print_task "Downloading ZiVPN Core"
    wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn && chmod +x /usr/local/bin/zivpn
    print_done "Downloading ZiVPN Core"
    
    mkdir -p /etc/zivpn
    echo "$domain_zivpn"  > /etc/zivpn/domain
    echo "$api_key" > /etc/zivpn/apikey
    
    # =========================
    # CONFIG
    # =========================
    print_task "Downloading config"
    wget -q https://raw.githubusercontent.com/myridwan/xzi/ipuk/config.json -O /etc/zivpn/config.json
    print_done "Downloading config"
    
    # =========================
    # SSL
    # =========================
    print_task "Generating SSL certificate"
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=ID/ST=JawaBarat/L=Bandung/O=${author}/OU=IT/CN=$domain_zivpn" \
    -keyout /etc/zivpn/zivpn.key -out /etc/zivpn/zivpn.crt &>/dev/null
    print_done "Generating SSL certificate"
    
    sysctl -w net.core.rmem_max=16777216 &>/dev/null
    sysctl -w net.core.wmem_max=16777216 &>/dev/null
    
    # =========================
    # SYSTEMD CORE
    # =========================
    cat > /etc/systemd/system/zivpn.service <<EOF
[Unit]
Description=ZiVPN UDP Server - MOD by ${author}
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # =========================
    # API SERVICE
    # =========================
    mkdir -p /etc/zivpn/api
    
    print_task "Downloading API source"
    wget -q https://raw.githubusercontent.com/myridwan/xzi/ipuk/zivpn-api.go -O /etc/zivpn/api/zivpn-api.go
    wget -q https://raw.githubusercontent.com/myridwan/xzi/ipuk/go.mod -O /etc/zivpn/api/go.mod
    print_done "Downloading API source"
    
    cd /etc/zivpn/api
    
    print_task "Compiling API"
    if go build -o zivpn-api zivpn-api.go &>/dev/null; then
        print_done "Compiling API"
    else
        print_fail "Compiling API"
    fi
    
    cat > /etc/systemd/system/zivpn-api.service <<EOF
[Unit]
Description=ZiVPN API Service - MOD by ${author}
After=network.target zivpn.service

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn/api
ExecStart=/etc/zivpn/api/zivpn-api
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # =========================
    # TELEGRAM BOT (OPTIONAL)
    # =========================
    echo -e "${BOLD}Telegram Bot Configuration${RESET}"
    echo -e "${GRAY}(Leave empty to skip)${RESET}"
    read -rp "Bot Token: " bot_token
    read -rp "Admin ID : " admin_id
    
    if [[ -n "$bot_token" && -n "$admin_id" ]]; then
        echo "{\"bot_token\":\"$bot_token\",\"admin_id\":$admin_id}" > /etc/zivpn/bot-config.json
        
        print_task "Downloading Bot source"
        wget -q https://raw.githubusercontent.com/myridwan/xzi/ipuk/zivpn-bot.go -O /etc/zivpn/api/zivpn-bot.go
        print_done "Downloading Bot source"
        
        cd /etc/zivpn/api
        go get github.com/go-telegram-bot-api/telegram-bot-api/v5 &>/dev/null
        
        print_task "Compiling Bot"
        if go build -o zivpn-bot zivpn-bot.go &>/dev/null; then
            print_done "Compiling Bot"
            
            cat > /etc/systemd/system/zivpn-bot.service <<EOF
[Unit]
Description=ZiVPN Telegram Bot - MOD by ${author}
After=network.target zivpn-api.service

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn/api
ExecStart=/etc/zivpn/api/zivpn-bot
Restart=always

[Install]
WantedBy=multi-user.target
EOF
            service enable --now zivpn-bot.service
        else
            echo -e "${YELLOW}Failed to compile bot, skipping...${NC}"
        fi
    else
        echo "Skipping Bot setup"
    fi
    
    # =========================
    # START SERVICES
    # =========================
    print_task "Starting services"
    service daemon-reload && \
    service enable --now zivpn zivpn-api &>/dev/null
    print_done "Starting services"
    
    iface=$(ip route | awk '/default/ {print $5}')
    iptables -t nat -A PREROUTING -i "$iface" -p udp --dport 6000:19999 -j DNAT --to :5667 2>/dev/null || true
    
    ufw allow 6000:19999/udp &>/dev/null
    ufw allow 5667/udp &>/dev/null
    ufw allow 8080/tcp &>/dev/null
    
    echo ""
    echo -e "${BOLD}ZiVPN Installation Complete${RESET}"
    echo -e "Domain : ${CYAN}$domain_zivpn${RESET}"
    echo -e "API    : ${CYAN}Port 8080${RESET}"
    echo -e "Token  : ${CYAN}$api_key${RESET}"
    echo -e "MOD by : ${CYAN}${author}${RESET}"
    echo ""
    
    print_success "ZiVPN Protocol"
}

# ============================================================
# NOOBZVPNS
# ============================================================
function ins_noobzvpns() {
    clear
    print_install "Memasang NOOBZVPNS"
    cd
    apt install git -y
    git clone https://github.com/rifstore/noobzvpn.git
    cd noobzvpn/
    chmod +x install.sh
    ./install.sh
    service enable noobzvpns
    service start noobzvpns
    print_success "NOOBZVPNS"
}

# ============================================================
# RESTART ALL PACKET
# ============================================================
function ins_restart(){
    clear
    print_install "Restarting All Packet"
    /etc/init.d/nginx restart
    /etc/init.d/openvpn restart
    /etc/init.d/ssh restart
    /etc/init.d/dropbear restart
    /etc/init.d/vnstat restart
    service restart haproxy
    /etc/init.d/cron restart
    service daemon-reload
    service enable --now nginx
    service enable --now xray
    service enable --now rc-local
    service enable --now dropbear
    service enable --now openvpn
    service enable --now cron
    service enable --now haproxy
    service enable --now netfilter-persistent
    service enable --now ws
    service enable --now noobzvpns
    service enable --now zivpn zivpn-api 2>/dev/null || true
    
    history -c
    echo "unset HISTFILE" >> /etc/profile
    cd
    rm -f /root/openvpn
    rm -f /root/key.pem
    rm -f /root/cert.pem
    print_success "All Packet"
}

# ============================================================
# MENU INSTALL
# ============================================================
function menu(){
    clear
    print_install "Memasang Menu Packet"
    wget ${REPO}bot1/menu.zip
    apt install p7zip-full -y
    7z x -pkcepu877 menu.zip
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    rm -rf menu
    rm -rf menu.zip
    
    # Tambah menu ZIVPN
    sed -i '/menu/a echo "9. ZIVPN Protocol"' /usr/local/sbin/menu 2>/dev/null || true
}

# ============================================================
# PROFILE SETUP
# ============================================================
function profile(){
    clear
    cat >/root/.profile <<EOF
if [ "\$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF
    
    cat >/etc/cron.d/xp_all <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/local/sbin/xp
END
    chmod 644 /root/.profile
    
    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
    echo "*/1 * * * * root echo -n > /var/log/zivpn.log" >>/etc/cron.d/log.zivpn 2>/dev/null || true
    service cron restart
    
    echo "/bin/false" >>/etc/shells
    echo "/usr/sbin/nologin" >>/etc/shells
    
    cat >/etc/rc.local <<EOF
#!/bin/bash
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
service restart netfilter-persistent
exit 0
EOF
    chmod +x /etc/rc.local
    
    print_success "Menu Packet"
}

# ============================================================
# ENABLE SERVICES
# ============================================================
function enable_services(){
    clear
    print_install "Enable Service"
    service daemon-reload
    service enable --now rc-local
    service enable --now cron
    service enable --now netfilter-persistent
    service restart nginx
    service restart xray
    service restart haproxy
    service restart zivpn zivpn-api 2>/dev/null || true
    print_success "Enable Service"
    clear
}

# ============================================================
# MAIN INSTALLATION FUNCTION
# ============================================================
function instal(){
    clear
    first_setup
    nginx_install
    base_package
    make_folder_xray
    pasang_domain
    pasang_ssl
    install_xray
    ssh
    api_tunnel
    udp_mini
    ssh_slow
    ins_SSHD
    ins_dropbear
    ins_vnstat
    ins_openvpn
    ins_backup
    ins_swab
    ins_Fail2ban
    ins_epro
    ins_noobzvpns
    ins_zivpn           # ← ZIVPN UDH DIGABUNG!
    ins_restart
    menu
    profile
    enable_services
}

# ============================================================
# START INSTALLATION
# ============================================================
instal

echo ""
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain
secs_to_human "$(($(date +%s) - ${start}))"
sudo hostnamectl set-hostname "$author"
clear

# ============================================================
# INSTALLATION COMPLETE
# ============================================================
echo -e "\033[96m==========================\033[0m"
echo -e "\033[92m      INSTALL SUCCES      \033[0m"
echo -e "\033[96m==========================\033[0m"
echo -e "Author  : ${CYAN}$author${NC}"
echo -e "IP      : ${CYAN}$MYIP${NC}"
echo -e "Domain  : ${CYAN}$(cat /etc/xray/domain 2>/dev/null)${NC}"
echo -e ""
echo -e "${BOLD}ZiVPN Info:${RESET}"
echo -e "  Domain : ${CYAN}$(cat /etc/zivpn/domain 2>/dev/null)${NC}"
echo -e "  Token  : ${CYAN}$(cat /etc/zivpn/apikey 2>/dev/null)${NC}"
echo -e "\033[96m==========================\033[0m"
echo -e ""
sleep 3
reboot
