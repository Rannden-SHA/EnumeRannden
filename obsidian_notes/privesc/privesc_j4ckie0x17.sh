#!/bin/bash
# Define colors
red='\e[31m'
reset='\e[0m'
green='\e[32m'
blue='\e[34m'
violet='\e[35m'

# Function to display the menu
menu() {
    echo -e "${red}|-----------------------------|${reset}"
    echo -e "${red}|   Welcome to Priv_Linux!    |${reset}"
    echo -e "${red}|       Dev By j4ckie0x17     |${reset}"
    echo -e "${red}|-----------------------------|${reset}\n"
}

# Print the menu
menu
echo -e "REMINDER: All the results will be saved at folder ${red}priv_linux_results${reset}, Example: (currentpath)/priv_linux_results/basic_commands.txt"
echo
# Function to handle SIGINT signal (Ctrl + C)
exit_handler() {
    echo -e "\n${red}Exiting...${reset}"
    exit 1
}

# Set the exit_handler function as the handler for SIGINT signal
trap exit_handler SIGINT

# Folder for output files
output_folder="priv_linux_results"

# Function to pause and wait for user input
pause() {
    read -p "Press Enter to continue..."
    echo
}
# Check if the output folder exists, if not, create it
if [ ! -d "$output_folder" ]; then
    mkdir "$output_folder"
fi

while true; do
    # Show menu
    echo -e "${red}Select an option:${reset}"
    echo
    echo -e "1. ${green}Basic Commands${reset}"
    echo -e "2. ${green}SUID, sudo, and Capabilities Permissions${reset}"
    echo -e "3. ${green}Internal Ports${reset}"
    echo -e "4. ${green}Folders with Write and/or Read Permissions${reset}"
    echo -e "5. ${green}Core system files${reset}"
    echo -e "6. ${green}Cronjobs/System processes${reset}"
    echo -e "7. ${green}Kernel check${reset}"
    echo -e "8. ${green}NFS (/etc/exports), if there is NFS${reset}"
    echo -e "9. ${green}pspy64 (procmon-manual)${reset}"
    echo -e "10. ${red}Exit${reset}"
    echo
    # Read user selection
    read -p "Option: " option

    # Execute the selected option
    case $option in
        1)
            # File for basic commands
            output_file="$output_folder/basic_commands.txt"
            [ -f "$output_file" ] && rm "$output_file"
            +
            echo -e "${red}============= Basic Commands =============${reset}"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}=========== Current User ================${reset}"
            echo -e "${blue}=========================================${reset}"
            whoami | tee -a "$output_file"
            echo -e "${red}\nid\n=====================\n${reset}" >> "$output_file"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}======= User and Group Information ======${reset}"
            echo -e "${blue}=========================================${reset}"
            id | tee -a "$output_file"
            echo -e "${red}\nenv\n=====================\n${reset}" >> "$output_file"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}========== User System Variables ========${reset}"
            echo -e "${blue}=========================================${reset}"
            env | tee -a "$output_file"
            echo -e "${red}\nps -eo\n=====================\n${reset}" >> "$output_file"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}=== Commands Executed on the System ===${reset}"
            echo -e "${blue}=========================================${reset}"
            ps -eo user,command | tee -a "$output_file"
            pause
            ;;
        2) 
            # File for SUID, sudo, and capabilities permissions
            output_file="$output_folder/suid_sudo_capabilities.txt"
            [ -f "$output_file" ] && rm "$output_file"
            read -p "Do you have the current user's password? (Y/N): " response
            if [ "$response" = "Y" ]; then
                read -sp "Enter the password: " password
            else
                echo -e "${red}No password available, proceeding with the process${reset}"
                password=""
            fi
            echo

            echo -e "${red}=== SUID, sudo, and Capabilities Permissions ===${reset}"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}========== SUID Permissions =============${reset}"
            echo -e "${blue}=========================================${reset}"
            # Loop through all files with SUID permission
            while IFS= read -r file; do
            # Check if the file is one of the known binaries
            if [[ $file =~ (dbus-daemon-launch-helper|ssh-keysign|su|newgrp|passwd|umount|chfn|gpasswd|chsh|mount|sudo|mount.nfs) ]]; then
                # Print the known binary in its default color
                echo "$file" | tee -a "$output_file"
            else
                # Print the other binaries in green color
                echo -e "${red}$file${reset}" | tee -a "$output_file"
            fi
            done < <(find / -type f -perm -u=s 2>/dev/null)
            echo -e "${red}\nsudo result\n=====================\n${reset}" >> "$output_file"
            echo -e "${violet}Visit https://gtfobins.github.io/ to check for matching SUID binaries${reset}"
            echo -e "${blue}============================================${reset}"
            echo -e "${blue}============ sudo Permissions ==============${reset}"
            echo -e "${blue}============================================${reset}"
            echo -e "${password}\n" | sudo -S -l | tee -a "$output_file"
            echo -e "${red}\nCapabilities result\n=====================\n${reset}" >> "$output_file"
            echo -e "${violet}Visit https://gtfobins.github.io/ to check for matching sudo binaries${reset}" 
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}============= Capabilities ==============${reset}"
            echo -e "${blue}=========================================${reset}"
            getcap -r / 2>/dev/null | tee -a "$output_file"
            echo -e "${violet}Visit https://gtfobins.github.io/ to check for matching capabilities${reset}"
            pause
            ;;
        3)
            # File for internal ports
            output_file="$output_folder/internal_ports.txt"
            [ -f "$output_file" ] && rm "$output_file"
            echo -e "${red}============= Internal Ports =============${reset}"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}=============== netstat =================${reset}"
            echo -e "${blue}=========================================${reset}"
            echo -e "${red}\nNetstat result\n=====================\n" >> "$output_file"
            netstat -tuln | tee -a "$output_file"
            echo -e "\nss -tulpn result\n=====================\n" >> "$output_file"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}============== ss -tulpn ================${reset}"
            echo -e "${blue}=========================================${reset}"
            ss -tulpn | tee -a "$output_file"
            pause
            ;;
        4)
            # File for folders with write and/or read permissions
            output_file="$output_folder/folders_permissions.txt"
            [ -f "$output_file" ] && rm "$output_file"
            echo -e "${red}===== Folders with Write and/or Read Permissions ===${reset}"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}============ Directories ================${reset}"
            echo -e "${blue}=========================================${reset}"
            echo -e "${red}\nDirectories\n=====================\n${reset}" >> "$output_file"
            find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u | tee -a "$output_file"
            echo -e "${red}\nWritable files\n=====================\n${reset}" >> "$output_file"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}============ Writable files =============${reset}"
            echo -e "${blue}=========================================${reset}"
            find / -writable 2>/dev/null | grep -v -i -E 'proc|run|sys|dev' | tee -a "$output_file"
            pause
            ;;
        5)
            # File for folders with write and/or read permissions
            output_file="$output_folder/core_system_files.txt"
            [ -f "$output_file" ] && rm "$output_file"
            echo -e "${red}=========== Core system files ============${reset}"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}============= /etc/passwd ===============${reset}"
            echo -e "${blue}=========================================${reset}"
            echo -e "${red}\n/etc/passwd\n=====================\n${reset}" >> "$output_file"
            grep "^.*sh$" /etc/passwd | tee -a "$output_file"
            echo -e "${red}\n/etc/shadow\n=====================\n${reset}" >> "$output_file"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}============= /etc/shadow ===============${reset}"
            echo -e "${blue}=========================================${reset}"
            cat /etc/shadow | tee -a "$output_file"
            echo -e "${red}\n/etc/issue\n=====================\n${reset}" >> "$output_file"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}============== /etc/issue ===============${reset}"
            echo -e "${blue}=========================================${reset}"
            cat /etc/issue | tee -a "$output_file"
            echo -e "${red}\n/etc/hostname\n=====================\n${reset}" >> "$output_file"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}============== /etc/hostname ============${reset}"
            echo -e "${blue}=========================================${reset}"
            cat /etc/hostname | tee -a "$output_file"
            echo -e "${red}\n/etc/login.defs\n=====================\n${reset}" >> "$output_file"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}============ /etc/login.defs ============${reset}"
            echo -e "${blue}=========================================${reset}"
            cat /etc/login.defs | tee -a "$output_file"
            echo -e "${red}\n/proc/version\n=====================\n${reset}" >> "$output_file"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}================= /proc/version ================${reset}"
            echo -e "${blue}=========================================${reset}"
            cat /proc/version | tee -a "$output_file"
            echo -e "${red}\n/proc/self/environ\n=====================\n${reset}" >> "$output_file"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}========== /proc/self/environ ===========${reset}"
            echo -e "${blue}=========================================${reset}"
            cat /proc/self/environ | tee -a "$output_file"
            echo -e "${red}\n/proc/sched_debug\n=====================\n${reset}" >> "$output_file"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}========== /proc/sched_debug ===========${reset}"
            echo -e "${blue}=========================================${reset}"
            cat /proc/sched_debug | tee -a "$output_file"
            pause
            ;;
        6)
            # File for folders with write and/or read permissions
            output_file="$output_folder/cronjobs.txt"
            [ -f "$output_file" ] && rm "$output_file"
            echo -e "${red}=============== Cronjobs =================${reset}"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}============== /etc/crontab =============${reset}"
            echo -e "${blue}=========================================${reset}"
            echo -e "${red}\nCrontab result\n=====================\n${reset}" >> "$output_file"
            cat /etc/crontab | tee -a "$output_file"
            echo -e "${red}\n/var/spool/cron result\n=====================\n" >> "$output_file"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}=========== /var/spool/cron =============${reset}"
            echo -e "${blue}=========================================${reset}"
            ls -la  /var/spool/cron | tee -a "$output_file"
            echo -e "${red}\n/etc/anacron result\n=====================\n${reset}" >> "$output_file"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}============== /etc/anacron =============${reset}"
            echo -e "${blue}=========================================${reset}"
            cat /etc/anacron | tee -a "$output_file"
            echo -e "${red}\nsystemctl list-timers result\n=====================\n${reset}" >> "$output_file"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}========= systemctl list-timers =========${reset}"
            echo -e "${blue}=========================================${reset}"
            systemctl list-timers | tee -a "$output_file"
            echo -e "${red}\nps aux\n=====================\n${reset}" >> "$output_file"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}================= ps aux ================${reset}"
            echo -e "${blue}=========================================${reset}"
            ps aux | tee -a "$output_file"
            pause
            ;;
        7)
            # File for folders with write and/or read permissions
            output_file="$output_folder/kernel.txt"
            [ -f "$output_file" ] && rm "$output_file"
            echo -e "${red}============= Kernel check ===============${reset}"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}================ uname -a ===============${reset}"
            echo -e "${blue}=========================================${reset}"
            echo -e "${red}\nuname -a result\n=====================\n${reset}" >> "$output_file"
            uname -a | tee -a "$output_file"
            echo -e "${red}\nlsb_release result\n=====================\n${reset}" >> "$output_file"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}=========== lsb_release -a ==============${reset}"
            echo -e "${blue}=========================================${reset}"
            lsb_release -a | tee -a "$output_file"
            pause
            ;;    
        8)
            # File for folders with write and/or read permissions
            output_file="$output_folder/nfs.txt"
            [ -f "$output_file" ] && rm "$output_file"
            echo -e "${red}=== NFS /etc/exports ===${reset}"
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}========== NFS - /etc/exports ===========${reset}"
            echo -e "${blue}=========================================${reset}"
            sed '/no_root_squash/s//\x1b[31m&\x1b[0m/' /etc/exports
            echo -e "${violet}If the 'no_root_squad' is in the file check that PE --> https://j4ckie0x17.gitbook.io/notes-pentesting/escalada-de-privilegios/linux#nfs${reset}"
            ;;
        9)
            echo -e "${blue}=========================================${reset}"
            echo -e "${blue}=========== pspy64 - procmon ============${reset}"
            echo -e "${blue}=========================================${reset}"
            old_process=$(ps -eo user,command)
            while true; do
            new_process=$(ps -eo user,command)
            diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -vE "procmon|command|kworker"
            old_process=$new_process
            done
            # Made by s4vitar
            ;;
        10)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option. Please select a number from 1 to 10."
            ;;
    esac

    # Pause to show results and wait for next selection
    read -p "Press Enter to continue..."
    echo
done
