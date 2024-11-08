#!/bin/bash

# to add:
# gdm3 config
# more service configurations ( better vsftpd, better apache, mariadb, mysql, postgresql, etc)
# better hosts config

# EUREKA!!! POINTS!!!
main(){
    checkPrivilege
    # hosts needs work
    initializeScript
    setupFirewall
    criticalServices
    removeProhibitedSoftware
    configureSudoers
    removeUnauthorizedUsers
    setUserPasswords
    configureSysctl
    configurePam
    filePriviledges
    locateProhibitedFiles
    updateSystem
}
# Checks for root priviledges
checkPrivilege() {
    if [[ $EUID -ne 0 ]]; then
      echo "This script must be run as root."
      exit 1
    fi
}

# Generates password for all Users
generatePassword() {
    local password=$(tr -dc 'A-Za-z0-9!@#$%^&*()_+=' </dev/urandom | head -c 12)
    echo "$password"
}

# Function to initialize the script and perform setup checks
initializeScript() {
    echo "Initializing script..."
    sudo chmod +x /usr/bin/*
    sudo chmod +r /usr/bin/*
    sudo apt install apparmor-profiles
    echo "System initialized."
}

# Function to set up a firewall for critical services
setupFirewall() {
    echo "Setting up firewall..."
    if ! command -v ufw &> /dev/null; then
        echo "ufw not found, installing ufw..."
        sudo apt-get install ufw -y
    fi
    sudo ufw reset
    sudo ufw enable
    sudo ufw deny incoming
    for service in "${critical_services[@]}"; do
        sudo ufw allow "$service"
    done
}

# !!!Configures hosts (WIP)!!!
hosts(){
    echo “Configuring /etc/hosts file”
    
    echo “ALL:ALL” > /etc/hosts.deny
    echo “sshd:ALL” > /etc/hosts.allow
    echo “order hosts, bind” > /etc/host.conf
    echo “multi on” >> /etc/host.conf
    echo “nospoof on” >> /etc/host.conf
}

# Critical Services Configurations
criticalServices() {
    echo "Configuring critical services..."
    for service in "${critical_services[@]}"; do
        # ??? Why is ssh start here again ???
        systemctl start ssh
        if [[ "$service" == "ssh" ]]; then
            bash helperScripts/ssh.sh
        elif [[ "$service" == "samba" ]]; then
            bash helperScripts/samba.sh
        elif [[ "$service" == "vsftpd" ]]; then
            bash helperScripts/vsftpd.sh
        elif [[ "$service" == "apache" ]]; then
            bash helperScripts/apache.sh
        else
            echo "No specific configuration set for $service."
        fi
    done
}


# Function to configure sysctl. Based on klaver and other sources
configureSysctl() {
    echo "Configuring sysctl for system and network tuning..."
    # Backup the current sysctl.conf
    cp /etc/sysctl.conf /etc/sysctl.conf.bak
    curl -s https://raw.githubusercontent.com/klaver/sysctl/refs/heads/master/sysctl.conf -o /etc/sysctl.conf && sysctl -p
    sysctl -p /etc/sysctl.conf
}



# Function to configure PAM password settings
configurePam() {
    echo "Configuring PAM for password complexity and account lock..."
    sudo apt install libpam-pwquality -y
    sudo apt install libpam-modules -y
    
# /etc/pam.d/common-auth
    if ! grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
        echo -e "auth\t\trequisite\t\t\tpam_faillock.so preauth silent audit deny=5 unlock_time=900 even_deny_root root_unlock_time=900" | sudo tee -a /etc/pam.d/common-auth
        echo -e "auth\t\trequisite\t\t\tpam_faillock.so authfail audit deny=5 unlock_time=900 even_deny_root root_unlock_time=900" | sudo tee -a /etc/pam.d/common-auth
    fi

    # /etc/pam.d/common-password
     if grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
        sudo sed -i '/pam_pwquality.so/ s/$/ retry=3 minlen=14 difok=3 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minclass=3 maxrepeat=2 dictcheck=1 maxsequence=3 gecoscheck enforce_for_root/' /etc/pam.d/common-password
    else
        echo -e "password\t\trequisite\t\t\tpam_pwquality.so retry=3 minlen=14 difok=3 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minclass=3 maxrepeat=2 maxsequence=3 gecoscheck enforce_for_root" | sudo tee -a /etc/pam.d/common-password
    fi

     if grep -q "pam_unix.so" /etc/pam.d/common-password; then
        sudo sed -i '/pam_unix.so/ s/$/ obscure use_authtok obscure sha512 rounds=800000 shadow remember=7/' /etc/pam.d/common-password
    else
        echo -e "password\t\[success=1 default=ignore]\t\t\pam_unix.so obscure use_authtok obscure sha512 rounds=800000 shadow remember=7" | sudo tee -a /etc/pam.d/common-password
    fi        

        # Configure /etc/login.defs
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 14/' /etc/login.defs
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
        sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
        sed -i 's/^FAILLOG_ENAB.*/FAILLOG_ENAB yes/' /etc/login.defs
        sed -i 's/^PASS_MAX_TRIES.*/PASS_MAX_TRIES 3/' /etc/login.defs
        sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 12/' /etc/login.defs


}

# Function to configure gdm3
#configureGDM3() {
#    echo "Configuring gdm3"
#}

# Function to remove unauthorized users
removeUnauthorizedUsers() {
    echo "Checking and removing unauthorized users..."
    authorized_uids=($(awk -F':' '{ if ($3 >= 1000) print $1 }' /etc/passwd))
    for user in "${authorized_uids[@]}"; do
        if ! [[ "${valid_users[@]}" =~ "$user" ]]; then
            echo "Removing unauthorized user: $user"
            sudo userdel -r "$user"
        fi
    done
}

# Function to configure sudo access based on valid sudo users
configureSudoers() {
    echo "Configuring sudoers..."
    for user in "${valid_sudo_users[@]}"; do
        if ! groups "$user" | grep -q sudo; then
            echo "Adding $user to sudo group"
            sudo usermod -aG sudo "$user"
        fi
    done

    # Remove users who shouldn't have sudo
    current_sudoers=($(getent group sudo | awk -F: '{print $4}' | tr ',' ' '))
    for sudoer in "${current_sudoers[@]}"; do
        if ! [[ "${valid_sudo_users[@]}" =~ "$sudoer" ]]; then
            echo "Removing $sudoer from sudo group"
            sudo deluser "$sudoer" sudo
        fi
    done
}

# Function to update and upgrade the system
updateSystem() {
    echo "Updating and upgrading the system..."
    sudo apt-get update -y && sudo apt-get upgrade -y && sudo apt-get dist-upgrade -y
    read -p "Do you want to reboot the system to apply kernel updates? (y/n): " answer
    if [[ "$answer" == "y" ]]; then
        echo "Rebooting the system..."
        sudo reboot
    elif [[ "$answer" == "n" ]]; then
        echo "No reboot will be performed. Exiting script."
        exit 0
    else
        echo "Invalid input. Please answer with 'yes' or 'no'."
        exit 1
    fi    
    
}

# Function to remove prohibited software and services
removeProhibitedSoftware() {
    echo "Removing prohibited or unnecessary software..."
    prohibited_software=(john john-data nmap nmap-common ndiff vuze frostwire aircrack-ng fcrackzip lcrack kismet freeciv minetest minetest-server medusa hydra hydra-gtk truecrack ophcrack ophcrack-cli pdfcrack sipcrack irpas zeitgeist-core zeitgeist-datahub python-zeitgeist rhythmbox-plugin-zeitgeist zeitgeist nikto cryptcat nc netcat tightvncserver x11vnc nfs xinetd telnet rlogind rshd rcmd rexecd rbootd rquotad rstatd rusersd rwalld rexd fingerd tftpd snmp samba postgresql sftpd vsftpd apache apache2 ftp mysql php pop3 icmp sendmail dovecot bind9 nginx netcat-traditional netcat-openbsd ncat pnetcat socat sock socket sbd tcpdump lighttpd zenmap wireshark crack crack-common cyphesis aisleriot wesnoth wordpress gameconqueror qbittorrent qbittorrent-nox utorrent utserver metasploit-framework deluge ettercap hashcat hashcat-data autopsy sqlmap wifite wifiphisher spiderfoot ffuf tcpdump reaver impacket-scripts dnsrecon phpggc p0f ncrack masscan bloodhound cewl johnny eyewitness driftnet evilginx2 yersinia theharvester armitage veil polenum bettercap dirsearch dirbuster legion cutycapt rsh-redone-client gobuster havoc rsh-client vncviewer enum4linux dmitry snort snort-common snort-common-libraries snort-doc snort-rules-default wfuzz )
    installed_software=($(dpkg -l | awk '{print $2}'))

    for software in "${installed_software[@]}"; do
        if ! [[ "${valid_software[@]}" =~ "$software" ]] && [[ "${prohibited_software[@]}" =~ "$software" ]]; then
            echo "Removing $software..."
            sudo apt-get remove --purge -y "$software"
        fi
    done
}

# Function to locate prohibited files in /home, including hidden files
locateProhibitedFiles() {
    echo "Locating prohibited files in /home directory..."
    # Search for specific file types, including hidden files
    prohibited_files=$(find /home -type f \( \
        -name "*.mp3" -o -name "*.txt" -o -name "*.wav" -o -name "*.wma" -o \
        -name "*.aac" -o -name "*.mp4" -o -name "*.mov" -o -name "*.avi" -o \
        -name "*.gif" -o -name "*.jpg" -o -name "*.png" -o -name "*.bmp" -o \
        -name "*.img" -o -name "*.exe" -o -name "*.msi" -o -name "*.bat" -o \
        -name "*.sh" -o -name ".*.mp3" -o -name ".*.txt" -o -name ".*.wav" -o \
        -name ".*.wma" -o -name ".*.aac" -o -name ".*.mp4" -o -name ".*.mov" -o \
        -name ".*.avi" -o -name ".*.gif" -o -name ".*.jpg" -o -name ".*.png" -o \
        -name ".*.bmp" -o -name ".*.img" -o -name ".*.exe" -o -name ".*.msi" -o \
        -name ".*.bat" -o -name ".*.sh" -o -name ".*.so" -o -name "*.php" -o -name ".*.php" \) 2>/dev/null)

    if [ -n "$prohibited_files" ]; then
        echo "Prohibited files found:"
        echo "$prohibited_files"
    else
        echo "No prohibited files found in /home directory."
    fi
}

# Function to set passwords for authorized users
setUserPasswords() {
    echo "Setting passwords for authorized users..."
    for user in "${valid_users[@]}"; do
        local new_password=$(generatePassword)
        echo "Setting password for $user"
        echo "$user:$new_password" | sudo chpasswd
        echo "User: $user, New Password: $new_password" >> /tmp/passwords.txt
    done
}

# Checks for the correct file permissions of default files
filePriviledges(){
    df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
    bash helperScripts/permissions.sh
}

# Read the contents of the files into arrays
critical_services=($(<helperScripts/authorizedcriticalservices.txt))
valid_users=($(<helperScripts/authorizedusers.txt))
valid_sudo_users=($(<helperScripts/authorizedsudousers.txt))

# Define valid software (critical services)
valid_software=("${critical_services[@]}")

# Main script
main

echo "$password"

echo "All tasks completed."
echo "Passwords have been saved to /tmp/passwords.txt."
