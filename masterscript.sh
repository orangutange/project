#!/bin/bash

# EUREKA!!! POINTS!!!
main(){
    setUp
    # hosts needs work
    initialize_script
    remove_prohibited_software
    setup_firewall
    configure_sudo_users
    remove_unauthorized_users
    set_passwords_for_users
    configure_sysctl
    criticalServices
    configure_pam
    filePriviledges
    check_and_repair_binary_poisoning
    remove_rootkits_malware
    locate_prohibited_files
    update_system
}
# Setting up the system for script execution
setUp(){
    checkPrivilege
}
# Checks for root priviledges
checkPrivilege() {
    if [[ $EUID -ne 0 ]]; then
      echo "This script must be run as root."
      exit 1
    fi
}

#
generatePassword() {
    local password=$(tr -dc 'a-zA-Z0-9!@#$%^&*()-_+=<>?' < /dev/urandom | head -c 20)
    echo "$password"
}

hosts(){
    echo “Configuring /etc/hosts file”
    
    echo “ALL:ALL” > /etc/hosts.deny
    echo “sshd:ALL” > /etc/hosts.allow
    echo “order hosts, bind” > /etc/host.conf
    echo “multi on” >> /etc/host.conf
    echo “nospoof on” >> /etc/host.conf
}
#SSH - ssh and other stuff cuz like if service isnt ssh then
criticalServices() {
    echo "Configuring critical services..."
    for service in "${critical_services[@]}"; do
        systemctl start ssh
        if [[ "$service" == "ssh" ]]; then
            echo "Configuring OpenSSH..."
            apt-get install -y libpam-google-authenticator
        #systemctl start ssh
            sudo sed -i 's/^#Protocol.*/Protocol 2/' /etc/ssh/sshd_config
            sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
            sudo sed -i 's/^#MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
            sudo sed -i 's/^#LoginGraceTime.*/LoginGraceTime 20/' /etc/ssh/sshd_config
            sudo sed -i 's/^#PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
            sudo sed -i 's/^#ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
            sudo sed -i 's/^#KerberosAuthentication.*/KerberosAuthentication no/' /etc/ssh/sshd_config
            sudo sed -i 's/^#GSSAPIAuthentication.*/GSSAPIAuthentication no/' /etc/ssh/sshd_config
            sudo sed -i 's/^#X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
            sudo sed -i 's/^#PermitUserEnvironment.*/PermitUserEnvironment no/' /etc/ssh/sshd_config
            sudo sed -i 's/^#AllowAgentForwarding.*/AllowAgentForwarding no/' /etc/ssh/sshd_config
            sudo sed -i 's/^#AllowTcpForwarding.*/AllowTcpForwarding no/' /etc/ssh/sshd_config
            sudo sed -i 's/^#PermitTunnel.*/PermitTunnel no/' /etc/ssh/sshd_config
            sudo sed -i 's/^#DebianBanner.*/DebianBanner no/' /etc/ssh/sshd_config
            sudo sed -i 's/^#LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
            sudo sed -i 's/^#IgnoreRhosts.*/IgnoreRhosts yes/' /etc/ssh/sshd_config
            sudo sed -i 's/^#HostbasedAuthentication.*/HostbasedAuthentication no/' /etc/ssh/sshd_config
            
            echo "auth required pam_google_authenticator.so" >> /etc/pam.d/sshd
            sed -i 's/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config

            sudo systemctl restart sshd

        elif [[ "$service" == "samba" ]]; then
            echo "Configuring Samba..."
            apt-get install -y samba
        apt-get -y install system-config-samba
                
                systemctl start smbd
            smb_conf="/etc/samba/smb.conf"
        ufw allow netbios-ns
        ufw allow netbios-dgm
        ufw allow netbios-ssn
        ufw allow microsoft-ds

            # Add the required configurations to the Samba global section
            echo "disable netbios = Yes" >> $smb_conf
            echo "server min protocol = SMB3" >> $smb_conf
            echo "smb ports = 445" >> $smb_conf
            echo "server signing = required" >> $smb_conf
            echo "min protocol = SMB3" >> $smb_conf
            echo "map to guest = never" >> $smb_conf
            echo "restrict anonymous = 2" >> $smb_conf
            echo "hosts allow = 127.0.0.1 192.168.1.0/24" >> $smb_conf
            echo "hosts deny = 0.0.0.0/0" >> $smb_conf
            echo "workgroup = WORKGROUP" >> $smb_conf
            echo "guest account = nobody" >> $smb_conf
            echo "allow insecure wide links = no" >> $smb_conf
            echo "security = user" >> $smb_conf
            echo "passdb backend = tdbsam" >> $smb_conf
            echo "printing = bsd" >> $smb_conf
            echo "printcap name = /dev/null" >> $smb_conf
            echo "load printers = no" >> $smb_conf
            echo "disable spoolss = yes" >> $smb_conf
            echo "log level = 1 vfs:10" >> $smb_conf
            echo "log file = /var/log/samba/sambavfs.log" >> $smb_conf
            echo "max log size = 50" >> $smb_conf
            echo "smb encrypt = required" >> $smb_conf
            echo "client min protocol = SMB3" >> $smb_conf
            echo "client max protocol = SMB3" >> $smb_conf
            echo "client signing = mandatory" >> $smb_conf
            echo "server signing = mandatory" >> $smb_conf

            # Disable the banner
            echo "server string = " >> $smb_conf

            # Restart Samba to apply changes
            systemctl restart smbd
            echo "Samba has been configured."
        #elif [[ "$service" == "vsftpd" ]]; then

        elif [[ "$service" == "apache" ]]; then
            sudo apt install apache -y
            sudo apt install apache2 -y
            sudo apt install httpd -y
            systemctl start apache
            systemctl start apache2
            systemctl start httpd
            # Disable WebDAV, status, and UserDir modules (Ubuntu and Mint paths)
            sed -i '/LoadModule dav_module/s/^/#/' /etc/apache2/apache2.conf
            sed -i '/LoadModule dav_fs_module/s/^/#/' /etc/apache2/apache2.conf
            sed -i '/LoadModule status_module/s/^/#/' /etc/apache2/apache2.conf
            sed -i '/LoadModule userdir_module/s/^/#/' /etc/apache2/apache2.conf
            
            # Section 3: Privileges, Permissions, and Ownership
            
            # Ensure Apache runs as a non-root user
            sed -i 's/^User .*/User www-data/' /etc/apache2/apache2.conf
            sed -i 's/^Group .*/Group www-data/' /etc/apache2/apache2.conf
            usermod -L www-data
            usermod -s /usr/sbin/nologin www-data
            
            # Restrict permissions on Apache files and directories
            find /etc/apache2 -type d -exec chmod 755 {} \;
            find /etc/apache2 -type f -exec chmod 644 {} \;
            
            # Section 4: Apache Access Control
            
            # Restrict access to the root directory
            echo -e "<Directory />\n\tAllowOverride None\n\tRequire all denied\n</Directory>" >> /etc/apache2/apache2.conf
            
            # Section 5: Features, Content, and Options
            
            # Restrict Options for OS root and web root directories
            echo -e "<Directory />\n\tOptions None\n\tAllowOverride None\n</Directory>" >> /etc/apache2/apache2.conf
            echo -e "<Directory /var/www/>\n\tOptions -Indexes\n\tAllowOverride None\n</Directory>" >> /etc/apache2/apache2.conf
            
            # Remove default HTML content
            rm -rf /var/www/html/*
            
            # Disable HTTP TRACE method and restrict HTTP methods to GET, POST, and HEAD
            echo -e "\nTraceEnable off" >> /etc/apache2/apache2.conf
            echo -e "\n<LimitExcept GET POST HEAD>\n\tRequire all denied\n</LimitExcept>" >> /etc/apache2/apache2.conf
            
            # Ensure access to .ht* and sensitive files is restricted
            echo -e "<Files ~ \"^\\.ht\">\n\tRequire all denied\n</Files>" >> /etc/apache2/apache2.conf
            echo -e "<FilesMatch \"\\.(inc|bak|old|orig|save|swp|tmp|dist)\">\n\tRequire all denied\n</FilesMatch>" >> /etc/apache2/apache2.conf
            
            # Section 6: Logging and Monitoring
            
            # Enable access and error logging
            sed -i '/CustomLog/s/^#//' /etc/apache2/apache2.conf
            sed -i '/ErrorLog/s/^#//' /etc/apache2/apache2.conf
            sed -i 's/LogLevel .*/LogLevel warn/' /etc/apache2/apache2.conf
            
            # Set up log rotation
            echo "/var/log/apache2/*log {
                daily
                missingok
                rotate 14
                compress
                delaycompress
                notifempty
                create 640 root adm
                sharedscripts
                postrotate
                    /usr/sbin/service apache2 reload > /dev/null 2>/dev/null || true
                endscript
            }" > /etc/logrotate.d/apache2
            
            # Section 7: SSL/TLS
            
            # Enforce SSL protocols and ciphers
            sed -i '/SSLCipherSuite/s/.*/SSLCipherSuite HIGH:!aNULL:!MD5/' /etc/apache2/mods-available/ssl.conf
            sed -i '/SSLProtocol/s/.*/SSLProtocol -all +TLSv1.2 +TLSv1.3/' /etc/apache2/mods-available/ssl.conf
            echo 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"' >> /etc/apache2/mods-available/ssl.conf
            
            # Section 8: Information Leakage
            
            # Set ServerTokens to Prod and disable ServerSignature
            sed -i '/ServerTokens/s/.*/ServerTokens Prod/' /etc/apache2/apache2.conf
            echo "ServerSignature Off" >> /etc/apache2/apache2.conf
            
            # Section 9: Denial of Service (DoS) Mitigations
            
            # Set Timeout to 10 seconds
            sed -i 's/^Timeout .*/Timeout 10/' /etc/apache2/apache2.conf
            
            # Enable KeepAlive and configure limits
            sed -i 's/^KeepAlive .*/KeepAlive On/' /etc/apache2/apache2.conf
            sed -i 's/^MaxKeepAliveRequests .*/MaxKeepAliveRequests 100/' /etc/apache2/apache2.conf
            sed -i 's/^KeepAliveTimeout .*/KeepAliveTimeout 5/' /etc/apache2/apache2.conf
            
            # Section 10: Request Limits
            
            # Set request limits to prevent buffer overflow and DoS attacks
            echo -e "\nLimitRequestLine 512" >> /etc/apache2/apache2.conf
            echo -e "\nLimitRequestFields 100" >> /etc/apache2/apache2.conf
            echo -e "\nLimitRequestFieldSize 1024" >> /etc/apache2/apache2.conf
            echo -e "\nLimitRequestBody 102400" >> /etc/apache2/apache2.conf
            
            # Section 11: SELinux Configuration (if using SELinux)
            
            # Ensure SELinux is enabled and in Enforcing mode (For Ubuntu-based distributions, if SELinux is present)
            if command -v sestatus &> /dev/null && sestatus | grep -q 'enabled'; then
                setenforce 1
                sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
                semanage permissive -d httpd_t
                setsebool -P httpd_can_network_connect 0
                setsebool -P httpd_can_sendmail 0
            fi
            
            # Section 12: AppArmor Configuration (if using AppArmor)
            
            # Ensure AppArmor is enabled and in Enforce mode
            if command -v apparmor_status &> /dev/null && apparmor_status | grep -q 'enabled'; then
                aa-enforce /etc/apparmor.d/usr.sbin.apache2
            fi
            
            # Reload Apache to apply changes
            systemctl reload apache2
        else
            echo "No specific configuration set for $service."
        fi
    done
}


#Function to configure sysctl. Based on klaver and other sources
configure_sysctl() {
    echo "Configuring sysctl for system and network tuning..."

    # Backup the current sysctl.conf
    cp /etc/sysctl.conf /etc/sysctl.conf.bak

    # Apply the provided sysctl configurations
    cat <<EOT >> /etc/sysctl.conf
# Kernel sysctl configuration
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.pid_max = 65535
kernel.maps_protect = 1
kernel.exec-shield = 1
kernel.randomize_va_space = 2
kernel.msgmnb = 65535
kernel.msgmax = 65535
fs.suid_dumpable = 0
kernel.kptr_restrict = 1
fs.file-max = 209708
vm.swappiness = 30
vm.dirty_ratio = 30
vm.dirty_background_ratio = 5
vm.mmap_min_addr = 4096
vm.overcommit_ratio = 50
vm.overcommit_memory = 0
kernel.shmmax = 268435456
kernel.shmall = 268435456
vm.min_free_kbytes = 65535
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.ip_forward = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.default.forwarding = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.tcp_fin_timeout = 7
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_local_port_range = 16384 65535
net.ipv4.tcp_rfc1337 = 1
net.ipv6.conf.all.autoconf=0
net.ipv6.conf.all.accept_ra=0
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_rmem = 8192 87380 16777216
net.ipv4.udp_rmem_min = 16384
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.ipv4.tcp_wmem = 8192 65536 16777216
net.ipv4.udp_wmem_min = 16384
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 16384
net.core.optmem_max = 65535
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_max_orphans = 16384
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.route.flush = 1
net.ipv6.route.flush = 1
EOT

    # Apply the new sysctl settings
    sysctl -p /etc/sysctl.conf
}



# Function to configure PAM password settings
configure_pam() {
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
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 15/' /etc/login.defs
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
        sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
        sed -i 's/^FAILLOG_ENAB.*/FAILLOG_ENAB yes/' /etc/login.defs
        sed -i 's/^PASS_MAX_TRIES.*/PASS_MAX_TRIES 3/' /etc/login.defs
        sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 12/' /etc/login.defs


}

# Function to remove unauthorized users
remove_unauthorized_users() {
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
configure_sudo_users() {
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
remove_rootkits_malware() {
    echo "Scanning for rootkits and malware"
    apt-get install -y chkrootkit rkhunter clamav
    chkrootkit
    freshclam
    clamscan -r / --remove
    echo "Rootkit and malware scan completed"
}



# Function to update and upgrade the system
update_system() {
    echo "Updating and upgrading the system..."
    sudo apt-get update -y && sudo apt-get upgrade -y
}

# Function to remove prohibited software and services
remove_prohibited_software() {
    echo "Removing prohibited or unnecessary software..."
    prohibited_software=(john john-data nmap vuze frostwire aircrack-ng fcrackzip lcrack kismet freeciv minetest minetest-server medusa hydra hydra-gtk truecrack ophcrack ophcrack-cli pdfcrack sipcrack irpas zeitgeist-core zeitgeist-datahub python-zeitgeist rhythmbox-plugin-zeitgeist zeitgeist nikto cryptcat nc netcat tightvncserver x11vnc nfs xinetd telnet rlogind rshd rcmd rexecd rbootd rquotad rstatd rusersd rwalld rexd fingerd tftpd snmp samba postgresql sftpd vsftpd apache apache2 ftp mysql php pop3 icmp sendmail dovecot bind9 nginx netcat-traditional netcat-openbsd ncat pnetcat socat sock socket sbd tcpdump lighttpd zenmap wireshark crack crack-common cyphesis aisleriot wesnoth wordpress gameconqueror qbittorrent qbittorrent-nox utorrent utserver metasploit-framework deluge ettercap hashcat)
    installed_software=($(dpkg -l | awk '{print $2}'))

    for software in "${installed_software[@]}"; do
        if ! [[ "${valid_software[@]}" =~ "$software" ]] && [[ "${prohibited_software[@]}" =~ "$software" ]]; then
            echo "Removing $software..."
            sudo apt-get remove --purge -y "$software"
        fi
    done
}

# Function to locate prohibited files in /home, including hidden files
locate_prohibited_files() {
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
        -name ".*.bat" -o -name ".*.sh" \) 2>/dev/null)

    if [ -n "$prohibited_files" ]; then
        echo "Prohibited files found:"
        echo "$prohibited_files"
    else
        echo "No prohibited files found in /home directory."
    fi
}

# Function to set up a firewall for critical services
setup_firewall() {
    echo "Setting up firewall..."
    if ! command -v ufw &> /dev/null; then
        echo "ufw not found, installing ufw..."
        sudo apt-get install ufw -y
    fi
    sudo ufw reset
    sudo ufw enable
    for service in "${critical_services[@]}"; do
        sudo ufw allow "$service"
    done
}

# Function to set passwords for authorized users
set_passwords_for_users() {
    echo "Setting passwords for authorized users..."
    for user in "${valid_users[@]}"; do
        local new_password=$(generatePassword)
        echo "Setting password for $user"
        echo "$user:$new_password" | sudo chpasswd
        echo "User: $user, New Password: $new_password" >> /tmp/passwords.txt
    done
}

# Function to initialize the script and perform setup checks
initialize_script() {
    echo "Initializing script..."
    sudo chmod +x /usr/bin/*
    sudo chmod +r /usr/bin/*
    echo "System initialized."
}

# Function to check for binary poisoning and repair compromised packages
check_and_repair_binary_poisoning() {
    echo "Checking for binary poisoning using debsums..."

    # Ensure debsums is installed
    if ! command -v debsums &> /dev/null; then
        echo "debsums not found. Installing debsums..."
        apt-get update && apt-get install -y debsums
    fi

    # Run debsums to check for modified binaries
    poisoned_files=$(debsums -s)

    # If there are modified files, print them and provide options
    if [ -n "$poisoned_files" ]; then
        echo "Binary poisoning detected. Modified files:"
        echo "$poisoned_files"
        
        echo "Attempting to repair compromised packages..."
        
        # Extract package names from debsums output and reinstall them
        for package in $(echo "$poisoned_files" | awk '{print $1}' | xargs dpkg -S | cut -d: -f1 | sort -u); do
            echo "Reinstalling package: $package"
            apt-get install --reinstall -y "$package"
        done

        echo "Repair process completed. Re-running debsums for verification..."
        debsums -s && echo "All binaries verified successfully." || echo "Some issues may still be present."
    else
        echo "No binary poisoning detected. All binaries are intact."
    fi
}

#Checks for the correct file permissions of default files
filePriviledges(){
    df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
    bash helperScripts/permissions.sh
}

# Prompt for user input
read -p "Enter the critical services (separated by space): " -a critical_services
read -p "Enter the valid users from the README (separated by space): " -a valid_users
read -p "Enter the valid sudo users (separated by space): " -a valid_sudo_users

# Define valid software (critical services)
valid_software=("${critical_services[@]}")

# Main script
main

echo $password

echo "All tasks completed."
echo "Passwords have been saved to /tmp/passwords.txt."
echo "Prohibited files located in /tmp/prohibited_files.txt."
