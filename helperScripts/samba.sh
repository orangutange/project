#!/bin/bash

# Install Samba
apt-get install -y samba
apt-get -y install system-config-samba

systemctl start smbd

smb_conf="/etc/samba/smb.conf"

ufw allow netbios-ns
ufw allow netbios-dgm
ufw allow netbios-ssn
ufw allow microsoft-ds
ufw allow 445

# Insert configurations under [global] section
sed -i '/\[global\]/a \
\
disable netbios = Yes\n\
smb ports = 445\n\
map to guest = never\n\
guest ok = no\n\
restrict anonymous = 2\n\
hosts allow = 127.0.0.1 192.168.1.0/24\n\
hosts deny = 0.0.0.0/0\n\
workgroup = WORKGROUP\n\
guest account = nobody\n\
allow insecure wide links = no\n\
security = user\n\
passdb backend = tdbsam\n\
printing = bsd\n\
printcap name = /dev/null\n\
load printers = no\n\
disable spoolss = yes\n\
log level = 1 vfs:10\n\
log file = /var/log/samba/sambavfs.log\n\
max log size = 50\n\
min protocol = SMB3\n\
server min protocol = SMB3\n\
client min protocol = SMB3\n\
client max protocol = SMB3\n\
ntlm auth = yes\n\
lanman auth = no\n\
client signing = mandatory\n\
server signing = mandatory\n\
smb encrypt = mandatory\n\
server string = '" $smb_conf

# Read authorized users from file and set up their Samba accounts
users_file="authorizedusers.txt"
if [ -f "$users_file" ]; then
    while IFS= read -r user || [ -n "$user" ]; do
        echo "Adding user $user to Samba."
        # Add the user to the system if not already added
        if ! id -u "$user" >/dev/null 2>&1; then
            adduser --disabled-password --gecos "" "$user"
        fi

        # Prompt for Samba password
        echo "Enter Samba password for user $user:"
        smbpasswd -a "$user"
        smbpasswd -e "$user"  # Enable the Samba user
        echo "User $user has been configured for Samba."
    done < "$users_file"
else
    echo "Error: Authorized users file '$users_file' not found."
    exit 1
fi

# Restart Samba to apply changes
systemctl reload smbd

echo "Samba has been successfully configured."
