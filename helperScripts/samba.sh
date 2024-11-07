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
