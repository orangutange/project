#Add more configurations to vsftpd, there's only a few as of now. 

systemctl start vsftpd
systemctl enable vsftpd

# Backup the files
echo "Backing up the default vsftpd.conf file..."
cp /etc/vsftpd.conf /etc/vsftpd.conf.bak

# Update vsftpd configuration
echo "Securing vsftpd configuration..."
vsftpd_conf="/etc/vsftpd.conf"

# MANUAL CONFIGURATIONS

# Anonymous_Enable = NO
sed -i 's/^anonymous_enable=.*/anonymous_enable=NO/' "$vsftpd_conf"

# Chroot_Local_User = YES
sed -i 's/^chroot_local_user=.*/chroot_local_user=YES/' "$vsftpd_conf"

# Local_Enable = YES
sed -i 's/^local_enable=.*/local_enable=YES/' "$vsftpd_conf"

# Write_Enable = YES
sed -i 's/^write_enable=.*/write_enable=YES/' "$vsftpd_conf"


# CHATGPT REALM (NO CLUE WHAT THEY WANNA DO HERE)

# Allow only secure connections
echo "Enforcing secure connections..."
sed -i 's/^ssl_enable=.*/ssl_enable=YES/' "$vsftpd_conf"
sed -i 's/^rsa_cert_file=.*/rsa_cert_file=\/etc\/ssl\/certs\/vsftpd.pem/' "$vsftpd_conf"
sed -i 's/^rsa_private_key_file=.*/rsa_private_key_file=\/etc\/ssl\/private\/vsftpd.key/' "$vsftpd_conf"
sed -i 's/^ssl_ciphers=.*/ssl_ciphers=HIGH:!ADH:!MD5:!RC4/' "$vsftpd_conf"
sed -i 's/^ssl_tlsv1=.*/ssl_tlsv1=YES/' "$vsftpd_conf"
sed -i 's/^ssl_sslv2=.*/ssl_sslv2=NO/' "$vsftpd_conf"
sed -i 's/^ssl_sslv3=.*/ssl_sslv3=NO/' "$vsftpd_conf"

# Restrict certain FTP commands
echo "Restricting certain FTP commands..."
echo "cmds_allowed=PASV, PORT, RETR, STOR, LIST, QUIT, DELE" >> "$vsftpd_conf"

# Restart vsftpd service to apply changes
echo "Restarting vsftpd service..."
systemctl restart vsftpd
