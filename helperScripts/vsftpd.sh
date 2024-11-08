# ok i added some i will add more when vsftpd comes in adv linux

# Install vsftpd
apt install vsftpd

# Start and enable vsftpd service
systemctl start vsftpd
systemctl enable vsftpd

# Backup the files
echo "Backing up the default vsftpd.conf file..."
cp /etc/vsftpd.conf /etc/vsftpd.conf.bak

# Update vsftpd configuration
echo "Securing vsftpd configuration..."
vsftpd_conf="/etc/vsftpd.conf"

# MANUAL CONFIGURATIONS

# Disable anonymous access (Ensuring no anonymous FTP login)
sed -i 's/^anonymous_enable=.*/anonymous_enable=NO/' "$vsftpd_conf"

# Enable local users (local user authentication enabled)
sed -i 's/^local_enable=.*/local_enable=YES/' "$vsftpd_conf"

# Disable write permissions for local users (if you want read-only access)
sed -i 's/^write_enable=.*/write_enable=NO/' "$vsftpd_conf"

# Set local user umask (permissions for uploaded files)
sed -i 's/^local_umask=.*/local_umask=022/' "$vsftpd_conf"

# Disable anonymous upload functionality (security measure)
sed -i 's/^anon_upload_enable=.*/anon_upload_enable=NO/' "$vsftpd_conf"

# (Optional) Comment out anon_root to restrict anonymous FTP root access
sed -i 's/^anon_root=.*/#anon_root=/srv/ftp/' "$vsftpd_conf"

# (Optional) Disable chown uploads (to avoid changing ownership of uploaded files)
sed -i 's/^chown_uploads=.*/#chown_uploads=NO/' "$vsftpd_conf"

# (Optional) Comment out chown_username (for root ownership, consider security risks)
sed -i 's/^chown_username=.*/#chown_username=root/' "$vsftpd_conf"

# (Optional) Use a non-privileged user for FTP (requires creation of 'ftpsecure' user)
# Uncomment below if the user ftpsecure is created
# sed -i 's/^nopriv_user=.*/#nopriv_user=ftpsecure/' "$vsftpd_conf"

# Disable promiscuous port mode (secures FTP port assignment)
sed -i 's/^port_promiscuous=.*/#port_promiscuous=NO/' "$vsftpd_conf"

# Set secure chroot directory (prevents users from accessing other areas of the filesystem)
sed -i 's/^secure_chroot_dir=.*/secure_chroot_dir=\/var\/run\/vsftpd\/empty/' "$vsftpd_conf"

# Enforce SSL encryption for secure data connections
sed -i 's/^ssl_enable=.*/ssl_enable=YES/' "$vsftpd_conf"

# Force SSL for data transfer (important for ensuring encrypted FTP)
sed -i 's/^force_local_data_ssl=.*/force_local_data_ssl=YES/' "$vsftpd_conf"

# Force SSL for local logins (ensures secure login)
sed -i 's/^force_local_logins_ssl=.*/force_local_logins_ssl=YES/' "$vsftpd_conf"

# Enforce secure SSL/TLS settings for better protection
sed -i 's/^rsa_cert_file=.*/rsa_cert_file=\/etc\/ssl\/certs\/vsftpd.pem/' "$vsftpd_conf"
sed -i 's/^rsa_private_key_file=.*/rsa_private_key_file=\/etc\/ssl\/private\/vsftpd.key/' "$vsftpd_conf"
sed -i 's/^ssl_ciphers=.*/ssl_ciphers=HIGH:!ADH:!MD5:!RC4/' "$vsftpd_conf"
sed -i 's/^ssl_tlsv1=.*/ssl_tlsv1=YES/' "$vsftpd_conf"
sed -i 's/^ssl_sslv2=.*/ssl_sslv2=NO/' "$vsftpd_conf"
sed -i 's/^ssl_sslv3=.*/ssl_sslv3=NO/' "$vsftpd_conf"

# Restrict certain FTP commands for better security
echo "cmds_allowed=PASV, PORT, RETR, STOR, LIST, QUIT, DELE" >> "$vsftpd_conf"

# Restart vsftpd service to apply changes
echo "Restarting vsftpd service..."
systemctl restart vsftpd

# Firewall settings for passive port range
echo "Configuring firewall for FTP passive ports..."
ufw allow 40000:50000/tcp

# (Optional) Create the ftpsecure user if nopriv_user=ftpsecure is used
# sudo useradd -r -s /usr/sbin/nologin ftpsecure

echo "vsftpd secure configuration complete!"
