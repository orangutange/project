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
