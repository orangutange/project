sudo apt install apache -y
sudo apt install apache2 -y
sudo apt install httpd -y
systemctl start apache
systemctl start apache2
systemctl start httpd

cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.bak

wget -qO- https://raw.githubusercontent.com/danvau7/very-secure-apache/refs/heads/master/apache2.conf > /etc/apache2/apache2.conf

# Set correct permissions and ownership
echo "Setting correct permissions and ownership..."
sudo chmod 644 "/etc/apache2/apache2.conf"
sudo chown root:root "/etc/apache2/apache2.conf"

#chown for permissions to all files
chown -R root:root /etc/apache2

# Reload Apache to apply changes
systemctl reload apache2
