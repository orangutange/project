sudo apt install apache -y
sudo apt install apache2 -y
sudo apt install httpd -y
systemctl start apache
systemctl start apache2
systemctl start httpd

# Path to the new apache2.conf file
NEW_CONF="apache2.conf"

# Path to the existing apache2.conf file
CURRENT_CONF="/etc/apache2/apache2.conf"

# Create a backup of the current apache2.conf
sudo cp "$CURRENT_CONF" "${CURRENT_CONF}.bak"

# Replace the current apache2.conf with the new one
sudo cp "$NEW_CONF" "$CURRENT_CONF"

# Set correct permissions and ownership
echo "Setting correct permissions and ownership..."
sudo chmod 644 "$CURRENT_CONF"
sudo chown root:root "$CURRENT_CONF"

#chown for permissions to all files
chown -R root:root /etc/apache2

# Reload Apache to apply changes
systemctl reload apache2
echo "Backed up '$CURRENT_CONF' to '${CURRENT_CONF}.bak', replaced it with '$NEW_CONF', and restarted Apache."

