#!/bin/bash

# Check if script is run with root/sudo privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run with sudo privileges" 
   exit 1
fi

# GitHub raw file URL
CONFIG_URL="https://raw.githubusercontent.com/danvau7/very-secure-php-ini/refs/heads/master/7.1.0%2B/php.ini"

# Path to the current PHP configuration
PHP_CONFIG="/etc/php/7.1/cli/php.ini"

# Backup the existing configuration
backup_file="${PHP_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
cp "$PHP_CONFIG" "$backup_file"

# Download the new configuration using wget
echo "Downloading PHP configuration from GitHub..."
wget -O "$PHP_CONFIG" "$CONFIG_URL"

# Check if download was successful
if [ $? -ne 0 ]; then
    echo "Failed to download configuration file"
    # Restore backup
    cp "$backup_file" "$PHP_CONFIG"
    exit 1
fi

# Reload PHP services
# Note: The exact command may vary depending on your system
systemctl restart php7.1-fpm
systemctl restart apache2
# Or for nginx:
# systemctl restart nginx

echo "PHP configuration has been updated and services reloaded."
echo "Backup of original configuration saved as: $backup_file"
