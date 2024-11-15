#!/bin/bash

echo "Configuring OpenSSH..."

# Install required packages
apt update
apt install -y openssh-server libpam-google-authenticator

# Ensure SSH service is started
systemctl enable ssh
systemctl start ssh

# Backup the sshd_config file
CONFIG_FILE="/etc/ssh/sshd_config"
BACKUP_FILE="/etc/ssh/sshd_config.bak.$(date +%F_%T)"
cp "$CONFIG_FILE" "$BACKUP_FILE"

# Update sshd_config settings
sed -i 's/^#\?Protocol.*/Protocol 2/' "$CONFIG_FILE"
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' "$CONFIG_FILE"
sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' "$CONFIG_FILE"
sed -i 's/^#\?LoginGraceTime.*/LoginGraceTime 20/' "$CONFIG_FILE"
sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$CONFIG_FILE"
sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' "$CONFIG_FILE"
sed -i 's/^#\?KerberosAuthentication.*/KerberosAuthentication no/' "$CONFIG_FILE"
sed -i 's/^#\?GSSAPIAuthentication.*/GSSAPIAuthentication no/' "$CONFIG_FILE"
sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' "$CONFIG_FILE"
sed -i 's/^#\?PermitUserEnvironment.*/PermitUserEnvironment no/' "$CONFIG_FILE"
sed -i 's/^#\?AllowAgentForwarding.*/AllowAgentForwarding no/' "$CONFIG_FILE"
sed -i 's/^#\?AllowTcpForwarding.*/AllowTcpForwarding no/' "$CONFIG_FILE"
sed -i 's/^#\?PermitTunnel.*/PermitTunnel no/' "$CONFIG_FILE"
sed -i 's/^#\?DebianBanner.*/DebianBanner no/' "$CONFIG_FILE"
sed -i 's/^#\?LogLevel.*/LogLevel VERBOSE/' "$CONFIG_FILE"
sed -i 's/^#\?IgnoreRhosts.*/IgnoreRhosts yes/' "$CONFIG_FILE"
sed -i 's/^#\?HostbasedAuthentication.*/HostbasedAuthentication no/' "$CONFIG_FILE"

# Add PAM configuration for Google Authenticator
echo "auth required pam_google_authenticator.so" >> /etc/pam.d/sshd

# Set correct ownership for SSH configuration files
chown -R root:root /etc/ssh

# Restart SSH service to apply changes
echo "Restarting SSH service..."
if systemctl reload ssh; then
    echo "SSH configuration updated successfully."
else
    echo "Failed to restart SSH. Please check the configuration."
    exit 1
fi

echo "OpenSSH has been configured and secured."
