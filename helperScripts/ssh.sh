echo "Configuring OpenSSH..."
apt install -y ssh 
apt-get install -y libpam-google-authenticator
systemctl start ssh
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
chown -R root:root /etc/ssh
sudo systemctl restart ssh
