remove_rootkits_malware() {
    echo "Scanning for rootkits and malware"
    apt-get install -y lynis
    sudo lynis audit system
    sudo dpkg -l | grep -E "crack|hack|attack|password|sniff|map|bit|client|hash|net|network|scan|email|address|domain|server|torrent|brute"
    echo "Rootkit and malware scan completed"
}
remove_rootkits_malware
