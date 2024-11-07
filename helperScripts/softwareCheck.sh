remove_rootkits_malware() {
    echo "Scanning for rootkits and malware"
    apt-get install -y lynis
    sudo lynis audit system
    sudo dpkg -l | grep -E "crack|hack|attack|password|sniff|map|bit|client|hash|net|network|scan|email|address|domain|server|torrent|brute"
    echo "Rootkit and malware scan completed"
}

check_for_suspicious() {
    apt-get install -y net-tools
    read -p "Do you want to see the list of ports listening? (y/n): " answer
    if [[ "$answer" == "y" ]]; then
        sudo netstat -tulpen | grep LISTEN
    elif [[ "$answer" == "n" ]]; then
        echo "Ok. Exiting script."
        exit 0
    else
        echo "Invalid input. Please answer with 'y' or 'n'."
        exit 1
    fi        

}


remove_rootkits_malware
check_for_suspicious
