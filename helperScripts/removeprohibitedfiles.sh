removeProhibitedSoftware() {
    echo "Removing prohibited or unnecessary software..."

    # Check if the file exists
    [[ ! -f unwanted.txt ]] && { echo "File unwanted.txt not found."; return 1; }

    # Read prohibited software list from the file
    prohibited_software=($(<unwanted.txt))

    # Loop through and remove each software package
    for software in "${prohibited_software[@]}"; do
        echo "Removing $software..."
        sudo apt-get remove --purge -y "$software"
    done

    # Clean up unused dependencies
    sudo apt autoremove -y
}
removeProhibitedSoftware
