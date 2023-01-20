# PCI-DSS Hardening Scripts for Ubuntu 20.04

This project is a set of shell scripts for applying hardening on an Ubuntu 20.04 system to meet the security requirements of PCI-DSS certification.

The scripts include security settings for various services and packages, including:
- SSH
- Firewall
- Log
- Passwords
- Automatic updates

## How to use
1. Download the scripts from the project repository.
2. Grant execution permissions to all scripts using the command:
sudo chmod +x script_name.sh
3. Run each script as a superuser. Example:
sudo ./script_name.sh
4. Be sure to test and verify the applied settings before implementing in a production environment.
5. It is recommended to make a backup of the system before running the scripts.

**Note:** The scripts have been tested and developed for Ubuntu 20.04, but can be adapted for other Linux distributions. Be sure to read and understand what each script does before running it. This project does not guarantee compliance with PCI-DSS and it is
