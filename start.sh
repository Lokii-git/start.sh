#!/bin/bash
# Kali Linux Initial Setup Script for Internal Pen Testing
# Author: Philip Burnham
# Purpose: Automates updates, upgrades, and essential tool installations.

# Define colors
GREEN='\e[32m'
RED='\e[31m'
BLUE='\e[34m'
YELLOW='\e[33m'
RESET='\e[0m'

# Define a resume flag to track re-login
RESUME_FLAG="$HOME/.docker_resume"

# Display Banner
cat << "EOF"
_________ .__                                       __                
\_   ___ \|  |   ____ _____ _________  _  _______ _/  |_  ___________ 
/    \  \/|  | _/ __ \\__  \\_  __ \ \/ \/ /\__  \\   __\/ __ \_  __ \
\     \___|  |_\  ___/ / __ \|  | \/\     /  / __ \|  | \  ___/|  | \/
 \______  /____/\___  >____  /__|    \/\_/  (____  /__|  \___  >__|   
        \/          \/     \/                    \/          \/       
EOF
echo -e "${BLUE}========================================================${RESET}"
echo -e "🚀 ${YELLOW}Kali Linux Internal Pentesting Setup Script v2.0.0${RESET} 🚀"
echo -e "${BLUE}========================================================${RESET}"

# Check for Internet Connectivity
echo -e "${BLUE}[-] Checking internet connectivity...${RESET}"
if ! ping -c 1 google.com &>/dev/null; then
    echo -e "${RED}[!] No internet connection detected. Ensure network access before running the script.${RESET}"
    exit 1
fi

# Ensure system date and time are correct
echo -e "${BLUE}[-] Checking and synchronizing system time...${RESET}"

# Install `ntpdate` if not available
if ! command -v ntpdate &>/dev/null; then
    sudo apt update > /dev/null 2>&1
    sudo apt install -y ntpdate > /dev/null 2>&1
fi

# Sync time with NTP server
if sudo ntpdate -q time.google.com > /dev/null 2>&1; then
    if sudo ntpdate time.google.com > /dev/null 2>&1; then
        echo -e "${GREEN}[+] System time synchronized successfully.${RESET}"
    else
        echo -e "${RED}[!] Time sync failed. Check network settings.${RESET}"
    fi
else
    echo -e "${RED}[!] Unable to reach NTP server. Time sync may be inaccurate.${RESET}"
fi

# Ensure CA certificates are up to date
echo -e "${BLUE}[-] Updating CA certificates...${RESET}"

# Update package lists quietly, but show errors if it fails
if sudo apt update > /dev/null 2>&1; then
    echo -e "${GREEN}[+] Package lists updated successfully.${RESET}"
else
    echo -e "${RED}[!] apt update failed! Check your internet connection.${RESET}"
fi

# Reinstall CA certificates while allowing errors to be seen
if sudo apt install --reinstall -y ca-certificates > /dev/null 2>&1; then
    echo -e "${GREEN}[+] CA certificates updated successfully.${RESET}"
else
    echo -e "${RED}[!] Failed to update CA certificates! This may affect SSL connections.${RESET}"
fi

# Run update-ca-certificates quietly, but show errors
if sudo update-ca-certificates > /dev/null 2>&1; then
    echo -e "${GREEN}[+] SSL certificates updated.${RESET}"
else
    echo -e "${RED}[!] SSL update failed! Some HTTPS requests may break.${RESET}"
fi

# Ensure jq is installed
if ! command -v jq &>/dev/null; then
    echo -e "${YELLOW}[/] jq is not installed. Installing now...${RESET}"
    
    # Run update first, then check if jq installs successfully
    sudo apt update -y > /dev/null 2>&1
    if sudo apt install -y jq > /dev/null 2>&1; then
        echo -e "${GREEN}[+] jq installed successfully.${RESET}"
    else
        echo -e "${RED}[!] jq installation failed! Please check your network connection.${RESET}"
    fi
fi

# Check if an update is available
echo -e "${BLUE}[-] Checking for script updates...${RESET}"
if command -v git &>/dev/null; then
    if [ -d "/home/kali/start.sh/.git" ]; then
        cd /home/kali/start.sh
        
        # Check if there are updates before pulling
        if git pull --dry-run 2>/dev/null | grep -q "origin"; then
            echo -e "${GREEN}[+] Update found! Pulling latest changes...${RESET}"
            git pull --quiet
            echo -e "${GREEN}[+] Update applied. Restarting script...${RESET}"
            exec /home/kali/start.sh/start.sh  # Restart the script with the updated version
        else
            echo -e "${GREEN}[+] Script is already up to date.${RESET}"
        fi
    else
        echo -e "${YELLOW}[/] Git repo missing. Cloning fresh copy...${RESET}"
        git clone https://github.com/Lokii-git/start.sh.git /home/kali/start.sh > /dev/null 2>&1
    fi
else
    echo -e "${YELLOW}[/] Git not found. Falling back to wget...${RESET}"
    wget -q -O /home/kali/start.sh/start.sh "https://raw.githubusercontent.com/Lokii-git/start.sh/main/start.sh"
fi




# Check for SSL Inspection
detect_ssl_inspection() {
    local domain="$1"
    local output=$(echo | openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null | openssl x509 -noout -issuer -subject 2>/dev/null)
    
    if [[ -z "$output" ]]; then
        echo -e "${YELLOW}[!] Could not retrieve SSL certificate for $domain. Check internet or firewall.${RESET}"
    elif [[ "$output" =~ "SonicWall" || "$output" =~ "Fortinet" || "$output" =~ "Proxy" || "$output" =~ "self-signed" ]]; then
        echo -e "${RED}[!] SSL Inspection detected for $domain. Request support to disable it!${RESET}"
    fi
}

echo -e "${BLUE}[-] Checking for SSL Inspection...${RESET}"
detect_ssl_inspection "docker.io"
detect_ssl_inspection "horizon3ai.com"
detect_ssl_inspection "s3.amazonaws.com"

# Ensure the user is in the Docker group
if ! groups | grep -q "\bdocker\b"; then
    echo -e "${RED}[!] Your user is not in the Docker group. Adding now...${RESET}"
    sudo usermod -aG docker "$USER"
    echo -e "${GREEN}[+] Added $USER to the 'docker' group.${RESET}"
    
    # Set flag to notify the user at the end
    touch "$RESUME_FLAG"
    NEEDS_REBOOT=true
fi

# Get the current hostname
CURRENT_HOSTNAME=$(hostname)

# Define the expected hostname (Kali default)
EXPECTED_HOSTNAME="kali"

# Ensure the hostname is set to "kali"
if [ "$CURRENT_HOSTNAME" != "$EXPECTED_HOSTNAME" ]; then
    echo -e "${RED}[!] System hostname is '$CURRENT_HOSTNAME' but should be '$EXPECTED_HOSTNAME'. Fixing now...${RESET}"
    sudo hostnamectl set-hostname "$EXPECTED_HOSTNAME"
    echo -e "${GREEN}[+] Hostname set to '$EXPECTED_HOSTNAME'.${RESET}"
else
    echo -e "${GREEN}[+] Hostname is already correctly set to '$EXPECTED_HOSTNAME'."
fi

# Ensure /etc/hosts contains the correct hostname entry
if ! grep -q "127.0.1.1 $EXPECTED_HOSTNAME" /etc/hosts; then
    echo -e "${RED}[!] Missing hostname entry in /etc/hosts. Adding now...${RESET}"
    echo "127.0.1.1 $EXPECTED_HOSTNAME" | sudo tee -a /etc/hosts
    echo -e "${GREEN}[+] Hostname entry added to /etc/hosts.${RESET}"
else
    echo -e "${GREEN}[+] /etc/hosts is correctly configured.${RESET}"
fi

# Update and upgrade Kali Linux silently
echo -e "${BLUE}[-] Updating and upgrading Kali Linux...${RESET}"
export DEBIAN_FRONTEND=noninteractive
sudo apt-mark hold python3 python3-dev python3-pip
sudo apt update -y > /dev/null 2>&1
sudo apt full-upgrade -y --allow-downgrades -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" > /dev/null 2>&1


# Install essential dependencies
echo -e "${BLUE}[-] Installing core dependencies...${RESET}"
sudo apt install -y git python3 python3-pip

# Disable Firefox's password manager
echo -e "${BLUE}[-] Disabling Firefox password settings...${RESET}"
FIREFOX_PREFS="/usr/lib/firefox-esr/defaults/pref/autoconfig.js"
FIREFOX_CFG="/usr/lib/firefox-esr/firefox.cfg"

# Suppress output while ensuring preferences are set
if [ ! -f "$FIREFOX_PREFS" ]; then
    {
        echo 'pref("general.config.filename", "firefox.cfg");'
        echo 'pref("general.config.obscure_value", 0);'
    } | sudo tee "$FIREFOX_PREFS" > /dev/null 2>&1
fi

# Write the Firefox config silently
sudo tee "$FIREFOX_CFG" > /dev/null 2>&1 <<EOF
// Firefox Configuration File
lockPref("signon.rememberSignons", false);
lockPref("network.cookie.lifetimePolicy", 2);
lockPref("browser.privatebrowsing.autostart", true);
EOF

echo -e "${GREEN}[+] Firefox password manager has been disabled.${RESET}"

# Verify tools directory structure
echo -e "${BLUE}[-] Setting up tools directories...${RESET}"
TOOLS_DIR="$HOME/client/tools"
TOOLS_WORKING_DIR="$HOME/tools"

mkdir -p "$TOOLS_DIR"
mkdir -p "$TOOLS_WORKING_DIR"

# Clone setup scripts from Git repository
echo -e "${BLUE}[-] Downloading setup scripts from Git repository...${RESET}"
SETUP_REPO="$TOOLS_WORKING_DIR/setup"
if [ ! -d "$SETUP_REPO" ]; then
    git clone https://github.com/Lokii-git/setup.git "$SETUP_REPO" > /dev/null 2>&1
else
    echo -e "${BLUE}[-] Repository already exists. Updating...${RESET}"
    git -C "$SETUP_REPO" pull > /dev/null 2>&1
fi

# Move setup scripts and clean up
if [ -d "$SETUP_REPO" ]; then
    mv "$SETUP_REPO"/* "$TOOLS_WORKING_DIR/"
    
    # Apply execute permissions to all .sh scripts
    find "$TOOLS_WORKING_DIR" -type f -name "*.sh" -exec chmod +x {} \;

    # Remove the setup repo folder
    rm -rf "$SETUP_REPO"
    echo -e "${GREEN}[+] Setup scripts moved, permissions set, and cleanup completed.${RESET}"
fi

# Install common penetration testing tools
echo -e "${BLUE}[-] Installing common penetration testing tools...${RESET}"
TOOLS=(
    nmap gobuster ffuf amass nuclei responder bloodhound neo4j
    impacket-scripts netexec enum4linux smbclient ldap-utils seclists
    evil-winrm proxychains4 tmux
)

# Ensure the package list is up to date
sudo apt update -y > /dev/null 2>&1

# Install tools, suppressing output but showing errors if they occur
if sudo apt install -y "${TOOLS[@]}" > /dev/null 2>&1; then
    echo -e "${GREEN}[+] Common penetration testing tools installed successfully.${RESET}"
else
    echo -e "${RED}[!] Failed to install some penetration testing tools! Check apt logs.${RESET}"
fi

# Upgrade pipx and pip while bypassing SSL errors temporarily
echo -e "${BLUE}[-] Installing pipx and upgrading pip...${RESET}"
python3 -m ensurepip --default-pip > /dev/null 2>&1

if pipx install pip --pip-args="--trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org" > /dev/null 2>&1; then
    echo -e "${GREEN}[+] pip installed successfully via pipx.${RESET}"
else
    echo -e "${RED}[!] Failed to install pip via pipx. Check your network and SSL settings.${RESET}"
fi

pipx upgrade-all > /dev/null 2>&1

# Install Default-HTTP-Login-Hunter
echo -e "${BLUE}[-] Installing Default-HTTP-Login-Hunter from GitHub...${RESET}"
if ! command -v default-http-login-hunter &>/dev/null; then
    sudo apt update > /dev/null 2>&1
    sudo apt install -y git python3-venv > /dev/null 2>&1

    # Clone Default-HTTP-Login-Hunter and check if it succeeds
    if sudo git clone https://github.com/InfosecMatter/default-http-login-hunter.git /opt/default-http-login-hunter > /dev/null 2>&1; then
        python3 -m venv /opt/default-http-login-hunter/venv
        /opt/default-http-login-hunter/venv/bin/pip install -r /opt/default-http-login-hunter/requirements.txt > /dev/null 2>&1
        
        # Ensure script is executable
        sudo chmod +x /opt/default-http-login-hunter/default-http-login-hunter.sh

        # Create symlink for easier access
        sudo ln -sf /opt/default-http-login-hunter/default-http-login-hunter.sh /usr/bin/default-http-login-hunter

        # Run fingerprint update
        echo -e "${BLUE}[-] Updating Default-HTTP-Login-Hunter fingerprints...${RESET}"
        /opt/default-http-login-hunter/default-http-login-hunter.sh update > /dev/null 2>&1

        echo -e "${GREEN}[+] Default-HTTP-Login-Hunter installed and updated successfully.${RESET}"
    else
        echo -e "${RED}[!] Failed to clone Default-HTTP-Login-Hunter. Check your SSL settings.${RESET}"
    fi
else
    echo -e "${GREEN}[+] Default-HTTP-Login-Hunter is already installed.${RESET}"
    
    # Ensure script is executable before updating
    sudo chmod +x /opt/default-http-login-hunter/default-http-login-hunter.sh

    # Ensure fingerprints are up to date
    echo -e "${BLUE}[-] Updating Default-HTTP-Login-Hunter fingerprints...${RESET}"
    /opt/default-http-login-hunter/default-http-login-hunter.sh update > /dev/null 2>&1
    echo -e "${GREEN}[+] Fingerprints updated successfully.${RESET}"
fi

# Install Certipy
echo -e "${BLUE}[-] Installing Certipy from GitHub...${RESET}"
if ! command -v certipy &>/dev/null; then
    sudo apt update > /dev/null 2>&1
    sudo apt install -y git python3-venv > /dev/null 2>&1

    # Clone Certipy and check if it succeeds
    if sudo git clone https://github.com/ly4k/Certipy.git /opt/certipy > /dev/null 2>&1; then
        python3 -m venv /opt/certipy/venv
        /opt/certipy/venv/bin/pip install /opt/certipy > /dev/null 2>&1

        # Create symlink for easy execution
        sudo ln -sf /opt/certipy/venv/bin/certipy /usr/bin/certipy

        echo -e "${GREEN}[+] Certipy installed successfully from GitHub.${RESET}"
    else
        echo -e "${RED}[!] Failed to clone Certipy. Check your SSL settings.${RESET}"
    fi
else
    echo -e "${GREEN}[+] Certipy is already installed.${RESET}"
fi

# Install Kerbrute
echo -e "${BLUE}[-] Installing Kerbrute...${RESET}"
if ! command -v kerbrute &>/dev/null; then
    wget --no-check-certificate --quiet -O kerbrute https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64
    if [ -f "kerbrute" ]; then
        chmod +x kerbrute > /dev/null 2>&1
        sudo mv kerbrute /usr/local/bin/kerbrute > /dev/null 2>&1
        echo -e "${GREEN}[+] Kerbrute installed successfully!${RESET}"
    else
        echo -e "${RED}[!] Failed to download Kerbrute. Check your network connection.${RESET}"
    fi
else
    echo -e "${GREEN}[+] Kerbrute is already installed.${RESET}"
fi

# Install Docker
echo -e "${BLUE}[-] Installing Docker...${RESET}"
if ! command -v docker &>/dev/null; then
    if sudo apt install -y docker.io > /dev/null 2>&1; then
        sudo systemctl enable --now docker > /dev/null 2>&1
        sudo usermod -aG docker "$USER" > /dev/null 2>&1
        echo -e "${GREEN}[+] Docker installed successfully.${RESET}"
    else
        echo -e "${RED}[!] Docker installation failed. Check your package sources and network connection.${RESET}"
    fi
else
    echo -e "${GREEN}[+] Docker is already installed.${RESET}"
fi


# Install RustScan via Docker
echo -e "${BLUE}[-] Installing RustScan using Docker...${RESET}"
if ! docker images | grep -q "rustscan"; then
    if docker pull rustscan/rustscan:latest > /dev/null 2>&1; then
        echo -e "${GREEN}[+] RustScan Docker image downloaded successfully!${RESET}"
    else
        echo -e "${RED}[!] Failed to download RustScan. Check your Docker setup and network connection.${RESET}"
    fi
else
    echo -e "${GREEN}[+] RustScan Docker image already exists.${RESET}"
fi

# Define shared folder path
SHARED_RUSTSCAN_DIR="$HOME/rustscan" 

# Ensure the shared folder exists
if [ ! -d "$SHARED_RUSTSCAN_DIR" ]; then
    mkdir -p "$SHARED_RUSTSCAN_DIR"
    chmod 777 "$SHARED_RUSTSCAN_DIR" > /dev/null 2>&1
    echo -e "${GREEN}[+] Created shared RustScan directory: $SHARED_RUSTSCAN_DIR ${RESET}"
fi

# Add RustScan aliases
echo -e "${BLUE}[-] Creating RustScan aliases...${RESET}"

# Add RustScan alias for single IP scanning
grep -q "alias rustscan=" "$HOME/.bashrc" || echo 'alias rustscan="docker run -it --rm --name rustscan --network host -v $HOME/rustscan:/rustscan rustscan/rustscan:latest"' >> "$HOME/.bashrc"
echo -e "${GREEN}[+] RustScan alias added to ~/.bashrc${RESET}"

# Add RustScan alias for scanning from an IP list file in the shared folder
grep -q "alias rustscan-file=" "$HOME/.bashrc" || echo 'alias rustscan-file="docker run -it --rm --name rustscan --network host -v $HOME/rustscan:/rustscan rustscan/rustscan:latest -iL /rustscan/iplist.txt -o /rustscan/rustscan_output.txt"' >> "$HOME/.bashrc"
echo -e "${GREEN}[+] RustScan file scan alias added to ~/.bashrc${RESET}"

# Apply aliases immediately for the current session
alias rustscan="docker run -it --rm --name rustscan --network host -v $HOME/rustscan:/rustscan rustscan/rustscan:latest" 
alias rustscan-file="docker run -it --rm --name rustscan --network host -v $HOME/rustscan:/rustscan rustscan/rustscan:latest -iL /rustscan/iplist.txt -o /rustscan/rustscan_output.txt"

# Inform the user
echo -e "${GREEN}[+] RustScan has been installed via Docker!${RESET}"
echo -e "${YELLOW}[/] A shared folder has been created at:${RESET} ${BLUE}$SHARED_RUSTSCAN_DIR${RESET}"
echo -e "${YELLOW}[/] To use RustScan with an IP list, place your file inside this folder as:${RESET} ${BLUE}iplist.txt${RESET}"
echo -e "    ${GREEN}rustscan-file${RESET}"
echo -e "${YELLOW}[/] Scan results will also be saved in this folder.${RESET}"
echo -e "${RED}[!] If the alias doesn't work immediately, restart your terminal or run:${RESET} ${BLUE}source ~/.bashrc${RESET}"

# Install NetExec (Replacement for CrackMapExec)
echo -e "${BLUE}[-] Installing NetExec...${RESET}"
if ! command -v netexec &>/dev/null; then
    sudo apt update > /dev/null 2>&1
    sudo apt install -y git python3-venv python3-pip > /dev/null 2>&1

    # Remove old NetExec installation if it exists
    if [ -d "/opt/netexec" ]; then
        sudo rm -rf /opt/netexec
    fi

    # Clone NetExec and check if it succeeds
    if sudo git clone https://github.com/Pennyw0rth/NetExec.git /opt/netexec > /dev/null 2>&1; then
        if sudo python3 -m pip install /opt/netexec/. > /dev/null 2>&1; then
            # Ensure NetExec is accessible from anywhere
            sudo ln -sf /opt/netexec/netexec.py /usr/local/bin/netexec
            sudo chmod +x /usr/local/bin/netexec

            # Check if the symlink was created successfully
            if [ -L "/usr/local/bin/netexec" ]; then
                echo -e "${GREEN}[+] NetExec installed and symlinked successfully!${RESET}"
            else
                echo -e "${RED}[!] Failed to create symlink for NetExec.${RESET}"
            fi
        else
            echo -e "${RED}[!] Failed to install NetExec. Check Python and Pip dependencies.${RESET}"
        fi
    else
        echo -e "${RED}[!] Failed to clone NetExec. Check your network connection and GitHub availability.${RESET}"
    fi
else
    echo -e "${GREEN}[+] NetExec is already installed.${RESET}"
fi


# Install latest Impacket
echo -e "${BLUE}[-] Installing Impacket...${RESET}"
if ! python3 -c "import impacket" &>/dev/null; then
    sudo apt update > /dev/null 2>&1
    sudo apt install -y git python3-pip > /dev/null 2>&1

    # Remove old Impacket installation if it exists
    if [ -d "/opt/impacket" ]; then
        sudo rm -rf /opt/impacket
    fi

    # Clone Impacket and check if it succeeds
    if sudo git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket > /dev/null 2>&1; then
        if sudo python3 -m pip install /opt/impacket/. > /dev/null 2>&1; then
            echo -e "${GREEN}[+] Impacket installed successfully!${RESET}"

            # Ensure Impacket scripts are available in PATH
            sudo ln -sf /opt/impacket/examples /usr/local/bin/impacket-scripts
            sudo chmod -R +x /usr/local/bin/impacket-scripts

            # Check if the symlink was created successfully
            if [ -L "/usr/local/bin/impacket-scripts" ]; then
                echo -e "${GREEN}[+] Impacket scripts symlinked to: ${BLUE}/usr/local/bin/impacket-scripts${RESET}"

            else
                echo -e "${RED}[!] Failed to create symlink for Impacket scripts.${RESET}"
            fi
        else
            echo -e "${RED}[!] Failed to install Impacket. Check Python and Pip dependencies.${RESET}"
        fi
    else
        echo -e "${RED}[!] Failed to clone Impacket. Check your network connection and GitHub availability.${RESET}"
    fi
else
    echo -e "${GREEN}[+] Impacket is already installed.${RESET}"
fi


# Create shortcut to Responder logs
echo -e "${BLUE}[-] Creating shortcut to Responder logs...${RESET}"
RESPONDER_LOGS_DIR="/usr/share/responder/logs"
LINK_NAME="$HOME/tools/responder_logs"

# Ensure the tools directory exists
mkdir -p "$HOME/tools"

# Check if the target Responder logs directory exists before creating a symlink
if [ -d "$RESPONDER_LOGS_DIR" ]; then
    if [ -L "$LINK_NAME" ] && [ "$(readlink -f "$LINK_NAME")" == "$RESPONDER_LOGS_DIR" ]; then
        echo -e "${GREEN}[+] Responder logs symlink already exists.${RESET}"
    else
        # Remove any existing file or incorrect symlink
        if [ -e "$LINK_NAME" ]; then
            echo -e "${RED}[!] $LINK_NAME exists but is not a symlink. Removing and recreating...${RESET}"
            rm -rf "$LINK_NAME"
        fi
        
        # Create the symlink
        ln -s "$RESPONDER_LOGS_DIR" "$LINK_NAME"
        echo -e "${GREEN}[+] Symlink created: $LINK_NAME -> $RESPONDER_LOGS_DIR ${RESET}"
    fi
else
    echo -e "${RED}[!] Responder logs directory not found: $RESPONDER_LOGS_DIR. Ensure Responder is installed.${RESET}"
fi

# Set up custom Kali Linux Message of the Day (MOTD)
echo -e "${BLUE}[-] Configuring Kali Linux MOTD...${RESET}"

# Disable default update-motd scripts to prevent them from overriding our custom MOTD
sudo chmod -x /etc/update-motd.d/* > /dev/null 2>&1

# Store the MOTD content in a variable
read -r -d '' MOTD_CONTENT << 'EOF'
_________ .__                                       __                
\_   ___ \|  |   ____ _____ _________  _  _______ _/  |_  ___________ 
/    \  \/|  | _/ __ \\__  \\_  __ \ \/ \/ /\__  \\   __\/ __ \_  __ \
\     \___|  |_\  ___/ / __ \|  | \/\     /  / __ \|  | \  ___/|  | \/
 \______  /____/\___  >____  /__|    \/\_/  (____  /__|  \___  >__|   
        \/          \/     \/                    \/          \/       
🚀 Pentesting Environment Ready! 🚀

📌 **RustScan Usage (via Docker)**
- Store target lists in: **$HOME/rustscan/**
- Run a single target scan:
  ➜  rustscan -a <TARGET_IP>
- Run a scan from a file:
  ➜  rustscan-file  (uses **$HOME/rustscan/iplist.txt**)
- Output saved to: **$HOME/rustscan/rustscan_output.txt**

📌 **Responder Logs**
- Logs are symlinked to: **$HOME/tools/responder_logs**
- View logs using:
  ➜  ls -l $HOME/tools/responder_logs

Happy Hacking! 😈
EOF

# Write MOTD without displaying it in the setup process
echo "$MOTD_CONTENT" | sudo tee /etc/motd > /dev/null
echo "$MOTD_CONTENT" | sudo tee /etc/update-motd.d/00-header > /dev/null
sudo chmod +x /etc/update-motd.d/00-header > /dev/null 2>&1

echo -e "${GREEN}[+] Custom MOTD applied successfully.${RESET}"

# Ensure SSH displays the MOTD on login
SSHD_CONFIG="/etc/ssh/sshd_config"

# Modify sshd_config to enable MOTD and SSH banner
echo -e "${BLUE}[-] Configuring SSH to display MOTD...${RESET}"

# Ensure PrintMotd is enabled
sudo sed -i 's/^PrintMotd no/PrintMotd yes/' "$SSHD_CONFIG"
grep -q "^PrintMotd" "$SSHD_CONFIG" || echo "PrintMotd yes" | sudo tee -a "$SSHD_CONFIG" > /dev/null

# Ensure SSH Banner is set correctly
sudo sed -i 's/^#Banner none/Banner \/etc\/motd/' "$SSHD_CONFIG"
grep -q "^Banner /etc/motd" "$SSHD_CONFIG" || echo "Banner /etc/motd" | sudo tee -a "$SSHD_CONFIG" > /dev/null

# Ensure PAM settings allow MOTD display
PAM_SSHD="/etc/pam.d/sshd"
if ! grep -q "pam_motd.so" "$PAM_SSHD"; then
    echo -e "${YELLOW}[/] Enabling MOTD in PAM settings...${RESET}"
    {
        echo "session optional pam_motd.so motd=/run/motd.dynamic"
        echo "session optional pam_motd.so noupdate"
    } | sudo tee -a "$PAM_SSHD" > /dev/null
fi

# Restart SSH service to apply changes
echo -e "${YELLOW}[/] Restarting SSH service...${RESET}"
sudo systemctl restart ssh
echo -e "${GREEN}[+] SSH is now configured to display the MOTD!${RESET}"

# Prompt for reboot (skip if running in a test mode)
if [[ "$1" != "--no-reboot" && "$NEEDS_REBOOT" == true ]]; then
    echo -e "${GREEN}[+] Initial setup completed successfully. Your environment is ready for penetration testing.${RESET}"
    echo -e "${YELLOW}[!] You must log out and back in for Docker group changes to take effect.${RESET}"
    read -p "[!] A reboot is recommended to apply changes. Reboot now? (y/n): " REBOOT
    if [[ "$REBOOT" == "y" || "$REBOOT" == "Y" ]]; then
        echo -e "${RED}[!] Rebooting system...${RESET}"
        sudo reboot
    else
        echo -e "${YELLOW}[/] Reboot skipped. Please reboot manually when convenient.${RESET}"
    fi
fi

