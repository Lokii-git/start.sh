#!/bin/bash
# Kali Linux Initial Setup Script for Internal Pen Testing
# Author: Philip Burnham
# Purpose: Automates updates, upgrades, and essential tool installations.

set -e  # Exit on any error

# Define colors
GREEN='\e[32m'
RED='\e[31m'
BLUE='\e[34m'
YELLOW='\e[33m'
RESET='\e[0m'

# Define a resume flag to track re-login
RESUME_FLAG="$HOME/.docker_resume"

# Display Banner
echo -e "${BLUE}==================================================${RESET}"
echo -e "🚀 ${YELLOW}Kali Linux Internal Pentesting Setup Script${RESET} 🚀"
echo -e "${BLUE}==================================================${RESET}"

# Ensure jq is installed
if ! command -v jq &>/dev/null; then
    echo -e "${YELLOW}[/] jq is not installed. Installing now...${RESET}"
    sudo apt update -y && sudo apt install -y jq
fi

# Define the GitHub repository and script path
REPO_URL="https://github.com/Lokii-git/start.sh"
LOCAL_SCRIPT="$0"
GITHUB_API_URL="https://api.github.com/repos/Lokii-git/start.sh/commits/main"

# Get the latest commit hash from GitHub
GITHUB_API_URL="https://api.github.com/repos/Lokii-git/start.sh/commits?per_page=1"
LATEST_COMMIT=$(curl -s $GITHUB_API_URL | jq -r '.[0].sha')

# Path to store the last updated commit hash
UPDATE_CHECK_FILE="$HOME/.startsh_last_update"

# Get the last recorded commit hash (if exists)
if [ -f "$UPDATE_CHECK_FILE" ]; then
    LAST_COMMIT=$(cat "$UPDATE_CHECK_FILE")
else
    LAST_COMMIT=""
fi

# Bypass SSL verification for git
git config --global http.sslVerify false

# Check if an update is available
if [[ "$LATEST_COMMIT" != "$LAST_COMMIT" ]]; then
    echo -e "${BLUE}[-] Update found! Downloading the latest version...${RESET}"
    
    # Download the latest script
    curl -s -o "$LOCAL_SCRIPT.tmp" "https://raw.githubusercontent.com/Lokii-git/start.sh/main/start.sh"

    # Ensure it was downloaded successfully
    if grep -q "start.sh" "$LOCAL_SCRIPT.tmp"; then
        chmod +x "$LOCAL_SCRIPT.tmp"
        mv "$LOCAL_SCRIPT.tmp" "$LOCAL_SCRIPT"
        echo "$LATEST_COMMIT" > "$UPDATE_CHECK_FILE"
        echo -e "${GREEN}[+] Update applied. Restarting script...${RESET}"
        exec "$LOCAL_SCRIPT" "$@"
    else
        echo -e "${RED}[!] Failed to download the update. Keeping the current version.${RESET}"
        rm -f "$LOCAL_SCRIPT.tmp"
    fi

else
    echo -e "${GREEN}[+] Script is up to date.${RESET}"
fi


# Define a resume flag to track re-login
RESUME_FLAG="$HOME/.docker_resume"

# Check if this is a resumed session after login
if [ -f "$RESUME_FLAG" ]; then
    echo -e "${BLUE}[-] Resuming script after re-login...${RESET}"
    rm "$RESUME_FLAG"  # Remove flag to avoid infinite loops
else
    # Check if the user is in the Docker group
    if ! groups | grep -q "\bdocker\b"; then
        echo -e "${RED}[!] Your user is not in the Docker group. Adding now...${RESET}"
        sudo usermod -aG docker "$USER"
        echo -e "${GREEN}[+] Added $USER to the 'docker' group.${RESET}"
        echo -e "${YELLOW}[/] You will now be logged out to apply changes. Rerun the start.sh script after logging back in if autoresume fails.${RESET}"

        # Store a flag to resume the script after login
        touch "$RESUME_FLAG"

        # Automate logout (works for GUI, SSH, and TTY)
        gnome-session-quit --no-prompt &>/dev/null || \
        pkill -KILL -u "$USER" || \
        logout || \
        exit

        # The script stops here, and when the user logs back in, it will resume
    else
        echo -e "${GREEN}[+] User already has Docker permissions.${RESET}"
    fi
fi

echo -e "${BLUE}[-] Checking system hostname configuration...${RESET}"

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

# Update and upgrade Kali Linux
echo -e "${BLUE}[-] Updating and upgrading Kali Linux...${RESET}"
sudo apt update -y && sudo apt full-upgrade -y --allow-downgrades --allow-remove-essential --allow-change-held-packages
#sudo apt autoremove -y && sudo apt autoclean -y

# Install essential dependencies
echo -e "${BLUE}[-] Installing core dependencies...${RESET}"
sudo apt install -y git curl python3 python3-pip

# Disable Firefox's password manager
echo -e "${BLUE}[-] Disabling Firefox password settings...${RESET}"
FIREFOX_PREFS="/usr/lib/firefox-esr/defaults/pref/autoconfig.js"
FIREFOX_CFG="/usr/lib/firefox-esr/firefox.cfg"

if [ ! -f "$FIREFOX_PREFS" ]; then
    echo 'pref("general.config.filename", "firefox.cfg");' | sudo tee "$FIREFOX_PREFS"
    echo 'pref("general.config.obscure_value", 0);' | sudo tee -a "$FIREFOX_PREFS"
fi

cat <<EOF | sudo tee "$FIREFOX_CFG"
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
    git clone https://github.com/Lokii-git/setup.git "$SETUP_REPO"
else
    echo -e "${BLUE}[-] Repository already exists. Updating...${RESET}"
    git -C "$SETUP_REPO" pull
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

sudo apt install -y "${TOOLS[@]}"

# Ensure CA certificates are up to date
echo -e "${BLUE}[-] Updating CA certificates...${RESET}"
sudo apt update && sudo apt install --reinstall -y ca-certificates
sudo update-ca-certificates

# Set SSL_CERT_FILE explicitly for Python
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# Upgrade pipx and pip while bypassing SSL errors temporarily
echo -e "${BLUE}[-] Installing pipx and upgrading pip...${RESET}"
python3 -m ensurepip --default-pip
pipx install pip --pip-args="--trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org"
pipx upgrade-all

# Install Certipy
echo -e "${BLUE}[-] Installing Certipy from GitHub...${RESET}"

if ! command -v certipy &>/dev/null; then
    # Install dependencies
    sudo apt update && sudo apt install -y git python3 python3-pip python3-venv

    # Ensure pip is upgraded
    python3 -m pip install --upgrade pip setuptools wheel

    # Clone and install Certipy from GitHub
    sudo git clone https://github.com/ly4k/Certipy.git /opt/certipy
    python3 -m pip install /opt/certipy

    # Create a symbolic link to run Certipy from anywhere
    sudo ln -sf /usr/local/bin/certipy /usr/bin/certipy

    echo -e "${GREEN}[+] Certipy installed successfully from GitHub.${RESET}"
else
    echo -e "${GREEN}[+] Certipy is already installed.${RESET}"
fi



# Install Kerbrute
echo -e "${BLUE}[-] Installing Kerbrute...${RESET}"
if ! command -v kerbrute &>/dev/null; then
    wget -O kerbrute https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64
    chmod +x kerbrute
    sudo mv kerbrute /usr/local/bin/kerbrute
    echo -e "${GREEN}[+] Kerbrute installed successfully!${RESET}"
else
    echo -e "${GREEN}[+] Kerbrute is already installed.${RESET}"
fi

# Install Docker
echo -e "${BLUE}[-] Installing Docker...${RESET}"
if ! command -v docker &>/dev/null; then
    sudo apt install -y docker.io
    sudo systemctl enable --now docker
    sudo usermod -aG docker "$USER"

    echo -e "${GREEN}[+] Docker installed successfully.${RESET}"
else
    echo -e "${GREEN}[+] Docker is already installed.${RESET}"
fi

# Install RustScan via Docker
echo -e "${BLUE}[-] Installing RustScan using Docker...${RESET}"
if ! docker images | grep -q "rustscan"; then
    docker pull rustscan/rustscan:latest
    echo -e "${GREEN}[+] RustScan Docker image downloaded successfully!${RESET}"
else
    echo -e "${GREEN}[+] RustScan Docker image already exists.${RESET}"
fi

# Define shared folder path
SHARED_RUSTSCAN_DIR="$HOME/rustscan"

# Ensure the shared folder exists
if [ ! -d "$SHARED_RUSTSCAN_DIR" ]; then
    mkdir -p "$SHARED_RUSTSCAN_DIR"
    echo -e "${GREEN}[+] Created shared RustScan directory: $SHARED_RUSTSCAN_DIR ${RESET}"
fi

# Set correct permissions so Docker can access it
chmod 777 "$SHARED_RUSTSCAN_DIR"

# Add RustScan alias for single IP scanning
echo -e "${BLUE}[-] Creating RustScan aliases...${RESET}"
if ! grep -q "alias rustscan=" "$HOME/.bashrc"; then
    echo 'alias rustscan="docker run -it --rm --name rustscan --network host -v $HOME/rustscan:/rustscan rustscan/rustscan:latest"' >> "$HOME/.bashrc"
    echo -e "${GREEN}[+] RustScan alias added to ~/.bashrc${RESET}"
else
    echo -e "${GREEN}[+] RustScan alias already exists in ~/.bashrc${RESET}"
fi

# Add RustScan alias for scanning from an IP list file in the shared folder
if ! grep -q "alias rustscan-file=" "$HOME/.bashrc"; then
    echo 'alias rustscan-file="docker run -it --rm --name rustscan --network host -v $HOME/rustscan:/rustscan rustscan/rustscan:latest -iL /rustscan/iplist.txt -o /rustscan/rustscan_output.txt"' >> "$HOME/.bashrc"
    echo -e "${GREEN}[+] RustScan file scan alias added to ~/.bashrc${RESET}"
else
    echo -e "${GREEN}[+] RustScan file scan alias already exists in ~/.bashrc${RESET}"
fi

# Apply aliases immediately for the current session
alias rustscan="docker run -it --rm --name rustscan --network host -v $HOME/rustscan:/rustscan rustscan/rustscan:latest"
alias rustscan-file="docker run -it --rm --name rustscan --network host -v $HOME/rustscan:/rustscan rustscan/rustscan:latest -iL /rustscan/iplist.txt -o /rustscan/rustscan_output.txt"

# Inform the user
echo -e "${GREEN}[+] RustScan has been installed via Docker!${RESET}"
echo -e "${YELLOW}[/] A shared folder has been created at: $SHARED_RUSTSCAN_DIR ${RESET}"
echo -e "${YELLOW}[/] Place your IP list inside this folder as 'iplist.txt' before running:"
echo -e "    rustscan-file"
echo -e "${YELLOW}[/] RustScan outputs will also be saved inside this folder.${RESET}"
echo -e "${RED}[!] If the alias doesn't work immediately, restart your terminal or run: source ~/.bashrc${RESET}"

# Install NetExec (Replacement for CrackMapExec)
echo -e "${BLUE}[-] Installing NetExec...${RESET}"
if ! command -v netexec &>/dev/null; then
    sudo rm -rf /opt/netexec
    sudo git clone https://github.com/Pennyw0rth/NetExec.git /opt/netexec
    sudo python3 -m pip install /opt/netexec/.
    echo -e "${GREEN}[+] NetExec installed successfully!${RESET}"
else
    echo -e "${GREEN}[+] NetExec is already installed.${RESET}"
fi

# Install latest Impacket
echo -e "${BLUE}[-] Installing Impacket...${RESET}"
if ! python3 -c "import impacket" &>/dev/null; then
    sudo git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket
    sudo python3 -m pip install /opt/impacket/.
else
    echo -e "${GREEN}[+] Impacket is already installed.${RESET}"
fi

# Create shortcut to Responder logs
echo -e "${BLUE}[-] Creating shortcut to Responder logs...${RESET}"
RESPONDER_LOGS_DIR="/usr/share/responder/logs"
LINK_NAME="$HOME/tools/responder_logs"

mkdir -p "$HOME/tools"

if [ -L "$LINK_NAME" ] && [ "$(readlink -f "$LINK_NAME")" == "$RESPONDER_LOGS_DIR" ]; then
    echo -e "${GREEN}[+] Responder logs symlink already exists.${RESET}"
elif [ -e "$LINK_NAME" ]; then
    echo -e "${RED}[!] $LINK_NAME exists but is not a symlink. Removing and recreating...${RESET}"
    rm -rf "$LINK_NAME"
    ln -s "$RESPONDER_LOGS_DIR" "$LINK_NAME"
    echo -e "${GREEN}[+] Symlink created: $LINK_NAME -> $RESPONDER_LOGS_DIR ${RESET}"
else
    ln -s "$RESPONDER_LOGS_DIR" "$LINK_NAME"
    echo -e "${GREEN}[+] Symlink created: $LINK_NAME -> $RESPONDER_LOGS_DIR ${RESET}"
fi

# Set up custom Kali Linux Message of the Day (MOTD)
echo -e "${BLUE}[-] Setting up Kali Linux login message...${RESET}"
sudo chmod -x /etc/update-motd.d/*
MOTD_CONTENT='
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
'

# Write MOTD to the correct locations
echo "$MOTD_CONTENT" | sudo tee /etc/motd > /dev/null
echo "$MOTD_CONTENT" | sudo tee /etc/update-motd.d/00-header > /dev/null
sudo chmod +x /etc/update-motd.d/00-header

echo -e "${GREEN}[+] Custom MOTD set for Kali Linux.${RESET}"

echo -e "${BLUE}[-] Ensuring SSH displays the MOTD on login...${RESET}"

# Modify /etc/ssh/sshd_config to enable MOTD
SSHD_CONFIG="/etc/ssh/sshd_config"

# Ensure PrintMotd is enabled
if grep -q "^PrintMotd no" "$SSHD_CONFIG"; then
    echo -e "${RED}[!] PrintMotd is set to 'no'. Fixing now...${RESET}"
    sudo sed -i 's/^PrintMotd no/PrintMotd yes/' "$SSHD_CONFIG"
    echo -e "${GREEN}[+] Enabled PrintMotd in SSH config.${RESET}"
elif ! grep -q "^PrintMotd" "$SSHD_CONFIG"; then
    echo -e "${RED}[!] PrintMotd is missing. Adding it...${RESET}"
    echo "PrintMotd yes" | sudo tee -a "$SSHD_CONFIG"
    echo -e "${GREEN}[+] Added PrintMotd to SSH config.${RESET}"
else
    echo -e "${GREEN}[+] PrintMotd is already correctly set to 'yes'.${RESET}"
fi

# Ensure SSH Banner is set to /etc/motd
if grep -q "^#Banner none" "$SSHD_CONFIG"; then
    echo -e "${RED}[!] Banner is disabled in SSH config. Fixing now...${RESET}"
    sudo sed -i 's/^#Banner none/Banner \/etc\/motd/' "$SSHD_CONFIG"
    echo -e "${GREEN}[+] Enabled MOTD banner in SSH config.${RESET}"
elif ! grep -q "^Banner /etc/motd" "$SSHD_CONFIG"; then
    echo -e "${RED}[!] Banner is missing. Adding it...${RESET}"
    echo "Banner /etc/motd" | sudo tee -a "$SSHD_CONFIG"
    echo -e "${GREEN}[+] Added Banner setting to SSH config.${RESET}"
else
    echo -e "${GREEN}[+] SSH Banner is already set correctly.${RESET}"
fi

# Ensure PAM settings allow MOTD display
PAM_SSHD="/etc/pam.d/sshd"
if ! grep -q "pam_motd.so" "$PAM_SSHD"; then
    echo -e "${RED}[!] PAM settings do not allow MOTD. Fixing now...${RESET}"
    echo "session optional pam_motd.so motd=/run/motd.dynamic" | sudo tee -a "$PAM_SSHD"
    echo "session optional pam_motd.so noupdate" | sudo tee -a "$PAM_SSHD"
    echo -e "${GREEN}[+] Enabled MOTD in PAM settings.${RESET}"
else
    echo -e "${GREEN}[+] PAM settings already allow MOTD.${RESET}"
fi

echo -e "${BLUE}[-] Ensuring SSH always displays Kali's MOTD...${RESET}"

SSHD_CONFIG="/etc/ssh/sshd_config"

# Ensure SSH always prints the MOTD
if ! grep -q "^PrintMotd yes" "$SSHD_CONFIG"; then
    echo "PrintMotd yes" | sudo tee -a "$SSHD_CONFIG"
    echo -e "${GREEN}[+] Enabled PrintMotd in SSH config.${RESET}"
fi

# Force SSH to use Kali’s MOTD and ignore MobaXterm's
if ! grep -q "^Banner /etc/motd" "$SSHD_CONFIG"; then
    echo "Banner /etc/motd" | sudo tee -a "$SSHD_CONFIG"
    echo -e "${GREEN}[+] Forced SSH to use Kali’s MOTD.${RESET}"
fi

# Restart SSH service to apply changes
sudo systemctl restart ssh
echo -e "${GREEN}[+] SSH is now configured to display only Kali's MOTD!${RESET}"

# Restart SSH service to apply changes
echo -e "${YELLOW}[/] Restarting SSH service...${RESET}"
sudo systemctl restart ssh
echo -e "${GREEN}[+] SSH is now configured to display the MOTD!${RESET}"

# Prompt for reboot (skip if running in a test mode)
if [[ "$1" != "--no-reboot" ]]; then
    echo -e "${GREEN}[+] Initial setup completed successfully. Your environment is ready for penetration testing.${RESET}"
    read -p "[!] A reboot is recommended to apply changes. Reboot now? (y/n): " REBOOT
    if [[ "$REBOOT" == "y" || "$REBOOT" == "Y" ]]; then
        echo -e "${RED}[!] Rebooting system...${RESET}"
        sudo reboot
    else
        echo -e "${YELLOW}[/] Reboot skipped. Please reboot manually when convenient.${RESET}"
    fi
fi
