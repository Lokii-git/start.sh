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
cat << "EOF"
_________ .__                                       __                
\_   ___ \|  |   ____ _____ _________  _  _______ _/  |_  ___________ 
/    \  \/|  | _/ __ \\__  \\_  __ \ \/ \/ /\__  \\   __\/ __ \_  __ \
\     \___|  |_\  ___/ / __ \|  | \/\     /  / __ \|  | \  ___/|  | \/
 \______  /____/\___  >____  /__|    \/\_/  (____  /__|  \___  >__|   
        \/          \/     \/                    \/          \/       
EOF
echo -e "${BLUE}========================================================${RESET}"
echo -e "🚀 ${YELLOW}Kali Linux Internal Pentesting Setup Script v1.7.2${RESET} 🚀"
echo -e "${BLUE}========================================================${RESET}"

# Ensure CA certificates are up to date
echo -e "${BLUE}[-] Updating CA certificates...${RESET}"
sudo apt update && sudo apt install --reinstall -y ca-certificates > /dev/null 2>&1
sudo update-ca-certificates > /dev/null 2>&1

# Set SSL_CERT_FILE explicitly for Python
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt > /dev/null 2>&1

# Ensure jq is installed
if ! command -v jq &>/dev/null; then
    echo -e "${YELLOW}[/] jq is not installed. Installing now...${RESET}"
    sudo apt update -y && sudo apt install -y jq
fi

# Define script update variables
SCRIPT_PATH="$(realpath "$0")"
REPO_URL="https://raw.githubusercontent.com/Lokii-git/start.sh/main/start.sh"
TMP_SCRIPT="/tmp/start.sh.tmp"

echo -e "${BLUE}[-] Checking for script updates...${RESET}"
wget --no-check-certificate -q -O /tmp/test_start.sh "$REPO_URL"

# Check if the script has changed
if ! cmp -s "$0" "/tmp/test_start.sh"; then
    echo -e "${YELLOW}[/] Update found! Creating updater...${RESET}"

    # Create the updater script
    cat << 'EOF' > /tmp/updater.sh
#!/bin/bash
echo "[-] Stopping old script..."
sleep 1

# Replace the old script
mv /tmp/test_start.sh "$SCRIPT_PATH"
chmod +x "$SCRIPT_PATH"

echo "[+] Update applied. Restarting..."
sleep 1

# Run the updated script
exec "$SCRIPT_PATH"
EOF

    # Make updater executable and run it
    chmod +x /tmp/updater.sh
    /tmp/updater.sh & disown

    echo -e "${GREEN}[+] Updater launched. Exiting old script.${RESET}"
    exit 0
else
    echo -e "${GREEN}[+] No update needed. Script is up to date.${RESET}"
    rm -f /tmp/test_start.sh
fi

# Check for SSL Inspection
detect_ssl_inspection() {
    local domain="$1"
    local output=$(echo | openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null | openssl x509 -noout -issuer -subject)
    if [[ "$output" =~ "SonicWall" || "$output" =~ "Fortinet" || "$output" =~ "Proxy" || "$output" =~ "self-signed" ]]; then
        echo -e "${RED}[!] SSL Inspection detected for $domain. Request support to disable it!${RESET}"
    else
        echo -e "${GREEN}[+] No SSL Inspection detected for $domain.${RESET}"
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
    echo -e "${YELLOW}[/] You will be logged out to apply changes. Rerun this script after logging back in.${RESET}"
    touch "$RESUME_FLAG"
    echo -e "${YELLOW}[/] Please log out and back in for Docker group changes to take effect.${RESET}"
else
    echo -e "${GREEN}[+] User already has Docker permissions.${RESET}"
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

# Install essential dependencies
echo -e "${BLUE}[-] Installing core dependencies...${RESET}"
sudo apt install -y git python3 python3-pip

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

# Clone and set up tools
echo -e "${BLUE}[-] Setting up pentesting tools...${RESET}"
TOOLS_DIR="$HOME/tools"
mkdir -p "$TOOLS_DIR"
cd "$TOOLS_DIR"

declare -A REPOS=(
    [kerbrute]="https://github.com/ropnop/kerbrute.git"
    [nmap]="https://github.com/nmap/nmap.git"
    [ffuf]="https://github.com/ffuf/ffuf.git"
)

for tool in "${!REPOS[@]}"; do
    if [ ! -d "$TOOLS_DIR/$tool" ]; then
        git clone --depth=1 "${REPOS[$tool]}" "$TOOLS_DIR/$tool"
        echo -e "${GREEN}[+] Installed $tool.${RESET}"
    else
        echo -e "${YELLOW}[/] $tool already exists. Pulling latest changes...${RESET}"
        git -C "$TOOLS_DIR/$tool" pull
    fi
done


#Upgrade pipx and pip while bypassing SSL errors temporarily
echo -e "${BLUE}[-] Installing pipx and upgrading pip...${RESET}"
python3 -m ensurepip --default-pip
pipx install pip --pip-args="--trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org"
pipx upgrade-all

#Install Certipy
echo -e "${BLUE}[-] Installing Certipy from GitHub...${RESET}"
if ! command -v certipy &>/dev/null; then
    sudo apt update && sudo apt install -y git python3-venv

    # Clone and install Certipy from GitHub
    sudo git -c http.sslVerify=false clone https://github.com/ly4k/Certipy.git /opt/certipy
    python3 -m venv /opt/certipy/venv
    /opt/certipy/venv/bin/pip install /opt/certipy

    # Create a global symlink so certipy is accessible system-wide
    sudo ln -sf /opt/certipy/venv/bin/certipy /usr/bin/certipy

    echo -e "${GREEN}[+] Certipy installed successfully from GitHub.${RESET}"
else
    echo -e "${GREEN}[+] Certipy is already installed.${RESET}"
fi

# Install Kerbrute
echo -e "${BLUE}[-] Installing Kerbrute...${RESET}"
if ! command -v kerbrute &>/dev/null; then
    wget --no-check-certificate --quiet -O kerbrute https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64
if [ -f "kerbrute" ]; then > /dev/null 2>&1
        chmod +x kerbrute > /dev/null 2>&1
    sudo mv kerbrute /usr/local/bin/kerbrute > /dev/null 2>&1
    echo -e "${GREEN}[+] Kerbrute installed successfully!${RESET}"
else
    echo -e "${RED}[!] Failed to download Kerbrute.${RESET}"
fi

# Install Docker
echo -e "${BLUE}[-] Installing Docker...${RESET}"
if ! command -v docker &>/dev/null; then
    sudo apt install -y docker.io > /dev/null 2>&1
    sudo systemctl enable --now docker > /dev/null 2>&1
    sudo usermod -aG docker "$USER" > /dev/null 2>&1

    echo -e "${GREEN}[+] Docker installed successfully.${RESET}"
else
    echo -e "${GREEN}[+] Docker is already installed.${RESET}"
fi

# Install RustScan via Docker
echo -e "${BLUE}[-] Installing RustScan using Docker...${RESET}"
if ! docker images | grep -q "rustscan"; then
    docker pull rustscan/rustscan:latest > 
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
chmod 777 "$SHARED_RUSTSCAN_DIR" > 

# Add RustScan alias for single IP scanning
echo -e "${BLUE}[-] Creating RustScan aliases...${RESET}"

# Remove existing RustScan aliases if they exist
sed -i '/alias rustscan/d' "$HOME/.bashrc"
sed -i '/alias rustscan-file/d' "$HOME/.bashrc"

# Add RustScan alias for single IP scanning
echo 'alias rustscan="docker run -it --rm --name rustscan --network host -v $HOME/rustscan:/rustscan rustscan/rustscan:latest"' >> "$HOME/.bashrc"
echo -e "${GREEN}[+] RustScan alias added to ~/.bashrc${RESET}"

# Add RustScan alias for scanning from an IP list file in the shared folder
echo 'alias rustscan-file="docker run -it --rm --name rustscan --network host -v $HOME/rustscan:/rustscan rustscan/rustscan:latest -iL /rustscan/iplist.txt -o /rustscan/rustscan_output.txt"' >> "$HOME/.bashrc"
echo -e "${GREEN}[+] RustScan file scan alias added to ~/.bashrc${RESET}"

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
    #sudo rm -rf /opt/netexec
    sudo git -c http.sslVerify=false clone https://github.com/Pennyw0rth/NetExec.git /opt/netexec 
    sudo python3 -m pip install /opt/netexec/. 
    echo -e "${GREEN}[+] NetExec installed successfully!${RESET}"
else
    echo -e "${GREEN}[+] NetExec is already installed.${RESET}"
fi

# Install latest Impacket
echo -e "${BLUE}[-] Installing Impacket...${RESET}"
if ! python3 -c "import impacket" &>/dev/null; then
    sudo git -c http.sslVerify=false clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket > /dev/null 2>&1
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
sudo chmod -x /etc/update-motd.d/* > /dev/null 2>&1
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
sudo chmod +x /etc/update-motd.d/00-header > /dev/null 2>&1

echo -e "${GREEN}[+] Custom MOTD set for Kali Linux.${RESET}"

echo -e "${BLUE}[-] Ensuring SSH displays the MOTD on login...${RESET}"

# Modify /etc/ssh/sshd_config to enable MOTD
SSHD_CONFIG="/etc/ssh/sshd_config" > /dev/null 2>&1

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
    sudo sed -i 's/^#Banner none/Banner \/etc\/motd/' "$SSHD_CONFIG" > /dev/null 2>&1
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

SSHD_CONFIG="/etc/ssh/sshd_config" > /dev/null 2>&1

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
echo -e "${YELLOW}[/] Restarting SSH service...${RESET}"
sudo systemctl restart ssh > /dev/null 2>&1
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
