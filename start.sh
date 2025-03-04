#!/bin/bash
# Kali Linux Initial Setup Script for Pen Testing
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
echo -e "${BLUE}========================================="
echo -e "🚀 ${YELLOW}Kali Linux Pentesting Setup Script${RESET} 🚀"
echo -e "${BLUE}=========================================${RESET}"

# Define the GitHub repository and script path
REPO_URL="https://github.com/Lokii-git/start.sh"
LOCAL_SCRIPT="$0"
GITHUB_API_URL="https://api.github.com/repos/Lokii-git/start.sh/commits/main"

# Get the latest commit hash from GitHub
LATEST_COMMIT=$(curl -s $GITHUB_API_URL | jq -r '.sha')

# Path to store the last updated commit hash
UPDATE_CHECK_FILE="$HOME/.startsh_last_update"

# Get the last recorded commit hash (if exists)
if [ -f "$UPDATE_CHECK_FILE" ]; then
    LAST_COMMIT=$(cat "$UPDATE_CHECK_FILE")
else
    LAST_COMMIT=""
fi

# Check if an update is available
if [[ "$LATEST_COMMIT" != "$LAST_COMMIT" ]]; then
    echo "[+] Update found! Downloading the latest version..."
    
    # Download the latest script
    wget -O "$LOCAL_SCRIPT.tmp" "https://raw.githubusercontent.com/Lokii-git/start.sh/main/start.sh"

    # Ensure it was downloaded successfully
    if [ -s "$LOCAL_SCRIPT.tmp" ]; then
        chmod +x "$LOCAL_SCRIPT.tmp"
        
        # Replace the current script with the updated one
        mv "$LOCAL_SCRIPT.tmp" "$LOCAL_SCRIPT"
        
        # Store the new commit hash
        echo "$LATEST_COMMIT" > "$UPDATE_CHECK_FILE"

        echo "[+] Update applied. Restarting script..."
        exec "$LOCAL_SCRIPT" "$@"
    else
        echo "[!] Failed to download the update. Keeping the current version."
        rm -f "$LOCAL_SCRIPT.tmp"
    fi
else
    echo "[+] Script is up to date."
fi


# Define a resume flag to track re-login
RESUME_FLAG="$HOME/.docker_resume"

# Check if this is a resumed session after login
if [ -f "$RESUME_FLAG" ]; then
    echo "[+] Resuming script after re-login..."
    rm "$RESUME_FLAG"  # Remove flag to avoid infinite loops
else
    # Check if the user is in the Docker group
    if ! groups | grep -q "\bdocker\b"; then
        echo "[!] Your user is not in the Docker group. Adding now..."
        sudo usermod -aG docker "$USER"
        echo "[+] Added $USER to the 'docker' group."
        echo "[+] You will now be logged out to apply changes. Rerun the start.sh script after logging back in if autoresume fails."

        # Store a flag to resume the script after login
        touch "$RESUME_FLAG"

        # Automate logout (works for GUI, SSH, and TTY)
        gnome-session-quit --no-prompt &>/dev/null || \
        pkill -KILL -u "$USER" || \
        logout || \
        exit

        # The script stops here, and when the user logs back in, it will resume
    else
        echo "[+] User already has Docker permissions."
    fi
fi

echo "[+] Checking system hostname configuration..."

# Get the current hostname
CURRENT_HOSTNAME=$(hostname)

# Define the expected hostname (Kali default)
EXPECTED_HOSTNAME="kali"

# Ensure the hostname is set to "kali"
if [ "$CURRENT_HOSTNAME" != "$EXPECTED_HOSTNAME" ]; then
    echo "[!] System hostname is '$CURRENT_HOSTNAME' but should be '$EXPECTED_HOSTNAME'. Fixing now..."
    sudo hostnamectl set-hostname "$EXPECTED_HOSTNAME"
    echo "[+] Hostname set to '$EXPECTED_HOSTNAME'."
else
    echo "[+] Hostname is already correctly set to '$EXPECTED_HOSTNAME'."
fi

# Ensure /etc/hosts contains the correct hostname entry
if ! grep -q "127.0.1.1 $EXPECTED_HOSTNAME" /etc/hosts; then
    echo "[!] Missing hostname entry in /etc/hosts. Adding now..."
    echo "127.0.1.1 $EXPECTED_HOSTNAME" | sudo tee -a /etc/hosts
    echo "[+] Hostname entry added to /etc/hosts."
else
    echo "[+] /etc/hosts is correctly configured."
fi

# Update and upgrade Kali Linux
echo "[+] Updating and upgrading Kali Linux..."
sudo apt update -y && sudo apt full-upgrade -y
sudo apt autoremove -y && sudo apt autoclean -y

# Install essential dependencies
echo "[+] Installing core dependencies..."
sudo apt install -y git curl python3 python3-pip

# Disable Firefox's password manager
echo "[+] Disabling Firefox password settings..."
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

echo "[+] Firefox password manager has been disabled."

# Verify tools directory structure
echo "[+] Setting up tools directories..."
TOOLS_DIR="$HOME/client/tools"
TOOLS_WORKING_DIR="$HOME/tools"

mkdir -p "$TOOLS_DIR"
mkdir -p "$TOOLS_WORKING_DIR"

# Clone setup scripts from Git repository
echo "[+] Downloading setup scripts from Git repository..."
SETUP_REPO="$TOOLS_WORKING_DIR/setup"
if [ ! -d "$SETUP_REPO" ]; then
    git clone https://github.com/Lokii-git/setup.git "$SETUP_REPO"
else
    echo "[+] Repository already exists. Updating..."
    git -C "$SETUP_REPO" pull
fi

# Move setup scripts and clean up
if [ -d "$SETUP_REPO" ]; then
    mv "$SETUP_REPO"/* "$TOOLS_WORKING_DIR/"
    
    # Apply execute permissions to all .sh scripts
    find "$TOOLS_WORKING_DIR" -type f -name "*.sh" -exec chmod +x {} \;

    # Remove the setup repo folder
    rm -rf "$SETUP_REPO"
    echo "[+] Setup scripts moved, permissions set, and cleanup completed."
fi

# Install common penetration testing tools
echo "[+] Installing common penetration testing tools..."
TOOLS=(
    nmap gobuster ffuf amass nuclei responder bloodhound neo4j
    impacket-scripts netexec enum4linux smbclient ldap-utils seclists
    evil-winrm proxychains4 tmux
)

sudo apt install -y "${TOOLS[@]}"

# Install Certipy using pipx
echo "[+] Installing Certipy..."
if ! command -v certipy &>/dev/null; then
    sudo apt install -y pipx
    python3 -m pipx ensurepath
    pipx install certipy-ad
else
    echo "[+] Certipy is already installed."
fi

# Install Kerbrute
echo "[+] Installing Kerbrute..."
if ! command -v kerbrute &>/dev/null; then
    wget -O kerbrute https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64
    chmod +x kerbrute
    sudo mv kerbrute /usr/local/bin/kerbrute
    echo "[+] Kerbrute installed successfully!"
else
    echo "[+] Kerbrute is already installed."
fi

# Install Docker
echo "[+] Installing Docker..."
if ! command -v docker &>/dev/null; then
    sudo apt install -y docker.io
    sudo systemctl enable --now docker
    sudo usermod -aG docker "$USER"

    echo "[+] Docker installed successfully."
else
    echo "[+] Docker is already installed."
fi

# Install RustScan via Docker
echo "[+] Installing RustScan using Docker..."
if ! docker images | grep -q "rustscan"; then
    docker pull rustscan/rustscan:latest
    echo "[+] RustScan Docker image downloaded successfully!"
else
    echo "[+] RustScan Docker image already exists."
fi

# Define shared folder path
SHARED_RUSTSCAN_DIR="$HOME/rustscan"

# Ensure the shared folder exists
if [ ! -d "$SHARED_RUSTSCAN_DIR" ]; then
    mkdir -p "$SHARED_RUSTSCAN_DIR"
    echo "[+] Created shared RustScan directory: $SHARED_RUSTSCAN_DIR"
fi

# Set correct permissions so Docker can access it
chmod 777 "$SHARED_RUSTSCAN_DIR"

# Add RustScan alias for single IP scanning
echo "[+] Creating RustScan aliases..."
if ! grep -q "alias rustscan=" "$HOME/.bashrc"; then
    echo 'alias rustscan="docker run -it --rm --name rustscan --network host -v $HOME/rustscan:/rustscan rustscan/rustscan:latest"' >> "$HOME/.bashrc"
    echo "[+] RustScan alias added to ~/.bashrc"
else
    echo "[+] RustScan alias already exists in ~/.bashrc"
fi

# Add RustScan alias for scanning from an IP list file in the shared folder
if ! grep -q "alias rustscan-file=" "$HOME/.bashrc"; then
    echo 'alias rustscan-file="docker run -it --rm --name rustscan --network host -v $HOME/rustscan:/rustscan rustscan/rustscan:latest -iL /rustscan/iplist.txt -o /rustscan/rustscan_output.txt"' >> "$HOME/.bashrc"
    echo "[+] RustScan file scan alias added to ~/.bashrc"
else
    echo "[+] RustScan file scan alias already exists in ~/.bashrc"
fi

# Apply aliases immediately for the current session
alias rustscan="docker run -it --rm --name rustscan --network host -v $HOME/rustscan:/rustscan rustscan/rustscan:latest"
alias rustscan-file="docker run -it --rm --name rustscan --network host -v $HOME/rustscan:/rustscan rustscan/rustscan:latest -iL /rustscan/iplist.txt -o /rustscan/rustscan_output.txt"

# Inform the user
echo "[+] RustScan has been installed via Docker!"
echo "[+] A shared folder has been created at: $SHARED_RUSTSCAN_DIR"
echo "[+] Place your IP list inside this folder as 'iplist.txt' before running:"
echo "    rustscan-file"
echo "[+] RustScan outputs will also be saved inside this folder."
echo "[!] If the alias doesn't work immediately, restart your terminal or run: source ~/.bashrc"

# Install NetExec (Replacement for CrackMapExec)
echo "[+] Installing NetExec..."
if ! command -v netexec &>/dev/null; then
    sudo rm -rf /opt/netexec
    sudo git clone https://github.com/Pennyw0rth/NetExec.git /opt/netexec
    sudo python3 -m pip install /opt/netexec/.
    echo "[+] NetExec installed successfully!"
else
    echo "[+] NetExec is already installed."
fi

# Install latest Impacket
echo "[+] Installing Impacket..."
if ! python3 -c "import impacket" &>/dev/null; then
    sudo git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket
    sudo python3 -m pip install /opt/impacket/.
else
    echo "[+] Impacket is already installed."
fi

# Create shortcut to Responder logs
echo "[+] Creating shortcut to Responder logs..."
RESPONDER_LOGS_DIR="/usr/share/responder/logs"
LINK_NAME="$HOME/tools/responder_logs"

mkdir -p "$HOME/tools"

if [ -L "$LINK_NAME" ] && [ "$(readlink -f "$LINK_NAME")" == "$RESPONDER_LOGS_DIR" ]; then
    echo "[+] Responder logs symlink already exists."
elif [ -e "$LINK_NAME" ]; then
    echo "[!] $LINK_NAME exists but is not a symlink. Removing and recreating..."
    rm -rf "$LINK_NAME"
    ln -s "$RESPONDER_LOGS_DIR" "$LINK_NAME"
    echo "[+] Symlink created: $LINK_NAME -> $RESPONDER_LOGS_DIR"
else
    ln -s "$RESPONDER_LOGS_DIR" "$LINK_NAME"
    echo "[+] Symlink created: $LINK_NAME -> $RESPONDER_LOGS_DIR"
fi

# Set up custom Kali Linux Message of the Day (MOTD)
echo "[+] Setting up Kali Linux login message..."
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

echo "[+] Custom MOTD set for Kali Linux."

echo "[+] Ensuring SSH displays the MOTD on login..."

# Modify /etc/ssh/sshd_config to enable MOTD
SSHD_CONFIG="/etc/ssh/sshd_config"

# Ensure PrintMotd is enabled
if grep -q "^PrintMotd no" "$SSHD_CONFIG"; then
    echo "[!] PrintMotd is set to 'no'. Fixing now..."
    sudo sed -i 's/^PrintMotd no/PrintMotd yes/' "$SSHD_CONFIG"
    echo "[+] Enabled PrintMotd in SSH config."
elif ! grep -q "^PrintMotd" "$SSHD_CONFIG"; then
    echo "[!] PrintMotd is missing. Adding it..."
    echo "PrintMotd yes" | sudo tee -a "$SSHD_CONFIG"
    echo "[+] Added PrintMotd to SSH config."
else
    echo "[+] PrintMotd is already correctly set to 'yes'."
fi

# Ensure SSH Banner is set to /etc/motd
if grep -q "^#Banner none" "$SSHD_CONFIG"; then
    echo "[!] Banner is disabled in SSH config. Fixing now..."
    sudo sed -i 's/^#Banner none/Banner \/etc\/motd/' "$SSHD_CONFIG"
    echo "[+] Enabled MOTD banner in SSH config."
elif ! grep -q "^Banner /etc/motd" "$SSHD_CONFIG"; then
    echo "[!] Banner is missing. Adding it..."
    echo "Banner /etc/motd" | sudo tee -a "$SSHD_CONFIG"
    echo "[+] Added Banner setting to SSH config."
else
    echo "[+] SSH Banner is already set correctly."
fi

# Ensure PAM settings allow MOTD display
PAM_SSHD="/etc/pam.d/sshd"
if ! grep -q "pam_motd.so" "$PAM_SSHD"; then
    echo "[!] PAM settings do not allow MOTD. Fixing now..."
    echo "session optional pam_motd.so motd=/run/motd.dynamic" | sudo tee -a "$PAM_SSHD"
    echo "session optional pam_motd.so noupdate" | sudo tee -a "$PAM_SSHD"
    echo "[+] Enabled MOTD in PAM settings."
else
    echo "[+] PAM settings already allow MOTD."
fi

echo "[+] Ensuring SSH always displays Kali's MOTD..."

SSHD_CONFIG="/etc/ssh/sshd_config"

# Ensure SSH always prints the MOTD
if ! grep -q "^PrintMotd yes" "$SSHD_CONFIG"; then
    echo "PrintMotd yes" | sudo tee -a "$SSHD_CONFIG"
    echo "[+] Enabled PrintMotd in SSH config."
fi

# Force SSH to use Kali’s MOTD and ignore MobaXterm's
if ! grep -q "^Banner /etc/motd" "$SSHD_CONFIG"; then
    echo "Banner /etc/motd" | sudo tee -a "$SSHD_CONFIG"
    echo "[+] Forced SSH to use Kali’s MOTD."
fi

# Restart SSH service to apply changes
sudo systemctl restart ssh
echo "[+] SSH is now configured to display only Kali's MOTD!"

echo "[+] Disabling MobaXterm’s ability to override MOTD..."

PAM_SSHD="/etc/pam.d/sshd"

# Remove any PAM motd updates that MobaXterm could trigger
sudo sed -i '/pam_motd.so/d' "$PAM_SSHD"

# Add a clean MOTD display setting
echo "session    required   pam_exec.so seteuid /bin/cat /etc/motd" | sudo tee -a "$PAM_SSHD"

# Restart SSH service to apply changes
echo "[+] Restarting SSH service..."
sudo systemctl restart ssh
echo "[+] SSH is now configured to display the MOTD!"

# Prompt for reboot (skip if running in a test mode)
if [[ "$1" != "--no-reboot" ]]; then
    echo "[+] Initial setup completed successfully. Your environment is ready for penetration testing."
    read -p "[!] A reboot is recommended to apply changes. Reboot now? (y/n): " REBOOT
    if [[ "$REBOOT" == "y" || "$REBOOT" == "Y" ]]; then
        echo "[+] Rebooting system..."
        sudo reboot
    else
        echo "[+] Reboot skipped. Please reboot manually when convenient."
    fi
fi
