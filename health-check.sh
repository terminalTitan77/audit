#!/bin/bash

export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# ============================================================
#  COMPREHENSIVE SERVER SECURITY AUDIT SCRIPT
#  Covers: Threat Protection | Software Updates | Server Health
#          Backup | Software Life Time | Proactive Defence
#          + Vulnerability Patch Checks
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

REPORT_FILE="/tmp/server_audit_$(date +%Y%m%d_%H%M%S).txt"
RECOMMENDATIONS=()
WARNINGS=()
CRITICAL=()

log() { echo -e "$1" | tee -a "$REPORT_FILE"; }
section() { log "\n${BLUE}${BOLD}========== $1 ==========${NC}"; }
ok() { log "  ${GREEN}[✔] $1${NC}"; }
warn() { log "  ${YELLOW}[⚠] $1${NC}"; WARNINGS+=("$1"); }
crit() { log "  ${RED}[✘] $1${NC}"; CRITICAL+=("$1"); }
info() { log "  ${CYAN}[i] $1${NC}"; }
add_rec() { RECOMMENDATIONS+=("$1"); }

# ============================================================
# SECTION 0: EOL & OS DETECTION (original logic preserved)
# ============================================================

declare -A EOL_VERSIONS=(
    [centos]="6 7 8"
    [cloudlinux]="6 7"
    [debian]="6 7 8 9 10"
    [rocky]="7"
    [almalinux]="7"
)

AMAZON_LINUX_EOL_VERSIONS=(
    "2010.11" "2011.09" "2012.03" "2012.09" "2013.03" "2013.09"
    "2014.03" "2014.09" "2015.03" "2015.09" "2016.03" "2016.09"
    "2017.03" "2017.09" "2018.03"
)

UBUNTU_EOL_VERSIONS=(
    "14.04" "14.10" "15.04" "15.10" "16.04" "16.10" "17.04" "17.10"
    "18.04" "18.10" "19.04" "19.10" "20.04" "20.10" "21.04" "21.10"
    "22.10" "23.04" "23.10"
)

collect_os_cp_details() {
    OS_NAME=""
    OS_VERSION=""
    CONTROL_PANEL_NAME=""
    CONTROL_PANEL_VERSION=""

    if [ -f /etc/redhat-release ]; then
        if grep -iq "Rocky" /etc/redhat-release; then
            OS_NAME="rocky"
            OS_VERSION=$(awk '{print $4}' /etc/redhat-release)
        elif grep -iq "AlmaLinux" /etc/redhat-release; then
            OS_NAME="almalinux"
            OS_VERSION=$(awk '{for (i=1; i<=NF; i++) if ($i ~ /^[0-9]+\.[0-9]+$/) {print $i; break}}' /etc/redhat-release)
        else
            OS_NAME=$(awk '{print $1}' /etc/redhat-release)
            OS_VERSION=$(awk '{for (i=1; i<=NF; i++) if ($i ~ /^[0-9]+\.[0-9]+(\.[0-9]+)?$/) {print $i; break}}' /etc/redhat-release)
        fi
    elif [ -f /etc/lsb-release ]; then
        OS_NAME=$(awk -F"=" '/DISTRIB_ID/{print $2}' /etc/lsb-release)
        OS_VERSION=$(awk -F"=" '/DISTRIB_RELEASE/{print $2}' /etc/lsb-release)
    elif [ -f /etc/debian_version ]; then
        OS_NAME="debian"
        OS_VERSION=$(head -1 /etc/debian_version)
    elif [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME=${ID,,}
        OS_VERSION=${VERSION_ID}
    fi

    if [[ "$OS_NAME" == "amzn" ]]; then
        OS_NAME="amazon_linux"
    fi

    if [ -f /usr/local/psa/version ]; then
        CONTROL_PANEL_NAME="plesk"
        CONTROL_PANEL_VERSION=$(awk '{print $1}' /usr/local/psa/version | cut -d "." -f 1)
    elif [ -f /usr/local/cpanel/cpanel ]; then
        CONTROL_PANEL_NAME="cpanel"
        CONTROL_PANEL_VERSION=$(/usr/local/cpanel/cpanel -V 2>/dev/null | awk '{print $1}')
    elif [ -f /usr/local/directadmin/directadmin ]; then
        CONTROL_PANEL_NAME="directadmin"
    elif [ -f /usr/local/cwpsrv/htdocs/resources/admin/include/version.php ]; then
        CONTROL_PANEL_NAME="cwp"
    elif [ -f /usr/local/vesta/bin/v-list-sys-vesta-updates ]; then
        CONTROL_PANEL_NAME="vestacp"
    elif [ -f /usr/local/ispconfig/server/lib/config.inc.php ]; then
        CONTROL_PANEL_NAME="ispconfig"
    elif [ -d /usr/local/CyberCP ]; then
        CONTROL_PANEL_NAME="cyberpanel"
    elif [ -d /usr/libexec/webmin ]; then
        CONTROL_PANEL_NAME="webmin"
    elif [ -d /opt/bitnami ]; then
        CONTROL_PANEL_NAME="bitnami"
    elif [ -d /etc/pve ]; then
        CONTROL_PANEL_NAME="proxmox"
    elif [ -d /usr/local/solusvm ]; then
        CONTROL_PANEL_NAME="solusvm"
    elif [ -d /usr/local/virtualizor ]; then
        CONTROL_PANEL_NAME="virtualizor"
    elif [ -d /opt/zimbra ]; then
        CONTROL_PANEL_NAME="zimbra"
    elif [ -f /etc/ampinstmgr.conf ] && [ -d /home/amp/.ampdata ]; then
        CONTROL_PANEL_NAME="AMP - Game Server Control Panel"
    elif [ -d /www/server/panel ]; then
        CONTROL_PANEL_NAME="aapanel"
    elif [ -d /usr/local/hestia ] || [ -d /usr/local/vesta ]; then
        CONTROL_PANEL_NAME="hestia"
    elif [ -d /usr/local/webuzo ] || [ -d /usr/local/ampps ]; then
        CONTROL_PANEL_NAME="webuzo"
    elif [ -d /var/lib/ajenti ] || [ -d /etc/ajenti ]; then
        CONTROL_PANEL_NAME="ajenti"
    elif [ -d /home/interworx ] || [ -d /usr/local/interworx ]; then
        CONTROL_PANEL_NAME="interworx"
    elif [ -d /usr/share/webmin/virtual-server ]; then
        CONTROL_PANEL_NAME="virtualmin"
    elif [ -d /usr/local/mgr5 ]; then
        CONTROL_PANEL_NAME="ispmanager"
    elif [ -d /var/www/froxlor ] || [ -d /etc/froxlor ]; then
        CONTROL_PANEL_NAME="froxlor"
    elif [ -d /opt/RunCloud/rc-agent ]; then
        CONTROL_PANEL_NAME="runcloud"
    elif [ -d /usr/local/apnscp ]; then
        CONTROL_PANEL_NAME="apnscp"
    elif [ -d /var/local/enhance ]; then
        CONTROL_PANEL_NAME="enhance"
    elif [ -d /var/aegir ]; then
        CONTROL_PANEL_NAME="aegir"
    fi
}

detect_vm() {
    if command -v hostnamectl >/dev/null 2>&1 && hostnamectl | grep -iq "virtualization"; then
        VM_STATUS="Virtual Machine"
    else
        VM_STATUS="Physical Machine"
    fi
}

check_eol_status() {
    EOL_STATUS="Supported"
    OS_NAME_LOWER=$(echo "$OS_NAME" | tr '[:upper:]' '[:lower:]')

    if [[ "$OS_NAME_LOWER" == "ubuntu" ]]; then
        for eol_version in "${UBUNTU_EOL_VERSIONS[@]}"; do
            if [[ "$OS_VERSION" == "$eol_version" ]]; then
                EOL_STATUS="End of Life"
                break
            fi
        done
    elif [[ "$OS_NAME_LOWER" == "amazon_linux" ]]; then
        for eol_version in "${AMAZON_LINUX_EOL_VERSIONS[@]}"; do
            if [[ "$OS_VERSION" == "$eol_version" ]]; then
                EOL_STATUS="End of Life"
                break
            fi
        done
        if [[ "$OS_VERSION" == "2" ]]; then
            EOL_STATUS="Supported"
        fi
    elif [[ -n "${EOL_VERSIONS[$OS_NAME_LOWER]}" ]]; then
        OS_MAJOR_VERSION=$(echo "$OS_VERSION" | cut -d '.' -f 1)
        for eol_version in ${EOL_VERSIONS[$OS_NAME_LOWER]}; do
            if [[ "$OS_MAJOR_VERSION" == "$eol_version" ]]; then
                EOL_STATUS="End of Life"
                break
            fi
        done
    fi
}

check_firewalls() {
    local active_services=()
    local inactive_services=()
    local firewalls=("iptables" "firewalld" "csf" "apf" "bitninja" "ufw" "imunify360" "psa-firewall" "cphulk" "fail2ban")

    for fw in "${firewalls[@]}"; do
        case $fw in
            "iptables")
                if iptables -nL &>/dev/null; then active_services+=("iptables")
                elif command -v iptables &>/dev/null; then inactive_services+=("iptables"); fi ;;
            "firewalld")
                if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then active_services+=("firewalld")
                elif command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q firewalld; then inactive_services+=("firewalld"); fi ;;
            "csf")
                if csf -l &>/dev/null; then active_services+=("CSF")
                elif command -v csf &>/dev/null; then inactive_services+=("CSF"); fi ;;
            "apf")
                if apf -s &>/dev/null; then active_services+=("APF")
                elif command -v apf &>/dev/null; then inactive_services+=("APF"); fi ;;
            "bitninja")
                if command -v bitninjacli &>/dev/null && bitninjacli --module=System --status | grep -q "running"; then active_services+=("BitNinja")
                elif command -v bitninjacli &>/dev/null; then inactive_services+=("BitNinja"); fi ;;
            "ufw")
                if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then active_services+=("UFW")
                elif command -v ufw &>/dev/null; then inactive_services+=("UFW"); fi ;;
            "imunify360")
                if command -v imunify360-agent &>/dev/null && imunify360-agent ip-list local list --limit 100 &>/dev/null; then active_services+=("Imunify360")
                elif command -v imunify360-agent &>/dev/null; then inactive_services+=("Imunify360"); fi ;;
            "psa-firewall")
                if [ "$CONTROL_PANEL_NAME" = "plesk" ]; then
                    PLESK_FW_DB_STATUS=$(plesk db "SELECT status FROM Modules WHERE name='firewall'" 2>/dev/null | awk 'NR==4 {print $2}')
                    if [ "$PLESK_FW_DB_STATUS" = "true" ] && /usr/local/psa/bin/modules/firewall/settings --is-enabled >/dev/null 2>&1; then
                        active_services+=("Plesk_Firewall")
                    elif [ "$PLESK_FW_DB_STATUS" = "true" ]; then
                        inactive_services+=("Plesk_Firewall")
                    fi
                fi ;;
            "cphulk")
                if ps aux | grep -i cphulk | grep -vq grep; then active_services+=("cPHulk")
                elif [[ -f /usr/local/cpanel/scripts/cphulkdwhitelist ]]; then inactive_services+=("cPHulk"); fi ;;
            "fail2ban")
                if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet fail2ban 2>/dev/null; then active_services+=("Fail2Ban")
                elif command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q fail2ban; then inactive_services+=("Fail2Ban"); fi ;;
        esac
    done

    ACTIVE_FIREWALLS="${active_services[*]:-None}"
    INACTIVE_FIREWALLS="${inactive_services[*]:-None}"
}

get_ip_address() {
    if [ ! -f /tmp/main_ip.txt ]; then
        wget -q -O /tmp/main_ip.txt http://whatismyip.akamai.com 2>/dev/null
    fi
    MAIN_IP=$(cat /tmp/main_ip.txt 2>/dev/null || hostname -I | awk '{print $1}')
}

# ============================================================
# SECTION 1: THREAT PROTECTION
# ============================================================
audit_threat_protection() {
    section "THREAT PROTECTION"

    # --- System Firewall ---
    log "\n  ${BOLD}[1.1] System Firewall${NC}"
    if [[ "$ACTIVE_FIREWALLS" != "None" ]]; then
        ok "Active firewall(s) detected: $ACTIVE_FIREWALLS"
    else
        crit "No active firewall detected!"
        add_rec "CRITICAL: Enable a firewall immediately (UFW, firewalld, CSF, or iptables)."
    fi
    if [[ "$INACTIVE_FIREWALLS" != "None" ]]; then
        warn "Installed but inactive firewall(s): $INACTIVE_FIREWALLS"
        add_rec "Enable inactive firewalls or remove them if not needed: $INACTIVE_FIREWALLS"
    fi

    # --- Malware Scanner ---
    log "\n  ${BOLD}[1.2] Malware Scanner${NC}"
    MALWARE_SCANNER_FOUND=0
    for scanner in clamav clamd maldet imunify360-agent; do
        if command -v $scanner &>/dev/null || command -v clamscan &>/dev/null; then
            ok "Malware scanner found: $scanner"
            MALWARE_SCANNER_FOUND=1
            break
        fi
    done
    if command -v maldet &>/dev/null; then
        ok "Linux Malware Detect (maldet) installed"
        MALWARE_SCANNER_FOUND=1
    fi
    if [[ "$CONTROL_PANEL_NAME" == "cpanel" ]] && command -v imunify360-agent &>/dev/null; then
        ok "Imunify360 malware scanner present"
        MALWARE_SCANNER_FOUND=1
    fi
    if [[ $MALWARE_SCANNER_FOUND -eq 0 ]]; then
        warn "No malware scanner detected"
        add_rec "Install a malware scanner: ClamAV (clamscan), Linux Malware Detect (maldet), or Imunify360."
    fi

    # --- Failed Login Detection ---
    log "\n  ${BOLD}[1.3] Failed Login Detection${NC}"
    FAILED_LOGIN_DETECTED=0
    if echo "$ACTIVE_FIREWALLS" | grep -qi "fail2ban"; then
        ok "Fail2Ban is active (failed login detection enabled)"
        FAILED_LOGIN_DETECTED=1
    fi
    if echo "$ACTIVE_FIREWALLS" | grep -qi "cphulk"; then
        ok "cPHulk brute-force protection is active"
        FAILED_LOGIN_DETECTED=1
    fi
    if echo "$ACTIVE_FIREWALLS" | grep -qi "csf"; then
        ok "CSF login failure daemon (lfd) active"
        FAILED_LOGIN_DETECTED=1
    fi
    if command -v fail2ban-client &>/dev/null && systemctl is-active --quiet fail2ban 2>/dev/null; then
        ok "Fail2Ban service is running"
        FAILED_LOGIN_DETECTED=1
    fi
    # Check auth log for recent brute-force signs
    FAILED_SSH=$(grep "Failed password" /var/log/auth.log 2>/dev/null | wc -l || grep "Failed password" /var/log/secure 2>/dev/null | wc -l || echo 0)
    if [[ "$FAILED_SSH" -gt 100 ]]; then
        warn "High number of SSH failed login attempts detected: $FAILED_SSH"
        add_rec "High SSH brute-force activity ($FAILED_SSH failed attempts). Enable Fail2Ban and consider changing SSH port."
    elif [[ "$FAILED_SSH" -gt 0 ]]; then
        info "SSH failed login attempts in log: $FAILED_SSH"
    fi
    if [[ $FAILED_LOGIN_DETECTED -eq 0 ]]; then
        warn "No failed login protection detected (Fail2Ban / cPHulk / CSF-lfd)"
        add_rec "Install Fail2Ban to protect against brute-force SSH/FTP/HTTP attacks."
    fi

    # --- Web Application Firewall ---
    log "\n  ${BOLD}[1.4] Web Application Firewall (WAF)${NC}"
    WAF_FOUND=0
    if command -v modsec_vendor &>/dev/null || [ -f /etc/modsecurity/modsecurity.conf ] || [ -f /usr/local/apache/conf/modsec2.user.conf ]; then
        ok "ModSecurity WAF detected"
        WAF_FOUND=1
    fi
    if command -v imunify360-agent &>/dev/null; then
        ok "Imunify360 WAF present"
        WAF_FOUND=1
    fi
    if [ -d /etc/nginx/conf.d ] && grep -rq "ModSecurity" /etc/nginx/conf.d/ 2>/dev/null; then
        ok "ModSecurity WAF found in Nginx config"
        WAF_FOUND=1
    fi
    # Check for Cloudflare (via IP headers or CF-Ray)
    if [ -f /etc/nginx/nginx.conf ] && grep -q "cloudflare\|CF-Connecting-IP" /etc/nginx/nginx.conf 2>/dev/null; then
        ok "Cloudflare proxy detected (WAF coverage likely)"
        WAF_FOUND=1
    fi
    if [[ $WAF_FOUND -eq 0 ]]; then
        warn "No Web Application Firewall (WAF) detected"
        add_rec "Consider installing ModSecurity WAF or using Cloudflare/Imunify360 for web application protection."
    fi

    # --- Rootkit Scanner ---
    log "\n  ${BOLD}[1.5] Rootkit Scanner${NC}"
    ROOTKIT_FOUND=0
    if command -v rkhunter &>/dev/null; then
        ok "rkhunter (rootkit hunter) installed"
        ROOTKIT_FOUND=1
        # Check last run
        RKHUNTER_LOG=$(find /var/log -name "rkhunter.log" 2>/dev/null | head -1)
        if [ -n "$RKHUNTER_LOG" ]; then
            LAST_RUN=$(stat -c %y "$RKHUNTER_LOG" 2>/dev/null | cut -d' ' -f1)
            info "rkhunter last ran: $LAST_RUN"
        else
            warn "rkhunter installed but no log found — may not have been run recently"
            add_rec "Run rkhunter: rkhunter --check --sk and schedule it in cron."
        fi
    fi
    if command -v chkrootkit &>/dev/null; then
        ok "chkrootkit installed"
        ROOTKIT_FOUND=1
    fi
    if [[ $ROOTKIT_FOUND -eq 0 ]]; then
        warn "No rootkit scanner detected"
        add_rec "Install rkhunter or chkrootkit for rootkit detection."
    fi
}

# ============================================================
# SECTION 2: SOFTWARE UPDATES
# ============================================================
audit_software_updates() {
    section "SOFTWARE UPDATES"

    # --- Control Panel Updates ---
    log "\n  ${BOLD}[2.1] Control Panel Updates${NC}"
    if [[ "$CONTROL_PANEL_NAME" == "cpanel" ]]; then
        info "cPanel version: $CONTROL_PANEL_VERSION"
        CP_UPDATE=$(/usr/local/cpanel/scripts/upcp --check 2>/dev/null | head -5)
        if echo "$CP_UPDATE" | grep -qi "up to date\|no update"; then
            ok "cPanel is up to date"
        elif [ -n "$CP_UPDATE" ]; then
            warn "cPanel update may be available: $CP_UPDATE"
            add_rec "Update cPanel: /usr/local/cpanel/scripts/upcp"
        else
            info "Could not check cPanel update status automatically"
        fi
    elif [[ "$CONTROL_PANEL_NAME" == "plesk" ]]; then
        info "Plesk version: $CONTROL_PANEL_VERSION"
        if command -v plesk &>/dev/null; then
            PLESK_VER=$(plesk version 2>/dev/null | head -1)
            info "Plesk version details: $PLESK_VER"
        fi
    elif [[ -z "$CONTROL_PANEL_NAME" ]]; then
        info "No control panel detected (bare server)"
    else
        info "Control panel: $CONTROL_PANEL_NAME $CONTROL_PANEL_VERSION — manual update check required"
    fi

    # --- Operating System Updates ---
    log "\n  ${BOLD}[2.2] Operating System Updates${NC}"
    OS_NAME_LOWER=$(echo "$OS_NAME" | tr '[:upper:]' '[:lower:]')
    if command -v apt-get &>/dev/null; then
        apt-get update -qq 2>/dev/null
        PENDING=$(apt-get -s upgrade 2>/dev/null | grep "^[0-9]* upgraded" | awk '{print $1}')
        SECURITY_PENDING=$(apt-get -s upgrade 2>/dev/null | grep -i security | wc -l)
        if [[ "$PENDING" -eq 0 ]]; then
            ok "System packages are up to date"
        elif [[ "$PENDING" -gt 0 ]]; then
            warn "$PENDING package(s) pending update ($SECURITY_PENDING security-related)"
            add_rec "Run: apt-get upgrade -y to apply $PENDING pending OS updates ($SECURITY_PENDING security)."
        fi
    elif command -v yum &>/dev/null; then
        PENDING=$(yum check-update 2>/dev/null | grep -v "^$\|^Loaded\|^Loading\|^Last\|^Plugin\|^Red Hat\|^\*" | wc -l)
        SEC_PENDING=$(yum check-update --security 2>/dev/null | grep -c "^[a-zA-Z]" || echo 0)
        if [[ "$PENDING" -le 1 ]]; then
            ok "System packages appear up to date"
        else
            warn "$PENDING package(s) pending update"
            add_rec "Run: yum update -y to apply pending OS updates."
        fi
    elif command -v dnf &>/dev/null; then
        PENDING=$(dnf check-update 2>/dev/null | grep -v "^$\|^Last\|^Loaded" | wc -l)
        if [[ "$PENDING" -le 1 ]]; then
            ok "System packages appear up to date (dnf)"
        else
            warn "$PENDING package(s) pending update (dnf)"
            add_rec "Run: dnf update -y to apply pending OS updates."
        fi
    else
        info "Package manager not detected — skipping OS update check"
    fi

    # --- PHP Version ---
    log "\n  ${BOLD}[2.3] PHP Version${NC}"
    PHP_EOL_VERSIONS=("5.6" "7.0" "7.1" "7.2" "7.3" "7.4" "8.0" "8.1")
    if command -v php &>/dev/null; then
        PHP_VER=$(php -r 'echo PHP_VERSION;' 2>/dev/null)
        PHP_MAJOR=$(echo "$PHP_VER" | cut -d'.' -f1-2)
        info "Default PHP version: $PHP_VER"
        PHP_EOL=0
        for eol in "${PHP_EOL_VERSIONS[@]}"; do
            if [[ "$PHP_MAJOR" == "$eol" ]]; then
                PHP_EOL=1
                break
            fi
        done
        if [[ $PHP_EOL -eq 1 ]]; then
            crit "PHP $PHP_VER is End of Life (EOL)!"
            add_rec "CRITICAL: Upgrade PHP from $PHP_VER to PHP 8.2 or 8.3. EOL PHP receives no security fixes."
        else
            ok "PHP $PHP_VER is supported"
        fi
    else
        info "PHP not found or not in PATH"
    fi
    # cPanel multi-PHP
    if [[ "$CONTROL_PANEL_NAME" == "cpanel" ]] && command -v /usr/local/cpanel/scripts/php_get_installed_versions &>/dev/null; then
        MULTI_PHP=$(/usr/local/cpanel/scripts/php_get_installed_versions 2>/dev/null)
        info "cPanel installed PHP versions: $MULTI_PHP"
    fi

    # --- CMS Detection & Version ---
    log "\n  ${BOLD}[2.4] CMS Detection${NC}"
    CMS_FOUND=0
    # WordPress
    WP_PATHS=$(find /home /var/www /srv/www -name "wp-login.php" -maxdepth 6 2>/dev/null | head -5)
    if [ -n "$WP_PATHS" ]; then
        CMS_FOUND=1
        while IFS= read -r wp; do
            WP_DIR=$(dirname "$wp")
            WP_VER=$(grep "wp_version = " "$WP_DIR/wp-includes/version.php" 2>/dev/null | awk -F"'" '{print $2}')
            if [ -n "$WP_VER" ]; then
                info "WordPress $WP_VER found at: $WP_DIR"
                # EOL WordPress versions (< 6.0 considered outdated)
                WP_MAJOR=$(echo "$WP_VER" | cut -d'.' -f1)
                WP_MINOR=$(echo "$WP_VER" | cut -d'.' -f2)
                if [[ "$WP_MAJOR" -lt 6 ]]; then
                    warn "WordPress $WP_VER is outdated (current major: 6.x)"
                    add_rec "Update WordPress at $WP_DIR from $WP_VER to latest 6.x."
                else
                    ok "WordPress $WP_VER appears current"
                fi
            fi
        done <<< "$WP_PATHS"
    fi
    # Joomla
    JOOMLA_PATHS=$(find /home /var/www /srv/www -name "configuration.php" -maxdepth 6 2>/dev/null | xargs grep -l "Joomla" 2>/dev/null | head -3)
    if [ -n "$JOOMLA_PATHS" ]; then
        CMS_FOUND=1
        info "Joomla installation(s) detected"
    fi
    # Drupal
    DRUPAL_PATHS=$(find /home /var/www /srv/www -name "drupal.js" -maxdepth 7 2>/dev/null | head -3)
    if [ -n "$DRUPAL_PATHS" ]; then
        CMS_FOUND=1
        info "Drupal installation(s) detected"
    fi
    if [[ $CMS_FOUND -eq 0 ]]; then
        info "No common CMS (WordPress/Joomla/Drupal) detected"
    fi

    # --- Web Server ---
    log "\n  ${BOLD}[2.5] Web Server Version${NC}"
    if command -v apache2 &>/dev/null; then
        APACHE_VER=$(apache2 -v 2>/dev/null | grep "Server version" | awk '{print $3}')
        info "Apache: $APACHE_VER"
        ok "Apache detected: $APACHE_VER"
    elif command -v httpd &>/dev/null; then
        APACHE_VER=$(httpd -v 2>/dev/null | grep "Server version" | awk '{print $3}')
        info "Apache (httpd): $APACHE_VER"
        ok "Apache httpd detected: $APACHE_VER"
    fi
    if command -v nginx &>/dev/null; then
        NGINX_VER=$(nginx -v 2>&1 | awk -F'/' '{print $2}')
        info "Nginx: $NGINX_VER"
        ok "Nginx detected: $NGINX_VER"
        # Nginx EOL check (before 1.24 is outdated)
        NGINX_MAJOR=$(echo "$NGINX_VER" | cut -d'.' -f1)
        NGINX_MINOR=$(echo "$NGINX_VER" | cut -d'.' -f2)
        if [[ "$NGINX_MAJOR" -eq 1 && "$NGINX_MINOR" -lt 24 ]]; then
            warn "Nginx $NGINX_VER may be outdated (current stable: 1.26.x)"
            add_rec "Update Nginx from $NGINX_VER to the latest stable version (1.26.x)."
        fi
    fi

    # --- Database Server ---
    log "\n  ${BOLD}[2.6] Database Server${NC}"
    if command -v mysql &>/dev/null || command -v mysqladmin &>/dev/null; then
        MYSQL_VER=$(mysql --version 2>/dev/null | awk '{print $5}' | tr -d ',')
        info "MySQL/MariaDB: $MYSQL_VER"
        MYSQL_MAJOR=$(echo "$MYSQL_VER" | cut -d'.' -f1)
        MYSQL_MINOR=$(echo "$MYSQL_VER" | cut -d'.' -f2)
        # MySQL 5.6 EOL, 5.7 EOL Oct 2023
        if echo "$MYSQL_VER" | grep -q "^5\.6\|^5\.7"; then
            crit "MySQL $MYSQL_VER is End of Life!"
            add_rec "CRITICAL: Upgrade MySQL from $MYSQL_VER to MySQL 8.0+ or MariaDB 10.11+."
        else
            ok "Database server: $MYSQL_VER"
        fi
    fi
    if command -v psql &>/dev/null; then
        PG_VER=$(psql --version 2>/dev/null | awk '{print $3}')
        info "PostgreSQL: $PG_VER"
        ok "PostgreSQL $PG_VER detected"
        PG_MAJOR=$(echo "$PG_VER" | cut -d'.' -f1)
        if [[ "$PG_MAJOR" -lt 13 ]]; then
            warn "PostgreSQL $PG_VER may be outdated or EOL"
            add_rec "Consider upgrading PostgreSQL from $PG_VER to version 15 or 16."
        fi
    fi

    # --- Other Softwares ---
    log "\n  ${BOLD}[2.7] Other Software Versions${NC}"
    if command -v openssl &>/dev/null; then
        SSL_VER=$(openssl version 2>/dev/null)
        info "OpenSSL: $SSL_VER"
        if echo "$SSL_VER" | grep -qE "OpenSSL 1\.0|OpenSSL 1\.1\.0"; then
            warn "OpenSSL version may be EOL: $SSL_VER"
            add_rec "Upgrade OpenSSL to 1.1.1 or 3.x — older versions have unpatched vulnerabilities."
        else
            ok "OpenSSL: $SSL_VER"
        fi
    fi
    if command -v exim &>/dev/null; then
        EXIM_VER=$(exim --version 2>/dev/null | head -1)
        info "Exim MTA: $EXIM_VER"
    fi
    if command -v postfix &>/dev/null; then
        POSTFIX_VER=$(postfix version 2>/dev/null | head -1 || postconf -d mail_version 2>/dev/null | awk -F= '{print $2}')
        info "Postfix MTA: $POSTFIX_VER"
    fi
}

# ============================================================
# SECTION 3: SERVER HEALTH
# ============================================================
audit_server_health() {
    section "SERVER HEALTH"

    # --- Server Uptime ---
    log "\n  ${BOLD}[3.1] Server Uptime${NC}"
    UPTIME_STR=$(uptime -p 2>/dev/null || uptime)
    info "Uptime: $UPTIME_STR"
    UPTIME_DAYS=$(awk '{print int($1/86400)}' /proc/uptime 2>/dev/null || echo 0)
    if [[ "$UPTIME_DAYS" -gt 180 ]]; then
        warn "Server has been up for $UPTIME_DAYS days — consider scheduled reboots for kernel updates"
        add_rec "Server uptime is $UPTIME_DAYS days. Schedule a maintenance reboot to apply kernel updates."
    elif [[ "$UPTIME_DAYS" -lt 1 ]]; then
        warn "Server uptime is less than 1 day — recent reboot occurred"
    else
        ok "Uptime: $UPTIME_STR"
    fi

    # --- HTTP Uptime (local check) ---
    log "\n  ${BOLD}[3.2] HTTP Service Status${NC}"
    HTTP_UP=0
    for port in 80 443; do
        if command -v curl &>/dev/null; then
            HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://localhost:$port/" 2>/dev/null || echo "000")
            if [[ "$HTTP_CODE" != "000" ]]; then
                ok "HTTP port $port responding (status: $HTTP_CODE)"
                HTTP_UP=1
            fi
        elif command -v wget &>/dev/null; then
            if wget -q --spider --timeout=5 "http://localhost:$port/" 2>/dev/null; then
                ok "HTTP port $port is responding"
                HTTP_UP=1
            fi
        fi
    done
    if [[ $HTTP_UP -eq 0 ]]; then
        if command -v apache2 &>/dev/null || command -v httpd &>/dev/null || command -v nginx &>/dev/null; then
            warn "Web server installed but HTTP ports 80/443 not responding on localhost"
            add_rec "Web server is installed but not responding on ports 80/443. Check service status."
        else
            info "No web server detected — HTTP check skipped"
        fi
    fi

    # --- CPU Usage ---
    log "\n  ${BOLD}[3.3] CPU Usage${NC}"
    CPU_IDLE=$(top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{print $8}' | tr -d '%id,' || echo "0")
    CPU_USED=$(echo "100 - ${CPU_IDLE:-0}" | bc 2>/dev/null || echo "N/A")
    LOAD=$(cat /proc/loadavg | awk '{print $1, $2, $3}')
    CPU_COUNT=$(nproc 2>/dev/null || grep -c processor /proc/cpuinfo)
    info "CPU cores: $CPU_COUNT | Load average: $LOAD"
    LOAD1=$(echo "$LOAD" | awk '{print $1}')
    LOAD_INT=$(echo "$LOAD1" | cut -d'.' -f1)
    if [[ "$LOAD_INT" -gt "$((CPU_COUNT * 2))" ]]; then
        crit "CPU load average ($LOAD1) is critically high for $CPU_COUNT core(s)!"
        add_rec "CRITICAL: CPU load ($LOAD1) is very high. Investigate runaway processes: top, htop, ps aux."
    elif [[ "$LOAD_INT" -gt "$CPU_COUNT" ]]; then
        warn "CPU load average ($LOAD1) exceeds number of CPUs ($CPU_COUNT)"
        add_rec "CPU load ($LOAD1) is elevated. Review running processes."
    else
        ok "CPU load average: $LOAD (${CPU_COUNT} cores) — normal"
    fi

    # --- RAM Usage ---
    log "\n  ${BOLD}[3.4] RAM Usage${NC}"
    RAM_TOTAL=$(free -m 2>/dev/null | awk '/^Mem/{print $2}')
    RAM_USED=$(free -m 2>/dev/null | awk '/^Mem/{print $3}')
    RAM_FREE=$(free -m 2>/dev/null | awk '/^Mem/{print $4}')
    if [ -n "$RAM_TOTAL" ] && [ "$RAM_TOTAL" -gt 0 ]; then
        RAM_PCT=$(echo "$RAM_USED * 100 / $RAM_TOTAL" | bc)
        info "RAM: ${RAM_USED}MB used / ${RAM_TOTAL}MB total (${RAM_PCT}%)"
        if [[ "$RAM_PCT" -ge 90 ]]; then
            crit "RAM usage critically high: ${RAM_PCT}%"
            add_rec "CRITICAL: RAM usage is ${RAM_PCT}%. Identify memory-hungry processes: free -m, ps aux --sort=-%mem"
        elif [[ "$RAM_PCT" -ge 75 ]]; then
            warn "RAM usage is high: ${RAM_PCT}%"
            add_rec "RAM usage is at ${RAM_PCT}%. Monitor memory usage closely."
        else
            ok "RAM usage: ${RAM_PCT}% (${RAM_USED}MB / ${RAM_TOTAL}MB)"
        fi
    fi

    # --- Disk Space Usage ---
    log "\n  ${BOLD}[3.5] Disk Space Usage${NC}"
    while IFS= read -r line; do
        DISK_USE=$(echo "$line" | awk '{print $5}' | tr -d '%')
        DISK_MNT=$(echo "$line" | awk '{print $6}')
        DISK_AVAIL=$(echo "$line" | awk '{print $4}')
        if [[ "$DISK_USE" -ge 90 ]]; then
            crit "Disk ${DISK_MNT}: ${DISK_USE}% used — critically full! (${DISK_AVAIL} free)"
            add_rec "CRITICAL: Disk $DISK_MNT is ${DISK_USE}% full. Free up space immediately."
        elif [[ "$DISK_USE" -ge 75 ]]; then
            warn "Disk ${DISK_MNT}: ${DISK_USE}% used (${DISK_AVAIL} free)"
            add_rec "Disk $DISK_MNT is ${DISK_USE}% used. Consider cleanup or expansion."
        else
            ok "Disk ${DISK_MNT}: ${DISK_USE}% used (${DISK_AVAIL} free)"
        fi
    done < <(df -h --output=source,size,used,avail,pcent,target 2>/dev/null | grep -E "^/dev/" | grep -v "tmpfs\|loop\|udev")

    # Check inode usage
    while IFS= read -r line; do
        INODE_USE=$(echo "$line" | awk '{print $5}' | tr -d '%')
        INODE_MNT=$(echo "$line" | awk '{print $6}')
        if [[ "$INODE_USE" -ge 90 ]]; then
            crit "Inode usage on ${INODE_MNT}: ${INODE_USE}% — critically high!"
            add_rec "CRITICAL: Inode exhaustion on $INODE_MNT (${INODE_USE}%). Find and remove many small files."
        elif [[ "$INODE_USE" -ge 75 ]]; then
            warn "Inode usage on ${INODE_MNT}: ${INODE_USE}%"
        fi
    done < <(df -i 2>/dev/null | grep -E "^/dev/" | grep -v "tmpfs\|loop\|udev")

    # --- Email Queue ---
    log "\n  ${BOLD}[3.6] Email Queue${NC}"
    if command -v exim &>/dev/null; then
        MAIL_QUEUE=$(exim -bpc 2>/dev/null || echo 0)
        info "Exim mail queue: $MAIL_QUEUE messages"
        if [[ "$MAIL_QUEUE" -gt 500 ]]; then
            crit "Exim queue is critically high: $MAIL_QUEUE messages"
            add_rec "CRITICAL: Exim mail queue has $MAIL_QUEUE messages. Investigate spam/mail loops."
        elif [[ "$MAIL_QUEUE" -gt 100 ]]; then
            warn "Exim queue elevated: $MAIL_QUEUE messages"
            add_rec "Exim queue has $MAIL_QUEUE messages — review for mail loops or spam."
        else
            ok "Exim mail queue: $MAIL_QUEUE messages — normal"
        fi
    elif command -v postqueue &>/dev/null; then
        MAIL_QUEUE=$(postqueue -p 2>/dev/null | tail -1 | awk '{print $1}' || echo 0)
        info "Postfix mail queue: $MAIL_QUEUE"
        if [[ "$MAIL_QUEUE" -gt 100 ]]; then
            warn "Postfix queue elevated: $MAIL_QUEUE messages"
            add_rec "Postfix queue has elevated messages ($MAIL_QUEUE). Check for mail issues."
        else
            ok "Postfix mail queue: $MAIL_QUEUE"
        fi
    else
        info "No mail server detected — email queue check skipped"
    fi

    # --- IP Reputation ---
    log "\n  ${BOLD}[3.7] IP Reputation${NC}"
    if [ -n "$MAIN_IP" ]; then
        info "Checking IP reputation for: $MAIN_IP"
        # Check Spamhaus via DNS
        REVERSED_IP=$(echo "$MAIN_IP" | awk -F'.' '{print $4"."$3"."$2"."$1}')
        SPAMHAUS=$(host "${REVERSED_IP}.zen.spamhaus.org" 2>/dev/null | grep -c "127.0.0.")
        SORBS=$(host "${REVERSED_IP}.dnsbl.sorbs.net" 2>/dev/null | grep -c "127.0.0.")
        SPAMCOP=$(host "${REVERSED_IP}.bl.spamcop.net" 2>/dev/null | grep -c "127.0.0.")
        if [[ "$SPAMHAUS" -gt 0 ]]; then
            crit "IP $MAIN_IP is listed on Spamhaus DNSBL!"
            add_rec "CRITICAL: Your IP ($MAIN_IP) is on the Spamhaus blacklist. Request delisting at https://www.spamhaus.org/lookup/"
        else
            ok "IP $MAIN_IP not listed on Spamhaus"
        fi
        if [[ "$SORBS" -gt 0 ]]; then
            warn "IP $MAIN_IP may be listed on SORBS"
            add_rec "IP $MAIN_IP is on SORBS blacklist. Check https://www.sorbs.net"
        else
            ok "IP $MAIN_IP not listed on SORBS"
        fi
        if [[ "$SPAMCOP" -gt 0 ]]; then
            warn "IP $MAIN_IP may be listed on SpamCop"
            add_rec "IP $MAIN_IP is on SpamCop blacklist. Check https://www.spamcop.net"
        else
            ok "IP $MAIN_IP not listed on SpamCop"
        fi
    else
        info "Main IP not available — skipping IP reputation check"
    fi
}

# ============================================================
# SECTION 4: BACKUP
# ============================================================
audit_backup() {
    section "BACKUP"

    # --- Local Backup ---
    log "\n  ${BOLD}[4.1] Local Backup${NC}"
    LOCAL_BACKUP_FOUND=0
    # Check cPanel backup config
    if [[ "$CONTROL_PANEL_NAME" == "cpanel" ]]; then
        if [ -f /etc/cpbackup.conf ]; then
            BACKUP_ENABLED=$(grep -i "BACKUP=" /etc/cpbackup.conf 2>/dev/null | cut -d= -f2)
            if [[ "$BACKUP_ENABLED" == "yes" ]]; then
                ok "cPanel local backup is enabled"
                LOCAL_BACKUP_FOUND=1
                BACKUP_DIR=$(grep "BACKUPDIR=" /etc/cpbackup.conf 2>/dev/null | cut -d= -f2)
                info "Backup directory: ${BACKUP_DIR:-default}"
            else
                warn "cPanel backup may be disabled in /etc/cpbackup.conf"
                add_rec "Enable cPanel backups in WHM > Backup Configuration."
            fi
        fi
    fi
    # Check Plesk backup
    if [[ "$CONTROL_PANEL_NAME" == "plesk" ]]; then
        PLESK_BACKUP_DIR=$(plesk bin backup_manager --list-local-backup-directories 2>/dev/null | head -2)
        if [ -n "$PLESK_BACKUP_DIR" ]; then
            ok "Plesk backup directories found"
            LOCAL_BACKUP_FOUND=1
        fi
    fi
    # Generic backup dirs
    for bdir in /backup /backups /home/backup /var/backup /opt/backup; do
        if [ -d "$bdir" ] && [ "$(ls -A $bdir 2>/dev/null)" ]; then
            ok "Backup directory found: $bdir"
            LOCAL_BACKUP_FOUND=1
        fi
    done
    # Check duplicity, rsnapshot, borgbackup
    for btool in duplicity rsnapshot borg rsync; do
        if command -v $btool &>/dev/null; then
            ok "Backup tool available: $btool"
            LOCAL_BACKUP_FOUND=1
        fi
    done
    if [[ $LOCAL_BACKUP_FOUND -eq 0 ]]; then
        warn "No local backup system detected"
        add_rec "Set up local backups. Use cPanel Backup Manager, rsync, or borg for automated backups."
    fi

    # --- Remote Backup ---
    log "\n  ${BOLD}[4.2] Remote Backup${NC}"
    REMOTE_BACKUP_FOUND=0
    # cPanel remote backup
    if [[ "$CONTROL_PANEL_NAME" == "cpanel" ]] && [ -f /etc/cpbackup.conf ]; then
        REMOTE_DEST=$(grep -i "BACKUPACCTS\|REMOTE" /etc/cpbackup.conf 2>/dev/null | head -3)
        if echo "$REMOTE_DEST" | grep -qi "ftp\|s3\|rsync\|ssh"; then
            ok "cPanel remote backup destination configured"
            REMOTE_BACKUP_FOUND=1
        fi
    fi
    # Check for S3 tools
    if command -v aws &>/dev/null || command -v s3cmd &>/dev/null; then
        ok "AWS CLI or s3cmd found — S3 backup may be configured"
        REMOTE_BACKUP_FOUND=1
    fi
    # Check for rclone
    if command -v rclone &>/dev/null; then
        ok "rclone found — remote backup capable"
        REMOTE_BACKUP_FOUND=1
    fi
    if [[ $REMOTE_BACKUP_FOUND -eq 0 ]]; then
        warn "No remote backup configuration detected"
        add_rec "Configure off-site/remote backups to S3, FTP, or remote SSH for disaster recovery."
    fi

    # --- Daily/Weekly/Monthly Backup Schedule ---
    log "\n  ${BOLD}[4.3] Backup Schedule${NC}"
    # Check crontab for backup jobs
    CRON_BACKUP=$(crontab -l 2>/dev/null | grep -i "backup\|rsync\|dump\|borg\|duplicity" | wc -l)
    CRON_SYSTEM=$(grep -r "backup\|rsync\|dump\|borg\|duplicity" /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null | wc -l)
    if [[ "$CRON_BACKUP" -gt 0 || "$CRON_SYSTEM" -gt 0 ]]; then
        ok "Backup cron jobs detected (${CRON_BACKUP} in user crontab, ${CRON_SYSTEM} in system cron)"
    else
        warn "No scheduled backup cron jobs detected"
        add_rec "Schedule automated backups using cron: daily for critical data, weekly for full system backup."
    fi
    if [[ "$CONTROL_PANEL_NAME" == "cpanel" ]]; then
        DAILY_BK=$(grep -i "BACKUPDAYS" /etc/cpbackup.conf 2>/dev/null)
        WEEKLY_BK=$(grep -i "WEEKLY" /etc/cpbackup.conf 2>/dev/null)
        MONTHLY_BK=$(grep -i "MONTHLY" /etc/cpbackup.conf 2>/dev/null)
        [ -n "$DAILY_BK" ] && info "cPanel daily backup setting: $DAILY_BK"
        [ -n "$WEEKLY_BK" ] && info "cPanel weekly backup: $WEEKLY_BK"
        [ -n "$MONTHLY_BK" ] && info "cPanel monthly backup: $MONTHLY_BK"
    fi

    # --- Recent Last Backup & Backup Size ---
    log "\n  ${BOLD}[4.4] Recent Backup Files${NC}"
    for bdir in /backup /backups /home/backup /var/backup /opt/backup; do
        if [ -d "$bdir" ]; then
            LATEST=$(find "$bdir" -type f \( -name "*.tar.gz" -o -name "*.tar.bz2" -o -name "*.zip" -o -name "*.sql.gz" \) -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1)
            if [ -n "$LATEST" ]; then
                LATEST_FILE=$(echo "$LATEST" | awk '{print $2}')
                LATEST_DATE=$(date -d "@$(echo "$LATEST" | awk '{print $1}' | cut -d. -f1)" "+%Y-%m-%d %H:%M" 2>/dev/null)
                LATEST_SIZE=$(du -sh "$LATEST_FILE" 2>/dev/null | awk '{print $1}')
                ok "Most recent backup: $LATEST_FILE"
                info "  Last backup date: $LATEST_DATE | Size: $LATEST_SIZE"
                # Check if backup is older than 7 days
                DAYS_OLD=$(( ( $(date +%s) - $(echo "$LATEST" | awk '{print int($1)}') ) / 86400 ))
                if [[ "$DAYS_OLD" -gt 7 ]]; then
                    warn "Most recent backup in $bdir is $DAYS_OLD days old"
                    add_rec "Backup in $bdir is $DAYS_OLD days old. Ensure daily backups are running."
                fi
            fi
        fi
    done
}

# ============================================================
# SECTION 5: SOFTWARE LIFE TIME (EOL)
# ============================================================
audit_software_lifetime() {
    section "SOFTWARE LIFE TIME (End of Life Status)"

    # --- Control Panel EOL ---
    log "\n  ${BOLD}[5.1] Control Panel Life Time${NC}"
    if [[ "$CONTROL_PANEL_NAME" == "cpanel" ]]; then
        info "cPanel version: $CONTROL_PANEL_VERSION"
        # cPanel EOL: versions below 110 are unsupported
        CP_NUM=$(echo "$CONTROL_PANEL_VERSION" | cut -d'.' -f1 2>/dev/null || echo 0)
        if [[ "$CP_NUM" -lt 110 ]] && [[ "$CP_NUM" -gt 0 ]]; then
            crit "cPanel version $CONTROL_PANEL_VERSION may be EOL (support typically requires 110+)"
            add_rec "Update cPanel to a supported version (110+)."
        else
            ok "cPanel $CONTROL_PANEL_VERSION appears current"
        fi
    elif [ -n "$CONTROL_PANEL_NAME" ]; then
        info "Control panel: $CONTROL_PANEL_NAME $CONTROL_PANEL_VERSION — check vendor EOL policy"
    else
        info "No control panel detected"
    fi

    # --- Operating System EOL (reuse earlier check) ---
    log "\n  ${BOLD}[5.2] Operating System Life Time${NC}"
    info "OS: $OS_NAME $OS_VERSION"
    if [[ "$EOL_STATUS" == "End of Life" ]]; then
        crit "$OS_NAME $OS_VERSION is End of Life — no security updates available!"
        add_rec "CRITICAL: Migrate from $OS_NAME $OS_VERSION to a supported OS version immediately."
    else
        ok "$OS_NAME $OS_VERSION is currently supported"
    fi
    # Kernel version info
    KERNEL=$(uname -r)
    info "Kernel: $KERNEL"

    # --- CMS EOL ---
    log "\n  ${BOLD}[5.3] CMS Life Time${NC}"
    WP_PATHS=$(find /home /var/www /srv/www -name "wp-login.php" -maxdepth 6 2>/dev/null | head -5)
    if [ -n "$WP_PATHS" ]; then
        while IFS= read -r wp; do
            WP_DIR=$(dirname "$wp")
            WP_VER=$(grep "wp_version = " "$WP_DIR/wp-includes/version.php" 2>/dev/null | awk -F"'" '{print $2}')
            [ -n "$WP_VER" ] && info "WordPress $WP_VER at $WP_DIR"
        done <<< "$WP_PATHS"
    fi

    # --- Software Stack EOL ---
    log "\n  ${BOLD}[5.4] Software Stack Life Time${NC}"
    # PHP EOL already covered in section 2 — show summary
    if command -v php &>/dev/null; then
        PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null)
        PHP_EOL_VERSIONS=("5.6" "7.0" "7.1" "7.2" "7.3" "7.4" "8.0" "8.1")
        PHP_IS_EOL=0
        for eol in "${PHP_EOL_VERSIONS[@]}"; do
            [[ "$PHP_VER" == "$eol" ]] && PHP_IS_EOL=1 && break
        done
        if [[ $PHP_IS_EOL -eq 1 ]]; then
            crit "PHP $PHP_VER is EOL"
        else
            ok "PHP $PHP_VER is within support lifecycle"
        fi
    fi
    # OpenSSL lifecycle
    if command -v openssl &>/dev/null; then
        OSSL=$(openssl version 2>/dev/null)
        info "OpenSSL: $OSSL"
    fi
    # Python
    if command -v python3 &>/dev/null; then
        PY_VER=$(python3 --version 2>/dev/null)
        info "Python: $PY_VER"
        PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)' 2>/dev/null)
        PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)' 2>/dev/null)
        if [[ "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 8 ]]; then
            warn "Python $PY_VER may be EOL"
            add_rec "Upgrade Python from $PY_VER to Python 3.10+ for security support."
        fi
    fi
}

# ============================================================
# SECTION 6: PROACTIVE DEFENCE
# ============================================================
audit_proactive_defence() {
    section "PROACTIVE DEFENCE"

    # --- /tmp Security ---
    log "\n  ${BOLD}[6.1] /tmp Security${NC}"
    TMP_SECURE=0
    TMP_MOUNT=$(mount | grep " /tmp " 2>/dev/null)
    if echo "$TMP_MOUNT" | grep -q "noexec"; then
        ok "/tmp is mounted with noexec flag"
        TMP_SECURE=1
    else
        warn "/tmp is NOT mounted with noexec — executables can run from /tmp"
        add_rec "Mount /tmp with noexec,nosuid,nodev flags to prevent exploit execution from /tmp."
    fi
    if echo "$TMP_MOUNT" | grep -q "nosuid"; then
        ok "/tmp is mounted with nosuid flag"
    fi
    # Check for tmpfs
    if echo "$TMP_MOUNT" | grep -q "tmpfs"; then
        ok "/tmp is on tmpfs (memory-based, secure)"
    fi
    # Sticky bit
    TMP_STICKY=$(stat -c "%a" /tmp 2>/dev/null)
    if [[ "$TMP_STICKY" == *"1"* ]] || [[ "$TMP_STICKY" == "1777" ]]; then
        ok "/tmp has sticky bit set (1777)"
    else
        warn "/tmp sticky bit not set (permissions: $TMP_STICKY)"
        add_rec "Set sticky bit on /tmp: chmod 1777 /tmp"
    fi

    # --- Reboot Procedure (kernel update pending) ---
    log "\n  ${BOLD}[6.2] Reboot / Kernel Update Procedure${NC}"
    RUNNING_KERNEL=$(uname -r)
    info "Running kernel: $RUNNING_KERNEL"
    if command -v needs-restarting &>/dev/null; then
        REBOOT_NEEDED=$(needs-restarting -r 2>&1 | grep -c "Reboot is required" || echo 0)
        if [[ "$REBOOT_NEEDED" -gt 0 ]]; then
            warn "System requires a reboot to apply kernel/library updates"
            add_rec "Schedule a reboot to apply pending kernel/library updates."
        else
            ok "No pending reboot required (needs-restarting)"
        fi
    elif [ -f /var/run/reboot-required ]; then
        warn "Reboot required file detected (/var/run/reboot-required)"
        add_rec "Schedule a reboot: /var/run/reboot-required exists (pending kernel/library update)."
        if [ -f /var/run/reboot-required.pkgs ]; then
            REBOOT_PKGS=$(cat /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ', ')
            info "Packages requiring reboot: $REBOOT_PKGS"
        fi
    else
        # Compare installed vs running kernel (Debian/Ubuntu)
        if command -v dpkg &>/dev/null; then
            INSTALLED_KERNEL=$(dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii' | awk '{print $2}' | grep -v generic | tail -1 | sed 's/linux-image-//')
            if [ -n "$INSTALLED_KERNEL" ] && [[ "$INSTALLED_KERNEL" != "$RUNNING_KERNEL" ]]; then
                warn "Installed kernel ($INSTALLED_KERNEL) differs from running kernel ($RUNNING_KERNEL)"
                add_rec "Reboot to activate kernel $INSTALLED_KERNEL."
            else
                ok "Running kernel matches installed kernel"
            fi
        fi
    fi

    # --- IP RDNS / Reverse DNS ---
    log "\n  ${BOLD}[6.3] IP Reverse DNS (rDNS)${NC}"
    if [ -n "$MAIN_IP" ]; then
        RDNS=$(host "$MAIN_IP" 2>/dev/null | awk '/pointer/{print $5}' | head -1)
        if [ -n "$RDNS" ] && [[ "$RDNS" != *"NXDOMAIN"* ]]; then
            ok "rDNS for $MAIN_IP: $RDNS"
            # Check if rDNS resolves back to IP (FCrDNS)
            FORWARD=$(host "$RDNS" 2>/dev/null | awk '/has address/{print $4}' | head -1)
            if [[ "$FORWARD" == "$MAIN_IP" ]]; then
                ok "Forward-confirmed rDNS (FCrDNS) matches: $RDNS → $FORWARD"
            else
                warn "FCrDNS mismatch: $RDNS resolves to $FORWARD (expected $MAIN_IP)"
                add_rec "Fix Forward-Confirmed Reverse DNS (FCrDNS) mismatch. rDNS should resolve back to $MAIN_IP."
            fi
        else
            warn "No rDNS (PTR record) found for $MAIN_IP"
            add_rec "Set up reverse DNS (PTR record) for $MAIN_IP — required for mail server reputation."
        fi
    fi

    # --- Malware Scan (recent) ---
    log "\n  ${BOLD}[6.4] Recent Malware Scan${NC}"
    MALWARE_SCAN_RECENT=0
    # ClamAV last scan
    CLAM_LOG=$(find /var/log -name "clamav*" -o -name "clamd.log" 2>/dev/null | head -1)
    if [ -n "$CLAM_LOG" ]; then
        CLAM_DATE=$(stat -c %y "$CLAM_LOG" 2>/dev/null | cut -d' ' -f1)
        CLAM_AGE=$(( ( $(date +%s) - $(stat -c %Y "$CLAM_LOG" 2>/dev/null) ) / 86400 ))
        if [[ "$CLAM_AGE" -le 7 ]]; then
            ok "ClamAV scan log found, last activity: $CLAM_DATE ($CLAM_AGE days ago)"
            MALWARE_SCAN_RECENT=1
        else
            warn "ClamAV log is $CLAM_AGE days old — no recent scan detected"
            add_rec "Run a ClamAV scan: clamscan -r /home --log=/var/log/clamav/scan.log"
        fi
    fi
    # maldet last scan
    if command -v maldet &>/dev/null; then
        MALDET_LOG=$(find /usr/local/maldetect/sess/ -name "*.log" 2>/dev/null | sort -t_ -k2 -n | tail -1)
        if [ -n "$MALDET_LOG" ]; then
            MALDET_AGE=$(( ( $(date +%s) - $(stat -c %Y "$MALDET_LOG" 2>/dev/null) ) / 86400 ))
            if [[ "$MALDET_AGE" -le 7 ]]; then
                ok "Maldet (LMD) last scan: $MALDET_AGE day(s) ago"
                MALWARE_SCAN_RECENT=1
            else
                warn "Maldet last scan was $MALDET_AGE days ago"
                add_rec "Run a maldet scan: maldet -a /home"
            fi
        fi
    fi
    if [[ $MALWARE_SCAN_RECENT -eq 0 ]] && ! command -v maldet &>/dev/null && ! [ -n "$CLAM_LOG" ]; then
        warn "No malware scanner or recent scan detected"
        add_rec "Install and schedule regular malware scans (ClamAV or maldet)."
    fi

    # --- Rootkit Check (recent) ---
    log "\n  ${BOLD}[6.5] Rootkit Check${NC}"
    if command -v rkhunter &>/dev/null; then
        RKH_LOG=$(find /var/log -name "rkhunter.log" 2>/dev/null | head -1)
        if [ -n "$RKH_LOG" ]; then
            RKH_AGE=$(( ( $(date +%s) - $(stat -c %Y "$RKH_LOG") ) / 86400 ))
            RKH_WARN=$(grep -c "Warning" "$RKH_LOG" 2>/dev/null || echo 0)
            if [[ "$RKH_AGE" -le 7 ]]; then
                if [[ "$RKH_WARN" -gt 0 ]]; then
                    warn "rkhunter last run: $RKH_AGE day(s) ago — found $RKH_WARN warning(s)"
                    add_rec "rkhunter found $RKH_WARN warnings. Review: $RKH_LOG"
                else
                    ok "rkhunter last ran $RKH_AGE day(s) ago — no warnings found"
                fi
            else
                warn "rkhunter log is $RKH_AGE days old — run rkhunter regularly"
                add_rec "Schedule rkhunter in cron: rkhunter --check --sk --report-warnings-only"
            fi
        else
            warn "rkhunter installed but no log found — run it"
            add_rec "Run rkhunter: rkhunter --check --sk"
        fi
    else
        warn "rkhunter not installed"
        add_rec "Install rkhunter: apt-get install rkhunter / yum install rkhunter"
    fi

    # --- SSH Root Access Security ---
    log "\n  ${BOLD}[6.6] SSH Root Access Security${NC}"
    SSHD_CONFIG="/etc/ssh/sshd_config"
    if [ -f "$SSHD_CONFIG" ]; then
        # PermitRootLogin
        ROOT_LOGIN=$(grep -i "^PermitRootLogin" "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}')
        if [[ "${ROOT_LOGIN,,}" == "yes" ]]; then
            crit "SSH PermitRootLogin is set to 'yes' — direct root SSH login allowed!"
            add_rec "CRITICAL: Disable root SSH login: set 'PermitRootLogin no' in $SSHD_CONFIG"
        elif [[ "${ROOT_LOGIN,,}" == "no" ]]; then
            ok "SSH PermitRootLogin: no (root login disabled)"
        elif [[ "${ROOT_LOGIN,,}" == "without-password" || "${ROOT_LOGIN,,}" == "prohibit-password" ]]; then
            ok "SSH PermitRootLogin: $ROOT_LOGIN (key-only root access)"
        else
            warn "SSH PermitRootLogin: '${ROOT_LOGIN:-not set}' — verify this is correct"
        fi

        # PasswordAuthentication
        PASS_AUTH=$(grep -i "^PasswordAuthentication" "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}')
        if [[ "${PASS_AUTH,,}" == "yes" ]]; then
            warn "SSH PasswordAuthentication is enabled — key-only auth recommended"
            add_rec "Disable SSH password auth and use key-based auth: 'PasswordAuthentication no' in $SSHD_CONFIG"
        elif [[ "${PASS_AUTH,,}" == "no" ]]; then
            ok "SSH PasswordAuthentication: no (key-only — secure)"
        else
            info "SSH PasswordAuthentication: '${PASS_AUTH:-default (yes)}'"
        fi

        # SSH Port
        SSH_PORT=$(grep -i "^Port" "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}')
        if [[ "${SSH_PORT}" == "22" || -z "$SSH_PORT" ]]; then
            warn "SSH running on default port 22 — consider changing to a non-standard port"
            add_rec "Change SSH port from 22 to a non-standard port to reduce scan noise."
        else
            ok "SSH running on non-default port: $SSH_PORT"
        fi

        # Protocol
        SSH_PROTO=$(grep -i "^Protocol" "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}')
        if [[ "$SSH_PROTO" == "1" ]]; then
            crit "SSH Protocol 1 is enabled — highly insecure!"
            add_rec "CRITICAL: Disable SSH Protocol 1. Set 'Protocol 2' in $SSHD_CONFIG"
        fi

        # MaxAuthTries
        MAX_TRIES=$(grep -i "^MaxAuthTries" "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}')
        if [ -n "$MAX_TRIES" ] && [[ "$MAX_TRIES" -le 3 ]]; then
            ok "SSH MaxAuthTries: $MAX_TRIES (good)"
        elif [ -n "$MAX_TRIES" ]; then
            warn "SSH MaxAuthTries: $MAX_TRIES — consider lowering to 3"
            add_rec "Lower SSH MaxAuthTries to 3 in $SSHD_CONFIG"
        fi
    else
        info "sshd_config not found — skipping SSH audit"
    fi

    # --- PHP Functions Security ---
    log "\n  ${BOLD}[6.7] PHP Functions Security${NC}"
    DANGEROUS_FUNCS="exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,phpinfo"
    if command -v php &>/dev/null; then
        DISABLED=$(php -r 'echo ini_get("disable_functions");' 2>/dev/null)
        if [ -n "$DISABLED" ]; then
            ok "PHP disabled_functions is set: $DISABLED"
            # Check if key dangerous functions are disabled
            for func in exec shell_exec system passthru; do
                if echo "$DISABLED" | grep -q "$func"; then
                    ok "PHP $func() is disabled"
                else
                    warn "PHP dangerous function not disabled: $func()"
                    add_rec "Add '$func' to PHP disable_functions in php.ini to harden PHP security."
                fi
            done
        else
            warn "PHP disable_functions is empty — all PHP functions enabled"
            add_rec "Set PHP disable_functions in php.ini: $DANGEROUS_FUNCS"
        fi
        # PHP expose_php
        EXPOSE=$(php -r 'echo ini_get("expose_php");' 2>/dev/null)
        if [[ "$EXPOSE" == "1" ]]; then
            warn "PHP expose_php is ON — PHP version exposed in HTTP headers"
            add_rec "Set 'expose_php = Off' in php.ini to hide PHP version from response headers."
        else
            ok "PHP expose_php is Off — version hidden from headers"
        fi
        # open_basedir
        OPENBASEDIR=$(php -r 'echo ini_get("open_basedir");' 2>/dev/null)
        if [ -z "$OPENBASEDIR" ]; then
            warn "PHP open_basedir is not set — filesystem access unrestricted"
            add_rec "Set PHP open_basedir to restrict PHP file access to web root."
        else
            ok "PHP open_basedir is set: $OPENBASEDIR"
        fi
    else
        info "PHP not found — PHP security check skipped"
    fi

    # --- Root Password Health ---
    log "\n  ${BOLD}[6.8] Root Password Health${NC}"
    # Check password age
    ROOT_PASS_INFO=$(chage -l root 2>/dev/null)
    if [ -n "$ROOT_PASS_INFO" ]; then
        LAST_CHANGED=$(echo "$ROOT_PASS_INFO" | grep "Last password change" | cut -d: -f2 | xargs)
        MAX_DAYS=$(echo "$ROOT_PASS_INFO" | grep "Maximum number of days" | cut -d: -f2 | xargs)
        EXPIRE=$(echo "$ROOT_PASS_INFO" | grep "Password expires" | cut -d: -f2 | xargs)
        info "Root password last changed: $LAST_CHANGED"
        info "Root password expires: $EXPIRE"
        if [[ "$MAX_DAYS" == "99999" || "$EXPIRE" == "never" ]]; then
            warn "Root password never expires"
            add_rec "Set a password expiry policy for root: chage -M 90 root"
        else
            ok "Root password has expiry policy set"
        fi
    fi
    # Check if root has a password at all (not locked)
    ROOT_LOCK=$(passwd -S root 2>/dev/null | awk '{print $2}')
    if [[ "$ROOT_LOCK" == "L" || "$ROOT_LOCK" == "LK" ]]; then
        ok "Root account password is locked (login via sudo/key only)"
    elif [[ "$ROOT_LOCK" == "P" ]]; then
        ok "Root account has a password set"
    else
        info "Root account status: $ROOT_LOCK"
    fi

    # --- Check for world-writable files in web roots ---
    log "\n  ${BOLD}[6.9] World-Writable Files Check${NC}"
    WW_COUNT=$(find /home /var/www /srv/www -maxdepth 5 -perm -o+w -not -type l 2>/dev/null | wc -l)
    if [[ "$WW_COUNT" -gt 50 ]]; then
        crit "Found $WW_COUNT world-writable files in web directories!"
        add_rec "CRITICAL: $WW_COUNT world-writable files found in web roots. Run: find /home /var/www -perm -o+w -exec chmod o-w {} \\;"
    elif [[ "$WW_COUNT" -gt 0 ]]; then
        warn "$WW_COUNT world-writable files found in web directories"
        add_rec "Review and fix world-writable files: find /home /var/www -perm -o+w"
    else
        ok "No world-writable files found in web directories"
    fi

    # --- SUID/SGID binaries check ---
    log "\n  ${BOLD}[6.10] SUID/SGID Binaries${NC}"
    SUID_COUNT=$(find / -not -path "/proc/*" -not -path "/sys/*" -perm /4000 -type f 2>/dev/null | wc -l)
    info "SUID binaries found: $SUID_COUNT"
    if [[ "$SUID_COUNT" -gt 20 ]]; then
        warn "High number of SUID binaries ($SUID_COUNT) — review for unnecessary ones"
        add_rec "Review SUID binaries: find / -perm /4000 -type f 2>/dev/null"
    else
        ok "SUID binary count within normal range: $SUID_COUNT"
    fi
}

# ============================================================
# SECTION 7: VULNERABILITY / PATCH CHECK
# ============================================================
audit_vulnerabilities() {
    section "VULNERABILITY & PATCH ADVISORY"

    log "\n  ${BOLD}[7.1] Known Kernel Vulnerabilities${NC}"
    KERNEL=$(uname -r)
    info "Running kernel: $KERNEL"

    # Spectre/Meltdown
    if [ -d /sys/devices/system/cpu/vulnerabilities ]; then
        for vuln in /sys/devices/system/cpu/vulnerabilities/*; do
            VULN_NAME=$(basename "$vuln")
            VULN_STATUS=$(cat "$vuln" 2>/dev/null)
            if echo "$VULN_STATUS" | grep -qi "Vulnerable\|Not affected"; then
                if echo "$VULN_STATUS" | grep -qi "Vulnerable"; then
                    warn "CPU Vulnerability [$VULN_NAME]: $VULN_STATUS"
                    add_rec "Kernel/CPU vulnerability detected: $VULN_NAME — $VULN_STATUS. Update kernel and microcode."
                else
                    ok "CPU [$VULN_NAME]: $VULN_STATUS"
                fi
            else
                info "CPU [$VULN_NAME]: $VULN_STATUS"
            fi
        done
    else
        info "CPU vulnerability sysfs not available on this kernel"
    fi

    # --- cPanel Security Advisories ---
    log "\n  ${BOLD}[7.2] cPanel Security Advisories${NC}"
    if [[ "$CONTROL_PANEL_NAME" == "cpanel" ]]; then
        info "Checking cPanel security advisories..."
        # cPanel publishes advisories at https://news.cpanel.com/category/security/
        CPANEL_SEC_CHECK=$(/usr/local/cpanel/scripts/check_cpanel_rpms 2>/dev/null | head -20)
        if [ -n "$CPANEL_SEC_CHECK" ]; then
            if echo "$CPANEL_SEC_CHECK" | grep -qi "FAILED\|mismatch\|problem"; then
                crit "cPanel RPM integrity check found issues!"
                log "$CPANEL_SEC_CHECK" | head -10
                add_rec "CRITICAL: cPanel RPM check detected issues. Run: /usr/local/cpanel/scripts/check_cpanel_rpms --fix"
            else
                ok "cPanel RPM integrity check passed"
            fi
        fi
        # Check for cPanel security patches
        if [ -f /usr/local/cpanel/version ]; then
            CPANEL_FULL_VER=$(cat /usr/local/cpanel/version 2>/dev/null)
            info "cPanel full version: $CPANEL_FULL_VER"
        fi
        # Security tier
        if [ -f /etc/cpupdate.conf ]; then
            TIER=$(grep "CPANEL=" /etc/cpupdate.conf 2>/dev/null | cut -d= -f2)
            info "cPanel update tier: ${TIER:-unknown}"
            if [[ "$TIER" == "RELEASE" || "$TIER" == "STABLE" ]]; then
                ok "cPanel on RELEASE/STABLE tier (receives security patches)"
            elif [[ "$TIER" == "EDGE" || "$TIER" == "CURRENT" ]]; then
                warn "cPanel on $TIER tier — may have pre-release code"
            fi
        fi
    else
        # --- Generic OS Security Advisories ---
        log "\n  ${BOLD}[7.2] OS Security Patches${NC}"
        if command -v apt-get &>/dev/null; then
            # Debian/Ubuntu unattended-upgrades
            if dpkg -l unattended-upgrades 2>/dev/null | grep -q "^ii"; then
                ok "unattended-upgrades package installed (auto security updates enabled)"
            else
                warn "unattended-upgrades not installed — security patches require manual action"
                add_rec "Install unattended-upgrades for automatic security updates: apt-get install unattended-upgrades"
            fi
            # List security updates available
            SEC_UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -i "security" | wc -l)
            if [[ "$SEC_UPDATES" -gt 0 ]]; then
                warn "$SEC_UPDATES security-related updates pending"
                add_rec "Apply $SEC_UPDATES pending security updates: apt-get upgrade -y"
            else
                ok "No pending security package updates detected (apt)"
            fi
        elif command -v yum &>/dev/null; then
            SEC_UPDATES=$(yum check-update --security 2>/dev/null | grep -c "^[a-zA-Z0-9]" || echo 0)
            if [[ "$SEC_UPDATES" -gt 1 ]]; then
                warn "$SEC_UPDATES security updates pending (yum)"
                add_rec "Apply pending security updates: yum update --security -y"
            else
                ok "No pending security updates (yum)"
            fi
        elif command -v dnf &>/dev/null; then
            SEC_UPDATES=$(dnf check-update --security 2>/dev/null | grep -c "^[a-zA-Z0-9]" || echo 0)
            if [[ "$SEC_UPDATES" -gt 1 ]]; then
                warn "$SEC_UPDATES security updates pending (dnf)"
                add_rec "Apply pending security updates: dnf update --security -y"
            else
                ok "No pending security updates (dnf)"
            fi
        fi
    fi

    # --- Plesk Security ---
    log "\n  ${BOLD}[7.3] Plesk Security Check${NC}"
    if [[ "$CONTROL_PANEL_NAME" == "plesk" ]]; then
        if command -v plesk &>/dev/null; then
            PLESK_VER=$(plesk version 2>/dev/null | head -1)
            info "Plesk version: $PLESK_VER"
            ok "Manual check: https://www.plesk.com/security-advisories"
            add_rec "Regularly check Plesk security advisories at https://www.plesk.com/security-advisories"
        fi
    fi

    # --- OpenSSL CVE Check ---
    log "\n  ${BOLD}[7.4] OpenSSL Vulnerability Check${NC}"
    if command -v openssl &>/dev/null; then
        OSSL_VER=$(openssl version | awk '{print $2}')
        info "OpenSSL version: $OSSL_VER"
        # Critical known vulnerable ranges
        if echo "$OSSL_VER" | grep -qE "^1\.0\.|^0\."; then
            crit "OpenSSL $OSSL_VER has known critical CVEs — upgrade immediately!"
            add_rec "CRITICAL: OpenSSL $OSSL_VER is vulnerable. Upgrade to OpenSSL 3.x."
        elif echo "$OSSL_VER" | grep -qE "^1\.1\.0"; then
            warn "OpenSSL $OSSL_VER (1.1.0) is EOL — upgrade to 1.1.1 or 3.x"
            add_rec "Upgrade OpenSSL from $OSSL_VER to 3.x for security support."
        else
            ok "OpenSSL $OSSL_VER is in a supported range"
        fi
    fi

    # --- SSL Certificate Check ---
    log "\n  ${BOLD}[7.5] SSL Certificate Expiry${NC}"
    if command -v openssl &>/dev/null; then
        for domain_dir in /etc/ssl/certs /etc/nginx/ssl /usr/local/psa/var/certificates /var/cpanel/ssl; do
            if [ -d "$domain_dir" ]; then
                find "$domain_dir" -name "*.crt" -o -name "*.pem" 2>/dev/null | head -5 | while read -r cert; do
                    EXPIRY=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
                    if [ -n "$EXPIRY" ]; then
                        EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null)
                        NOW_EPOCH=$(date +%s)
                        DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
                        CERT_NAME=$(basename "$cert")
                        if [[ "$DAYS_LEFT" -lt 0 ]]; then
                            crit "SSL cert EXPIRED: $CERT_NAME (expired $EXPIRY)"
                            add_rec "CRITICAL: SSL certificate $CERT_NAME has expired. Renew immediately."
                        elif [[ "$DAYS_LEFT" -lt 14 ]]; then
                            crit "SSL cert expires in $DAYS_LEFT days: $CERT_NAME"
                            add_rec "CRITICAL: SSL cert $CERT_NAME expires in $DAYS_LEFT days. Renew now."
                        elif [[ "$DAYS_LEFT" -lt 30 ]]; then
                            warn "SSL cert expires in $DAYS_LEFT days: $CERT_NAME"
                            add_rec "SSL cert $CERT_NAME expires in $DAYS_LEFT days. Schedule renewal."
                        else
                            ok "SSL cert $CERT_NAME: $DAYS_LEFT days until expiry"
                        fi
                    fi
                done
            fi
        done
    fi

    # --- Listening Services / Open Ports ---
    log "\n  ${BOLD}[7.6] Open Ports / Listening Services${NC}"
    if command -v ss &>/dev/null; then
        OPEN_PORTS=$(ss -tlnp 2>/dev/null)
    elif command -v netstat &>/dev/null; then
        OPEN_PORTS=$(netstat -tlnp 2>/dev/null)
    fi
    if [ -n "$OPEN_PORTS" ]; then
        info "Listening services:"
        echo "$OPEN_PORTS" | grep -E "LISTEN" | awk '{print "    " $4 " " $7}' | tee -a "$REPORT_FILE"
        # Check dangerous common open ports
        DANGEROUS_PORTS=("23:Telnet" "21:FTP" "137:NetBIOS" "139:SMB" "445:SMB" "3306:MySQL-public" "5432:PostgreSQL-public" "6379:Redis-public" "27017:MongoDB-public")
        for port_label in "${DANGEROUS_PORTS[@]}"; do
            PORT=$(echo "$port_label" | cut -d: -f1)
            LABEL=$(echo "$port_label" | cut -d: -f2)
            if echo "$OPEN_PORTS" | grep -q ":${PORT} "; then
                if ! echo "$OPEN_PORTS" | grep ":${PORT} " | grep -q "127.0.0.1\|::1"; then
                    warn "Port $PORT ($LABEL) is publicly exposed!"
                    add_rec "Port $PORT ($LABEL) is listening publicly. Restrict it to localhost or firewall it."
                fi
            fi
        done
        # Telnet specifically
        if command -v systemctl &>/dev/null && systemctl is-active --quiet telnet 2>/dev/null; then
            crit "Telnet service is running — extremely insecure!"
            add_rec "CRITICAL: Disable Telnet immediately. Use SSH instead: systemctl disable telnet --now"
        fi
    fi

    # --- Check for common web vulnerabilities ---
    log "\n  ${BOLD}[7.7] Apache/Nginx Security Headers${NC}"
    HEADERS_OK=0
    if command -v curl &>/dev/null; then
        RESP_HEADERS=$(curl -sI --connect-timeout 5 "http://localhost/" 2>/dev/null || curl -skI --connect-timeout 5 "https://localhost/" 2>/dev/null)
        if [ -n "$RESP_HEADERS" ]; then
            for header in "X-Frame-Options" "X-Content-Type-Options" "Strict-Transport-Security" "Content-Security-Policy"; do
                if echo "$RESP_HEADERS" | grep -qi "$header"; then
                    ok "Security header present: $header"
                    HEADERS_OK=1
                else
                    warn "Security header missing: $header"
                    add_rec "Add HTTP security header '$header' to your web server configuration."
                fi
            done
            # Server version disclosure
            SERVER_HEADER=$(echo "$RESP_HEADERS" | grep -i "^Server:" | head -1)
            if echo "$SERVER_HEADER" | grep -qE "[0-9]+\.[0-9]+"; then
                warn "Web server version disclosed in header: $SERVER_HEADER"
                add_rec "Hide web server version from HTTP headers (ServerTokens Prod for Apache / server_tokens off for Nginx)."
            fi
        fi
    fi
}

# ============================================================
# SECTION 8: FINAL SUMMARY & RECOMMENDATIONS
# ============================================================
print_summary() {
    section "AUDIT SUMMARY & RECOMMENDATIONS"

    log "\n${BOLD}System Overview:${NC}"
    log "  Hostname         : $HOSTNAME"
    log "  Main IP          : $MAIN_IP"
    log "  OS               : $OS_NAME $OS_VERSION"
    log "  EOL Status       : $EOL_STATUS"
    log "  System Type      : $VM_STATUS"
    log "  Control Panel    : ${CONTROL_PANEL_NAME:-None} ${CONTROL_PANEL_VERSION:-}"
    log "  Kernel           : $(uname -r)"
    log "  Active Firewalls : $ACTIVE_FIREWALLS"
    log "  Inactive FWs     : $INACTIVE_FIREWALLS"

    log "\n${BOLD}Audit Statistics:${NC}"
    log "  ${RED}Critical Issues : ${#CRITICAL[@]}${NC}"
    log "  ${YELLOW}Warnings        : ${#WARNINGS[@]}${NC}"
    log "  ${CYAN}Recommendations : ${#RECOMMENDATIONS[@]}${NC}"

    if [[ ${#CRITICAL[@]} -gt 0 ]]; then
        log "\n${RED}${BOLD}━━━ CRITICAL ISSUES (Fix Immediately) ━━━${NC}"
        for i in "${!CRITICAL[@]}"; do
            log "  ${RED}[$((i+1))] ${CRITICAL[$i]}${NC}"
        done
    fi

    if [[ ${#WARNINGS[@]} -gt 0 ]]; then
        log "\n${YELLOW}${BOLD}━━━ WARNINGS (Fix Soon) ━━━${NC}"
        for i in "${!WARNINGS[@]}"; do
            log "  ${YELLOW}[$((i+1))] ${WARNINGS[$i]}${NC}"
        done
    fi

    if [[ ${#RECOMMENDATIONS[@]} -gt 0 ]]; then
        log "\n${CYAN}${BOLD}━━━ RECOMMENDATIONS ━━━${NC}"
        for i in "${!RECOMMENDATIONS[@]}"; do
            log "  ${CYAN}[$((i+1))] ${RECOMMENDATIONS[$i]}${NC}"
        done
    fi

    # Security Score
    SCORE=100
    SCORE=$((SCORE - (${#CRITICAL[@]} * 15)))
    SCORE=$((SCORE - (${#WARNINGS[@]} * 5)))
    [[ $SCORE -lt 0 ]] && SCORE=0

    log "\n${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    if [[ $SCORE -ge 80 ]]; then
        log "${GREEN}${BOLD}  SECURITY SCORE: ${SCORE}/100 — GOOD${NC}"
    elif [[ $SCORE -ge 60 ]]; then
        log "${YELLOW}${BOLD}  SECURITY SCORE: ${SCORE}/100 — NEEDS ATTENTION${NC}"
    else
        log "${RED}${BOLD}  SECURITY SCORE: ${SCORE}/100 — CRITICAL${NC}"
    fi
    log "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log "\n  Full report saved to: $REPORT_FILE"
    log "  Audit completed at: $(date)"
}

# ============================================================
# MAIN EXECUTION
# ============================================================
log "${BOLD}${BLUE}"
log "╔══════════════════════════════════════════════════════════════╗"
log "║         COMPREHENSIVE SERVER SECURITY AUDIT                  ║"
log "║         $(date '+%Y-%m-%d %H:%M:%S')                              ║"
log "╚══════════════════════════════════════════════════════════════╝${NC}"

if [[ $EUID -ne 0 ]]; then
    log "${RED}WARNING: Not running as root. Some checks will be limited.${NC}"
    log "${YELLOW}Recommended: Run with sudo or as root for full audit.${NC}"
fi

log "\nInitializing..."
echo "Starting comprehensive system information and firewall check..."
sleep 1

echo "Collecting system information..."
collect_os_cp_details

echo "Detecting system type..."
detect_vm

echo "Checking EOL status..."
check_eol_status

echo "Scanning firewalls..."
check_firewalls

echo "Getting IP address..."
get_ip_address

# Run all audit sections
audit_threat_protection
audit_software_updates
audit_server_health
audit_backup
audit_software_lifetime
audit_proactive_defence
audit_vulnerabilities
print_summary

log "\n${GREEN}${BOLD}System information check completed!${NC}"