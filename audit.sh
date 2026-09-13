#!/bin/bash

pass_count=0
info_count=0
warn_count=0
critical_count=0

risk_score=0
risk_level="LOW"

print_finding(){
	local severity="$1"
	local finding_id="$2" 
	local message="$3"

	echo "[$severity] $finding_id | $message"

	case "$severity" in
        	PASS)
           		 pass_count=$((pass_count + 1))
            		 ;;
        	INFO)
            		info_count=$((info_count + 1))
           		 ;;
       		WARN)
            		warn_count=$((warn_count + 1))
           		 ;;
        	CRITICAL)
           		 critical_count=$((critical_count + 1))
            		 ;;
   	 esac	
}

print_recommendation() {
    local recommendation="$1"
    echo "       Recommendation: $recommendation"
}

echo "==================================="
echo "    LINUX SECURITY AUDITOR         "
echo "==================================="

echo ""
echo "[1] System Information"
echo "----------------------------------------"
echo "Hostname      : $(hostname)"
echo "OS            : $(. /etc/os-release && echo "$PRETTY_NAME")"
echo "Kernel        : $(uname -r)"
echo "Architecture  : $(uname -m)"
echo "Virtualization: $(systemd-detect-virt 2>/dev/null || echo "Unknown")"

echo ""
echo "[2] Firewall Status"
echo "----------------------------------------"

if command -v ufw > /dev/null 2>&1; then
        if sudo ufw status | grep -q "Status: active"; then
                print_finding "PASS" "NET-001" "UFW firewall is active"
        else
                print_finding "WARN" "NET-001" "UFW firewall is inactive"
		print_recommendation "Enable and configure the UFW firewall."
	fi
else
	echo "[INFO] UFW is not installed"
fi

echo ""
echo "[3] SSH Server Check"
echo "----------------------------------------"

if command -v sshd >/dev/null 2>&1; then
    echo "[INFO] SSH server is installed"

    if systemctl is-active --quiet ssh; then
        print_finding "INFO" "NET-002" "SSH server is running"

        if sudo grep -RqsE "^[[:space:]]*PermitRootLogin[[:space:]]+no" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null; then
            echo "[PASS] SSH root login is disabled"
        else
            print_finding "INFO" "NET-002" "SSH root login may be enabled"
        fi
    else
        echo "[PASS] SSH server is installed but not running"
    fi
else
    print_finding "INFO" "NET-002" "SSH server is not installed"
fi

echo ""
echo "[4] User Account Check"
echo "----------------------------------------"

uid_zero_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)

if [ "$uid_zero_users" = "root" ]; then
	print_finding "PASS" "AUTH-001" "Only root has UID 0"
else
	print_finding "CRITICAL" "AUTH-001" "Multiple accounts have UID 0"
	echo "$uid_zero_users"
fi

echo ""
echo "[INFO] NORMAL USER ACCOUNTS:"
awk -F: '$3 >= 1000 && $3 < 65534 {print $1, $3, $7}' /etc/passwd 

echo ""
echo "[5] Password Status Check"
echo "----------------------------------------"

for user in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do

    password_status=$(sudo awk -F: -v u="$user" '$1 == u {print $2}' /etc/shadow)

    if [ -z "$password_status" ]; then
        echo "[WARN] $user has no password configured"
    
    elif [[ "$password_status" == !* || "$password_status" == \** ]]; then
        print_finding "PASS" "AUTH-002" "$user password login is locked / disabled"
    else
        print_finding "INFO" "AUTH-002" "$user has an active password configured"
    fi

done

echo ""
echo "[6] Sudo Privilege Check"
echo "----------------------------------------"

sudo_users=$(getent group sudo | cut -d: -f4)

if [ -z "$sudo_users" ]; then
	echo "[PASS] No user with sudo privileges found"
else
	print_finding "INFO" "AUTH-003" "Users with sudo privileges: "
	echo "$sudo_users"
fi

echo ""
echo "[7] File Permissions Check"
echo "----------------------------------------"


world_writable_files=$(sudo find / -xdev -type f -perm -0002 -print 2>/dev/null)

if [ -z "$world_writable_files" ]; then
	print_finding "PASS" "FILE-001" "No world-writable files detected"
else
	print_finding "WARN" "FILE-001" "World-writable files detected: "
	echo "$world_writable_files" | head -20
fi

echo ""
echo "[8] SUID File Check"
echo "----------------------------------------"

suid_files=$(sudo find / -xdev -type f -perm -4000 -print 2>/dev/null)

if [ -z "$suid_files" ]; then
	echo "[PASS] No SUID files "
else
	suid_count=$(echo "$suid_files" | wc -l)
	print_finding "INFO" "FILE-002" "$suid_count SUID files detected"
fi

echo ""
echo "[9] Network Port Check"
echo "----------------------------------------"

listening_ports=$(sudo ss -tulnp | awk 'NR>1 && ($5 ~ /^0\.0\.0\.0:/ || $5 ~ /^\[::\]:/)')

if [ -z "$listening_ports" ]; then
    echo "[PASS] No network-facing ports detected"
else
    print_finding "INFO" "NET-003" "Network-facing ports detected: "
    echo "$listening_ports"
fi

echo ""
echo "[10] System Updates Check"
echo "----------------------------------------"

updates=$(apt list --upgradable 2>/dev/null | tail -n +2)

if [ -z "$updates" ]; then
	echo "[PASS] System is up to date"
else
	updates_count=$(echo "$updates" | wc -l)
	print_finding "WARN" "SYS-002" "$updates_count package updates are available"
	print_recommendation "Review and install available system updates."
	echo "[INFO] Run 'sudo apt upgrade' to install updates"
fi

echo ""
echo "[11] Cron Job Check"
echo "----------------------------------------"

root_cron=$(sudo crontab -l 2>/dev/null)

if [ -z "$root_cron" ]; then
	print_finding "PASS" "PERSIST-001" "No root user cron jobs configured"
else
	echo "[WARN] Root cron jobs detected: " 
	echo "$root_cron"
fi

cron_files=$(sudo find /etc/cron.d /etc/cron.daily /etc/cron.hourly)

if [ -n "$cron_files" ]; then
	echo "[INFO] System cron entries detected: "
	echo "$cron_files"
fi

echo ""
echo "[12] Failed Authentication Check"
echo "----------------------------------------"

failed_logins=$(sudo grep -ai "authentication failure" /var/log/auth.log 2>/dev/null | grep -v "COMMAND")

if [ -z "$failed_logins" ]; then
	echo "Total Failures: 0"
	print_finding "PASS" "AUTH-004" "No authentication failures detected"
else
	failed_count=$(echo "$failed_logins" | wc -l)
	echo "Total Failures: $failed_count"
	echo "Recent Failures: "
	        echo "$failed_logins" | head -10 | awk '{print NR ".", "Time:", $1, " | User:", $NF}'
	
	echo ""
	print_finding "WARN" "AUTH-004" "Authentication failures detected"
	print_recommendation "Review authentication logs and investigate repeated failures."
fi

echo ""
echo "[13] System Error Check"
echo "----------------------------------------"

system_errors=$(sudo journalctl -p err -b --no-pager 2>/dev/null)

if [ -z "$system_errors" ]; then
	echo "Errors Detected: 0"
	print_finding "PASS" "SYS-003" "No system errors detected"
else
	error_count=$(echo "$sysytem_errors" | wc -l)
	echo "Errors detected: $error_count"
	print_finding "WARN" "SYS-003" "System errors detected"
	print_recommendation "Review recent system errors and investigate recurring failures."
fi

echo ""
echo "[14] Password Aging Check"
echo "----------------------------------------"

for user in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do
	
	expiry=$(sudo chage -l "$user" 2>/dev/null | grep "Password expires")

	if echo "$expiry" | grep -q "never"; then
		print_finding "WARN" "AUTH-005" "$user password never expires"
		print_recommendation "Configure an appropriate password expiration policy."
	else
		print_finding "PASS" "AUTH-005" "$user has password expiration configured"
	fi

done

echo ""
echo "[15] World-Writable Directory Check"
echo "----------------------------------------"

writable_d=$(sudo find / -xdev -type d -perm -0002 -print 2>/dev/null)

if [ -z "$writable_d" ]; then
	print_finding "PASS" "FILE-003" "No world-writable directories detected"
else
	d_count=$(echo "$writable_d" | wc -l)
	print_finding "INFO" "FILE-003" "$d_count world-writable directories detected"
	echo "Review these directories to identify unexpected writable locations: "
	echo "$writable_d"
fi

# Calculate risk score
risk_score=$((info_count * 1 + warn_count * 5 + critical_count * 10))

if [ "$risk_score" -ge 50 ]; then
    risk_level="HIGH"
elif [ "$risk_score" -ge 25 ]; then
    risk_level="MEDIUM"
else
    risk_level="LOW"
fi

echo ""
echo "==================================="
echo "          AUDIT SUMMARY"
echo "==================================="
echo "PASS     : $pass_count"
echo "INFO     : $info_count"
echo "WARN     : $warn_count"
echo "CRITICAL : $critical_count"
echo ""
echo "Risk Score : $risk_score/100"
echo "Risk Level : $risk_level"
