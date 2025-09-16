
Tools Used:

 Ubuntu Server
 UFW (firewall)
fail2ban (ban brute-force attackers)
 SSH (harden access)
 tcpdump, tshark (traffic capture & analysis)

Deliverables:

Before/After state summary
Applied commands list
 Screenshots & evidence
 PCAP and analysis files



 Setup

Terminal A: Admin session (run main commands).
Terminal B: Secondary session (test SSH logins, monitor logs).


sudo -i
mkdir -p /root/network-analysis/{before,captures,analysis,after,report,screenshots}
cd /root/network-analysis


Install required tools:


apt update
apt install -y tcpdump tshark ufw fail2ban net-tools iftop


 1. Collect BEFORE State


hostnamectl > before/hostnamectl.txt
uname -a     > before/uname.txt
df -h        > before/df.txt

ss -tuln     > before/ss_tuln.txt
netstat -tulpen > before/netstat.txt 2>/dev/null || true

ufw status verbose > before/ufw_status.txt 2>/dev/null || true
iptables-save > before/iptables.txt 2>/dev/null || true

cp /etc/ssh/sshd_config before/sshd_config.txt
ss -tnp | grep ssh > before/ssh_listening.txt

systemctl status fail2ban --no-pager > before/fail2ban_status.txt
fail2ban-client status > before/fail2ban_client.txt

tail -n 500 /var/log/auth.log > before/auth_log_tail.txt






 2. Start Packet Capture


mkdir -p /root/network-analysis/captures
nohup tcpdump -i any -s 0 -w captures/capture.pcap -C 200 -W 10 'not (net 127.0.0.0/8)' \
  > captures/tcpdump.nohup 2>&1 &
pgrep -a tcpdump > captures/tcpdump_ps.txt


 3. Monitor Logs (Terminal B)


tail -F /var/log/auth.log | grep --line-buffered -E "Failed password|Invalid user" &
watch -n 2 'ss -tnpa | head -n 50'


 4. SSH Hardening

Backup config


cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F_%T)


 Disable root login


sed -ri 's/^\s*PermitRootLogin\s+.*/PermitRootLogin no/' /etc/ssh/sshd_config \
  || echo 'PermitRootLogin no' >> /etc/ssh/sshd_config


 Test key-based login (Terminal B)


ssh -i /path/to/private_key user@server-ip


Disable password authentication

bash
sed -ri 's/^\s*PasswordAuthentication\s+.*/PasswordAuthentication no/' /etc/ssh/sshd_config \
  || echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
systemctl restart sshd


 5. UFW Firewall

ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw limit OpenSSH

ufw deny 23/tcp
ufw deny 3389/tcp

ufw --force enable
ufw status verbose > after/ufw_status.txt

 6. Fail2ban

apt install -y fail2ban

cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
action = ufw


enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
EOF

systemctl restart fail2ban
fail2ban-client status sshd > after/fail2ban_sshd_status.txt


7. Stop Capture
pkill -f tcpdump
ls -lh captures/ > captures/ls_after_capture.txt




 8. Analyze Captures & Logs


mkdir -p analysis
PCAP=$(ls captures/capture*.pcap | head -n1)

# HTTP Basic auth
tshark -r "$PCAP" -Y "http.authorization" \
  -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri -e http.authorization \
  > analysis/http_auth_headers.txt

# Search for creds
strings captures/capture*.pcap | egrep -i "user(name)?=|password=|Authorization: Basic" \
  > analysis/possible_creds_strings.txt

# FTP creds
tshark -r "$PCAP" -Y 'ftp.request.command == "USER" || ftp.request.command == "PASS"' \
  -T fields -e ftp.request.command -e ftp.request.arg > analysis/ftp_creds.txt

# DNS queries
tshark -r "$PCAP" -Y "dns" -T fields -e dns.qry.name > analysis/dns_queries.txt

# SSH brute force from logs
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr \
  > analysis/failed_pass_counts.txt




9. Collect AFTER State
ss -tuln > after/ss_tuln.txt
ufw status verbose > after/ufw_status.txt
cp /etc/ssh/sshd_config after/sshd_config.txt
systemctl status fail2ban --no-pager > after/fail2ban_status.txt
tail -n 200 /var/log/auth.log > after/auth_log_tail.txt



BEFORE:
- Open ports: see before/ss_tuln.txt
- SSH config: see before/sshd_config.txt
- Firewall: see before/ufw_status.txt
    

ACTIONS:
- Disabled root login
- Enforced key-based auth
- Enabled UFW (deny incoming, allow outgoing, limit SSH)
- Enabled fail2ban for sshd
- Captured and analyzed network traffic

AFTER:
- Open ports: see after/ss_tuln.txt
- SSH config: see after/sshd_config.txt
- Firewall: see after/ufw_status.txt
- Fail2ban active: see after/fail2ban_sshd_status.txt
- Analysis results: see analysis/

Output:
  before/ss_tuln.txt:
      Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0         
tcp   LISTEN 0      128    127.0.0.1:631       0.0.0.0

before/sshd_config.txt:
PermitRootLogin yes
PasswordAuthentication yes  

analysis/failed_pass_counts.txt
15 192.168.1.101
7  203.0.113.5

after/sshd_config.txt
PermitRootLogin no
PasswordAuthentication no

after/ufw_status.txt
Status: active

To                         Action      From
--                         ------      ----
22/tcp (OpenSSH)           ALLOW       Anywhere
22/tcp (OpenSSH (v6))      ALLOW       Anywhere (v6)

after/fail2ban_status.txt
Status
|- Number of jail:      1
`- Jail list:   sshd

sshd jail:
|- Currently banned:    2
|- Total banned:        2
`- Banned IP list: 192.168.1.101 203.0.113.5




Do you also want me to make a **bash script version** of this README (automating everything into a single script), so you just run it once and collect all deliverables automatically?
