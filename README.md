# pfSense Installation Guide

pfSense is a free and open-source Firewall. A free network firewall distribution based on FreeBSD

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 2 cores minimum (4+ cores recommended)
  - RAM: 2GB minimum (4GB+ recommended for production)
  - Storage: 10GB minimum
  - Network: 443 ports required
- **Operating System**: 
  - Linux: Any modern distribution (RHEL, Debian, Ubuntu, CentOS, Fedora, Arch, Alpine, openSUSE)
  - macOS: 10.14+ (Mojave or newer)
  - Windows: Windows Server 2016+ or Windows 10 Pro
  - FreeBSD: 11.0+
- **Network Requirements**:
  - Port 443 (default pfsense port)
  - Firewall rules configured
- **Dependencies**:
  - FreeBSD base system
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Install EPEL repository if needed
sudo dnf install -y epel-release

# Install pfsense
sudo dnf install -y pfsense FreeBSD base system

# Enable and start service
sudo systemctl enable --now pfsense

# Configure firewall
sudo firewall-cmd --permanent --add-service=pfsense || \
  sudo firewall-cmd --permanent --add-port={default_port}/tcp
sudo firewall-cmd --reload

# Verify installation
pfsense --version || systemctl status pfsense
```

### Debian/Ubuntu

```bash
# Update package index
sudo apt update

# Install pfsense
sudo apt install -y pfsense FreeBSD base system

# Enable and start service
sudo systemctl enable --now pfsense

# Configure firewall
sudo ufw allow 443

# Verify installation
pfsense --version || systemctl status pfsense
```

### Arch Linux

```bash
# Install pfsense
sudo pacman -S pfsense

# Enable and start service
sudo systemctl enable --now pfsense

# Verify installation
pfsense --version || systemctl status pfsense
```

### Alpine Linux

```bash
# Install pfsense
apk add --no-cache pfsense

# Enable and start service
rc-update add pfsense default
rc-service pfsense start

# Verify installation
pfsense --version || rc-service pfsense status
```

### openSUSE/SLES

```bash
# Install pfsense
sudo zypper install -y pfsense FreeBSD base system

# Enable and start service
sudo systemctl enable --now pfsense

# Configure firewall
sudo firewall-cmd --permanent --add-service=pfsense || \
  sudo firewall-cmd --permanent --add-port={default_port}/tcp
sudo firewall-cmd --reload

# Verify installation
pfsense --version || systemctl status pfsense
```

### macOS

```bash
# Using Homebrew
brew install pfsense

# Start service
brew services start pfsense

# Verify installation
pfsense --version
```

### FreeBSD

```bash
# Using pkg
pkg install pfsense

# Enable in rc.conf
echo 'pfsense_enable="YES"' >> /etc/rc.conf

# Start service
service pfsense start

# Verify installation
pfsense --version || service pfsense status
```

### Windows

```powershell
# Using Chocolatey
choco install pfsense

# Or using Scoop
scoop install pfsense

# Verify installation
pfsense --version
```

## Initial Configuration

### Basic Configuration

```bash
# Create configuration directory if needed
sudo mkdir -p /cf/conf

# Set up basic configuration
sudo tee /cf/conf/pfsense.conf << 'EOF'
# pfSense Configuration
net.pf.states_hashsize=1048576
EOF

# Set appropriate permissions
sudo chown -R pfsense:pfsense /cf/conf || \
  sudo chown -R $(whoami):$(whoami) /cf/conf

# Test configuration
sudo pfsense --test || sudo pfsense configtest
```

### Security Hardening

```bash
# Create dedicated user (if not created by package)
sudo useradd --system --shell /bin/false pfsense || true

# Secure configuration files
sudo chmod 750 /cf/conf
sudo chmod 640 /cf/conf/*.conf

# Enable security features
# See security section for detailed hardening steps
```

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable service
sudo systemctl enable pfsense

# Start service
sudo systemctl start pfsense

# Stop service
sudo systemctl stop pfsense

# Restart service
sudo systemctl restart pfsense

# Reload configuration
sudo systemctl reload pfsense

# Check status
sudo systemctl status pfsense

# View logs
sudo journalctl -u pfsense -f
```

### OpenRC (Alpine Linux)

```bash
# Enable service
rc-update add pfsense default

# Start service
rc-service pfsense start

# Stop service
rc-service pfsense stop

# Restart service
rc-service pfsense restart

# Check status
rc-service pfsense status

# View logs
tail -f /var/log/pfsense.log
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'pfsense_enable="YES"' >> /etc/rc.conf

# Start service
service pfsense start

# Stop service
service pfsense stop

# Restart service
service pfsense restart

# Check status
service pfsense status
```

### launchd (macOS)

```bash
# Using Homebrew services
brew services start pfsense
brew services stop pfsense
brew services restart pfsense

# Check status
brew services list | grep pfsense

# View logs
tail -f $(brew --prefix)/var/log/pfsense.log
```

### Windows Service Manager

```powershell
# Start service
net start pfsense

# Stop service
net stop pfsense

# Using PowerShell
Start-Service pfsense
Stop-Service pfsense
Restart-Service pfsense

# Check status
Get-Service pfsense

# Set to automatic startup
Set-Service pfsense -StartupType Automatic
```

## Advanced Configuration

### Performance Optimization

```bash
# Configure performance settings
cat >> /cf/conf/pfsense.conf << 'EOF'
# Performance tuning
net.pf.states_hashsize=1048576
EOF

# Apply system tuning
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
echo "vm.swappiness=10" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Restart service to apply changes
sudo systemctl restart pfsense
```

### High Availability Setup

```bash
# Configure clustering/HA (if supported)
# This varies greatly by tool - see official documentation

# Example load balancing configuration
# Configure multiple instances on different ports
# Use HAProxy or nginx for load balancing
```

## Reverse Proxy Setup

### nginx Configuration

```nginx
upstream pfsense_backend {
    server 127.0.0.1:443;
    keepalive 32;
}

server {
    listen 80;
    server_name pfsense.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name pfsense.example.com;

    ssl_certificate /etc/ssl/certs/pfsense.crt;
    ssl_certificate_key /etc/ssl/private/pfsense.key;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";

    location / {
        proxy_pass http://pfsense_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

### Apache Configuration

```apache
<VirtualHost *:80>
    ServerName pfsense.example.com
    Redirect permanent / https://pfsense.example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName pfsense.example.com
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/pfsense.crt
    SSLCertificateKeyFile /etc/ssl/private/pfsense.key
    
    # Security headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options SAMEORIGIN
    Header always set X-XSS-Protection "1; mode=block"
    
    ProxyRequests Off
    ProxyPreserveHost On
    
    <Location />
        ProxyPass http://127.0.0.1:443/
        ProxyPassReverse http://127.0.0.1:443/
    </Location>
    
    # WebSocket support (if needed)
    RewriteEngine on
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/?(.*) "ws://127.0.0.1:443/$1" [P,L]
</VirtualHost>
```

### HAProxy Configuration

```haproxy
global
    maxconn 4096
    log /dev/log local0
    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 5000
    timeout client 50000
    timeout server 50000

frontend pfsense_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/pfsense.pem
    redirect scheme https if !{ ssl_fc }
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header X-Frame-Options SAMEORIGIN
    http-response set-header X-XSS-Protection "1; mode=block"
    
    default_backend pfsense_backend

backend pfsense_backend
    balance roundrobin
    option httpchk GET /health
    server pfsense1 127.0.0.1:443 check
```

### Caddy Configuration

```caddy
pfsense.example.com {
    reverse_proxy 127.0.0.1:443 {
        header_up Host {upstream_hostport}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }
    
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options nosniff
        X-Frame-Options SAMEORIGIN
        X-XSS-Protection "1; mode=block"
    }
    
    encode gzip
}
```

## Security Configuration

### Basic Security Setup

```bash
# Create dedicated user
sudo useradd --system --shell /bin/false --home /cf/conf pfsense || true

# Set ownership
sudo chown -R pfsense:pfsense /cf/conf
sudo chown -R pfsense:pfsense /var/log

# Set permissions
sudo chmod 750 /cf/conf
sudo chmod 640 /cf/conf/*
sudo chmod 750 /var/log

# Configure firewall (UFW)
sudo ufw allow from any to any port 443 proto tcp comment "pfSense"

# Configure firewall (firewalld)
sudo firewall-cmd --permanent --new-service=pfsense
sudo firewall-cmd --permanent --service=pfsense --add-port={default_port}/tcp
sudo firewall-cmd --permanent --add-service=pfsense
sudo firewall-cmd --reload

# SELinux configuration (if enabled)
sudo setsebool -P httpd_can_network_connect on
sudo semanage port -a -t http_port_t -p tcp 443 || true
```

### SSL/TLS Configuration

```bash
# Generate self-signed certificate (for testing)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/pfsense.key \
    -out /etc/ssl/certs/pfsense.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=pfsense.example.com"

# Set proper permissions
sudo chmod 600 /etc/ssl/private/pfsense.key
sudo chmod 644 /etc/ssl/certs/pfsense.crt

# For production, use Let's Encrypt
sudo certbot certonly --standalone -d pfsense.example.com
```

### Fail2ban Configuration

```ini
# /etc/fail2ban/jail.d/pfsense.conf
[pfsense]
enabled = true
port = 443
filter = pfsense
logpath = /var/log/*.log
maxretry = 5
bantime = 3600
findtime = 600
```

```ini
# /etc/fail2ban/filter.d/pfsense.conf
[Definition]
failregex = ^.*Failed login attempt.*from <HOST>.*$
            ^.*Authentication failed.*from <HOST>.*$
            ^.*Invalid credentials.*from <HOST>.*$
ignoreregex =
```

## Database Setup

### PostgreSQL Backend (if applicable)

```bash
# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE pfsense_db;
CREATE USER pfsense_user WITH ENCRYPTED PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE pfsense_db TO pfsense_user;
\q
EOF

# Configure connection in pfSense
echo "DATABASE_URL=postgresql://pfsense_user:secure_password_here@localhost/pfsense_db" | \
  sudo tee -a /cf/conf/pfsense.env
```

### MySQL/MariaDB Backend (if applicable)

```bash
# Create database and user
sudo mysql << EOF
CREATE DATABASE pfsense_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'pfsense_user'@'localhost' IDENTIFIED BY 'secure_password_here';
GRANT ALL PRIVILEGES ON pfsense_db.* TO 'pfsense_user'@'localhost';
FLUSH PRIVILEGES;
EOF

# Configure connection
echo "DATABASE_URL=mysql://pfsense_user:secure_password_here@localhost/pfsense_db" | \
  sudo tee -a /cf/conf/pfsense.env
```

### SQLite Backend (if applicable)

```bash
# Create database directory
sudo mkdir -p /var/lib/pfsense
sudo chown pfsense:pfsense /var/lib/pfsense

# Initialize database
sudo -u pfsense pfsense init-db
```

## Performance Optimization

### System Tuning

```bash
# Kernel parameters for better performance
cat << 'EOF' | sudo tee -a /etc/sysctl.conf
# Network performance tuning
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_tw_reuse = 1

# Memory tuning
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
EOF

# Apply settings
sudo sysctl -p

# Configure system limits
cat << 'EOF' | sudo tee -a /etc/security/limits.conf
pfsense soft nofile 65535
pfsense hard nofile 65535
pfsense soft nproc 32768
pfsense hard nproc 32768
EOF
```

### Application Tuning

```bash
# Configure application-specific performance settings
cat << 'EOF' | sudo tee -a /cf/conf/performance.conf
# Performance configuration
net.pf.states_hashsize=1048576

# Connection pooling
max_connections = 1000
connection_timeout = 30

# Cache settings
cache_size = 256M
cache_ttl = 3600

# Worker processes
workers = 4
threads_per_worker = 4
EOF

# Restart to apply settings
sudo systemctl restart pfsense
```

## Monitoring

### Prometheus Integration

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: 'pfsense'
    static_configs:
      - targets: ['localhost:443/metrics']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### Health Check Script

```bash
#!/bin/bash
# /usr/local/bin/pfsense-health

# Check if service is running
if ! systemctl is-active --quiet pfsense; then
    echo "CRITICAL: pfSense service is not running"
    exit 2
fi

# Check if port is listening
if ! nc -z localhost 443 2>/dev/null; then
    echo "CRITICAL: pfSense is not listening on port 443"
    exit 2
fi

# Check response time
response_time=$(curl -o /dev/null -s -w '%{time_total}' http://localhost:443/health || echo "999")
if (( $(echo "$response_time > 5" | bc -l) )); then
    echo "WARNING: Slow response time: ${response_time}s"
    exit 1
fi

echo "OK: pfSense is healthy (response time: ${response_time}s)"
exit 0
```

### Log Monitoring

```bash
# Configure log rotation
cat << 'EOF' | sudo tee /etc/logrotate.d/pfsense
/var/log/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 pfsense pfsense
    postrotate
        systemctl reload pfsense > /dev/null 2>&1 || true
    endscript
}
EOF

# Test log rotation
sudo logrotate -d /etc/logrotate.d/pfsense
```

## 9. Backup and Restore

### Backup Script

```bash
#!/bin/bash
# /usr/local/bin/pfsense-backup

BACKUP_DIR="/backup/pfsense"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/pfsense_backup_$DATE.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Stop service (if needed for consistency)
echo "Stopping pfSense service..."
systemctl stop pfsense

# Backup configuration
echo "Backing up configuration..."
tar -czf "$BACKUP_FILE" \
    /cf/conf \
    /var/lib/pfsense \
    /var/log

# Backup database (if applicable)
if command -v pg_dump &> /dev/null; then
    echo "Backing up database..."
    sudo -u postgres pg_dump pfsense_db | gzip > "$BACKUP_DIR/pfsense_db_$DATE.sql.gz"
fi

# Start service
echo "Starting pfSense service..."
systemctl start pfsense

# Clean old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE"
```

### Restore Script

```bash
#!/bin/bash
# /usr/local/bin/pfsense-restore

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Stop service
echo "Stopping pfSense service..."
systemctl stop pfsense

# Restore files
echo "Restoring from backup..."
tar -xzf "$BACKUP_FILE" -C /

# Restore database (if applicable)
DB_BACKUP=$(echo "$BACKUP_FILE" | sed 's/.tar.gz$/_db.sql.gz/')
if [ -f "$DB_BACKUP" ]; then
    echo "Restoring database..."
    zcat "$DB_BACKUP" | sudo -u postgres psql pfsense_db
fi

# Fix permissions
chown -R pfsense:pfsense /cf/conf
chown -R pfsense:pfsense /var/lib/pfsense

# Start service
echo "Starting pfSense service..."
systemctl start pfsense

echo "Restore completed successfully"
```

## 6. Troubleshooting

### Common Issues

1. **Service won't start**:
```bash
# Check service status and logs
sudo systemctl status pfsense
sudo journalctl -u pfsense -n 100 --no-pager

# Check for port conflicts
sudo ss -tlnp | grep 443
sudo lsof -i :443

# Verify configuration
sudo pfsense --test || sudo pfsense configtest

# Check permissions
ls -la /cf/conf
ls -la /var/log
```

2. **Cannot access web interface**:
```bash
# Check if service is listening
sudo ss -tlnp | grep pfsense
curl -I http://localhost:443

# Check firewall rules
sudo firewall-cmd --list-all
sudo iptables -L -n | grep 443

# Check SELinux (if enabled)
getenforce
sudo ausearch -m avc -ts recent | grep pfsense
```

3. **High memory/CPU usage**:
```bash
# Monitor resource usage
top -p $(pgrep nginx)
htop -p $(pgrep nginx)

# Check for memory leaks
ps aux | grep nginx
cat /proc/$(pgrep nginx)/status | grep -i vm

# Analyze logs for errors
grep -i error /var/log/*.log | tail -50
```

4. **Database connection errors**:
```bash
# Test database connection
psql -U pfsense_user -d pfsense_db -c "SELECT 1;"
mysql -u pfsense_user -p pfsense_db -e "SELECT 1;"

# Check database service
sudo systemctl status postgresql
sudo systemctl status mariadb
```

### Debug Mode

```bash
# Enable debug logging
echo "debug = true" | sudo tee -a /cf/conf/pfsense.conf

# Restart with debug mode
sudo systemctl stop pfsense
sudo -u pfsense pfsense --debug

# Watch debug logs
tail -f /var/log/debug.log
```

### Performance Analysis

```bash
# Profile CPU usage
sudo perf record -p $(pgrep nginx) sleep 30
sudo perf report

# Analyze network traffic
sudo tcpdump -i any -w /tmp/pfsense.pcap port 443
sudo tcpdump -r /tmp/pfsense.pcap -nn

# Monitor disk I/O
sudo iotop -p $(pgrep nginx)
```

## Integration Examples

### Docker Deployment

```yaml
# docker-compose.yml
version: '3.8'

services:
  pfsense:
    image: pfsense:pfsense
    container_name: pfsense
    restart: unless-stopped
    ports:
      - "443:443"
    environment:
      - TZ=UTC
      - PUID=1000
      - PGID=1000
    volumes:
      - ./config:/cf/conf
      - ./data:/var/lib/pfsense
      - ./logs:/var/log
    networks:
      - pfsense_network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:443/health"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  pfsense_network:
    driver: bridge
```

### Kubernetes Deployment

```yaml
# pfsense-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pfsense
  labels:
    app: pfsense
spec:
  replicas: 1
  selector:
    matchLabels:
      app: pfsense
  template:
    metadata:
      labels:
        app: pfsense
    spec:
      containers:
      - name: pfsense
        image: pfsense:pfsense
        ports:
        - containerPort: 443
        env:
        - name: TZ
          value: UTC
        volumeMounts:
        - name: config
          mountPath: /cf/conf
        - name: data
          mountPath: /var/lib/pfsense
        livenessProbe:
          httpGet:
            path: /health
            port: 443
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 443
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: config
        configMap:
          name: pfsense-config
      - name: data
        persistentVolumeClaim:
          claimName: pfsense-data
---
apiVersion: v1
kind: Service
metadata:
  name: pfsense
spec:
  selector:
    app: pfsense
  ports:
  - protocol: TCP
    port: 443
    targetPort: 443
  type: LoadBalancer
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pfsense-data
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

### Ansible Playbook

```yaml
---
# pfsense-playbook.yml
- name: Install and configure pfSense
  hosts: all
  become: yes
  vars:
    pfsense_version: latest
    pfsense_port: 443
    pfsense_config_dir: /cf/conf
  
  tasks:
    - name: Install dependencies
      package:
        name:
          - FreeBSD base system
        state: present
    
    - name: Install pfSense
      package:
        name: pfsense
        state: present
    
    - name: Create configuration directory
      file:
        path: "{{ pfsense_config_dir }}"
        state: directory
        owner: pfsense
        group: pfsense
        mode: '0750'
    
    - name: Deploy configuration
      template:
        src: pfsense.conf.j2
        dest: "{{ pfsense_config_dir }}/pfsense.conf"
        owner: pfsense
        group: pfsense
        mode: '0640'
      notify: restart pfsense
    
    - name: Start and enable service
      systemd:
        name: pfsense
        state: started
        enabled: yes
        daemon_reload: yes
    
    - name: Configure firewall
      firewalld:
        port: "{{ pfsense_port }}/tcp"
        permanent: yes
        immediate: yes
        state: enabled
  
  handlers:
    - name: restart pfsense
      systemd:
        name: pfsense
        state: restarted
```

### Terraform Configuration

```hcl
# pfsense.tf
resource "aws_instance" "pfsense_server" {
  ami           = var.ami_id
  instance_type = "t3.medium"
  
  vpc_security_group_ids = [aws_security_group.pfsense.id]
  
  user_data = <<-EOF
    #!/bin/bash
    # Install pfSense
    apt-get update
    apt-get install -y pfsense FreeBSD base system
    
    # Configure pfSense
    systemctl enable pfsense
    systemctl start pfsense
  EOF
  
  tags = {
    Name = "pfSense Server"
    Application = "pfSense"
  }
}

resource "aws_security_group" "pfsense" {
  name        = "pfsense-sg"
  description = "Security group for pfSense"
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "pfSense Security Group"
  }
}
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo dnf check-update pfsense
sudo dnf update pfsense

# Debian/Ubuntu
sudo apt update
sudo apt upgrade pfsense

# Arch Linux
sudo pacman -Syu pfsense

# Alpine Linux
apk update
apk upgrade pfsense

# openSUSE
sudo zypper ref
sudo zypper update pfsense

# FreeBSD
pkg update
pkg upgrade pfsense

# Always backup before updates
/usr/local/bin/pfsense-backup

# Restart after updates
sudo systemctl restart pfsense
```

### Regular Maintenance Tasks

```bash
# Clean old logs
find /var/log -name "*.log" -mtime +30 -delete

# Vacuum database (if PostgreSQL)
sudo -u postgres vacuumdb --analyze pfsense_db

# Check disk usage
df -h | grep -E "(/$|pfsense)"
du -sh /var/lib/pfsense

# Update security patches
sudo unattended-upgrade -d

# Review security logs
sudo aureport --summary
sudo journalctl -u pfsense | grep -i "error\|fail\|deny"
```

### Health Monitoring Checklist

- [ ] Service is running and enabled
- [ ] Web interface is accessible
- [ ] Database connections are healthy
- [ ] Disk usage is below 80%
- [ ] No critical errors in logs
- [ ] Backups are running successfully
- [ ] SSL certificates are valid
- [ ] Security updates are applied

## Additional Resources

- Official Documentation: https://docs.pfsense.org/
- GitHub Repository: https://github.com/pfsense/pfsense
- Community Forum: https://forum.pfsense.org/
- Wiki: https://wiki.pfsense.org/
- Docker Hub: https://hub.docker.com/r/pfsense/pfsense
- Security Advisories: https://security.pfsense.org/
- Best Practices: https://docs.pfsense.org/best-practices
- API Documentation: https://api.pfsense.org/
- Comparison with OPNsense, IPFire, Sophos, FortiGate: https://docs.pfsense.org/comparison

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.
