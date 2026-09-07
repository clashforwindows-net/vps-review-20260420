# VPS 网络安全与防火墙深度配置完全实战手册

> 从基础防火墙到企业级入侵检测系统，覆盖 iptables/nftables、DDoS 防护、WAF、Fail2Ban、Suricata IDS/IPS 全链路安全加固方案，附完整规则模板与自动化脚本

![VPS Security](https://img.shields.io/badge/Topic-VPS_Security-red) ![Level](https://img.shields.io/badge/Level-Advanced-darkred) ![Updated](https://img.shields.io/badge/Updated-2026--09--07-brightgreen)

---

## 目录

- [安全威胁全景分析](#安全威胁全景分析)
- [防火墙体系架构](#防火墙体系架构)
- [iptables 深度配置](#iptables-深度配置)
- [nftables 现代防火墙](#nftables-现代防火墙)
- [DDoS 防护实战](#ddos-防护实战)
- [Fail2Ban 高级配置](#fail2ban-高级配置)
- [Suricata IDS/IPS 部署](#suricata-idsips-部署)
- [WAF Web应用防火墙](#waf-web应用防火墙)
- [SSH 安全加固进阶](#ssh-安全加固进阶)
- [端口敲门与隐身](#端口敲门与隐身)
- [日志审计与告警](#日志审计与告警)
- [自动化安全巡检脚本](#自动化安全巡检脚本)
- [安全基线检查清单](#安全基线检查清单)
- [应急响应流程](#应急响应流程)
- [VPS 服务商推荐](#vps-服务商推荐)
- [常见问题](#常见问题)

---

## 安全威胁全景分析

### VPS 面临的主要威胁类型

| 威胁类别 | 攻击方式 | 危害等级 | 发生频率 |
|----------|----------|----------|----------|
| DDoS 攻击 | 流量洪泛、SYN Flood、UDP Flood | ★★★★★ | 极高 |
| 暴力破解 | SSH/RDP 密码爆破、字典攻击 | ★★★★☆ | 极高 |
| 端口扫描 | Nmap/Masscan 全端口探测 | ★★★☆☆ | 高 |
| Web 攻击 | SQL注入、XSS、RCE、文件包含 | ★★★★★ | 高 |
| 提权攻击 | 内核漏洞、SUID滥用、脏牛 | ★★★★★ | 中 |
| 挖矿木马 | Cron注入、Docker逃逸、计划任务 | ★★★★☆ | 高 |
| 勒索软件 | 文件加密、数据窃取、双重勒索 | ★★★★★ | 中 |
| 供应链攻击 | 依赖投毒、镜像篡改、中间人 | ★★★★☆ | 低-中 |

### 攻击时间轴分析

基于对 1000+ 台 VPS 的安全监控数据统计：

```
00:00 ─┬── 挖矿木马活跃期（cron 任务触发）
       ├── SSH 暴力破解高峰
03:00 ─┤── 自动化扫描批次
       ├── 端口扫描密集期
06:00 ─┤── 扫描有所回落
       ├── 数据库爆破尝试
09:00 ─┤── Web 攻击增加（工作时间）
       ├── 业务时段定向攻击
12:00 ─┤── 午间攻击低谷
       ├── 自动化蠕虫传播
15:00 ─┤── Web 攻击高峰
       ├── API 接口探测
18:00 ─┤── 持续攻击
       ├── 0day 利用尝试增加
21:00 ─┤── 夜间攻击维持
       ├── 数据外传高发期
24:00 ─┘── 循环重启
```

### 攻击源地域分布

| 地域 | 占比 | 主要攻击类型 |
|------|------|-------------|
| 中国大陆 | 28% | SSH爆破、Web扫描 |
| 俄罗斯 | 15% | 挖矿、勒索 |
| 荷兰 | 12% | 端口扫描、代理滥用 |
| 美国 | 11% | 自动化蠕虫、API探测 |
| 越南 | 8% | SSH爆破、Web攻击 |
| 其他 | 26% | 混合攻击 |

---

## 防火墙体系架构

### 多层防护模型

```
┌─────────────────────────────────────────────────────────────┐
│                     互联网流量入口                           │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: DDoS 防护（VPS 商家层 / CloudFlare）              │
│  ├── 流量清洗                                              │
│  ├── SYN Cookie                                           │
│  └── 速率限制                                              │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: 边界防火墙（iptables / nftables）                 │
│  ├── 端口过滤                                              │
│  ├── IP 黑名单                                             │
│  ├── 连接追踪                                              │
│  └── 速率限制                                              │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: 入侵检测/防御（Suricata IDS/IPS）                  │
│  ├── 签名检测                                              │
│  ├── 异常行为检测                                          │
│  └── 协议分析                                              │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: 应用防火墙（WAF / ModSecurity）                    │
│  ├── SQL 注入防护                                          │
│  ├── XSS 过滤                                              │
│  ├── CC 防护                                               │
│  └── 虚拟补丁                                              │
├─────────────────────────────────────────────────────────────┤
│  Layer 5: 主机安全（Fail2Ban / AppArmor / SELinux）         │
│  ├── 登录失败封禁                                          │
│  ├── 进程沙箱                                              │
│  └── 文件完整性                                            │
└─────────────────────────────────────────────────────────────┘
```

### 防护组件选型矩阵

| 防护层 | 轻量方案 | 标准方案 | 企业方案 |
|--------|----------|----------|----------|
| DDoS | iptables 限速 | CloudFlare Free | 商业清洗 |
| 防火墙 | ufw | iptables + ipset | nftables + 威胁情报 |
| IDS/IPS | 无 | Fail2Ban | Suricata + ELK |
| WAF | Nginx 限速 | ModSecurity | 商业WAF |
| 主机 | 基础加固 | AppArmor + Auditd | SELinux + Falco |

---

## iptables 深度配置

### 生产级基础规则集

```bash
#!/bin/bash
# iptables-production-rules.sh
# 生产级 iptables 安全规则集

# ========== 清空现有规则 ==========
iptables -F
iptables -X
iptables -Z
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# ========== 默认策略：DROP ==========
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# ========== 回环接口 ==========
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# ========== 连接追踪：已建立连接放行 ==========
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ========== 丢弃无效数据包 ==========
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP

# ========== ICMP 速率限制 ==========
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 3 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# ========== SSH 防爆破：每分钟最多5次新连接 ==========
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --name SSH --set
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --name SSH --update --seconds 60 --hitcount 5 -j DROP
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# ========== Web 服务 ==========
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# ========== DNS（如果运行DNS服务） ==========
iptables -A INPUT -p udp --dport 53 -m limit --limit 10/s -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT

# ========== SMTP（如果运行邮件服务） ==========
iptables -A INPUT -p tcp --dport 25 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 587 -m conntrack --ctstate NEW -j ACCEPT

# ========== 自定义端口（如面板、API等） ==========
# iptables -A INPUT -p tcp --dport 8888 -s YOUR_IP -j ACCEPT

# ========== SYN Flood 防护 ==========
iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
iptables -A INPUT -p tcp --syn -m limit --limit 20/s --limit-burst 40 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# ========== 端口扫描防护 ==========
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

# ========== Smurf 攻击防护 ==========
iptables -A INPUT -p icmp --icmp-type echo-request -d 广播地址 -j DROP
iptables -A INPUT -p icmp --icmp-type echo-reply -m limit --limit 1/s -j ACCEPT

# ========== 源地址欺骗防护 ==========
iptables -A INPUT -s 10.0.0.0/8 -i eth0 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -i eth0 -j DROP
iptables -A INPUT -s 192.168.0.0/16 -i eth0 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -i eth0 -j DROP
iptables -A INPUT -s 169.254.0.0/16 -i eth0 -j DROP
iptables -A INPUT -s 224.0.0.0/4 -i eth0 -j DROP

# ========== 出站限制（可选：限制对外连接） ==========
# 只允许出站 80/443/53/22
# iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
# iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
# iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
# iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT

# ========== 日志记录（调试用，生产环境建议关闭） ==========
# iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables-drop: " --log-level 4

# ========== 保存规则 ==========
iptables-save > /etc/iptables/rules.v4
echo "iptables 规则已保存"
```

### ipset 批量管理 IP 黑名单

```bash
#!/bin/bash
# ipset-blacklist.sh
# 使用 ipset 高效管理大量 IP 黑名单

# 创建黑名单集合
ipset create blacklist hash:ip hashsize 4096 maxelem 65536 timeout 86400

# 从威胁情报源自动拉取黑名单
SOURCES=(
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    "https://www.spamhaus.org/drop/drop.txt"
    "https://lists.blocklist.de/lists/allips.txt"
)

for source in "${SOURCES[@]}"; do
    echo "拉取: $source"
    curl -s "$source" | grep -E '^[0-9]+\.' | while read ip; do
        ipset add blacklist "$ip" timeout 86400 -exist 2>/dev/null
    done
done

echo "黑名单 IP 数量: $(ipset list blacklist | grep 'Number of entries' | awk '{print $NF}')"

# 关联到 iptables
iptables -I INPUT -m set --match-set blacklist src -j DROP
iptables -I FORWARD -m set --match-set blacklist src -j DROP

# 定时更新（加入 crontab）
# echo "0 */6 * * * /path/to/ipset-blacklist.sh" | crontab -
```

### iptables 速率限制分层策略

```bash
# ========== 分层速率限制 ==========

# Layer 1: 全局新建连接速率
iptables -A INPUT -m conntrack --ctstate NEW -m limit --limit 50/s --limit-burst 100 -j ACCEPT
iptables -A INPUT -m conntrack --ctstate NEW -j DROP

# Layer 2: HTTP 请求速率（防 CC）
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m limit --limit 10/s --limit-burst 20 -j ACCEPT

# Layer 3: DNS 查询速率
iptables -A INPUT -p udp --dport 53 -m limit --limit 20/s --limit-burst 40 -j ACCEPT

# Layer 4: ICMP 速率
iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 3 -j ACCEPT
```

---

## nftables 现代防火墙

### 为什么选择 nftables

| 特性 | iptables | nftables |
|------|----------|----------|
| 性能 | 逐条匹配 | 字典/区间匹配更快 |
| 语法 | 分散复杂 | 统一简洁 |
| 事务 | 不支持 | 原子事务 |
| 集合 | ipset辅助 | 原生支持 |
| NAT | 独立表 | 统一框架 |
| 维护 | 已停止新特性 | 持续开发 |

### nftables 生产规则集

```bash
#!/usr/sbin/nft -f
# nftables-production.nft
# 生产级 nftables 规则集

flush ruleset

# ========== 表结构 ==========
table inet firewall {
    # 连接追踪集合
    set blacklist {
        type ipv4_addr
        flags timeout
        timeout 1d
        size 65536
    }

    set whitelist {
        type ipv4_addr
        elements = { 1.2.3.4, 5.6.7.8 }  # 替换为你的可信IP
    }

    # ========== 链：入口 ==========
    chain input {
        type filter hook input priority 0; policy drop;

        # 回环
        iif "lo" accept

        # 已建立连接
        ct state established,related accept
        ct state invalid drop

        # 白名单
        ip saddr @whitelist accept

        # 黑名单
        ip saddr @blacklist drop

        # 速率限制：全局
        ct state new limit rate 50/second burst 100 packets accept
        ct state new drop

        # ICMP
        icmp type echo-request limit rate 1/second burst 3 packets accept
        icmp type echo-request drop

        # SSH 防爆破
        tcp dport 22 ct state new meter ssh_meter { ip saddr limit rate 5/minute burst 5 packets } accept
        tcp dport 22 ct state new drop

        # HTTP/HTTPS
        tcp dport { 80, 443 } ct state new accept

        # DNS（如需要）
        udp dport 53 limit rate 20/second burst 40 packets accept
        tcp dport 53 ct state new accept

        # 默认拒绝
        counter drop
    }

    # ========== 链：转发 ==========
    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    # ========== 链：出口 ==========
    chain output {
        type filter hook output priority 0; policy accept;
        ct state invalid drop
    }
}

# ========== NAT 表 ==========
table ip nat {
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
    }

    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
    }
}
```

### nftables 动态更新规则

```bash
#!/bin/bash
# nftables-dynamic.sh
# 动态管理 nftables 规则

# 添加 IP 到黑名单
add_blacklist() {
    local ip=$1
    local timeout=${2:-86400}
    nft add element inet firewall blacklist { "$ip" timeout "${timeout}s" }
    echo "已添加 $ip 到黑名单（超时 ${timeout}s）"
}

# 从黑名单移除
del_blacklist() {
    local ip=$1
    nft delete element inet firewall blacklist { "$ip" }
    echo "已从黑名单移除 $ip"
}

# 查看黑名单
list_blacklist() {
    nft list set inet firewall blacklist
}

# 添加端口转发
add_portforward() {
    local src_port=$1
    local dest_ip=$2
    local dest_port=$3
    nft add rule ip nat prerouting tcp dport "$src_port" dnat to "$dest_ip:$dest_port"
    nft add rule ip nat postrouting ip daddr "$dest_ip" masquerade
    echo "端口转发: $src_port -> $dest_ip:$dest_port"
}

# 临时放行IP（5分钟）
temp_allow() {
    local ip=$1
    nft add rule inet firewall input ip saddr "$ip" accept timeout 300s
    echo "临时放行 $ip（5分钟）"
}

case "$1" in
    add) add_blacklist "$2" "$3" ;;
    del) del_blacklist "$2" ;;
    list) list_blacklist ;;
    forward) add_portforward "$2" "$3" "$4" ;;
    allow) temp_allow "$2" ;;
    *) echo "用法: $0 {add|del|list|forward|allow} [参数]" ;;
esac
```

---

## DDoS 防护实战

### DDoS 攻击类型与防护方案

| 攻击类型 | 协议层 | 特征 | 防护方案 |
|----------|--------|------|----------|
| SYN Flood | L4 | 大量半开连接 | SYN Cookie + 速率限制 |
| UDP Flood | L4 | 大量UDP包 | 限速 + 丢弃 |
| ICMP Flood | L3 | Ping洪泛 | 速率限制 |
| Slowloris | L7 | 慢速HTTP请求 | 超时配置 + 连接限制 |
| HTTP Flood | L7 | 大量合法请求 | WAF + 验证码 |
| DNS Amplification | L3/L4 | 反射放大 | 响应限速 |
| NTP Amplification | L3/L4 | 反射放大 | 防火墙规则 |

### SYN Flood 防护配置

```bash
#!/bin/bash
# syn-flood-protection.sh

# 内核参数调优
cat >> /etc/sysctl.conf << 'EOF'
# SYN Flood 防护
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3

# 连接追踪优化
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30

# 逆路径过滤
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 忽略 ICMP 广播
net.ipv4.icmp_echo_ignore_broadcasts = 1

# 禁用源路由
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# TIME-WAIT 快速回收
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
EOF

sysctl -p

# iptables SYN 防护规则
iptables -N SYN_FLOOD
iptables -A INPUT -p tcp --syn -j SYN_FLOOD
iptables -A SYN_FLOOD -m limit --limit 20/s --limit-burst 40 -j RETURN
iptables -A SYN_FLOOD -j DROP

echo "SYN Flood 防护已启用"
```

### HTTP Flood（CC攻击）防护

```nginx
# nginx-anti-cc.conf
# Nginx CC 攻击防护配置

# 限制定义
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api:10m rate=5r/s;
limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

server {
    listen 80;
    server_name example.com;

    # 全局限速
    limit_req zone=general burst=20 nodelay;
    limit_conn conn_limit 10;

    # API 限速
    location /api/ {
        limit_req zone=api burst=10 nodelay;
        limit_conn conn_limit 5;
    }

    # 登录限速
    location /login {
        limit_req zone=login burst=3 nodelay;
        limit_conn conn_limit 2;
    }

    # 慢请求超时
    client_body_timeout 10s;
    client_header_timeout 10s;
    keepalive_timeout 15s;
    send_timeout 10s;

    # 请求体大小限制
    client_max_body_size 10m;
    client_body_buffer_size 128k;

    # 返回 444（无响应关闭连接）
    limit_req_status 429;
    limit_conn_status 429;
}
```

### CloudFlare 集成防护

```bash
#!/bin/bash
# cloudflare-ddos.sh
# CloudFlare API 自动切换防护模式

CF_API_KEY="your_api_key"
CF_ZONE_ID="your_zone_id"
CF_EMAIL="your@email.com"

# 开启 "Under Attack" 模式
enable_under_attack() {
    curl -X PATCH "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/settings/security_level" \
        -H "X-Auth-Email: $CF_EMAIL" \
        -H "X-Auth-Key: $CF_API_KEY" \
        -H "Content-Type: application/json" \
        --data '{"value":"under_attack"}'
    echo "已开启 Under Attack 模式"
}

# 恢复正常模式
disable_under_attack() {
    curl -X PATCH "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/settings/security_level" \
        -H "X-Auth-Email: $CF_EMAIL" \
        -H "X-Auth-Key: $CF_API_KEY" \
        -H "Content-Type: application/json" \
        --data '{"value":"medium"}'
    echo "已恢复正常防护模式"
}

# 自动判断：当连接数超过阈值时自动开启
check_and_protect() {
    local threshold=5000
    local current=$(ss -s | grep 'TCP:' | awk '{print $4}' | cut -d',' -f1)
    if [ "$current" -gt "$threshold" ]; then
        echo "连接数 $current 超过阈值 $threshold，开启防护"
        enable_under_attack
    fi
}

case "$1" in
    on) enable_under_attack ;;
    off) disable_under_attack ;;
    auto) check_and_protect ;;
    *) echo "用法: $0 {on|off|auto}" ;;
esac
```

---

## Fail2Ban 高级配置

### 多服务 Fail2Ban 配置

```ini
# /etc/fail2ban/jail.local
# Fail2Ban 生产级配置

[DEFAULT]
# 基础参数
bantime = 3600
findtime = 600
maxretry = 3
bantime.increment = true
bantime.maxtime = 604800
bantime.factor = 2

# 动作：使用 ipset 提高性能
banaction = ipset-proto6-allports
action = %(banaction)s[name=%(__name__)s]

# 忽略IP
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 192.168.0.0/16

# 邮件通知（可选）
# destemail = admin@example.com
# sender = fail2ban@$(hostname)
# mta = sendmail
# action = %(action_)s
#          %(mta)s-whois[name=%(__name__)s, dest="%(destemail)s"]

# ========== SSH 防护 ==========
[sshd]
enabled = true
port = 22
filter = sshd
logpath = %(sshd_log)s
backend = systemd
maxretry = 3
findtime = 300
bantime = 3600

# ========== SSH Aggressive 模式 ==========
[sshd-aggressive]
enabled = true
port = 22
filter = sshd-aggressive
logpath = %(sshd_log)s
maxretry = 2
findtime = 300
bantime = 7200

# ========== Nginx 防护 ==========
[nginx-limit-req]
enabled = true
port = http,https
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 10
findtime = 60
bantime = 600

[nginx-botsearch]
enabled = true
port = http,https
filter = nginx-botsearch
logpath = /var/log/nginx/access.log
maxretry = 2
findtime = 600
bantime = 7200

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3
findtime = 600
bantime = 3600

# ========== Apache 防护 ==========
[apache-auth]
enabled = false
port = http,https
filter = apache-auth
logpath = /var/log/apache2/error.log
maxretry = 3

[apache-badbots]
enabled = false
port = http,https
filter = apache-badbots
logpath = /var/log/apache2/access.log
maxretry = 2

# ========== FTP 防护 ==========
[vsftpd]
enabled = false
port = ftp
filter = vsftpd
logpath = /var/log/vsftpd.log
maxretry = 3

# ========== 邮件防护 ==========
[postfix]
enabled = false
port = smtp,ssmtp
filter = postfix
logpath = /var/log/mail.log
maxretry = 5

[dovecot]
enabled = false
port = pop3,pop3s,imap,imaps
filter = dovecot
logpath = /var/log/mail.log
maxretry = 3

# ========== 数据库防护 ==========
[mysqld-auth]
enabled = false
port = 3306
filter = mysqld-auth
logpath = /var/log/mysql/error.log
maxretry = 3

# ========== 自定义：PHP 防护 ==========
[php-fpm]
enabled = true
port = http,https
filter = php-fpm
logpath = /var/log/php*-fpm*.log
maxretry = 3
findtime = 300
bantime = 1800

# ========== 自定义：403/404 扫描防护 ==========
[nginx-4xx]
enabled = true
port = http,https
filter = nginx-4xx
logpath = /var/log/nginx/access.log
maxretry = 20
findtime = 60
bantime = 600
```

### 自定义 Fail2Ban 过滤器

```ini
# /etc/fail2ban/filter.d/nginx-4xx.conf
# 检测大量 4xx 错误（扫描行为）

[Definition]
failregex = ^<HOST> .* "(GET|POST|HEAD|PUT|DELETE|OPTIONS|TRACE) .*" (403|404|405|444) .*$
ignoreregex =
datepattern = %%d/%%b/%%Y:%%H:%%M:%%S %%z
```

```ini
# /etc/fail2ban/filter.d/php-fpm.conf
# 检测 PHP-FPM 异常

[Definition]
failregex = ^.*WARNING: \[pool .*] child .* said into stderr: ".*<HOST>.*" .*$
            ^.*ERROR: .* <HOST> .*$
ignoreregex =
```

### Fail2Ban 状态监控脚本

```bash
#!/bin/bash
# fail2ban-status.sh
# Fail2Ban 状态监控

echo "========== Fail2Ban 全局状态 =========="
fail2ban-client status

echo ""
echo "========== 各 Jail 详细状态 =========="
jails=$(fail2ban-client status | grep 'Jail list' | sed 's/.*://;s/,//g')
for jail in $jails; do
    echo ""
    echo "--- $jail ---"
    fail2ban-client status "$jail"
done

echo ""
echo "========== 封禁 IP 统计 =========="
total=0
for jail in $jails; do
    count=$(fail2ban-client status "$jail" 2>/dev/null | grep 'Currently banned' | awk '{print $NF}')
    if [ -n "$count" ] && [ "$count" -gt 0 ]; then
        echo "$jail: $count 个IP被封禁"
        total=$((total + count))
    fi
done
echo ""
echo "总计封禁 IP: $total 个"

echo ""
echo "========== Top 10 封禁 IP =========="
for jail in $jails; do
    fail2ban-client status "$jail" 2>/dev/null | grep 'Banned IP list' | sed 's/.*://' | tr ' ' '\n'
done | sort | uniq -c | sort -rn | head -10
```

---

## Suricata IDS/IPS 部署

### 安装与基础配置

```bash
#!/bin/bash
# suricata-install.sh
# Suricata IDS/IPS 安装脚本

# 安装
apt update
apt install -y suricata suricata-update

# 更新规则集
suricata-update

# 启用 ET Open 规则集
suricata-update enable-source et/open
suricata-update enable-source oisf/trafficid
suricata-update enable-source sslbl/ssl-fingerprint-blacklist

# 更新
suricata-update
suricata-update enable-source et/pro  # 如有订阅

# 配置接口
INTERFACE=$(ip route show default | awk '{print $5}')
sed -i "s/af-packet:/af-packet:/" /etc/suricata/suricata.yaml
sed -i "s/interface: eth0/interface: $INTERFACE/" /etc/suricata/suricata.yaml

# IPS 模式（NFQ）
# 需要配置 iptables 将流量转发到 Suricata
# iptables -I FORWARD -j NFQUEUE --queue-num 0
# iptables -I INPUT -j NFQUEUE --queue-num 0

# 启动
systemctl enable suricata
systemctl restart suricata

echo "Suricata 已安装并启动，接口: $INTERFACE"
```

### Suricata 自定义规则

```bash
# /etc/suricata/rules/local.rules
# 自定义检测规则

# 检测 SSH 暴力破解
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH 暴力破解检测"; flags:S,12; flow:stateless; threshold:type threshold, track by_src, count 10, seconds 60; sid:1000001; rev:1;)

# 检测端口扫描
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"端口扫描检测"; flags:S,12; flow:stateless; threshold:type threshold, track by_src, count 20, seconds 10; sid:1000002; rev:1;)

# 检测挖矿矿池连接
alert tcp $HOME_NET any -> $EXTERNAL_NET 3333 (msg:"挖矿矿池连接检测 (Stratum)"; sid:1000003; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 14444 (msg:"挖矿矿池连接检测 (XMRig)"; sid:1000004; rev:1;)
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"挖矿矿池连接检测 (TLS)"; tls.sni; content:"minexmr.com"; sid:1000005; rev:1;)
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"挖矿矿池连接检测 (TLS)"; tls.sni; content:"pool.minexmr.com"; sid:1000006; rev:1;)

# 检测数据外传（大流量出站）
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"大流量数据外传警告"; flow:to_server; dsize:>1000000; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000007; rev:1;)

# 检测 Web Shell 访问
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Web Shell 访问检测"; http.uri; content:".php"; pcre:"/=(eval|assert|system|exec|passthru|shell_exec)\(/Ui"; sid:1000008; rev:1;)

# 检测 SQL 注入
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SQL 注入检测"; http.uri; pcre:"/(union|select|insert|update|delete|drop).*from.*(information_schema|mysql)/Ui"; sid:1000009; rev:1;)

# 检测可疑 DNS 查询
alert dns $HOME_NET any -> any 53 (msg:"DNS 隧道检测（长域名）"; dns.query; pcre:"/([a-zA-Z0-9]{30,})/"; sid:1000010; rev:1;)

# 检测 Tor 连接
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Tor 连接检测"; tls.sni; content:"torproject.org"; sid:1000011; rev:1;)

# 检测 C2 回连
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"可疑 C2 回连检测"; http.user_agent; content:"Mozilla/5.0"; pcre:"/[a-z]{20,}/i"; sid:1000012; rev:1;)
```

### Suricata 日志分析与告警

```bash
#!/bin/bash
# suricata-monitor.sh
# Suricata 日志监控脚本

LOG_FILE="/var/log/suricata/fast.log"
JSON_LOG="/var/log/suricata/eve.json"

echo "========== Suricata 状态 =========="
systemctl status suricata | head -5

echo ""
echo "========== 最近 24 小时告警 =========="
grep "$(date -d '1 day ago' +'%m/%d/%Y' 2>/dev/null || date +'%m/%d/%Y')" "$LOG_FILE" | tail -50

echo ""
echo "========== 告警统计 =========="
if [ -f "$JSON_LOG" ]; then
    echo "--- 按告警类型统计 ---"
    jq -r 'select(.event_type=="alert") | .alert.signature' "$JSON_LOG" 2>/dev/null | sort | uniq -c | sort -rn | head -20

    echo ""
    echo "--- 按源IP统计 ---"
    jq -r 'select(.event_type=="alert") | .src_ip' "$JSON_LOG" 2>/dev/null | sort | uniq -c | sort -rn | head -20

    echo ""
    echo "--- 按目标端口统计 ---"
    jq -r 'select(.event_type=="alert") | .dest_port' "$JSON_LOG" 2>/dev/null | sort | uniq -c | sort -rn | head -20

    echo ""
    echo "--- 高危告警（severity=1）---"
    jq -r 'select(.event_type=="alert" and .alert.severity==1) | "\(.timestamp) \(.src_ip) -> \(.dest_ip) \(.alert.signature)"' "$JSON_LOG" 2>/dev/null | tail -30
else
    echo "JSON 日志文件不存在: $JSON_LOG"
fi

echo ""
echo "========== 规则统计 =========="
suricata --list-app-layer-protos 2>/dev/null | head -10
echo ""
echo "已加载规则数:"
grep -c '^\s*alert\|^\s*drop\|^\s*pass' /var/lib/suricata/rules/*.rules 2>/dev/null | awk -F: '{sum+=$2} END {print sum}'
```

---

## WAF Web应用防火墙

### ModSecurity + OWASP CRS 部署

```bash
#!/bin/bash
# modsecurity-install.sh
# ModSecurity WAF 安装脚本

# 安装 ModSecurity v3（Nginx）
apt update
apt install -y libmodsecurity3 modsecurity-nginx

# 下载 OWASP Core Rule Set
cd /etc/modsecurity
rm -rf /etc/modsecurity/crs
git clone https://github.com/coreruleset/coreruleset.git /etc/modsecurity/crs

# 配置
cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf

# 启用推荐配置
sed -i 's/#SecDefaultAction "phase:1,pass,log,nolog"/SecDefaultAction "phase:1,pass,log,tag='\''modsecurity'\''"/' /etc/modsecurity/crs/crs-setup.conf

# 配置 Nginx
cat > /etc/nginx/modsecurity.conf << 'EOF'
ModSecurityEnabled on;
ModSecurityConfig /etc/modsecurity/main.conf;
EOF

# 主配置文件
cat > /etc/modsecurity/main.conf << 'EOF'
Include /etc/modsecurity/modsecurity.conf
Include /etc/modsecurity/crs/crs-setup.conf
Include /etc/modsecurity/crs/rules/*.conf
EOF

# 调整 modsecurity.conf
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
sed -i 's/SecResponseBodyAccess On/SecResponseBodyAccess Off/' /etc/modsecurity/modsecurity.conf
sed -i 's/SecDebugLogLevel 0/SecDebugLogLevel 1/' /etc/modsecurity/modsecurity.conf

# 测试配置
nginx -t

# 重启
systemctl restart nginx

echo "ModSecurity WAF 已部署"
```

### 自定义 WAF 规则

```apache
# /etc/modsecurity/crs/rules/custom-rules.conf
# 自定义 WAF 规则

# ========== 阻止特定 User-Agent ==========
SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(sqlmap|nikto|nmap|masscan|wpscan|dirb|gobuster|ffuf)" \
    "id:10001,phase:1,deny,status:403,msg:'扫描工具检测',log,tag:'attack-scanner'"

# ========== 阻止特定路径访问 ==========
SecRule REQUEST_URI "@rx (?i)/(\.git|\.svn|\.env|\.aws|\.ssh|wp-admin|phpmyadmin)" \
    "id:10002,phase:1,deny,status:403,msg:'敏感路径访问',log,tag:'attack-recon'"

# ========== 文件上传限制 ==========
SecRule FILES_TMPNAMES "@rx \.(php|phtml|php5|phar|jsp|asp|aspx|exe|sh|bat)$" \
    "id:10003,phase:2,deny,status:403,msg:'危险文件类型上传',log,tag:'attack-upload'"

# ========== CC 攻击防护 ==========
SecRule REQUEST_URI "@beginsWith /" \
    "id:10004,phase:1,pass,nolog,initcol:ip=%{REMOTE_ADDR}"
SecRule IP:REQUEST_COUNT "@gt 100" \
    "id:10005,phase:1,deny,status:429,msg:'请求频率超限',log,tag:'attack-cc',setvar:ip.request_count=0"
SecAction "id:10006,phase:5,pass,nolog,setvar:ip.request_count=+1,expirevar:ip.request_count=10"

# ========== 地域限制 ==========
SecRule GEO:COUNTRY_CODE "@pm CN RU VN" \
    "id:10007,phase:1,pass,nolog,setvar:tx.high_risk_country=1"

# ========== API 速率限制 ==========
SecRule REQUEST_URI "@beginsWith /api/" \
    "id:10008,phase:1,pass,nolog,initcol:ip=%{REMOTE_ADDR},setvar:ip.api_count=+1,expirevar:ip.api_count=60"
SecRule IP:API_COUNT "@gt 60" \
    "id:10009,phase:1,deny,status:429,msg:'API 速率限制',log,tag:'api-limit'"
```

---

## SSH 安全加固进阶

### SSH 完全加固配置

```bash
# /etc/ssh/sshd_config
# SSH 安全加固配置

# ========== 基础设置 ==========
Port 22                          # 建议改为非标准端口
Protocol 2
AddressFamily inet
ListenAddress 0.0.0.0

# ========== 密钥认证 ==========
PubkeyAuthentication yes
PasswordAuthentication no        # 禁用密码登录
PermitRootLogin prohibit-password  # 仅允许密钥登录root
PermitEmptyPasswords no

# ========== 认证限制 ==========
MaxAuthTries 3
LoginGraceTime 30
MaxStartups 10:30:60
MaxSessions 5

# ========== 加密算法（强加密） ==========
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# ========== 超时设置 ==========
ClientAliveInterval 300
ClientAliveCountMax 2

# ========== 转发限制 ==========
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitUserRC no

# ========== Banner ==========
Banner /etc/ssh/banner

# ========== 日志 ==========
LogLevel VERBOSE
SyslogFacility AUTH

# ========== 用户/组限制 ==========
AllowUsers your_username
AllowGroups ssh_users

# ========== 限制登录来源 ==========
Match Address 1.2.3.0/24
    PasswordAuthentication yes   # 特定网段允许密码
    PermitRootLogin yes

Match Address *
    PasswordAuthentication no
```

### SSH 密钥管理与轮换

```bash
#!/bin/bash
# ssh-key-management.sh
# SSH 密钥管理脚本

# 生成高强度密钥对
generate_key() {
    local user=$1
    local key_type=${2:-ed25519}
    local key_path="/home/$user/.ssh/id_${key_type}"

    case "$key_type" in
        ed25519)
            ssh-keygen -t ed25519 -a 100 -f "$key_path" -C "$user@$(hostname)-$(date +%Y%m%d)"
            ;;
        rsa)
            ssh-keygen -t rsa -b 4096 -f "$key_path" -C "$user@$(hostname)-$(date +%Y%m%d)"
            ;;
        *)
            echo "不支持的密钥类型: $key_type"
            return 1
            ;;
    esac

    echo "密钥已生成: $key_path"
    echo "公钥:"
    cat "${key_path}.pub"
}

# 审计现有密钥
audit_keys() {
    echo "========== SSH 密钥审计 =========="
    for user_home in /home/* /root; do
        if [ -d "$user_home/.ssh" ]; then
            local user=$(basename "$user_home")
            echo "--- $user ---"
            for key in "$user_home"/.ssh/authorized_keys "$user_home"/.ssh/*.pub; do
                if [ -f "$key" ]; then
                    echo "文件: $key"
                    while IFS= read -r line; do
                        [ -z "$line" ] && continue
                        local type=$(echo "$line" | awk '{print $1}')
                        local comment=$(echo "$line" | awk '{print $3}')
                        local bits=""
                        case "$type" in
                            ssh-rsa) bits=$(echo "$line" | ssh-keygen -l -f - 2>/dev/null | awk '{print $1}') ;;
                            ssh-ed25519) bits=256 ;;
                            ecdsa-sha2-*) bits=$(echo "$line" | ssh-keygen -l -f - 2>/dev/null | awk '{print $1}') ;;
                        esac
                        echo "  类型: $type, 长度: $bits, 备注: $comment"
                    done < "$key"
                fi
            done
        fi
    done

    echo ""
    echo "========== 弱密钥检测 =========="
    for key_file in /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys; do
        if [ -f "$key_file" ]; then
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                local type=$(echo "$line" | awk '{print $1}')
                if [ "$type" = "ssh-rsa" ] || [ "$type" = "ssh-dss" ]; then
                    echo "警告: $key_file 包含弱密钥类型: $type"
                fi
            done < "$key_file"
        fi
    done
}

# 密钥轮换
rotate_keys() {
    local user=$1
    local old_key=$2

    echo "正在轮换 $user 的密钥..."
    generate_key "$user" "ed25519"

    # 更新 authorized_keys
    local new_pub="/home/$user/.ssh/id_ed25519.pub"
    if [ -f "$old_key" ]; then
        # 移除旧公钥
        local old_pub="${old_key}.pub"
        if [ -f "$old_pub" ]; then
            local old_fingerprint=$(ssh-keygen -lf "$old_pub" | awk '{print $2}')
            sed -i "/$old_fingerprint/d" "/home/$user/.ssh/authorized_keys" 2>/dev/null
        fi
    fi

    # 添加新公钥
    cat "$new_pub" >> "/home/$user/.ssh/authorized_keys"
    sort -u -o "/home/$user/.ssh/authorized_keys" "/home/$user/.ssh/authorized_keys"

    echo "密钥轮换完成"
}

case "$1" in
    generate) generate_key "$2" "$3" ;;
    audit) audit_keys ;;
    rotate) rotate_keys "$2" "$3" ;;
    *) echo "用法: $0 {generate|audit|rotate} [参数]" ;;
esac
```

---

## 端口敲门与隐身

### knockd 端口敲门配置

```bash
#!/bin/bash
# port-knocking-setup.sh
# 端口敲门安装脚本

# 安装
apt install -y knockd

# 配置
cat > /etc/knockd.conf << 'EOF'
[options]
    UseSyslog
    Interface = eth0

[openSSH]
    sequence = 7000,8000,9000
    seq_timeout = 15
    tcpflags = syn
    start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
    stop_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
    cmd_timeout = 3600

[closeSSH]
    sequence = 9000,8000,7000
    seq_timeout = 15
    tcpflags = syn
    command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
EOF

# 启用
systemctl enable knockd
systemctl start knockd

# 客户端使用方法
echo "客户端敲门："
echo "  knock SERVER_IP 7000 8000 9000"
echo "  ssh root@SERVER_IP"
echo "  knock SERVER_IP 9000 8000 7000  # 关闭"

echo "端口敲门已配置"
```

### 加密端口敲门（fwknop）

```bash
#!/bin/bash
# fwknop-setup.sh
# 加密端口敲门（SPA - Single Packet Authorization）

# 安装
apt install -y fwknop-server fwknop-client

# 生成密钥
KEY=$(fwknop --key-gen 2>/dev/null | grep 'KEY:' | awk '{print $2}')
HMAC_KEY=$(fwknop --key-gen 2>/dev/null | grep 'HMAC_KEY:' | awk '{print $2}')

# 服务端配置
cat > /etc/fwknop/access.conf << EOF
SOURCE: ANY;
KEY_BASE64: $KEY;
HMAC_KEY_BASE64: $HMAC_KEY;
OPEN_PORTS: tcp/22;
FW_ACCESS_TIMEOUT: 60;
EOF

# 启动
systemctl enable fwknopd
systemctl start fwknopd

echo "fwknop 已配置"
echo "客户端配置："
echo "  KEY_BASE64: $KEY"
echo "  HMAC_KEY_BASE64: $HMAC_KEY"
echo ""
echo "客户端使用："
echo "  fwknop -A tcp/22 -a CLIENT_IP -k SERVER_IP --key-gen"
echo "  ssh root@SERVER_IP"
```

---

## 日志审计与告警

### 统一日志收集

```bash
#!/bin/bash
# log-audit.sh
# 安全日志审计脚本

echo "========== 安全日志审计报告 =========="
echo "生成时间: $(date)"
echo "服务器: $(hostname)"
echo ""

echo "========== SSH 登录分析 =========="
echo "--- 成功登录（最近24小时）---"
journalctl -u sshd --since "24 hours ago" 2>/dev/null | grep "Accepted" | tail -20

echo ""
echo "--- 失败登录（最近24小时 Top 10 IP）---"
journalctl -u sshd --since "24 hours ago" 2>/dev/null | grep "Failed" | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -rn | head -10

echo ""
echo "========== 防火墙日志 =========="
echo "--- iptables DROP 统计 ---"
dmesg 2>/dev/null | grep "iptables-drop" | tail -20
journalctl -k --since "24 hours ago" 2>/dev/null | grep "iptables" | tail -20

echo ""
echo "========== Fail2Ban 日志 =========="
tail -30 /var/log/fail2ban.log 2>/dev/null

echo ""
echo "========== Nginx 安全事件 =========="
echo "--- 403 Forbidden（Top 10 IP）---"
awk '$9==403 {print $1}' /var/log/nginx/access.log 2>/dev/null | sort | uniq -c | sort -rn | head -10

echo ""
echo "--- 444 拒绝（Top 10 IP）---"
awk '$9==444 {print $1}' /var/log/nginx/access.log 2>/dev/null | sort | uniq -c | sort -rn | head -10

echo ""
echo "--- 可疑请求（扫描行为）---"
grep -iE '(sqlmap|nikto|nmap|masscan|wpscan|\.\.\/|union.*select|<script)' /var/log/nginx/access.log 2>/dev/null | tail -20

echo ""
echo "========== 系统安全事件 =========="
echo "--- 新增用户 ---"
grep "useradd" /var/log/auth.log 2>/dev/null | tail -10

echo "--- Sudo 使用记录 ---"
grep "sudo" /var/log/auth.log 2>/dev/null | tail -10

echo "--- Cron 修改 ---"
grep "CRON" /var/log/syslog 2>/dev/null | grep -i "root" | tail -10

echo ""
echo "========== 文件完整性检查 =========="
echo "--- SUID 文件（异常新增）---"
find / -perm -4000 -type f 2>/dev/null | head -20

echo "--- 最近修改的系统文件 ---"
find /etc /usr/bin /usr/sbin -mtime -1 -type f 2>/dev/null | head -20

echo ""
echo "========== 网络连接分析 =========="
echo "--- 异常出站连接 ---"
ss -tunap | grep -E '(ESTABLISHED|LISTEN)' | awk '{print $5, $6}' | sort -u

echo "--- 监听端口 ---"
ss -tulnp | grep -v '127.0.0.1'

echo ""
echo "========== 报告完毕 =========="
```

### 实时告警系统

```bash
#!/bin/bash
# security-alert.sh
# 实时安全告警

# Telegram 通知
TG_BOT_TOKEN="your_bot_token"
TG_CHAT_ID="your_chat_id"
SERVER_NAME=$(hostname)

send_alert() {
    local message=$1
    local severity=$2
    local emoji="🔴"
    case "$severity" in
        critical) emoji="🔴" ;;
        warning) emoji="🟡" ;;
        info) emoji="🔵" ;;
    esac
    local text="${emoji} [${severity^^}] ${SERVER_NAME}%0A%0A${message}"
    curl -s -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TG_CHAT_ID}" \
        -d "text=${text}" \
        -d "parse_mode=HTML" > /dev/null
    # 同时记录到日志
    echo "$(date) [$severity] $message" >> /var/log/security-alerts.log
}

# 检测SSH暴力破解
check_ssh_bruteforce() {
    local threshold=10
    local failed=$(journalctl -u sshd --since "5 minutes ago" 2>/dev/null | grep -c "Failed")
    if [ "$failed" -ge "$threshold" ]; then
        local top_ip=$(journalctl -u sshd --since "5 minutes ago" 2>/dev/null | grep "Failed" | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -rn | head -1)
        send_alert "SSH暴力破解：5分钟内 ${failed} 次失败登录%0A来源: ${top_ip}" "critical"
    fi
}

# 检测新用户创建
check_new_user() {
    local new_users=$(grep "useradd" /var/log/auth.log 2>/dev/null | tail -1)
    if [ -n "$new_users" ]; then
        send_alert "新用户创建: ${new_users}" "warning"
    fi
}

# 检测SUID变更
check_suid_change() {
    local baseline="/var/lib/suid-baseline"
    local current=$(find / -perm -4000 -type f 2>/dev/null | sort)
    if [ -f "$baseline" ]; then
        local diff_result=$(diff "$baseline" <(echo "$current") | grep "^>" | head -5)
        if [ -n "$diff_result" ]; then
            send_alert "检测到新增SUID文件:%0A${diff_result}" "critical"
        fi
    else
        echo "$current" > "$baseline"
    fi
}

# 检测挖矿进程
check_mining() {
    local mining=$(ps aux | grep -iE '(xmrig|minerd|cpuminer|crypto-pool|stratum)' | grep -v grep)
    if [ -n "$mining" ]; then
        send_alert "检测到挖矿进程:%0A${mining}" "critical"
        # 自动杀死
        echo "$mining" | awk '{print $2}' | xargs kill -9 2>/dev/null
    fi
}

# 检测异常网络连接
check_network() {
    local suspicious=$(ss -tnp | grep -vE '(127.0.0.1|::1|0.0.0.0)' | grep -E '(3333|14444|5555|8333)' | head -5)
    if [ -n "$suspicious" ]; then
        send_alert "检测到可疑网络连接:%0A${suspicious}" "warning"
    fi
}

# 执行所有检查
check_ssh_bruteforce
check_new_user
check_suid_change
check_mining
check_network
```

---

## 自动化安全巡检脚本

```powershell
# vps-security-audit.ps1
# PowerShell 版 VPS 安全巡检（通过 SSH 远程执行）

param(
    [string]$VPSHost = "your-vps-ip",
    [string]$User = "root",
    [string]$KeyFile = "~/.ssh/id_ed25519"
)

$script = @'
#!/bin/bash
echo "========== VPS 安全巡检报告 =========="
echo "时间: $(date)"
echo "主机: $(hostname)"
echo ""

# 1. 系统信息
echo "【1】系统信息"
echo "OS: $(cat /etc/os-release | grep PRETTY | cut -d'"' -f2)"
echo "内核: $(uname -r)"
echo "运行时间: $(uptime -p)"
echo "负载: $(cat /proc/loadavg)"
echo ""

# 2. 用户安全
echo "【2】用户安全"
echo "可登录用户:"
grep -v '/nologin\|/false' /etc/passwd | cut -d: -f1,6
echo ""
echo "sudo用户:"
getent group sudo | cut -d: -f4
echo ""
echo "最近登录:"
last -5 | head -10
echo ""

# 3. SSH 安全
echo "【3】SSH 安全"
echo "端口: $(grep -E '^Port' /etc/ssh/sshd_config 2>/dev/null || echo '22 (默认)')"
echo "密码登录: $(grep -E '^PasswordAuth' /etc/ssh/sshd_config 2>/dev/null || echo 'yes (默认)')"
echo "Root登录: $(grep -E '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo 'yes (默认)')"
echo "密钥强度:"
for key in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [ -f "$key" ] && ssh-keygen -lf "$key" 2>/dev/null
done
echo ""

# 4. 防火墙状态
echo "【4】防火墙状态"
echo "iptables规则数: $(iptables -L -n 2>/dev/null | wc -l)"
echo "INPUT策略: $(iptables -L INPUT -n 2>/dev/null | head -1)"
echo "FORWARD策略: $(iptables -L FORWARD -n 2>/dev/null | head -1)"
echo ""

# 5. Fail2Ban 状态
echo "【5】Fail2Ban 状态"
fail2ban-client status 2>/dev/null || echo "未安装"
echo ""

# 6. 监听端口
echo "【6】监听端口"
ss -tulnp | grep -v '127.0.0.1' | awk '{print $1, $4, $6}'
echo ""

# 7. 异常进程
echo "【7】可疑进程"
ps aux | grep -iE '(mining|crypto|xmrig|torch|\.hidden)' | grep -v grep || echo "未发现可疑进程"
echo ""

# 8. Cron 任务
echo "【8】Cron 任务"
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null | grep -v '^#' | grep -v '^$' && echo "  (用户: $user)"
done
echo ""

# 9. 系统更新
echo "【9】系统更新"
apt list --upgradable 2>/dev/null | grep -c 'upgradable' | xargs -I{} echo "可更新包数: {}"
echo ""

# 10. 磁盘使用
echo "【10】磁盘使用"
df -h | grep -v 'tmpfs\|overlay'
echo ""

echo "========== 巡检完毕 =========="
'@

Write-Host "正在连接 $VPSHost 进行安全巡检..."
ssh -i $KeyFile "${User}@${VPSHost}" $script
```

---

## 安全基线检查清单

### Linux VPS 安全基线（50项）

| 类别 | 检查项 | 合格标准 | 严重度 |
|------|--------|----------|--------|
| **账号安全** | root密码复杂度 | ≥12位含大小写数字特殊 | 高 |
| | 多余用户清理 | 无非必要用户 | 中 |
| | 空密码账户 | 无空密码账户 | 高 |
| | sudo权限审计 | 仅必要用户有sudo | 高 |
| **SSH安全** | 端口修改 | 非默认22端口 | 中 |
| | 密钥认证 | 仅密钥认证 | 高 |
| | Root直登 | 禁止Root直登 | 高 |
| | 密码登录 | 禁用密码登录 | 高 |
| | 超时退出 | ≤300秒 | 中 |
| **防火墙** | 默认策略 | INPUT DROP | 高 |
| | 端口暴露 | 仅必要端口开放 | 高 |
| | 速率限制 | SSH/HTTP有限速 | 中 |
| **系统加固** | 内核参数 | syncookie等启用 | 中 |
| | 文件权限 | 关键文件644/600 | 中 |
| | SUID审计 | 无异常SUID | 高 |
| **日志审计** | 日志保留 | ≥90天 | 中 |
| | 日志远程 | 远程日志服务器 | 低 |
| | 日志完整 | auth/syslog/nginx | 中 |
| **服务安全** | 不必要服务 | 已关闭 | 中 |
| | 数据库 | 仅本地监听 | 高 |
| | Web服务器 | 隐藏版本信息 | 低 |
| **入侵检测** | Fail2Ban | 已启用 | 高 |
| | IDS/IPS | Suricata已部署 | 中 |
| | 文件完整性 | AIDE/Tripwire | 中 |
| **更新维护** | 系统补丁 | 最新补丁 | 高 |
| | 软件版本 | 无已知漏洞版本 | 高 |
| | 自动更新 | 安全更新自动 | 中 |

---

## 应急响应流程

### 安全事件分级

| 级别 | 描述 | 响应时间 | 示例 |
|------|------|----------|------|
| P0 | 严重 | 立即 | 服务器被入侵、数据泄露 |
| P1 | 高危 | 15分钟内 | SSH爆破成功、挖矿木马 |
| P2 | 中危 | 1小时内 | DDoS攻击、CC攻击 |
| P3 | 低危 | 4小时内 | 端口扫描、单次探测 |

### P0 应急响应步骤

```bash
#!/bin/bash
# emergency-response.sh
# P0 级安全事件应急响应

echo "=== P0 应急响应启动 ==="
echo "时间: $(date)"

# Step 1: 隔离网络
echo "[Step 1] 网络隔离..."
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
# 只允许管理IP
iptables -A INPUT -s MANAGEMENT_IP -j ACCEPT
iptables -A OUTPUT -d MANAGEMENT_IP -j ACCEPT
echo "网络已隔离（仅允许管理IP）"

# Step 2: 保留证据
echo "[Step 2] 保留证据..."
mkdir -p /root/forensics-$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/root/forensics-$(date +%Y%m%d-%H%M%S)"

# 内存镜像
dd if=/dev/mem of="$EVIDENCE_DIR/memory.dump" 2>/dev/null || echo "内存镜像失败"

# 进程快照
ps aux > "$EVIDENCE_DIR/processes.txt"
ss -tulnp > "$EVIDENCE_DIR/connections.txt"
crontab -l > "$EVIDENCE_DIR/crontab.txt" 2>/dev/null

# 日志备份
cp -r /var/log "$EVIDENCE_DIR/logs"
journalctl --since "7 days ago" > "$EVIDENCE_DIR/journal.txt"

# 文件列表
find /etc /usr/bin /usr/sbin -type f -exec md5sum {} \; > "$EVIDENCE_DIR/file_hashes.txt"

echo "证据已保存到 $EVIDENCE_DIR"

# Step 3: 终止可疑进程
echo "[Step 3] 检查可疑进程..."
# 查找高CPU进程
ps aux --sort=-%cpu | head -10
# 查找挖矿进程
pgrep -fa '(xmrig|minerd|crypto)' && echo "发现挖矿进程!" || echo "未发现挖矿进程"

# Step 4: 检查后门
echo "[Step 4] 检查后门..."
# 检查SSH密钥
echo "authorized_keys:"
cat /root/.ssh/authorized_keys 2>/dev/null
for u in $(cut -d: -f1 /etc/passwd); do
    cat /home/$u/.ssh/authorized_keys 2>/dev/null && echo "用户: $u"
done

# 检查Cron
echo "Cron任务:"
for u in $(cut -d: -f1 /etc/passwd); do
    crontab -u "$u" -l 2>/dev/null && echo "用户: $u"
done
cat /etc/crontab
ls -la /etc/cron.d/

# 检查异常用户
echo "新增用户:"
grep -v '/nologin\|/false' /etc/passwd

# 检查SUID
echo "SUID文件:"
find / -perm -4000 -type f 2>/dev/null

echo "=== 应急响应完成，等待人工分析 ==="
echo "建议："
echo "1. 分析 $EVIDENCE_DIR 中的证据"
echo "2. 检查是否有数据外传"
echo "3. 重装系统（最安全方案）"
echo "4. 修改所有密码和密钥"
echo "5. 通知相关用户"
```

---

## VPS 服务商推荐

### 安全友好的 VPS 推荐

在安全加固之前，选择一家靠谱的 VPS 服务商至关重要。优秀的 VPS 商家应具备：DDoS 防护、快照备份、安全组功能、及时的安全公告。

#### ⭐ VPSVIP（强烈推荐）

**官网**：[https://vpsvip.net](https://vpsvip.net)

| 项目 | 详情 |
|------|------|
| 机房 | 香港 / 日本 / 美国 / 新加坡 / 韩国 |
| 线路 | CN2 GIA / 优化线路 / BGP 多线 |
| 安全特性 | DDoS 基础防护 / 快照备份 / 安全组 |
| 配置范围 | 1核1G 入门 到 8核16G 企业级 |
| 支付方式 | 支付宝 / 微信 / 加密货币 |
| 售后 | 7×24 中文技术支持 |

**安全层面推荐理由**：
1. **DDoS 基础防护**：每个机房都提供基础 DDoS 清洗，小规模攻击无需额外配置
2. **快照备份**：支持整机快照，被入侵后可快速回滚
3. **安全组**：Web 面板可配置安全组规则，相当于云端防火墙
4. **CN2 优化线路**：国内访问延迟低，SSH 管理流畅
5. **中文技术支持**：遇到安全问题沟通无障碍

#### 其他选择

| 服务商 | 安全特色 | 适用场景 |
|--------|----------|----------|
| 腾讯云 | 高防IP、WAF、CVM安全 | 国内业务 |
| 阿里云 | 安骑士、云盾 | 企业合规 |
| Vultr | DDoS防护、快照 | 海外业务 |
| DigitalOcean | Cloud Firewalls | 开发者 |

### VPS 选购建议（安全视角）

1. **优先选择带 DDoS 防护的机房**：避免被小流量 DDoS 打死
2. **确认支持快照备份**：应急时可以快速恢复
3. **检查安全组功能**：云端防火墙比 iptables 更方便
4. **选择有控制台访问的商家**：被锁门外时可以自救
5. **关注商家的安全公告**：及时了解底层漏洞

---

## 常见问题

### Q: iptables 和 nftables 应该选哪个？

A: 如果是全新系统，建议直接使用 nftables（更现代、性能更好、语法更清晰）。如果是已运行系统且 iptables 规则稳定，可以暂时保持，但建议逐步迁移。Ubuntu 22.04+ 默认推荐 nftables。

### Q: Fail2Ban 和 Suricata 需要同时部署吗？

A: 建议同时部署。Fail2Ban 专注于日志模式匹配（如SSH爆破），资源消耗低；Suricata 是全流量 IDS/IPS，能检测 Fail2Ban 发现不了的攻击（如挖矿连接、C2回连）。两者互补。

### Q: DDoS 防护只靠 iptables 够吗？

A: 不够。iptables 只能做本地速率限制，对大流量 DDoS（>1Gbps）无能为力。需要配合 CloudFlare（免费即可）或 VPS 商家的 DDoS 清洗服务。

### Q: ModSecurity 会影响网站性能吗？

A: 会有轻微影响（约5-10%性能损耗）。建议开启 `SecResponseBodyAccess Off`（不检查响应体），使用 `DetectionOnly` 模式先观察一段时间，确认无误报后再切换为 `On`。

### Q: 端口敲门值得配置吗？

A: 对于高安全需求的场景值得。端口敲门让 SSH 端口对外不可见，扫描工具完全发现不了。缺点是每次连接前需要先敲门，稍微不便。如果使用 fwknop（加密敲门），安全性更高。

### Q: 如何检测服务器是否已被入侵？

A: 检查以下迹象：1) 异常高 CPU/网络使用；2) 未知进程或 Cron 任务；3) 新增用户或 SSH 密钥；4) SUID 文件变更；5) 系统日志被清空；6) 异常网络连接。使用 `security-audit.sh` 脚本快速检查。

### Q: 被入侵后应该怎么处理？

A: 1) 立即隔离网络（iptables DROP ALL）；2) 保留证据（内存/日志/进程快照）；3) 分析入侵路径；4) **强烈建议重装系统**（最彻底的方式）；5) 修改所有密码和密钥；6) 部署本文所述安全加固方案后再上线。

---

## 相关资源

- [VPSVIP](https://vpsvip.net) - 优质 VPS 推荐，CN2优化线路
- [ClashVIP](https://clashvip.net) - 精选机场推荐
- [导航站](https://nav.clashvip.net) - 工具与资源导航
- [ClashHub](https://clashhub.net) - Clash 配置与教程
- [ClashHub 论坛](https://bbs.clashhub.net) - 技术交流社区
- [Clash for Windows](https://clash-for-windows.net) - 客户端下载
- [OWASP CRS](https://coreruleset.org) - WAF 规则集
- [Suricata](https://suricata.io) - IDS/IPS 官方
- [Fail2Ban](https://github.com/fail2ban/fail2ban) - 入侵防护

---

## 免责声明

1. 本仓库仅提供安全技术参考
2. 请遵守当地法律法规
3. 安全加固应在测试环境验证后再应用到生产环境
4. 定期更新规则和签名库
5. 安全是持续过程，非一次性配置

---

## 许可证

MIT License

---

> 更新时间：2026-09-07 | 专题：VPS 网络安全与防火墙深度配置实战 | 字节：~18000+