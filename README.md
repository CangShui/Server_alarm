# Server-Monitor

通过 SSH 远程采集服务器的在线状态与登录事件，实时监控并推送分级告警。

支持四类监控目标：

| 类型 | 采集内容 | 说明 |
|------|----------|------|
| `ssh_login` | 当前登录终端 + SSH 登录/失败事件 | Linux 系统 SSH 登录监控 |
| `openvpn` | OpenVPN 状态日志中的在线客户端 | VPN 在线监控 |
| `ikev2` | strongSwan `ipsec statusall` 在线连接 | VPN 在线监控 |
| `generic` | 通用 IP 提取 | 自定义命令 |


## 部署方式 (Debian Docker Compose)

### 1. 安装 Docker 和 Docker Compose

```bash
# Docker
curl -fsSL https://get.docker.com | bash
# Docker Compose 插件
apt install -y docker-compose-plugin
```

### 2. 准备部署目录

```bash
mkdir -p /opt/vpn-alarm && cd /opt/vpn-alarm
```

下载 `docker-compose.yml` 和 `config.json` 到该目录:

```bash
wget https://raw.githubusercontent.com/CangShui/server_alarm/main/docker-compose.yml
wget https://raw.githubusercontent.com/CangShui/server_alarm/main/config.json
```

下载 `GeoLite2-City.mmdb` 到该目录（可选，用于城市级 IP 归属地解析）:

```bash
wget -O GeoLite2-City.mmdb "https://raw.githubusercontent.com/CangShui/server_alarm/main/GeoLite2-City.mmdb"
```

> **注意**: `GeoLite2-City.mmdb` 不提供也不会影响系统核心功能（服务器监控、在线统计、告警推送），仅城市级 IP 解析不可用。
> 该文件随本仓库一起分发，使用需遵循 [MaxMind GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula)，并保留署名：
> `This product includes GeoLite Data created by MaxMind, available from https://www.maxmind.com`。

### 3. 修改配置

编辑 `config.json`，填入你的服务器信息和通知渠道：

```bash
nano config.json
```

### 4. 启动服务

```bash
docker compose up -d
```

访问 `http://<服务器IP>:5000` 查看监控面板。

---

## 发布 Release (用于自动构建镜像)

1. **推送代码到 GitHub**:
   ```bash
   git remote add origin https://github.com/CangShui/server_alarm.git
   git push -u origin main
   ```

2. **在 GitHub 上创建 Release**:
   - 进入仓库 `https://github.com/CangShui/server_alarm`
   - 点击 `Releases` → `Create a new release`
   - 填写 Tag (如 `v1.0.0`)、标题和说明
   - 点击 `Publish release`

3. **自动构建**: GitHub Actions 会自动构建 Docker 镜像并推送到 `ghcr.io/cangshui/server_alarm`。

---

## 配置说明

编辑 `config.json` 后通过 `docker compose up -d` 启动即可（或重启容器: `docker compose restart`）。

- **servers**: SSH 服务器列表，支持 `ikev2` / `openvpn` / `ssh_login`（Linux 系统 SSH 登录监控）三种类型
- **notifications**: 支持 Telegram Bot 和 Webhook 通知
- **geo_file_path**: GeoIP 数据库路径（默认 `/app/GeoLite2-City.mmdb`，需用户自行下载并通过 volume 挂载）
- **trusted_cities**: 信任城市列表，默认 `["北京"]`；已连接客户端若明确解析到列表外城市则为紧急告警
- **emergency_repeat_interval**: 紧急告警重复通知间隔（秒），默认 300 秒
- **access_control_enabled**: 访问控制总开关，默认 `false`（不开启则不拦截任何访问）
- **allowed_ips**: Web 访问白名单（IP / 网段），默认 `["127.0.0.1"]`，详见下方「访问控制」
- **trust_proxy**: 是否采信反向代理转发头（`X-Forwarded-For` / `X-Real-IP` / `Forwarded`），默认 `false`
- **trusted_proxies**: 可信代理地址列表（IP / 网段），默认 `[]`；只有来源命中该列表才采信转发头

### 访问控制（IP 白名单）

访问控制有一个**总开关** `access_control_enabled`，**默认关闭**：

- **关闭时（默认）**：无论 `allowed_ips` 怎么配置，都**不做任何拦截**，任何 IP 都能正常访问。
- **开启后**：只有白名单内的 IP 才能访问本系统（`/status`、`/history`、`/config` 及所有 `/api/*`），
  不在白名单内的请求一律返回 **HTTP 403**，并写入 `logs/stdout.log`（`[ACCESS] 拒绝访问: ...`）。

在「系统配置 → 访问控制」中勾选/取消「启用访问控制」，点击「保存配置」后生效。

**规则格式**（在「系统配置 → 访问控制」中增删，点击「保存配置」后生效）：

| 写法 | 含义 |
|------|------|
| `127.0.0.1` | 单个 IP（内置，不可删除） |
| `192.168.1.10` | 单个 IP |
| `192.168.1.0/24` | 网段（192.168.1.0 ~ 192.168.1.255） |
| `192.168.1.1/24` | 同样视为 `192.168.1.0/24`，会自动规范化 |
| `10.8.0.0/24`、`2001:db8::/32` | 网段（同时支持 IPv6） |

**重要说明：**

1. **回环地址永远放行**：`127.0.0.0/8` 与 `::1` 无条件允许，不可被任何规则排除。
   这保证了本机管理入口和容器内置 HEALTHCHECK（从 `127.0.0.1` 请求 `/healthz`）始终可用。
2. **升级不会把任何人挡在门外**：旧版 `config.json` 既没有 `access_control_enabled` 也没有 `allowed_ips`，
   升级后总开关取默认值 **关闭**、白名单取默认值 `["127.0.0.1"]`，但不拦截任何访问。
   只有你**主动勾选「启用访问控制」并保存**之后，白名单才会真正生效。
3. **启用前先确认白名单包含当前管理 IP**：例如 `"allowed_ips": ["127.0.0.1", "192.168.1.0/24"]`。
4. **请勿把自己当前的 IP 排除**：开启总开关并保存后立即生效，误删会被挡在门外。
   届时可在服务器上把 `config.json` 的 `access_control_enabled` 改回 `false` 并重启容器恢复访问。
5. **反向代理场景**：系统对"容器 / 反代环境下的取 IP 准确性"做了专门处理，见下一节。

### 容器与反向代理环境下的取 IP 准确性

系统把 **TCP 直连来源（peer）** 与 **真实客户端（client）** 分开处理，避免容器网络把来源 IP 弄丢或弄错：

| 访问路径 | 容器看到的来源 | 说明 |
|----------|----------------|------|
| 局域网客户端 → `http://<主机>:5000` | 真实客户端 IP | Docker 的 DNAT 规则会保留源 IP，判定准确 |
| 宿主机 → `127.0.0.1:5000` | **通常是网桥网关（如 `172.19.0.1`）** | 走的是 docker-proxy，不是真回环，需按提示放行 |
| 容器内 HEALTHCHECK | `127.0.0.1` | 真回环，恒放行，不受白名单影响 |
| 前置 Nginx / Traefik / WAF 反代 | 代理 IP（常为 `127.0.0.1`） | 必须开启 `trust_proxy` 并配置 `trusted_proxies` 才会采信转发链 |

**转发头采信规则（防伪造）：**

1. `trust_proxy` 默认 **`false`** → 完全不采信任何转发头，只认 TCP 来源。
2. `trust_proxy` 已开启但 `trusted_proxies` 为空 → 仍不采信（安全回退）。
3. 请求来源 **不在** `trusted_proxies` 里 → 忽略它带来的 `X-Forwarded-For`（防伪造）。
4. 来源可信 → 从右往左跳过可信代理，取第一个非可信地址作为真实客户端。
5. **「回环恒放行」只对真正的本机直连生效**。若可信代理跑在 `127.0.0.1` 上，判定会继续使用转发链里的真实客户端——否则反代场景下白名单会被整体绕过。
6. 远端连接若声称自己是 `127.0.0.1`，一律判为伪造并拒绝。

**排障提示**：被拦截时，403 页面（以及 `/api/*` 的 JSON 响应）会直接显示「真实客户端 / TCP 直连来源 / 转发链 / 取值来源 / 判定依据」，按上面的 IP 加白名单即可；配置页也会显示「当前这次访问被识别为」。

### Linux SSH 登录监控的命令写法

`ssh_login` 类型靠“你填的命令”去取两类信息，建议按下面的模板填，**不要用 `tail -n 30` 直接读日志**：

```bash
who -u 2>/dev/null; if [ -r /var/log/auth.log ]; then tail -n 2000 /var/log/auth.log | grep -a sshd | tail -n 30; elif [ -r /var/log/secure ]; then tail -n 2000 /var/log/secure | grep -a sshd | tail -n 30; else journalctl -u ssh -u sshd -n 30 --no-pager -o short-iso 2>/dev/null; fi
```

**为什么要这么写：**

| 坑 | 后果 | 模板里的对策 |
|----|------|--------------|
| `&&` 连接 | 前一段命令失败（如日志文件不存在），后面整段不执行，**一条登录都采不到** | 改用 `;` |
| `tail -n 30` 不过滤 | cron 每分钟产生 2~4 行，30 行窗口 **2~3 分钟就被刷满**，SSH 记录被挤出 | `grep -a sshd` 先过滤，再 `tail -n 30` |
| 只认一种日志源 | 新 Debian 无 `auth.log`、老系统无 journald | `auth.log` → `secure` → `journalctl` 三级回退 |
| 多个日志源重复 | 同一条登录被记两次 | 解析器按「状态+用户+IP+时间+端口」自动去重（`who` 活跃会话按**终端名** `pts/N` 区分，同 IP 多终端各算一条） |

**状态页的展示口径：**

- 「当前在线终端」= `who -u` 里**带远程 IP 的活跃会话**，日志事件不计入；同一公网 IP 下的 `pts/0`、`pts/1` 等**各自算一个终端**，表格中单列「终端」以便区分
- 表格里每行都带「来源」标签：`实时在线`（who）/ `登录成功` / `登录失败`（日志）
- 命中「排除IP / 排除用户名」的行会额外标注 `已排除`，等级降为「提示」，只记录不通知

### 告警等级

| 等级 | 判定 | 通知策略 |
|------|------|----------|
| 提示 | OpenVPN 请求未分配虚拟 IP，或 SSH 认证失败（密码错误/无效用户等） | 只记录事件和原始日志快照，不发送通知 |
| 重要 | 客户端已连接/SSH登录成功，且城市可信或无法明确解析城市 | 发送一次通知 |
| 紧急 | 客户端已连接/SSH登录成功，且本地 GeoIP 明确解析到非信任城市 | 立即通知，并按配置间隔重复通知直到会话断开/恢复 |

通知标题会带 `[重要]` 或 `[紧急]`。紧急重复通知不会重复写入事件记录。

> 注意: 如需使用 SSH 密钥认证，请将密钥文件放在部署目录并通过 volumes 挂载到容器内。

### 告警与扫描暂停（维护窗口）

首页「当前状态」顶部有一个暂停开关，用于**计划内维护**：在升级、割接、重启等窗口内，
一键停掉采集与告警，避免刷屏告警和误报。

**可选时长**（下拉框，接口只接受这五个值）：

| 选项 | 时长 | 秒数 |
|------|------|------|
| 5 分钟 | 5min | 300 |
| 30 分钟 | 30min | 1800 |
| 1 小时 | 1h | 3600 |
| 5 小时 | 5h | 18000 |
| 24 小时 | 24h | 86400 |

**暂停期间会发生什么：**

| 行为 | 暂停中 | 恢复后 |
|------|--------|--------|
| 定时采集（`periodic_scan`） | 每一轮直接跳过，不连接任何服务器 | 下一轮自动恢复 |
| 手动「立即采集」 | 按钮置灰；即使直接调 `POST /api/scan` 也会返回 **HTTP 409** | 正常执行 |
| 告警推送（Telegram / Webhook） | 全部抑制，只写审计日志 | 正常推送 |
| 紧急告警重复通知 | 停止（采集被跳过，不会再触发） | 仍在线的紧急会话按间隔继续通知 |
| `/healthz` 健康检查 | 仍然 `healthy`（暂停是人为操作，不判为故障） | `healthy` |
| 自愈 watchdog | **不会**因「上次扫描超时」重启容器 | 正常判定 |
| 事件日志 / 数据库 | 不新增事件；暂停状态本身落库 | 正常写入 |

**几个要点：**

1. **到期自动恢复**：到点后第一轮定时采集会自动重新开始，无需人工干预；页面会提示「暂停已结束」。
2. **重启不丢**：暂停状态存在数据库 `config_store` 表（`alert_scan_pause`）里，
   容器重启、watchdog 自愈重启后仍然有效，不会在维护窗口内突然又开始扫描告警。
3. **可提前结束**：点「立即恢复」立刻取消暂停，下一轮定时采集马上恢复。
4. **测试通知例外**：`/api/test-notification`（配置页的「测试通知」）属于人工联调，
   **不受暂停开关抑制**，方便在暂停期间确认渠道是否正常。
5. **失败即放行**：读取暂停状态出错时按「未暂停」处理，保证监控不会因为一次读库失败而永久静默。

**对应接口：**

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/pause` | 查询当前暂停状态与可选时长 |
| `POST` | `/api/pause` | 开始/续期暂停，body: `{"duration": "5m"}` |
| `POST` | `/api/resume` | 立即恢复（取消暂停） |
| `GET` | `/api/status` | 响应中新增 `pause` 与 `pause_choices` 字段，首页据此渲染开关 |

**排查用日志**：`logs/audit-dev.log` 中搜索关键词
`已暂停所有告警与扫描` / `已手动恢复告警与扫描` / `扫描跳过` / `告警抑制` / `请求被拒绝`，
即可看到「谁在什么时候暂停了多久、期间跳过了哪些扫描、抑制了哪些告警」的完整链路
（前端点击、参数校验、业务执行、响应返回共用同一个 `traceId`）。

## 数据库与日志

首次 `docker compose up -d` 启动后，以下文件/目录将在宿主机部署目录自动生成：

- `data/vpn_alarm.db` — SQLite 数据库文件（表结构自动初始化，初始无历史数据）
- `scan_records` 仅作为当前状态计算所需的内部状态快照，不再提供独立的“扫描历史”页面或 API
- `data/event_snapshots/` — 事件触发时刻的原始采集日志快照（如 OpenVPN 的 `openvpn-status.log`），可在「事件日志」点击「查看日志」打开
- `logs/` — 日志目录
  - `logs/stdout.log` — 应用业务日志（采集记录、事件检测、调度信息等）
  - `logs/stderr.log` — Flask/Werkzeug 访问日志和错误信息
  - `logs/audit-dev.log` — 带 TraceID 的页面/API 白话审计日志

> 以上文件均通过 `docker-compose.yml` 的 volumes 挂载实现持久化，容器重启不会丢失数据。

### 数据目录位置与环境变量

程序启动时会自动挑选一个**能承载 SQLite 写事务**的目录存放数据库与事件快照，顺序为：

1. 环境变量 `SERVER_MONITOR_DATA_DIR` 指定的目录（最高优先级）；
2. 程序所在目录下的 `data/`（Docker 与常规部署的默认值）；
3. 本机 `~/.local/share/server-monitor/`（兜底）。

> **为什么需要兜底**：SQLite 依赖 POSIX 文件锁。若程序目录放在 CIFS/SMB 等网络盘上（例如把项目放在挂载的 Windows 共享盘），文件锁会失效，任何写事务都会直接抛出 `sqlite3.OperationalError: database is locked`，表现为“启动就报错”。此时程序会自动改用本机目录并在 stderr 打印一条警告，无需手工干预。
>
> 如需显式指定（例如把数据放到固定位置），设置环境变量即可：`SERVER_MONITOR_DATA_DIR=/var/lib/server-monitor`。

### 日志自动回收

系统内置 **日志自动轮转与回收** 机制，防止日志目录无限膨胀：

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `log_retention_days` | 30 | 保留天数，超过此天数的归档日志文件自动删除 |

**工作机制：**

1. **启动时轮转** — 容器启动时，若 `stdout.log` / `stderr.log` 的最后修改日期不是当天，则自动归档为 `stdout.YYYY-MM-DD.log` / `stderr.YYYY-MM-DD.log`，新建空白文件继续写入。
2. **启动时清理** — 启动时扫描 `logs/` 目录，删除所有超过保留天数的归档日志文件。
3. **每日自动回收** — 每天凌晨 3:00 定时执行：清理过期归档 + 跨天运行时日志轮转。
4. **配置保存时清理** — 在 Web 后台修改并保存 `log_retention_days` 后立即按新天数执行一次清理。
5. **活跃日志保护** — 当前正在写入的 `stdout.log` 和 `stderr.log`（不带日期后缀）**永远不会被删除**，仅清理带日期后缀的归档文件。

**归档文件名示例：**
```
logs/stdout.2026-06-30.log
logs/stderr.2026-06-30.log
```

**修改保留天数：**
1. 访问 Web 后台 → `/config` 页面
2. 修改「日志文件保留天数」
3. 点击「保存配置」

或直接编辑 `config.json`：
```json
{
  "log_retention_days": 30
}
```

### 常用查看命令

```bash
# 实时跟踪业务日志
tail -f logs/stdout.log

# 查看最近 50 行访问日志
tail -50 logs/stderr.log

# 搜索特定服务器日志
grep "服务器名称" logs/stdout.log
```

## 健康检查

系统提供 `/healthz` 接口用于运行状态监控，返回结构化 JSON：

```bash
curl http://localhost:5000/healthz
```

### 检查项

| 检查项 | 说明 |
|--------|------|
| `flask` | Flask 应用可响应 |
| `database` | SQLite 数据库可访问 |
| `scheduler` | APScheduler 已启动 |
| `scan_job` | 周期扫描任务 `periodic_scan` 存在 |
| `last_scan` | 最近一次扫描未超时（阈值 = 3× 扫描间隔 + 60 秒缓冲） |

### 响应示例

**健康** (HTTP 200)：
```json
{
  "status": "healthy",
  "checks": {
    "flask": {"status": "ok"},
    "database": {"status": "ok"},
    "scheduler": {"status": "ok"},
    "scan_job": {"status": "ok", "next_run": "2026-06-30 12:00:00"},
    "last_scan": {
      "status": "ok",
      "last_scan_time": "2026-06-30 11:59:30",
      "elapsed_seconds": 30.5,
      "scan_interval": 60,
      "threshold_seconds": 240
    }
  },
  "timestamp": "2026-06-30 12:00:00"
}
```

**不健康** (HTTP 503)：
```json
{
  "status": "unhealthy",
  "checks": {
    "flask": {"status": "ok"},
    "database": {"status": "ok"},
    "scheduler": {"status": "fail", "error": "调度器未运行"},
    "scan_job": {"status": "fail", "error": "调度器未初始化"},
    "last_scan": {"status": "fail", "error": "上次扫描已过去 300 秒，超过阈值 240 秒"}
  },
  "timestamp": "2026-06-30 12:05:00"
}
```

### Docker 健康检查

Docker 镜像内置了 `HEALTHCHECK`（30s 间隔 / 10s 超时 / 3 次重试 / 60s 启动缓冲），自动通过 `/healthz` 判定容器状态。使用 `docker ps` 或 `docker inspect` 可查看容器健康状态。

### 自愈重启机制

系统内置 **watchdog 自愈线程**，持续监控关键健康指标（数据库、调度器、扫描任务、扫描超时）。当关键故障持续超过阈值时，进程主动以非零退出码退出，由 Docker 的 `restart: unless-stopped` 策略自动重启容器，形成完整恢复闭环。

| 配置项 | 说明 |
|--------|------|
| `restart: unless-stopped` | 容器非正常退出时自动重启（`docker-compose.yml`） |
| watchdog 检查周期 | 扫描间隔的一半，最低 15 秒 |
| 退出阈值 | max(300 秒, 5 × 扫描间隔)，采用保守策略避免误杀 |
| 启动缓冲 | watchdog 启动后等待 60 秒再开始检查 |
| 故障恢复 | healthy 恢复后自动清零累计状态，支持瞬时抖动 |

**不会触发退出的情况：**
- SSH 单次采集失败（局部问题，不影响整体健康判定）
- 瞬时网络抖动导致 1-2 次检查失败
- `/healthz` 返回 HTTP 503 但持续时间未达阈值

**会触发退出的关键故障：**
1. 调度器未运行
2. 周期扫描任务丢失
3. 最近扫描超时超过阈值
4. 数据库不可访问

容器重启后，Docker 日志中可见明确退出原因：
```
[WATCHDOG] 关键 unhealthy 已持续 360s，超过阈值 300s，主动退出进程
```

---

## 许可说明

本系统使用 MaxMind 的 `GeoLite2-City.mmdb` 进行城市级 IP 归属地解析。该文件随本仓库一起分发，但被 `.dockerignore` 排除、不会进入 Docker 镜像；不提供它也不会影响系统核心功能（服务器监控、在线统计、告警推送），仅城市级 IP 解析不可用。

使用该数据库需遵循 [MaxMind GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula)。按 EULA 第 3 条要求保留以下署名：

> This product includes GeoLite Data created by MaxMind, available from https://www.maxmind.com

注意事项：

- EULA 第 6.3 条要求 MaxMind 发布新版数据库后 **30 天内停止使用并销毁旧版**，请定期更新仓库内的 `GeoLite2-City.mmdb`。
- 未经授权不得用于商业用途，使用者需自行确认合规性。
