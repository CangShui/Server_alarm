"""
配置管理模块 - 读写 config.json，同时支持从网页修改
"""
import json
import os
import threading

from access_control import (
    normalize_allowlist, normalize_trusted_proxies, coerce_bool,
    DEFAULT_ENABLED, DEFAULT_TRUST_PROXY,
)

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')

# 线程锁保护配置读写（RLock 支持同一线程重入）
_config_lock = threading.RLock()

# 上次成功解析的配置（内存缓存）：文件损坏时用它兜底，避免 fail-open 到不安全默认值
_LAST_GOOD_CONFIG = {'value': None}

# 默认配置
DEFAULT_CONFIG = {
    "servers": [],
    "scan_interval": 60,
    "connection_alert_window": 300,
    "status_refresh_interval": 5,
    "geo_file_path": "",
    "scan_history_retention": 10000,
    "event_history_retention": 5000,
    "log_retention_days": 30,
    "trusted_cities": ["北京"],
    "access_control_enabled": DEFAULT_ENABLED,
    "allowed_ips": ["127.0.0.1"],
    "trust_proxy": DEFAULT_TRUST_PROXY,
    "trusted_proxies": [],
    "emergency_repeat_interval": 300,
    "notifications": {
        "telegram": {"enabled": False, "token": "", "chat_id": ""},
        "webhook": {"enabled": False, "url": "", "content_type": "application/json",
                     "headers": {}, "body_template": '{"msg": "{{message}}"}'}
    }
}


def _deep_copy_default():
    return json.loads(json.dumps(DEFAULT_CONFIG))


def _safe_int(value, default, minimum=None):
    """把任意输入安全转为 int；非法值回退默认，绝不因单个坏字段抛弃整份配置。"""
    try:
        result = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    if minimum is not None and result < minimum:
        return minimum
    return result


def _normalize_config(cfg):
    source = cfg or {}
    normalized = _deep_copy_default()
    normalized.update(source)
    normalized['servers'] = list(source.get('servers') or [])
    for srv in normalized['servers']:
        if isinstance(srv, dict):
            # 兜底 host/port/type 等关键字段，避免缺键时 do_scan 抛 KeyError 拖垮整轮扫描
            srv.setdefault('host', '')
            srv.setdefault('port', 22)
            srv.setdefault('type', '')
            srv.setdefault('name', '')
            srv.setdefault('password', '')
            srv.setdefault('username', '')
            srv.setdefault('ssh_key_path', '')
            srv.setdefault('ssh_key_passphrase', '')
            srv.setdefault('exclude_ips', [])
            srv.setdefault('exclude_users', [])
    normalized['scan_interval'] = _safe_int(normalized.get('scan_interval'), 60, minimum=1)
    normalized['connection_alert_window'] = _safe_int(normalized.get('connection_alert_window'), 300, minimum=1)
    normalized['status_refresh_interval'] = _safe_int(normalized.get('status_refresh_interval'), 5, minimum=1)
    normalized['geo_file_path'] = str(normalized.get('geo_file_path') or '').strip()
    normalized['scan_history_retention'] = _safe_int(normalized.get('scan_history_retention'), 10000, minimum=0)
    normalized['event_history_retention'] = _safe_int(normalized.get('event_history_retention'), 5000, minimum=0)
    normalized['log_retention_days'] = _safe_int(normalized.get('log_retention_days'), 30, minimum=1)
    trusted_cities = normalized.get('trusted_cities', ['北京'])
    if isinstance(trusted_cities, str):
        trusted_cities = [item.strip() for item in trusted_cities.replace('，', ',').split(',')]
    normalized['trusted_cities'] = [str(item).strip() for item in (trusted_cities or []) if str(item).strip()]
    # 访问白名单：过滤非法项、去重，并强制包含内置规则 127.0.0.1
    # 总开关默认关闭（DEFAULT_ENABLED=False），关闭时不拦截任何访问
    normalized['access_control_enabled'] = coerce_bool(
        normalized.get('access_control_enabled'), default=DEFAULT_ENABLED
    )
    normalized['allowed_ips'] = normalize_allowlist(normalized.get('allowed_ips'))
    # 反向代理：默认不采信转发头；只有来源命中 trusted_proxies 时才采信 XFF
    normalized['trust_proxy'] = coerce_bool(
        normalized.get('trust_proxy'), default=DEFAULT_TRUST_PROXY
    )
    normalized['trusted_proxies'] = normalize_trusted_proxies(normalized.get('trusted_proxies'))
    normalized['emergency_repeat_interval'] = _safe_int(normalized.get('emergency_repeat_interval'), 300, minimum=10)

    notifications = source.get('notifications') or {}
    default_notifications = _deep_copy_default()['notifications']
    merged_notifications = json.loads(json.dumps(default_notifications))
    merged_notifications.update(notifications)

    telegram = merged_notifications.get('telegram') or {}
    telegram_defaults = default_notifications['telegram'].copy()
    telegram_defaults.update(telegram)
    merged_notifications['telegram'] = telegram_defaults

    webhook = merged_notifications.get('webhook') or {}
    webhook_defaults = default_notifications['webhook'].copy()
    webhook_defaults.update(webhook)
    webhook_defaults['headers'] = dict(webhook_defaults.get('headers') or {})
    merged_notifications['webhook'] = webhook_defaults

    normalized['notifications'] = merged_notifications
    return normalized


def load_config():
    """加载配置"""
    with _config_lock:
        if not os.path.exists(CONFIG_PATH):
            return _deep_copy_default()
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
            normalized = _normalize_config(cfg)
            _LAST_GOOD_CONFIG['value'] = normalized
            return normalized
        except Exception as e:
            # 解析失败绝不能静默回退到“默认配置”——那会把访问控制开关关掉、
            # 清空服务器列表（fail-open）。这里保留上次已知良好配置（内存缓存）。
            print(f"[WARN] 加载配置失败: {e}，将沿用上次已知良好配置", flush=True)
            with _config_lock:
                cached = _LAST_GOOD_CONFIG.get('value')
            if cached is not None:
                return json.loads(json.dumps(cached))
            return _deep_copy_default()


# 脱敏/掩码保护策略已彻底删除。
# 所有配置字段按真实值明文读取和保存，不再做任何脱敏展示或掩码值保留。


def save_config(config):
    """保存配置到文件（直接写入用户提交内容，不做掩码识别或旧值保留）"""
    with _config_lock:
        try:
            normalized = _normalize_config(config)
            # 原子写：先写临时文件再 os.replace，避免截断后崩溃/断电留下半截 JSON
            # （半截文件会导致下次加载解析失败）。
            tmp_path = CONFIG_PATH + '.tmp'
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(normalized, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, CONFIG_PATH)
            # 配置含明文口令/token，尽量收紧文件权限（已存在文件也一并修正）
            try:
                os.chmod(CONFIG_PATH, 0o600)
            except OSError:
                pass
            _LAST_GOOD_CONFIG['value'] = normalized
            return True
        except Exception as e:
            print(f"[ERROR] 保存配置失败: {e}")
            return False


def get_safe_config():
    """获取配置（直接返回真实值，不再脱敏）"""
    cfg = load_config()
    safe = json.loads(json.dumps(cfg))  # deep copy
    for srv in safe.get('servers', []):
        # 设置占位字段为 False，兼容模板旧逻辑
        srv['password_display_placeholder'] = False
        srv['ssh_key_passphrase_placeholder'] = False
        # 确保新增字段存在
        srv.setdefault('ssh_key_path', '')
        srv.setdefault('ssh_key_passphrase', '')
        srv.setdefault('exclude_ips', [])
        srv.setdefault('exclude_users', [])
    return safe
