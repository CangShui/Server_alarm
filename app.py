"""
Server-Monitor - 主应用入口
Flask Web + APScheduler 定时采集 + SQLite 存储
"""
import json
import sys
import os
import re
import time
import threading
import uuid
import html
from datetime import datetime, timedelta

from flask import Flask, render_template, request, jsonify, redirect, url_for, g

# 将当前目录加入 sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import init_db, save_scan_record, save_event, get_latest_scan_per_server, \
    get_recent_events, get_known_ips, db_ping, get_db_stats, \
    get_events_paginated, get_event_snapshot, prune_all, \
    save_pause_state, load_pause_state
from collector import collect_server
from geo_resolver import init_resolvers, resolve_ip, resolve_ips, get_resolver_status
from notifier import send_telegram, send_webhook
from config_manager import load_config, save_config, get_safe_config
from access_control import is_permanent_rule, check_request_access

from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)

_AUDIT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
_AUDIT_FILE = os.path.join(_AUDIT_DIR, 'audit-dev.log')
_audit_lock = threading.Lock()


def _audit_log(stage, message, **fields):
    """开发级白话审计日志，统一落盘到 logs/audit-dev.log。"""
    try:
        os.makedirs(_AUDIT_DIR, exist_ok=True)
        trace_id = fields.pop('trace_id', None)
        if not trace_id:
            # 后台线程（定时采集 / watchdog）没有请求上下文，取不到 g.trace_id；
            # 此时用 'background' 兜底，避免整条审计日志被 app context 异常吞掉。
            try:
                trace_id = getattr(g, 'trace_id', '-')
            except RuntimeError:
                trace_id = 'background'
        # 主 message 同样净化换行/回车：否则带 \n 的内容可被用来在日志里伪造出“合法”的整行记录
        safe_message = str(message).replace('\r', ' ').replace('\n', ' ')[:1000]
        safe_trace_id = str(trace_id).replace('\r', ' ').replace('\n', ' ')[:128]
        safe_fields = ' '.join(
            f'{key}={str(value).replace(chr(13), " ").replace(chr(10), " ")[:500]}'
            for key, value in fields.items()
        )
        line = (f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")} '
                f'[{stage}] traceId={safe_trace_id} {safe_message}'
                f'{(" " + safe_fields) if safe_fields else ""}\n')
        with _audit_lock:
            with open(_AUDIT_FILE, 'a', encoding='utf-8') as audit_file:
                audit_file.write(line)
    except Exception:
        # 审计日志失败不能影响主业务；主错误仍会由 stderr/stdout 日志记录。
        pass


@app.before_request
def _audit_request_arrival():
    g.trace_id = (request.headers.get('X-Trace-ID') or uuid.uuid4().hex)
    g.request_started_at = time.time()
    _audit_log(
        '请求到达',
        '请求已进入 Server-Monitor，准备执行访问控制和业务处理',
        method=request.method,
        path=request.path,
        remote_addr=request.remote_addr or '',
        query=request.query_string.decode('utf-8', errors='replace')[:300]
    )


@app.after_request
def _audit_response(response):
    elapsed_ms = int((time.time() - getattr(g, 'request_started_at', time.time())) * 1000)
    response.headers['X-Trace-ID'] = getattr(g, 'trace_id', '-')
    _audit_log(
        '响应返回',
        '请求处理完成，响应即将返回调用方',
        status_code=response.status_code,
        elapsed_ms=elapsed_ms,
        result='成功' if response.status_code < 400 else '失败或拒绝'
    )
    return response


@app.teardown_request
def _audit_exception(exc):
    if exc is not None:
        _audit_log(
            '异常',
            '请求处理过程中发生未处理异常',
            exception_type=type(exc).__name__,
            reason=str(exc),
            business_impact='本次请求可能未完成'
        )


@app.errorhandler(Exception)
def _handle_unexpected_error(exc):
    """未捕获异常统一出口：API 路径返回 JSON，页面路径给出可读提示。

    前端用 r.json() 解析响应；若异常直接走 Flask 默认 HTML 500，前端解析会失败，
    用户只看到“接口无响应”。这里保证 API 契约始终是 JSON。
    """
    from werkzeug.exceptions import HTTPException
    if isinstance(exc, HTTPException):
        # 保留 404/403 等语义状态码；API 路径返回 JSON 而不是 HTML
        if request.path.startswith('/api/') or request.path == '/healthz':
            return jsonify({'ok': False, 'error': exc.description}), exc.code
        return exc
    _audit_log(
        '异常',
        '接口处理出现未捕获异常，已返回统一 JSON 错误',
        exception_type=type(exc).__name__,
        reason=str(exc)[:300],
        business_impact='本次请求失败，已返回错误信息'
    )
    if request.path.startswith('/api/') or request.path == '/healthz':
        return jsonify({'ok': False, 'error': '服务器内部错误，请查看日志'}), 500
    return exc, 500

# ---- 全局状态 ----
last_client_ips = {}   # server_name -> set of IPs
last_online_counts = {}  # server_name -> int
alerted_client_keys = {}  # server_name -> set of (ip, marker)
active_emergency_alerts = {}  # (server_name, ip, marker) -> {last_notified_at, detail}
_unreachable_alert_state = {}  # server_name -> last_notified_at（服务不可达告警限流）
_collect_lock = threading.Lock()
scheduler = None
_last_scan_start_time = None   # datetime
_last_scan_end_time = None     # datetime

# ---- 自愈 watchdog 全局状态 ----
_watchdog_first_unhealthy_time = None  # datetime: 首次检测到关键 unhealthy 的时间
_watchdog_consecutive_unhealthy_count = 0  # 连续关键 unhealthy 次数
_watchdog_enabled = True  # 控制 watchdog 线程启停（测试用）

# 会导致进程主动退出的关键健康检查项
CRITICAL_CHECKS = {'database', 'scheduler', 'scan_job', 'last_scan', 'status_page', 'api_status'}

# ---- 告警与扫描暂停 ----
# 首页开关可选时长（白名单，接口只接受这里的 key，避免任意秒数绕过前端）
PAUSE_DURATION_CHOICES = [
    {'key': '5m', 'label': '5 分钟', 'seconds': 300},
    {'key': '30m', 'label': '30 分钟', 'seconds': 1800},
    {'key': '1h', 'label': '1 小时', 'seconds': 3600},
    {'key': '5h', 'label': '5 小时', 'seconds': 18000},
    {'key': '24h', 'label': '24 小时', 'seconds': 86400},
]
_PAUSE_DURATION_MAP = {item['key']: item for item in PAUSE_DURATION_CHOICES}
_PAUSE_TIME_FORMAT = '%Y-%m-%d %H:%M:%S'


def _pause_state_label(state):
    """把落库的 duration_key 还原成人类可读时长文案。"""
    if not state:
        return ''
    key = str(state.get('duration_key') or '')
    item = _PAUSE_DURATION_MAP.get(key)
    if item:
        return item['label']
    seconds = state.get('duration_seconds')
    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        return key
    return f'{seconds} 秒'


def get_pause_status():
    """统一读取「告警与扫描是否暂停」的当前状态。

    返回结构（API / 健康检查 / 扫描闸门 / 告警闸门共用同一份口径）：
        {
          paused: bool,              当前是否处于暂停中
          until: 'YYYY-mm-dd HH:MM:SS' | None,   暂停到期时间
          remaining_seconds: int,    剩余秒数（未暂停为 0）
          duration_key / duration_label / duration_seconds,  本次选择的时长
          started_at: str,           本次暂停的开始时间
          expired: bool              是否刚刚自然到期（用于前端提示）
        }
    自然到期时会顺手清掉过期记录，避免状态一直挂在“已暂停”上。
    """
    state = load_pause_state()
    now = datetime.now()
    empty = {
        'paused': False,
        'until': None,
        'remaining_seconds': 0,
        'duration_key': '',
        'duration_label': '',
        'duration_seconds': 0,
        'started_at': '',
        'expired': False,
    }
    if not state:
        return empty

    until_raw = str(state.get('pause_until') or '').strip()
    until = None
    try:
        until = datetime.strptime(until_raw, _PAUSE_TIME_FORMAT)
    except ValueError:
        until = None

    if until is None:
        # 记录损坏（时间格式非法）：清掉，按未暂停处理，避免永久卡在暂停态
        print(f"[PAUSE] 暂停到期时间无法解析（{until_raw!r}），已清除该状态", flush=True)
        try:
            save_pause_state(None)
        except Exception:
            pass
        return empty

    if until <= now:
        # 自然到期：清除记录，让定时采集下一轮自动恢复
        print(f"[PAUSE] 暂停已自然到期（{until_raw}），自动恢复采集与告警", flush=True)
        try:
            save_pause_state(None)
        except Exception:
            pass
        result = dict(empty)
        result['until'] = until.strftime(_PAUSE_TIME_FORMAT)
        result['duration_key'] = str(state.get('duration_key') or '')
        result['duration_label'] = _pause_state_label(state)
        result['duration_seconds'] = int(state.get('duration_seconds') or 0)
        result['started_at'] = str(state.get('started_at') or '')
        result['expired'] = True
        return result

    remaining = int((until - now).total_seconds())
    return {
        'paused': True,
        'until': until.strftime(_PAUSE_TIME_FORMAT),
        'remaining_seconds': remaining,
        'duration_key': str(state.get('duration_key') or ''),
        'duration_label': _pause_state_label(state),
        'duration_seconds': int(state.get('duration_seconds') or 0),
        'started_at': str(state.get('started_at') or ''),
        'expired': False,
    }


def is_paused():
    """便捷判断：当前是否处于暂停中。"""
    try:
        return bool(get_pause_status().get('paused'))
    except Exception as exc:
        # 读取失败按“未暂停”处理（fail-open），保证监控不会因为一次读库失败而永久静默
        print(f"[PAUSE] 读取暂停状态异常，本次按未暂停处理: {exc}", flush=True)
        return False


def start_pause(duration_key):
    """开始/续期暂停。

    参数 duration_key 必须是 PAUSE_DURATION_CHOICES 里的 key；
    返回 (是否成功, 状态字典或错误说明)。
    """
    key = str(duration_key or '').strip().lower()
    item = _PAUSE_DURATION_MAP.get(key)
    if item is None:
        return False, f"不支持的暂停时长: {duration_key!r}（可选: {', '.join(_PAUSE_DURATION_MAP)}）"

    now = datetime.now()
    until = now + timedelta(seconds=item['seconds'])
    state = {
        'pause_until': until.strftime(_PAUSE_TIME_FORMAT),
        'started_at': now.strftime(_PAUSE_TIME_FORMAT),
        'duration_key': item['key'],
        'duration_seconds': item['seconds'],
    }
    affected = save_pause_state(state)
    if not affected:
        return False, '暂停状态写入数据库失败，请查看日志'
    print(f"[PAUSE] 已暂停告警与扫描 {item['label']}（到 {state['pause_until']} 自动恢复）", flush=True)
    return True, get_pause_status()


def stop_pause():
    """立即恢复（取消暂停）。返回 (是否成功, 状态字典)。"""
    affected = save_pause_state(None)
    print(f"[PAUSE] 已手动恢复告警与扫描（清除暂停状态，影响行数={affected}）", flush=True)
    return bool(affected), get_pause_status()



def _coerce_bool(value):
    """把任意输入安全地转换为布尔值，兼容字符串 'false'/'0' 等。"""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().casefold()
    if text in ('false', '0', 'no', 'off', 'none', 'null', 'undefined', ''):
        return False
    return bool(text)


def _normalize_client_details(raw_details):
    normalized = []
    for item in raw_details or []:
        if not isinstance(item, dict):
            continue
        # 事件兜底：即使状态格式异常或地址缺失，也保留一条可追踪的请求记录。
        ip = str(item.get('ip') or '').strip() or '未知'
        seconds = item.get('connected_seconds')
        try:
            seconds = int(seconds) if seconds is not None else None
        except (TypeError, ValueError):
            seconds = None
        try:
            bytes_received = int(item.get('bytes_received') or 0)
        except (TypeError, ValueError):
            bytes_received = 0
        try:
            bytes_sent = int(item.get('bytes_sent') or 0)
        except (TypeError, ValueError):
            bytes_sent = 0
        normalized.append({
            'ip': ip,
            'connected_since': str(item.get('connected_since') or '').strip(),
            'connected_seconds': seconds,
            'source': str(item.get('source') or '').strip(),
            'common_name': str(item.get('common_name') or '').strip(),
            'real_address': str(item.get('real_address') or '').strip(),
            'virtual_ip': str(item.get('virtual_ip') or '').strip(),
            'bytes_received': bytes_received,
            'bytes_sent': bytes_sent,
            'authenticated': _coerce_bool(item.get('authenticated', False)),
            'observed_request': _coerce_bool(item.get('observed_request', True)),
            'request_key': str(item.get('request_key') or '').strip(),
            'user': str(item.get('user') or '').strip(),
            'port': str(item.get('port') or '').strip(),
            # 终端名（pts/0、pts/1…）是 SSH 活跃会话的唯一标识，
            # 同一公网 IP 下的多个终端必须靠它区分，不能丢失。
            'terminal': str(item.get('terminal') or '').strip(),
            'auth_method': str(item.get('auth_method') or '').strip(),
            'status_type': str(item.get('status_type') or '').strip(),
            # 命中用户配置的「排除 IP / 排除用户名」规则 → 仅降级为「提示」，不丢弃、不通知
            'excluded': _coerce_bool(item.get('excluded', False))
        })
    return normalized


def _get_session_marker(detail):
    connected = detail.get('connected_since') or str(detail.get('connected_seconds') or 'unknown')
    real_address = detail.get('real_address') or 'unknown'
    virtual_ip = detail.get('virtual_ip') or 'no-vip'
    common_name = detail.get('common_name') or 'no-cn'
    status_type = detail.get('status_type') or ''
    port = detail.get('port') or ''
    terminal = detail.get('terminal') or ''
    if detail.get('source') == 'ssh_login' or status_type:
        return f'ssh|{status_type}|{common_name}|{connected}|{port}|{terminal}'
    return f'{virtual_ip}|{common_name}|{connected}|{real_address}'


def _get_alertable_sessions(client_details, window_seconds):
    sessions = []
    for detail in _normalize_client_details(client_details):
        seconds = detail.get('connected_seconds')
        if seconds is None or seconds < 0:
            continue
        if seconds <= window_seconds:
            sessions.append(detail)
    return sessions


def _format_connection_age(seconds):
    if seconds is None:
        return '连接时间未知'
    return f'已连接 {seconds} 秒'


def _resolve_location(ip):
    """返回 GeoIP 原始结果和展示文本。解析失败时不猜测城市。"""
    try:
        geo = resolve_ip(ip)
    except Exception as e:
        geo = {'city': '-', 'region': '-', 'country': '-', 'source': '无解析器', 'error': str(e)}
    parts = []
    for key in ('city', 'region', 'country'):
        val = str(geo.get(key, '')).strip()
        if val and val != '-':
            parts.append(val)
    return geo, (' | '.join(parts) if parts else '未知地区')


def _normalize_city_name(value):
    return str(value or '').strip().casefold().removesuffix('市')


def _is_trusted_city(geo, trusted_cities):
    # 内网/保留地址无法判定城市，按“未知”处理，绝不能当成“非信任城市紧急告警”
    if geo.get('is_private'):
        return None
    city = _normalize_city_name(geo.get('city'))
    if not city or city in ('-', '内网', '局域网'):
        return None
    trusted = {_normalize_city_name(item) for item in (trusted_cities or []) if _normalize_city_name(item)}
    return city in trusted


def _classify_session(server_type, detail, geo, trusted_cities):
    """提示: 命中排除规则 / OpenVPN 未分配虚拟 IP / SSH 认证失败；重要: 已连接/已登录；紧急: 已连接/已登录且明确不在信任城市。

    命中「排除 IP / 排除用户名」的记录不再被屏蔽，而是统一降级为「提示」：
    仍然写入事件日志与原始日志快照，但遵循告警等级规则，不发送任何通知。
    """
    if detail.get('excluded'):
        return '提示'
    if server_type == 'openvpn' and not detail.get('authenticated'):
        return '提示'
    if server_type == 'ssh_login' and not detail.get('authenticated'):
        return '提示'
    trusted = _is_trusted_city(geo, trusted_cities)
    if trusted is False:
        return '紧急'
    return '重要'


def notify_event(event_type, detail, server_name='', severity='重要', repeat=False):
    """按等级发送通知。提示级只记录事件，不调用通知渠道。

    系统处于「暂停告警与扫描」状态时，任何渠道的告警都会被抑制：
    只写审计日志，不调用 Telegram / Webhook，避免维护窗口内弹告警。
    """
    if severity == '提示':
        return []
    pause = get_pause_status()
    if pause.get('paused'):
        print(f"[PAUSE] 告警被抑制: 事件={event_type} 服务器={server_name} 等级={severity} "
              f"剩余={pause.get('remaining_seconds')}秒", flush=True)
        _audit_log(
            '告警抑制',
            '系统处于暂停状态，本次告警未发送到任何通知渠道（属于预期行为）',
            event_type=event_type,
            server_name=server_name,
            severity=severity,
            pause_until=pause.get('until'),
            remaining_seconds=pause.get('remaining_seconds'),
            business_impact='暂停期间不会产生任何告警推送'
        )
        return [f"已暂停，告警被抑制（剩余 {pause.get('remaining_seconds')} 秒）"]
    cfg = load_config()
    notif = cfg.get('notifications', {})
    messages = []
    repeat_text = '（持续告警）' if repeat else ''
    title = f'[{severity}] Server-Monitor 告警{repeat_text}'

    # Telegram
    tg = notif.get('telegram', {})
    if tg.get('enabled'):
        msg = f"<b>{title}</b>\n类型: {event_type}\n服务器: {server_name}\n时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n详情: {detail}"
        ok, info = send_telegram(tg.get('token'), tg.get('chat_id'), msg)
        messages.append(f"Telegram: {info}")
        print(f"[NOTIFY] {severity} | Telegram | 事件: {event_type} | 服务器: {server_name} | {'成功' if ok else '失败'}: {info}", flush=True)

    # Webhook
    wh = notif.get('webhook', {})
    if wh.get('enabled'):
        msg = f"[{severity}] [{event_type}] {server_name}: {detail}"
        ok, info = send_webhook(wh, msg)
        messages.append(f"Webhook: {info}")
        print(f"[NOTIFY] {severity} | Webhook | 事件: {event_type} | 服务器: {server_name} | {'成功' if ok else '失败'}: {info}", flush=True)

    return messages


def do_scan():
    """执行一次完整采集"""
    global _last_scan_start_time, _last_scan_end_time

    # ---- 暂停闸门（定时任务与手动采集共用同一个入口） ----
    pause = get_pause_status()
    if pause.get('paused'):
        now = datetime.now()
        # 暂停期间不采集、不检测事件、不告警；但仍推进“最近扫描时间”，
        # 否则 watchdog 会把“人为暂停”误判成“扫描卡死”而主动重启容器。
        _last_scan_start_time = now
        _last_scan_end_time = now
        print(f"[PAUSE] 本轮扫描已跳过（剩余 {pause.get('remaining_seconds')} 秒，"
              f"预计 {pause.get('until')} 自动恢复）", flush=True)
        _audit_log(
            '扫描跳过',
            '系统处于暂停状态，本轮采集被跳过，未连接任何服务器，也未产生任何告警',
            pause_until=pause.get('until'),
            remaining_seconds=pause.get('remaining_seconds'),
            duration_label=pause.get('duration_label'),
            business_impact='暂停期间不扫描、不告警，属于预期行为'
        )
        return []

    _last_scan_start_time = datetime.now()

    cfg = load_config()
    servers = cfg.get('servers', [])
    alert_window = max(1, int(cfg.get('connection_alert_window', 300)))
    scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    results = []

    for srv in servers:
        if not srv.get('enabled', True):
            continue

        # 注意：默认参数会被立即求值，缺 host/port 时会抛 KeyError 拖垮整轮扫描；
        # 用 `or` 短路，并在 _normalize_config 里对 host/port 做兜底。
        srv_name = srv.get('name') or f"{srv.get('host', '')}:{srv.get('port', '')}"
        print(f"[{datetime.now()}] 采集: {srv_name} ...", flush=True)

        # 执行 SSH 采集
        result = collect_server(srv)
        results.append((srv, result))

        # 保存扫描记录
        save_scan_record(
            server_name=srv_name,
            server_type=srv.get('type', ''),
            scan_time=scan_time,
            online_count=result['online_count'],
            client_ips=result['client_ips'],
            client_details=result.get('client_details', []),
            raw_output=result['raw_output'],
            status=result['status'],
            error_message=result['error_message'],
            duration_ms=result['duration_ms']
        )

        # ---- 事件检测 ----
        with _collect_lock:
            prev_ips = last_client_ips.get(srv_name, set())
            prev_alerted_keys = alerted_client_keys.get(srv_name, set())

            # 1. 服务不可达
            if result['status'] != 'success':
                detail = f"服务不可达: {result['error_message']}"
                print(f"  [EVENT] {detail}", flush=True)
                # 限流：服务器持续不可达时不要每轮都发通知（否则变成每分钟一条的告警风暴）。
                # 仅在首次不可达、或距上次通知超过 emergency_repeat_interval 时才再次通知。
                _unreachable_interval = max(10, int(cfg.get('emergency_repeat_interval', 300)))
                _now = time.time()
                _last = _unreachable_alert_state.get(srv_name, 0)
                if _now - _last >= _unreachable_interval:
                    notify_event('服务不可达', result['error_message'], srv_name, severity='重要')
                    _unreachable_alert_state[srv_name] = _now

            else:
                server_type = srv.get('type', '')
                # 服务恢复：清掉不可达限流状态，下次真掉线能立刻通知
                _unreachable_alert_state.pop(srv_name, None)
                new_ips = set(result['client_ips'])
                new_count = result['online_count']
                client_details = _normalize_client_details(result.get('client_details', []))
                # SSH 监控的 active_session 项仅表示此时此刻 who 在线，不作为新增登录告警候选
                alert_candidates = [d for d in client_details if d.get('status_type') != 'active_session'] if server_type == 'ssh_login' else client_details
                alertable_sessions = _get_alertable_sessions(alert_candidates, alert_window)
                # OpenVPN 的每一行都是已观察到的当前状态列表中的请求；
                # 但 SSH 登录是历史事件流：必须受告警窗口过滤，只有在告警窗口内发生的登录/失败才触发通知和告警。
                sessions_to_record = client_details if server_type == 'openvpn' else alertable_sessions
                current_session_keys = {(detail['ip'], _get_session_marker(detail)) for detail in client_details}
                trusted_cities = cfg.get('trusted_cities', ['北京'])
                repeat_interval = max(10, int(cfg.get('emergency_repeat_interval', 300)))
                now_ts = time.time()
                classified = {}

                for detail_item in client_details:
                    session_key = (detail_item['ip'], _get_session_marker(detail_item))
                    geo, location = _resolve_location(detail_item['ip'])
                    severity = _classify_session(server_type, detail_item, geo, trusted_cities)
                    classified[session_key] = (severity, geo, location, detail_item)

                for detail_item in sessions_to_record:
                    session_key = (detail_item['ip'], _get_session_marker(detail_item))
                    if session_key in prev_alerted_keys:
                        continue

                    severity, geo, location, _ = classified[session_key]
                    connected_since = str(detail_item.get('connected_since', '')).strip()
                    authenticated = bool(detail_item.get('authenticated')) if server_type in ('openvpn', 'ssh_login') else True
                    if server_type == 'ssh_login':
                        user_name = detail_item.get('user') or detail_item.get('common_name') or 'unknown'
                        auth_method = detail_item.get('auth_method') or 'auth'
                        if detail_item.get('excluded'):
                            # 命中排除规则：保留记录但降级为提示，明确标注原因，避免误读为登录失败
                            event_type = 'ssh_login_excluded'
                            action_text = f'SSH登录(已排除,用户:{user_name})'
                        elif severity == '提示':
                            event_type = 'ssh_login_failed'
                            action_text = f'SSH登录失败(用户:{user_name})'
                        else:
                            event_type = 'ssh_login_success'
                            action_text = f'SSH登录成功(用户:{user_name})'
                    else:
                        event_type = 'connection_request' if severity == '提示' else 'new_client_alert'
                        action_text = '未认证连接请求' if severity == '提示' else '新客户端上线'
                    extra = ''
                    if server_type == 'openvpn':
                        extra = (f"，CN={detail_item.get('common_name') or 'UNDEF'}"
                                 f"，虚拟IP={detail_item.get('virtual_ip') or '未分配'}")
                    elif server_type == 'ssh_login':
                        port_info = f", 端口={detail_item.get('port')}" if detail_item.get('port') else ''
                        extra = f"，方式={detail_item.get('auth_method') or '未知'}{port_info}"
                    notify_detail = f"{action_text}: {detail_item['ip']}（{location}{extra}）"
                    # 通知消息不再重复动作词（“新客户端上线: IP（…）”只出现一次）
                    notify_text = f"{detail_item['ip']}（{location}{extra}）"
                    structured = json.dumps({
                        'ip': detail_item['ip'],
                        'connected_since': connected_since,
                        'location': location,
                        'city': geo.get('city', '-'),
                        'severity': severity,
                        'authenticated': authenticated,
                        'common_name': detail_item.get('common_name', ''),
                        'virtual_ip': detail_item.get('virtual_ip', ''),
                        'user': detail_item.get('user', ''),
                        'excluded': bool(detail_item.get('excluded'))
                    }, ensure_ascii=False)
                    event_detail = f"{notify_detail}|||{structured}"
                    should_notify = severity in ('重要', '紧急')
                    print(f"  [EVENT] [{severity}] {notify_detail}", flush=True)
                    save_event(
                        event_type,
                        srv_name,
                        event_detail,
                        notified=1 if should_notify else 0,
                        snapshot_content=result.get('raw_output', ''),
                        severity=severity
                    )
                    if should_notify:
                        notify_event(action_text, notify_text, srv_name, severity=severity)
                    if severity == '紧急':
                        emergency_key = (srv_name, session_key[0], session_key[1])
                        active_emergency_alerts[emergency_key] = {
                            'last_notified_at': now_ts,
                            'detail': notify_text,
                            'event_type': action_text
                        }

                # 清理已断开或不再是紧急等级的会话，并按间隔重复通知仍在线的紧急会话
                current_emergency_keys = {
                    (srv_name, key[0], key[1])
                    for key, value in classified.items()
                    if value[0] == '紧急'
                }
                # 容器重启后继续跟踪当前仍在线的紧急会话，从本次采集开始计时。
                for session_key, value in classified.items():
                    severity, geo, location, detail_item = value
                    if severity != '紧急':
                        continue
                    emergency_key = (srv_name, session_key[0], session_key[1])
                    if emergency_key in active_emergency_alerts:
                        continue
                    extra = ''
                    if server_type == 'openvpn':
                        extra = (f"，CN={detail_item.get('common_name') or 'UNDEF'}"
                                 f"，虚拟IP={detail_item.get('virtual_ip') or '未分配'}")
                    elif server_type == 'ssh_login':
                        port_info = f", 端口={detail_item.get('port')}" if detail_item.get('port') else ''
                        extra = f"，方式={detail_item.get('auth_method') or '未知'}{port_info}"
                    action_text_emer = f'SSH登录成功(用户:{detail_item.get("user") or detail_item.get("common_name") or "unknown"})' if server_type == 'ssh_login' else '新客户端上线'
                    active_emergency_alerts[emergency_key] = {
                        'last_notified_at': now_ts,
                        'detail': f"{detail_item['ip']}（{location}{extra}）",
                        'event_type': action_text_emer
                    }
                for emergency_key in list(active_emergency_alerts):
                    if emergency_key[0] != srv_name:
                        continue
                    if emergency_key not in current_emergency_keys:
                        print(f"  [EMERGENCY] 客户端已断开，停止持续告警: {emergency_key[1]}", flush=True)
                        active_emergency_alerts.pop(emergency_key, None)
                        continue
                    state = active_emergency_alerts[emergency_key]
                    if now_ts - state['last_notified_at'] >= repeat_interval:
                        notify_event(
                            state['event_type'], state['detail'], srv_name,
                            severity='紧急', repeat=True
                        )
                        state['last_notified_at'] = now_ts

                # 更新缓存
                last_client_ips[srv_name] = new_ips
                last_online_counts[srv_name] = new_count
                alerted_client_keys[srv_name] = prev_alerted_keys.intersection(current_session_keys)
                alerted_client_keys[srv_name].update({
                    (detail['ip'], _get_session_marker(detail)) for detail in sessions_to_record
                })

            print(f"  -> 状态={result['status']}, 在线={result['online_count']}, "
                  f"IPs={result['client_ips']}, 耗时={result['duration_ms']}ms", flush=True)

    _last_scan_end_time = datetime.now()
    return results


def on_scan_interval_changed():
    """扫描间隔变更后重新调度"""
    global scheduler
    cfg = load_config()
    interval = int(cfg.get('scan_interval', 60))
    if scheduler:
        try:
            scheduler.remove_job('periodic_scan')
        except Exception:
            pass
        scheduler.add_job(
            do_scan,
            'interval',
            seconds=interval,
            id='periodic_scan',
            replace_existing=True,
            max_instances=1
        )
        print(f"[SCHEDULER] 扫描间隔已更新为 {interval} 秒", flush=True)


def health_check():
    """健康检查：返回所有子检查的状态和详细信息"""
    checks = {}
    healthy = True

    # 1. Flask 应用可响应 — 此函数能执行即证明 Flask 可响应
    checks['flask'] = {'status': 'ok'}

    # 2. 数据库可访问
    try:
        db_ok = db_ping()
        checks['database'] = {'status': 'ok' if db_ok else 'fail'}
        if not db_ok:
            healthy = False
    except Exception as e:
        checks['database'] = {'status': 'fail', 'error': str(e)}
        healthy = False

    # 3. APScheduler 已启动
    try:
        if scheduler is not None and scheduler.running:
            checks['scheduler'] = {'status': 'ok'}
        else:
            checks['scheduler'] = {'status': 'fail', 'error': '调度器未运行'}
            healthy = False
    except Exception as e:
        checks['scheduler'] = {'status': 'fail', 'error': str(e)}
        healthy = False

    # 4. 周期扫描任务存在
    try:
        if scheduler is not None:
            job = scheduler.get_job('periodic_scan')
            if job is not None:
                checks['scan_job'] = {'status': 'ok', 'next_run': str(job.next_run_time) if job.next_run_time else None}
            else:
                checks['scan_job'] = {'status': 'fail', 'error': 'periodic_scan 任务不存在'}
                healthy = False
        else:
            checks['scan_job'] = {'status': 'fail', 'error': '调度器未初始化'}
            healthy = False
    except Exception as e:
        checks['scan_job'] = {'status': 'fail', 'error': str(e)}
        healthy = False

    # 5. 最近一次扫描时间未超时
    #    注意：系统处于「暂停扫描」状态时，扫描本来就是被有意停掉的，
    #    不能判定为 unhealthy（否则 watchdog 会在 24 小时暂停期间把容器反复重启）。
    cfg = load_config()
    scan_interval = max(1, int(cfg.get('scan_interval', 60)))
    # 阈值策略：3 倍扫描间隔 + 60 秒缓冲（保守合理）
    threshold = scan_interval * 3 + 60
    pause = get_pause_status()

    last_time = _last_scan_end_time or _last_scan_start_time
    if pause.get('paused'):
        checks['last_scan'] = {
            'status': 'ok',
            'paused': True,
            'last_scan_time': last_time.strftime('%Y-%m-%d %H:%M:%S') if last_time else None,
            'elapsed_seconds': round((datetime.now() - last_time).total_seconds(), 1) if last_time else None,
            'scan_interval': scan_interval,
            'threshold_seconds': threshold,
            'pause_until': pause.get('until'),
            'note': '告警与扫描已暂停，暂停期间不执行扫描，不计入超时判定'
        }
    elif last_time is not None:
        elapsed = (datetime.now() - last_time).total_seconds()
        last_scan_str = last_time.strftime('%Y-%m-%d %H:%M:%S')
        if elapsed <= threshold:
            checks['last_scan'] = {
                'status': 'ok',
                'last_scan_time': last_scan_str,
                'elapsed_seconds': round(elapsed, 1),
                'scan_interval': scan_interval,
                'threshold_seconds': threshold
            }
        else:
            checks['last_scan'] = {
                'status': 'fail',
                'last_scan_time': last_scan_str,
                'elapsed_seconds': round(elapsed, 1),
                'scan_interval': scan_interval,
                'threshold_seconds': threshold,
                'error': f'上次扫描已过去 {elapsed:.0f} 秒，超过阈值 {threshold} 秒'
            }
            healthy = False
    else:
        checks['last_scan'] = {
            'status': 'fail',
            'last_scan_time': None,
            'elapsed_seconds': None,
            'scan_interval': scan_interval,
            'threshold_seconds': threshold,
            'error': '尚未执行过扫描'
        }
        healthy = False

    # 6. 用户路径检查：/status 页面可渲染
    try:
        with app.test_client() as client:
            resp = client.get('/status')
            if resp.status_code == 200:
                checks['status_page'] = {'status': 'ok', 'type': 'user_path'}
            else:
                checks['status_page'] = {'status': 'fail', 'type': 'user_path',
                                         'error': f'/status 返回 HTTP {resp.status_code}'}
                healthy = False
    except Exception as e:
        checks['status_page'] = {'status': 'fail', 'type': 'user_path', 'error': str(e)}
        healthy = False

    # 7. 用户路径检查：/api/status 可返回正确数据
    try:
        with app.test_client() as client:
            resp = client.get('/api/status')
            if resp.status_code == 200:
                data = resp.get_json()
                if data and data.get('ok'):
                    checks['api_status'] = {'status': 'ok', 'type': 'user_path'}
                else:
                    checks['api_status'] = {'status': 'fail', 'type': 'user_path',
                                            'error': f'/api/status 返回异常数据: {data}'}
                    healthy = False
            else:
                checks['api_status'] = {'status': 'fail', 'type': 'user_path',
                                        'error': f'/api/status 返回 HTTP {resp.status_code}'}
                healthy = False
    except Exception as e:
        checks['api_status'] = {'status': 'fail', 'type': 'user_path', 'error': str(e)}
        healthy = False

    # 8. 告警/扫描暂停状态（信息项：暂停是人为操作，不参与健康判定）
    checks['pause'] = {
        'status': 'ok',
        'paused': pause.get('paused'),
        'until': pause.get('until'),
        'remaining_seconds': pause.get('remaining_seconds', 0),
        'duration_label': pause.get('duration_label', ''),
        'note': '告警与扫描暂停中，恢复后自动继续采集' if pause.get('paused') else '未暂停'
    }

    # 为已有内部检查项补充 type 标记
    _internal_check_names = {'flask', 'database', 'scheduler', 'scan_job', 'last_scan', 'pause'}
    for check_name in checks:
        if 'type' not in checks[check_name]:
            checks[check_name]['type'] = 'internal' if check_name in _internal_check_names else 'user_path'

    return {
        'status': 'healthy' if healthy else 'unhealthy',
        'checks': checks,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }, healthy


def _get_watchdog_threshold():
    """获取自愈 watchdog 的持续 unhealthy 阈值（秒）。
    采用保守策略：max(300 秒, 5 倍扫描间隔)"""
    try:
        cfg = load_config()
        scan_interval = max(1, int(cfg.get('scan_interval', 60)))
    except Exception:
        scan_interval = 60
    return max(300, scan_interval * 5)


def _watchdog_loop():
    """后台 watchdog 线程：周期性调用内部健康检查，持续关键 unhealthy 超阈值时主动退出。
    关键故障类型：数据库不可访问、调度器未运行、周期扫描任务丢失、最近扫描超时、/status 页面渲染异常、/api/status 接口异常。
    退出前输出明确日志，使用 os._exit(1) 确保非 0 退出码让 Docker 重启容器。"""
    global _watchdog_first_unhealthy_time, _watchdog_consecutive_unhealthy_count

    # 首次延迟：给系统足够的启动缓冲时间
    time.sleep(60)

    while _watchdog_enabled:
        try:
            check_interval = max(15, int(load_config().get('scan_interval', 60)) // 2)
        except Exception:
            check_interval = 30

        try:
            result, healthy = health_check()
        except Exception as e:
            print(f"[WATCHDOG] 健康检查执行异常: {e}", flush=True)
            time.sleep(check_interval)
            continue

        # 判断是否存在关键故障
        critical_fails = []
        for check_name in CRITICAL_CHECKS:
            check_info = result.get('checks', {}).get(check_name)
            if check_info and check_info.get('status') == 'fail':
                critical_fails.append(check_name)

        if critical_fails:
            now = datetime.now()
            if _watchdog_first_unhealthy_time is None:
                _watchdog_first_unhealthy_time = now
            _watchdog_consecutive_unhealthy_count += 1

            duration = (now - _watchdog_first_unhealthy_time).total_seconds()
            threshold = _get_watchdog_threshold()

            print(f"[WATCHDOG] 关键 unhealthy 持续 {duration:.0f}s / 阈值 {threshold}s "
                  f"(连续 {_watchdog_consecutive_unhealthy_count} 次), "
                  f"失败检查: {critical_fails}", flush=True)

            if duration >= threshold:
                print(f"[WATCHDOG] 关键 unhealthy 已持续 {duration:.0f}s，超过阈值 {threshold}s，主动退出进程", flush=True)
                sys.stdout.flush()
                sys.stderr.flush()
                os._exit(1)
        else:
            # 健康恢复，清零故障累计
            if _watchdog_consecutive_unhealthy_count > 0:
                print(f"[WATCHDOG] 健康恢复，重置故障累计 "
                      f"(之前连续 {_watchdog_consecutive_unhealthy_count} 次 unhealthy)", flush=True)
            _watchdog_first_unhealthy_time = None
            _watchdog_consecutive_unhealthy_count = 0

        time.sleep(check_interval)


# ==================== 日志轮转与自动清理 ====================

LOG_DIR = '/app/logs'
_ARCHIVE_PATTERN = re.compile(r'^(stdout|stderr)\.(\d{4}-\d{2}-\d{2})\.log$')


def _rotate_active_log_files():
    """启动时轮转：如果 stdout.log / stderr.log 的最后修改日期不是今天，将其归档为 .YYYY-MM-DD.log。
    必须在重定向 stdout/stderr 之前调用，此时旧文件句柄尚未由本进程持有。"""
    os.makedirs(LOG_DIR, exist_ok=True)
    today = datetime.now().strftime('%Y-%m-%d')

    for base_name in ('stdout', 'stderr'):
        active_path = os.path.join(LOG_DIR, f'{base_name}.log')
        if not os.path.exists(active_path):
            continue
        # 检查文件大小，空文件不归档（可能是新创建的空文件）
        if os.path.getsize(active_path) == 0:
            continue
        mtime = os.path.getmtime(active_path)
        file_date = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d')
        if file_date == today:
            continue  # 已经是今天的日志，无需轮转
        archive_path = os.path.join(LOG_DIR, f'{base_name}.{file_date}.log')
        if os.path.exists(archive_path):
            # 归档文件已存在，直接删除旧文件以避免重复归档
            os.remove(active_path)
            print(f"[LOGROTATE] {base_name}.log 的归档 {archive_path} 已存在，删除原文件", flush=True)
        else:
            os.rename(active_path, archive_path)
            print(f"[LOGROTATE] 归档日志: {active_path} → {archive_path}", flush=True)


def _cleanup_old_archives():
    """清理超过保留天数的归档日志文件（不触碰当前活跃的 stdout.log / stderr.log）。"""
    try:
        cfg = load_config()
        retention_days = max(1, int(cfg.get('log_retention_days', 30)))
    except Exception:
        retention_days = 30

    cutoff = datetime.now() - timedelta(days=retention_days)
    deleted_count = 0

    try:
        for fname in os.listdir(LOG_DIR):
            match = _ARCHIVE_PATTERN.match(fname)
            if not match:
                continue
            try:
                file_date = datetime.strptime(match.group(2), '%Y-%m-%d')
            except ValueError:
                continue
            if file_date < cutoff:
                try:
                    os.remove(os.path.join(LOG_DIR, fname))
                    deleted_count += 1
                    print(f"[LOGROTATE] 已删除过期日志: {fname} (保留 {retention_days} 天)", flush=True)
                except OSError as e:
                    print(f"[LOGROTATE] 删除失败: {fname}: {e}", flush=True)
    except Exception as e:
        print(f"[LOGROTATE] 清理归档日志时出错: {e}", flush=True)

    if deleted_count > 0:
        print(f"[LOGROTATE] 本轮共清理 {deleted_count} 个过期归档日志文件", flush=True)


def _daily_log_maintenance():
    """每日日志维护：清理过期归档 + 运行时日志轮转（将当前活跃日志按日归档并重开文件句柄）。"""
    today = datetime.now().strftime('%Y-%m-%d')

    # 先清理过期归档
    _cleanup_old_archives()

    # 运行时轮转活跃日志（如果当前文件最后修改日期不是今天）
    for base_name in ('stdout', 'stderr'):
        active_path = os.path.join(LOG_DIR, f'{base_name}.log')
        if not os.path.exists(active_path):
            continue
        if os.path.getsize(active_path) == 0:
            continue
        try:
            mtime = os.path.getmtime(active_path)
            file_date = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d')
        except OSError:
            continue
        if file_date == today:
            continue  # 今天已轮转

        archive_path = os.path.join(LOG_DIR, f'{base_name}.{file_date}.log')
        # 保存当前流引用
        old_stream = sys.stdout if base_name == 'stdout' else sys.stderr
        try:
            old_stream.flush()
            old_stream.close()
        except Exception:
            pass

        try:
            if os.path.exists(archive_path):
                os.remove(active_path)
            else:
                os.rename(active_path, archive_path)
        except OSError as e:
            print(f"[LOGROTATE] 轮转 {base_name}.log 失败: {e}", flush=True)
            # 无论如何都要重新打开文件，否则日志会丢失
        finally:
            new_stream = open(active_path, 'a', buffering=1)
            if base_name == 'stdout':
                sys.stdout = new_stream
            else:
                sys.stderr = new_stream

        print(f"[LOGROTATE] 运行时轮转: {base_name}.log → {archive_path}", flush=True)


# ==================== 访问控制（IP 白名单） ====================

# 被拒绝的浏览器请求返回的静态提示页（内联，避免未登录时再依赖静态资源）
_BLOCKED_PAGE = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><title>403 访问被拒绝</title>
<style>body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
background:#f5f6fa;color:#2c3e50;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}}
.box{{background:#fff;padding:32px 40px;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.08);max-width:660px;}}
h1{{font-size:20px;margin:0 0 12px;color:#c0392b;}} p{{font-size:14px;line-height:1.7;margin:8px 0;}}
code{{background:#f0f0f0;padding:2px 6px;border-radius:3px;font-size:13px;}}
table{{border-collapse:collapse;font-size:13px;margin:10px 0;}}
td{{padding:3px 12px 3px 0;vertical-align:top;}} td:first-child{{color:#888;white-space:nowrap;}}
.tip{{color:#888;font-size:12px;line-height:1.7;border-top:1px solid #eee;padding-top:10px;}}</style></head>
<body><div class="box">
<h1>403 访问被拒绝</h1>
<p>被识别的客户端 IP <code>{ip}</code> 不在访问白名单中。</p>
<table>
<tr><td>真实客户端</td><td><code>{ip}</code></td></tr>
<tr><td>TCP 直连来源</td><td><code>{peer}</code></td></tr>
<tr><td>转发链</td><td><code>{forwarded}</code></td></tr>
<tr><td>IP 取值来源</td><td><code>{source}</code></td></tr>
<tr><td>判定依据</td><td>{reason}</td></tr>
</table>
<p>如需放行，请在服务器上编辑 <code>config.json</code> 的 <code>allowed_ips</code> 字段后重启容器，
或从白名单内的机器访问 <code>/config</code> 页面添加规则。</p>
<p>诊断详情（本页不受白名单限制，可随时打开）：<a href="/ipcheck">/ipcheck</a></p>
<p class="tip">容器环境下上面两个 IP 可能不同：局域网直连时二者一致；经 Docker 端口映射的“本机访问”，
「TCP 直连来源」通常显示为网桥网关（例如 172.19.0.1）；若前面挂了反向代理，
需把代理地址加入 <code>trusted_proxies</code> 并开启 <code>trust_proxy</code> 才会采信转发链。<br>
内置规则 <code>127.0.0.1</code> 永久允许（仅对真正的本机直连生效），无法删除。</p>
</div></body></html>"""

# 访问自检页：始终可访问（不参与白名单拦截），只回显请求者自身信息，用于排查取 IP 问题
_IPCHECK_PAGE = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><title>访问自检</title>
<style>body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
background:#f5f6fa;color:#2c3e50;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}}
.box{{background:#fff;padding:28px 36px;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.08);max-width:680px;}}
h1{{font-size:19px;margin:0 0 14px;}} code{{background:#f0f0f0;padding:2px 6px;border-radius:3px;font-size:13px;}}
table{{border-collapse:collapse;font-size:13px;width:100%;}}
td{{padding:6px 12px 6px 0;vertical-align:top;border-bottom:1px solid #f2f2f2;}}
td:first-child{{color:#888;white-space:nowrap;width:132px;}}
.ok{{color:#27ae60;font-weight:bold;}} .no{{color:#c0392b;font-weight:bold;}}
.tip{{margin-top:14px;font-size:12px;color:#888;line-height:1.75;border-top:1px solid #eee;padding-top:10px;}}
a{{color:#3498db;}}</style></head>
<body><div class="box">
<h1>访问自检</h1>
<table>
<tr><td>访问控制开关</td><td>{enabled_text}</td></tr>
<tr><td>本次判定</td><td>{allowed_text}</td></tr>
<tr><td>真实客户端</td><td><code>{client}</code></td></tr>
<tr><td>TCP 直连来源</td><td><code>{peer}</code></td></tr>
<tr><td>转发链</td><td><code>{forwarded}</code></td></tr>
<tr><td>IP 取值来源</td><td><code>{source}</code></td></tr>
<tr><td>判定依据</td><td>{reason}</td></tr>
</table>
<p class="tip">{tip}<br>
JSON 版本：<a href="/ipcheck?format=json">/ipcheck?format=json</a></p>
</div></body></html>"""


@app.before_request
def _enforce_access_allowlist():
    """访问白名单拦截：总开关关闭时完全不拦截；开启后不在白名单内的 IP 一律拒绝并记录日志。"""
    # 自检页始终放行：被挡住的人必须能看到"自己被识别成哪个 IP"，否则无法自救
    if request.path == '/ipcheck':
        _audit_log('中间件-访问控制', '自检页按设计始终放行', result='通过', reason='/ipcheck 为自救诊断入口')
        return None

    try:
        cfg = load_config()
    except Exception as e:
        print(f"[ACCESS] 读取访问控制配置失败，按不拦截处理: {e}", flush=True)
        _audit_log('中间件-访问控制', '读取访问控制配置失败，采用安全可用性回退并放行',
                   result='通过', reason=str(e))
        return None

    # 总开关：默认关闭；未开启时不拦截任何访问
    if not _coerce_bool(cfg.get('access_control_enabled')):
        _audit_log('中间件-访问控制', '访问控制总开关关闭，本次请求不做 IP 拦截',
                   result='通过')
        return None

    allowed, info = check_request_access(request, cfg)
    if allowed:
        _audit_log('中间件-访问控制', '客户端命中访问白名单或本机放行规则',
                   result='通过', client_ip=info['client'], peer_ip=info['peer'],
                   reason=info['reason'])
        return None

    print(f"[ACCESS] 拒绝访问: client={info['client']} peer={info['peer']} "
          f"source={info['source']} forwarded={info['forwarded'] or '-'} "
          f"method={request.method} path={request.path} "
          f"ua={(request.headers.get('User-Agent') or '')[:100]}", flush=True)
    _audit_log(
        '请求被拦截',
        '客户端 IP 不在访问白名单，请求未进入业务逻辑',
        layer='IP白名单',
        result='拒绝',
        client_ip=info['client'],
        peer_ip=info['peer'],
        reason=info['reason'],
        status_code=403,
        business_impact='本次页面或接口请求未执行'
    )

    # API 请求返回 JSON，浏览器页面请求返回可读提示页
    if request.path.startswith('/api/') or request.path == '/healthz':
        return jsonify({
            'ok': False,
            'error': f'您的 IP ({info["client"]}) 不在访问白名单中',
            'client_ip': info['client'],
            'peer_ip': info['peer'],
            'forwarded_for': info['forwarded'],
            'ip_source': info['source'],
        }), 403
    return _BLOCKED_PAGE.format(
        # 这些值可能源自客户端请求头，进 HTML 前必须转义（防反射型 XSS）
        ip=html.escape(str(info['client'])),
        peer=html.escape(str(info['peer'])),
        forwarded=html.escape(str(info['forwarded'] or '（无）')),
        source=html.escape(str(info['source'])),
        reason=html.escape(str(info['reason'])),
    ), 403


# ==================== Flask 路由 ====================

@app.route('/healthz')
def api_healthz():
    """健康检查接口：返回结构化 JSON，unhealthy 时返回 HTTP 503"""
    result, healthy = health_check()
    status_code = 200 if healthy else 503
    return jsonify(result), status_code


@app.route('/ipcheck')
def ip_check_page():
    """访问自检页：排查"我的访问被识别成哪个 IP"。

    该路径不参与白名单拦截（否则被挡住的用户无法自查），且只回显请求者自身信息，
    不展示白名单内容。支持 /ipcheck?format=json 获取 JSON。
    """
    try:
        cfg = load_config()
        enabled = _coerce_bool(cfg.get('access_control_enabled'))
        trust_proxy = _coerce_bool(cfg.get('trust_proxy'))
        allowed, info = check_request_access(request, cfg)
    except Exception as e:
        print(f"[ACCESS] /ipcheck 执行异常: {e}", flush=True)
        return jsonify({'ok': False, 'error': f'自检失败: {e}'}), 500

    data = {
        'ok': True,
        'access_control_enabled': enabled,
        'trust_proxy': trust_proxy,
        'allowed': allowed,
        'client_ip': info['client'],
        'peer_ip': info['peer'],
        'forwarded_for': info['forwarded'],
        'ip_source': info['source'],
        'reason': info['reason'],
    }
    if request.args.get('format') == 'json':
        return jsonify(data)

    if not enabled:
        tip = ('访问控制总开关当前为「关闭」，不会拦截任何访问，上面的判定仅作参考。'
               '开启后若与本页显示的「真实客户端」不符，请把该 IP 加入白名单。')
    elif allowed:
        tip = ('本次访问已被放行。若你在排查取 IP 问题，请核对「真实客户端」是否与预期一致；'
               '若不一致，请检查是否需要开启 trust_proxy 并配置 trusted_proxies。')
    else:
        tip = ('本次访问会被拒绝。请把上面的「真实客户端」加入 访问控制 → 白名单 后保存。'
               '若你确实是经反向代理访问，还需开启 trust_proxy 并把代理地址加入 trusted_proxies。')

    return _IPCHECK_PAGE.format(
        enabled_text='<span class="ok">开启</span>' if enabled else '<span class="ok">关闭（不拦截任何访问）</span>',
        allowed_text=('<span class="ok">放行</span>' if allowed else '<span class="no">拒绝</span>') if enabled
                     else '<span class="ok">放行（未启用访问控制）</span>',
        # 这些字段可能来自客户端头，进 HTML 前必须转义（防反射型 XSS）
        client=html.escape(str(info['client'] or '未知')),
        peer=html.escape(str(info['peer'] or '未知')),
        forwarded=html.escape(str(info['forwarded'] or '（无）')),
        source=html.escape(str(info['source'] or '-')),
        reason=html.escape(str(info['reason'] or '-')),
        tip=tip,
    )


@app.route('/')
def index():
    return redirect(url_for('status_page'))


@app.route('/status')
def status_page():
    """当前状态页 — 前端通过 AJAX 自动刷新"""
    cfg = load_config()
    return render_template('status.html',
                           status_refresh_interval=max(3, int(cfg.get('status_refresh_interval', 5))),
                           now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))


@app.route('/history')
def history_page():
    """事件日志页。扫描历史已移除，页面仅展示真实告警/提示事件。"""
    _audit_log('业务入口', '进入事件日志页面，准备渲染页面模板')
    return render_template('history.html',
                           now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))


@app.route('/api/events')
def api_events():
    """API: 分页查询事件日志"""
    # 非法/缺失参数兜底，避免 int() 抛错把接口打成 500
    try:
        page = max(1, int(request.args.get('page', 1)))
    except (TypeError, ValueError):
        page = 1
    try:
        page_size = max(1, min(200, int(request.args.get('page_size', 50))))
    except (TypeError, ValueError):
        page_size = 50
    _audit_log('业务入口', '开始分页读取事件日志',
               page=page, page_size=page_size, database_operation='查询 events 表')
    items, total, clamped_page = get_events_paginated(page=page, page_size=page_size)
    _audit_log('数据库查询', '事件日志分页查询完成',
               requested_page=page, actual_page=clamped_page,
               page_size=page_size, returned_count=len(items), total=total)
    return jsonify({
        'ok': True,
        'items': items,
        'total': total,
        'page': clamped_page,
        'page_size': page_size,
        'trace_id': g.trace_id
    })


@app.route('/api/client-log', methods=['POST'])
def api_client_log():
    """前端审计日志上报：将页面加载、接口成功/失败统一落到项目日志目录。"""
    payload = request.get_json(silent=True) or {}
    _audit_log(
        '前端层',
        str(payload.get('message') or '前端页面上报了一条审计日志'),
        page=str(payload.get('page') or '')[:100],
        action=str(payload.get('action') or '')[:100],
        result=str(payload.get('result') or '')[:100],
        detail=str(payload.get('detail') or '')[:500]
    )
    return jsonify({'ok': True, 'trace_id': g.trace_id})


@app.route('/api/events/<int:event_id>/snapshot')
def api_event_snapshot(event_id):
    """API: 读取事件触发时刻保存的原始采集日志（如 openvpn-status.log）"""
    rec = get_event_snapshot(event_id)
    if not rec:
        return jsonify({'ok': False, 'error': '该事件没有保存原始日志快照'}), 404
    return jsonify({
        'ok': True,
        'event_id': rec['event']['id'],
        'event_time': rec['event']['event_time'],
        'event_type': rec['event']['event_type'],
        'severity': rec['event'].get('severity', '重要'),
        'server_name': rec['event']['server_name'],
        'filename': rec['filename'],
        'content': rec['content']
    })


@app.route('/config')
def config_page():
    """系统配置页"""
    safe_cfg = get_safe_config()
    allow_rules = [
        {'rule': rule, 'locked': is_permanent_rule(rule)}
        for rule in (safe_cfg.get('allowed_ips') or [])
    ]
    # 当前请求的 IP 判定结果，供用户在页面上自查（排查容器/反代环境下的取 IP 问题）
    try:
        _allowed, client_info = check_request_access(request, safe_cfg)
    except Exception:
        client_info = {'client': '', 'peer': '', 'forwarded': '', 'source': ''}
    return render_template('config.html', config=safe_cfg, allow_rules=allow_rules,
                           client_info=client_info,
                           now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))


@app.route('/api/config', methods=['GET'])
def api_get_config():
    """API: 获取完整配置（含明文密码，仅 API 用）"""
    cfg = load_config()
    return jsonify(cfg)


@app.route('/api/config', methods=['POST'])
def api_save_config():
    """API: 保存配置"""
    import traceback as _tb
    try:
        new_config = request.get_json(force=True)
        if not new_config:
            return jsonify({'ok': False, 'error': '请求体为空'}), 400
        ok = save_config(new_config)
        if ok:
            # 保存后立刻按新保留条数裁剪历史数据
            prune_result = prune_all()
            if prune_result['scan_deleted'] > 0 or prune_result['event_deleted'] > 0:
                print(f"[CONFIG] 保存后裁剪: 扫描-{prune_result['scan_deleted']}条, 事件-{prune_result['event_deleted']}条", flush=True)
            # 保存后立刻按新保留天数清理过期归档日志
            _cleanup_old_archives()
            # 更新调度间隔
            print("[DEBUG] save ok, calling on_scan_interval_changed...", flush=True)
            on_scan_interval_changed()
            print("[DEBUG] on_scan_interval_changed done, calling init_resolvers...", flush=True)
            # 重新初始化解析器（文件路径可能已变更）
            init_resolvers()
            print("[DEBUG] init_resolvers done", flush=True)
            return jsonify({'ok': True, 'message': '配置已保存'})
        else:
            return jsonify({'ok': False, 'error': '写入文件失败'}), 500
    except Exception as e:
        print(f"[ERROR] api_save_config exception: {_tb.format_exc()}", flush=True)
        return jsonify({'ok': False, 'error': str(e)}), 400


@app.route('/api/scan', methods=['POST'])
def api_trigger_scan():
    """API: 手动触发扫描（暂停期间拒绝执行）"""
    pause = get_pause_status()
    if pause.get('paused'):
        _audit_log(
            '请求被拒绝',
            '系统处于暂停状态，手动采集请求被拒绝，未进入采集业务逻辑',
            reject_layer='暂停闸门',
            reason='告警与扫描已暂停',
            status_code=409,
            pause_until=pause.get('until'),
            remaining_seconds=pause.get('remaining_seconds'),
            business_impact='本次未采集任何服务器，也未产生任何告警'
        )
        return jsonify({
            'ok': False,
            'paused': True,
            'error': f"告警与扫描已暂停（剩余 {pause.get('remaining_seconds')} 秒），请先恢复后再采集",
            'pause': pause
        }), 409
    try:
        _audit_log('业务入口', '收到手动采集请求，开始执行一次完整采集')
        results = do_scan()
        return jsonify({
            'ok': True,
            'results': [{
                'server': srv.get('name', ''),
                'status': res['status'],
                'online_count': res['online_count'],
                'client_ips': res['client_ips'],
                'error_message': res['error_message'],
                'duration_ms': res['duration_ms']
            } for srv, res in results]
        })
    except Exception as e:
        _audit_log('异常', '手动采集执行失败', exception_type=type(e).__name__,
                   reason=str(e)[:300], business_impact='本次手动采集未完成')
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/pause', methods=['GET'])
def api_get_pause():
    """API: 查询当前「告警与扫描暂停」状态"""
    pause = get_pause_status()
    return jsonify({
        'ok': True,
        'pause': pause,
        'choices': PAUSE_DURATION_CHOICES,
        'trace_id': g.trace_id
    })


@app.route('/api/pause', methods=['POST'])
def api_set_pause():
    """API: 暂停所有告警与扫描。

    请求体: {"duration": "5m" | "30m" | "1h" | "5h" | "24h"}
    """
    payload = request.get_json(silent=True) or {}
    raw_duration = payload.get('duration')
    duration_key = str(raw_duration or '').strip().lower()
    allowed = ', '.join(_PAUSE_DURATION_MAP)
    _audit_log(
        '参数校验',
        '校验暂停时长参数',
        field='duration',
        source='body',
        actual_value=duration_key or '（空）',
        expected_rule=f'必须是以下之一: {allowed}',
        result='通过' if duration_key in _PAUSE_DURATION_MAP else '失败'
    )
    if duration_key not in _PAUSE_DURATION_MAP:
        _audit_log(
            '请求被拒绝',
            '暂停时长不在允许范围内，请求被拒绝，未进入业务逻辑',
            reject_layer='参数校验',
            reason=f'不支持的暂停时长: {raw_duration!r}',
            status_code=400,
            business_impact='暂停未生效，系统仍在正常扫描与告警'
        )
        return jsonify({
            'ok': False,
            'error': f"不支持的暂停时长，可选: {allowed}",
            'choices': PAUSE_DURATION_CHOICES
        }), 400

    item = _PAUSE_DURATION_MAP[duration_key]
    ok, result = start_pause(duration_key)
    if not ok:
        _audit_log('异常', '暂停状态写入失败，暂停未生效',
                   exception_type='PausePersistError', reason=str(result)[:300],
                   business_impact='暂停未生效，系统仍在正常扫描与告警')
        return jsonify({'ok': False, 'error': result}), 500

    _audit_log(
        '业务执行',
        f"已暂停所有告警与扫描 {item['label']}",
        duration_key=item['key'],
        duration_seconds=item['seconds'],
        pause_until=result.get('until'),
        before='正常扫描并告警',
        after=f"暂停扫描与告警至 {result.get('until')}",
        business_impact=f"{item['label']}内不再采集、不再推送任何告警，到期自动恢复"
    )
    return jsonify({'ok': True, 'pause': result, 'message': f"已暂停 {item['label']}"})


@app.route('/api/resume', methods=['POST'])
def api_resume():
    """API: 立即恢复（取消暂停）"""
    before = get_pause_status()
    ok, result = stop_pause()
    _audit_log(
        '业务执行',
        '已手动恢复告警与扫描',
        before=f"暂停中（至 {before.get('until')}）" if before.get('paused') else '未暂停',
        after='正常扫描并告警',
        affected_rows=1 if ok else 0,
        business_impact='下一轮定时采集立即恢复，告警推送同步恢复'
    )
    return jsonify({'ok': True, 'pause': result, 'message': '已恢复告警与扫描'})


@app.route('/api/status')
def api_status():
    """API: 当前状态（仅展示 config.json 中存在且启用的服务器）"""
    cfg = load_config()
    # 收集当前配置中启用服务器的名称集合
    enabled_names = set()
    for srv in cfg.get('servers', []):
        if srv.get('enabled', True):
            enabled_names.add(srv.get('name', ''))

    latest = get_latest_scan_per_server()
    result = []
    for rec in latest:
        # 只展示配置中真实存在且启用的服务器，过滤掉测试残留等
        if rec['server_name'] not in enabled_names:
            continue
        try:
            ips = json.loads(rec['client_ips']) if isinstance(rec['client_ips'], str) else rec['client_ips']
        except Exception:
            ips = []
        try:
            client_details = json.loads(rec.get('client_details') or '[]') if isinstance(rec.get('client_details'), str) else (rec.get('client_details') or [])
        except Exception:
            client_details = []
        normalized_details = _normalize_client_details(client_details)
        if rec['server_type'] == 'openvpn':
            normalized_details = [item for item in normalized_details if item.get('authenticated')]
        elif rec['server_type'] == 'ssh_login':
            # 当前状态卡片只展示 who 提供的实时在线终端。
            # Accepted/Failed 日志属于事件流，只进入事件日志页面，不再混入服务器卡片。
            actives = [it for it in normalized_details if it.get('status_type') == 'active_session']

            def _dedup(items):
                seen, out = set(), []
                for it in items:
                    # 用「终端名」区分同一 IP 下的多个 SSH 会话（pts/0、pts/1…），
                    # 否则同机同用户同 IP 的并发终端会被误判为同一条而丢失。
                    key = (it.get('status_type'), it.get('user'), it.get('ip'),
                           it.get('connected_since'), it.get('port'), it.get('terminal'))
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(it)
                return out

            actives = _dedup(actives)
            normalized_details = actives
            # 在线数 = 当前活跃终端会话数。相同 IP 下的 pts/0、pts/1 是两个会话。
            online_count_display = len(actives)

        # 收集最终展示在表格中的所有 IP 以及当前在线 IP，统一进行地理位置解析
        all_ips_to_resolve = set(ips)
        for d in normalized_details:
            ip_val = d.get('ip')
            if ip_val and ip_val != '未知':
                all_ips_to_resolve.add(ip_val)
        geo_data = resolve_ips(list(all_ips_to_resolve))

        # SSH 类型的在线数按「当前活跃终端」实时统计（历史扫描记录里存的是旧口径）
        display_online = rec['online_count']
        if rec['server_type'] == 'ssh_login':
            display_online = online_count_display
        result.append({
            'server': rec['server_name'],
            'type': rec['server_type'],
            'scan_time': rec['scan_time'],
            'online_count': display_online,
            # 前端用它实时计算「距今」，不再依赖采集时的静态快照
            'server_now': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'client_ips': ips,
            'client_details': normalized_details,
            'geo_data': geo_data,
            'status': rec['status'],
            'error_message': rec['error_message'],
            'duration_ms': rec['duration_ms']
        })
    return jsonify({
        'ok': True,
        'servers': result,
        'resolver_status': get_resolver_status(),
        'db_stats': get_db_stats(),
        'pause': get_pause_status(),
        'pause_choices': PAUSE_DURATION_CHOICES,
        'refresh_interval': max(3, int(cfg.get('status_refresh_interval', 5))),
        'now': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })


@app.route('/api/test-notification', methods=['POST'])
def api_test_notification():
    """API: 测试通知发送（属于人工联调，不受暂停开关影响，但会记录暂停状态）"""
    pause = get_pause_status()
    _audit_log(
        '业务入口',
        '收到测试通知请求，开始向已启用的渠道发送测试消息',
        paused=pause.get('paused'),
        pause_until=pause.get('until'),
        note='测试通知由人工主动触发，不受暂停开关抑制'
    )
    cfg = load_config()
    notif = cfg.get('notifications', {})
    test_msg = "这是一条 Server-Monitor 测试通知。如果您收到此消息，说明通知渠道配置正确。"
    results = {}

    tg = notif.get('telegram', {})
    if tg.get('enabled'):
        ok, info = send_telegram(tg.get('token'), tg.get('chat_id'), test_msg)
        results['telegram'] = {'ok': ok, 'message': info}
        print(f"[NOTIFY-TEST] Telegram | {'成功' if ok else '失败'}: {info}", flush=True)
    else:
        results['telegram'] = {'ok': False, 'message': 'Telegram 通知未启用'}
        print(f"[NOTIFY-TEST] Telegram | 跳过: 通知未启用", flush=True)

    wh = notif.get('webhook', {})
    if wh.get('enabled'):
        ok, info = send_webhook(wh, test_msg)
        results['webhook'] = {'ok': ok, 'message': info}
        print(f"[NOTIFY-TEST] Webhook | {'成功' if ok else '失败'}: {info}", flush=True)
    else:
        results['webhook'] = {'ok': False, 'message': 'Webhook 通知未启用'}
        print(f"[NOTIFY-TEST] Webhook | 跳过: 通知未启用", flush=True)

    return jsonify({'ok': True, 'results': results})


@app.route('/api/resolver-status')
def api_resolver_status():
    """API: 解析器状态"""
    return jsonify({'ok': True, 'resolvers': get_resolver_status()})


# ==================== 启动 ====================

def main():
    global scheduler

    # ---- 日志轮转（必须在重定向 stdout/stderr 之前） ----
    _rotate_active_log_files()

    # 将 stdout / stderr 重定向到日志文件，配合 docker compose 挂载实现持久化
    log_dir = '/app/logs'
    os.makedirs(log_dir, exist_ok=True)
    sys.stdout = open(os.path.join(log_dir, 'stdout.log'), 'a', buffering=1)
    sys.stderr = open(os.path.join(log_dir, 'stderr.log'), 'a', buffering=1)

    # ---- 启动时清理过期归档日志 ----
    _cleanup_old_archives()

    print("=" * 60)
    print("  Server-Monitor v1.0")
    print("=" * 60)

    # 初始化
    print("[INIT] 初始化数据库...")
    init_db()

    print("[INIT] 初始化城市解析器...")
    init_resolvers()
    rs = get_resolver_status()
    for r in rs:
        print(f"  - {r['name']}: available={r['available']}, {r.get('error', '')}")

    # 首次采集
    print("[INIT] 执行首次采集...")
    do_scan()

    # 启动调度器
    cfg = load_config()
    interval = int(cfg.get('scan_interval', 60))
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        do_scan,
        'interval',
        seconds=interval,
        id='periodic_scan',
        replace_existing=True,
        max_instances=1
    )
    # 每日日志维护（清理过期归档 + 运行时轮转），在凌晨 3:00 执行
    scheduler.add_job(
        _daily_log_maintenance,
        'cron',
        hour=3,
        minute=0,
        id='daily_log_maintenance',
        replace_existing=True,
        max_instances=1
    )
    scheduler.start()
    print(f"[SCHEDULER] 定时采集已启动，间隔 {interval} 秒")
    retention = int(cfg.get('log_retention_days', 30))
    print(f"[SCHEDULER] 每日日志维护已启动（凌晨 3:00），日志保留 {retention} 天")

    # 启动自愈 watchdog 后台线程
    watchdog_thread = threading.Thread(target=_watchdog_loop, daemon=True, name='watchdog')
    watchdog_thread.start()
    print(f"[WATCHDOG] 自愈 watchdog 已启动，阈值 {_get_watchdog_threshold()}s (max(300, 5×{interval}))")

    # 启动 Flask
    print("[WEB] 启动 Web 服务 http://127.0.0.1:5000")
    print("  页面: /status | /history | /config")
    print("=" * 60)

    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)


if __name__ == '__main__':
    main()
