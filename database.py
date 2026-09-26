"""
数据库模块 - SQLite 持久化存储
"""
import sqlite3
import json
import os
import re
import sys
import tempfile
from datetime import datetime

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _sqlite_writable(directory):
    """探测目录能否真正承载 SQLite 写事务。

    SQLite 依赖 POSIX 文件锁（fcntl）；在 CIFS/SMB 等网络盘上锁会失效，
    任何写事务都会立刻抛 `database is locked`。用一个一次性库实测，
    只有真能建表并写入才算可用。
    """
    probe = None
    try:
        os.makedirs(directory, exist_ok=True)
        fd, probe = tempfile.mkstemp(prefix='.sqlite-probe-', dir=directory)
        os.close(fd)
        conn = sqlite3.connect(probe, timeout=3)
        try:
            conn.execute('PRAGMA busy_timeout=3000')
            conn.execute('CREATE TABLE IF NOT EXISTS _probe (a INTEGER)')
            conn.execute('INSERT INTO _probe VALUES (1)')
            conn.commit()
        finally:
            conn.close()
        return True
    except Exception:
        return False
    finally:
        for suffix in ('', '-journal', '-wal', '-shm'):
            try:
                os.remove(probe + suffix)
            except (OSError, TypeError):
                pass


def _default_data_dir():
    """程序自带 data 目录不可用时的本机兜底目录。"""
    xdg = os.environ.get('XDG_DATA_HOME')
    if xdg:
        return os.path.join(xdg, 'server-monitor')
    return os.path.join(os.path.expanduser('~'), '.local', 'share', 'server-monitor')


def _resolve_data_dir():
    """决定数据目录（数据库 + 事件快照）。

    优先级：
      1. 环境变量 `SERVER_MONITOR_DATA_DIR`（显式指定，最高优先级）；
      2. 程序所在目录下的 `data/`（Docker 与常规部署的默认值）；
      3. 本机 `~/.local/share/server-monitor/`（程序目录在网络盘上时的兜底）。
    只选实测能承载 SQLite 写事务的目录，避免部署在 CIFS 上时启动即
    `database is locked`。
    """
    explicit = os.environ.get('SERVER_MONITOR_DATA_DIR')
    if explicit:
        os.makedirs(explicit, exist_ok=True)
        return explicit

    project_data = os.path.join(_BASE_DIR, 'data')
    if _sqlite_writable(project_data):
        return project_data

    fallback = _default_data_dir()
    if _sqlite_writable(fallback):
        print(
            f"[DB] 警告：{project_data} 无法承载 SQLite 写事务"
            "（常见于 CIFS/SMB 网络盘，文件锁失效）。"
            f"已自动改用本机目录 {fallback}；如需指定请设置环境变量 "
            "SERVER_MONITOR_DATA_DIR。",
            file=sys.stderr, flush=True,
        )
        return fallback

    # 两者都不可写：退回项目目录，让后续报错暴露真实问题。
    return project_data


DATA_DIR = _resolve_data_dir()
DB_PATH = os.path.join(DATA_DIR, 'vpn_alarm.db')
SNAPSHOT_DIR = os.path.join(DATA_DIR, 'event_snapshots')


def get_connection(timeout=30):
    """新建一个 SQLite 连接。

    - `busy_timeout` 调大，避免多线程写入时立刻 `database is locked`；
    - 每个调用方各自持有连接，用完必须 close()。
    """
    conn = sqlite3.connect(DB_PATH, timeout=timeout)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA busy_timeout=30000')
    return conn


def init_db():
    """初始化数据库表（确保父目录存在）"""
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)
    conn = get_connection()
    try:
        # WAL 能显著降低读写互相阻塞；CIFS/网络盘上可能不支持，失败就忽略继续。
        try:
            conn.execute('PRAGMA journal_mode=WAL')
        except Exception:
            pass
        # 让 DDL/写入走 IMMEDIATE 事务，减少多线程下 database is locked。
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS scan_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_name TEXT NOT NULL,
            server_type TEXT,
            scan_time TEXT NOT NULL,
            online_count INTEGER DEFAULT 0,
            client_ips TEXT DEFAULT '[]',
            client_details TEXT DEFAULT '[]',
            raw_output TEXT DEFAULT '',
            status TEXT DEFAULT 'success',
            error_message TEXT DEFAULT '',
            duration_ms INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            event_type TEXT NOT NULL,
            server_name TEXT,
            detail TEXT,
            notified INTEGER DEFAULT 0,
            snapshot_file TEXT DEFAULT '',
            severity TEXT DEFAULT '重要'
        );

        CREATE TABLE IF NOT EXISTS config_store (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT
        );
        ''')
        scan_columns = [row['name'] for row in conn.execute('PRAGMA table_info(scan_records)').fetchall()]
        if 'client_details' not in scan_columns:
            conn.execute("ALTER TABLE scan_records ADD COLUMN client_details TEXT DEFAULT '[]'")
        event_columns = [row['name'] for row in conn.execute('PRAGMA table_info(events)').fetchall()]
        if 'snapshot_file' not in event_columns:
            conn.execute("ALTER TABLE events ADD COLUMN snapshot_file TEXT DEFAULT ''")
        if 'severity' not in event_columns:
            conn.execute("ALTER TABLE events ADD COLUMN severity TEXT DEFAULT '重要'")
        conn.commit()
    finally:
        conn.close()
    # 修复 severity 字段引入前的历史事件等级（一次性，幂等）
    reclassify_legacy_events()
    # 修复历史“提示”事件的文案与类型（一次性，幂等）
    fix_legacy_prompt_wording()


def fix_legacy_prompt_wording():
    """历史“提示”事件文案与类型纠正（一次性）。

    2.0.6 之前所有新客户端告警（包括未认证请求）都记为
    event_type=new_client_alert、详情以“新客户端上线”开头。
    这里把已重算为“提示”的事件改为 connection_request / “未认证连接请求”，
    并清理可能重复的地点分组（如 （波兰）（波兰））。
    """
    conn = None
    try:
        conn = get_connection()
        marker = conn.execute(
            "SELECT value FROM config_store WHERE key='prompt_wording_fix_done'"
        ).fetchone()
        if marker:
            return 0
        rows = conn.execute(
            "SELECT id, detail FROM events "
            "WHERE severity='提示' AND event_type='new_client_alert'"
        ).fetchall()
        updated = 0
        for row in rows:
            detail = row['detail'] or ''
            if '|||' in detail:
                human, structured = detail.split('|||', 1)
            else:
                human, structured = detail, ''
            human = human.replace('新客户端上线', '未认证连接请求', 1)
            # 清理重复地点分组，如 （波兰）（波兰）
            human = re.sub(r'（([^（）]*?)）（\1）', r'（\1）', human)
            new_detail = f"{human}|||{structured}" if structured else human
            conn.execute(
                "UPDATE events SET event_type='connection_request', detail=? WHERE id=?",
                (new_detail, row['id'])
            )
            updated += 1
        conn.execute(
            "INSERT OR REPLACE INTO config_store (key, value, updated_at) "
            "VALUES ('prompt_wording_fix_done', '1', ?)",
            (datetime.now().strftime('%Y-%m-%d %H:%M:%S'),)
        )
        conn.commit()
        if updated:
            print(f"[DB] 提示事件文案修复完成：更新 {updated} 条", flush=True)
        return updated
    except Exception as exc:
        print(f"[DB] 提示事件文案修复失败: {exc}", flush=True)
        return 0
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _extract_event_ip(detail):
    """从事件 detail 的结构化 JSON 中提取 IP，供重算等级时匹配。"""
    if not detail:
        return None
    match = re.search(r'"ip"\s*:\s*"([^"]+)"', detail)
    return match.group(1) if match else None


def _norm_city_name(value):
    return str(value or '').strip().casefold().removesuffix('市')


def reclassify_legacy_events():
    """按事件快照（无快照时回退到对应扫描记录）重算旧事件等级。

    severity 字段是在 2.0.6 才引入的，旧记录被 ALTER 默认填成“重要”。
    这里根据当时的原始 openvpn-status 输出重新判定：
      - 未认证（UNDEF / 无虚拟 IP）→ 提示
      - 已认证且地点明确非信任城市 → 紧急
      - 其余（信任城市 / 地点未知）→ 重要
    通过 config_store 标记只执行一次，幂等安全。
    """
    try:
        from config_manager import load_config
        from collector import _parse_openvpn
    except Exception as exc:
        print(f"[DB] 旧事件等级重算跳过（依赖不可用）: {exc}", flush=True)
        return 0
    conn = None
    try:
        conn = get_connection()
        marker = conn.execute(
            "SELECT value FROM config_store WHERE key='severity_backfill_done'"
        ).fetchone()
        if marker:
            return 0

        trusted = {
            _norm_city_name(item)
            for item in (load_config().get('trusted_cities') or ['北京'])
            if _norm_city_name(item)
        }
        rows = conn.execute(
            "SELECT id, server_name, event_type, detail, snapshot_file, severity FROM events"
        ).fetchall()
        updated = 0
        for row in rows:
            detail = row['detail'] or ''
            ip = _extract_event_ip(detail)
            raw = None

            # 优先用事件触发时刻的快照
            path = _snapshot_path(row['snapshot_file'])
            if path and os.path.isfile(path):
                try:
                    with open(path, 'r', encoding='utf-8', errors='replace') as f:
                        raw = f.read()
                except OSError:
                    raw = None

            # 快照缺失时回退到包含该 IP 的最新扫描原始输出
            if raw is None and ip:
                scan_row = conn.execute(
                    "SELECT raw_output FROM scan_records "
                    "WHERE server_name=? AND raw_output LIKE ? "
                    "ORDER BY id DESC LIMIT 1",
                    (row['server_name'], '%' + ip + '%')
                ).fetchone()
                if scan_row and scan_row['raw_output']:
                    raw = scan_row['raw_output']

            if not raw:
                continue
            try:
                _ips, _count, details = _parse_openvpn(raw)
            except Exception:
                continue
            if not details:
                continue

            matched = next((d for d in details if d['ip'] == ip), None) if ip else None
            if matched is None and len(details) == 1:
                matched = details[0]
            if matched is None:
                continue

            location = ''
            loc_match = re.search(r'"location"\s*:\s*"([^"]*)"', detail)
            if loc_match:
                location = loc_match.group(1)

            if not matched.get('authenticated'):
                new_severity = '提示'
            else:
                loc_norm = _norm_city_name(location)
                if loc_norm and '未知' not in loc_norm and '-' not in loc_norm:
                    new_severity = '重要' if any(
                        item and item in loc_norm for item in trusted
                    ) else '紧急'
                else:
                    new_severity = '重要'

            if new_severity != (row['severity'] or '重要'):
                conn.execute(
                    "UPDATE events SET severity=? WHERE id=?", (new_severity, row['id'])
                )
                updated += 1

        conn.execute(
            "INSERT OR REPLACE INTO config_store (key, value, updated_at) "
            "VALUES ('severity_backfill_done', '1', ?)",
            (datetime.now().strftime('%Y-%m-%d %H:%M:%S'),)
        )
        conn.commit()
        if updated:
            print(f"[DB] 旧事件等级重算完成：更新 {updated} 条", flush=True)
        return updated
    except Exception as exc:
        print(f"[DB] 旧事件等级重算失败: {exc}", flush=True)
        return 0
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _prune_scan_records(conn, max_retention):
    """按最大保留条数裁剪扫描记录（保留最新的）"""
    if not max_retention or max_retention <= 0:
        return
    count_row = conn.execute('SELECT COUNT(*) as c FROM scan_records').fetchone()
    total = count_row['c']
    if total > max_retention:
        delete_count = total - max_retention
        # 删除最旧的记录，保留最新的 max_retention 条
        conn.execute(
            'DELETE FROM scan_records WHERE id NOT IN (SELECT id FROM scan_records ORDER BY id DESC LIMIT ?)',
            (max_retention,)
        )
        print(f"[DB] 裁剪扫描记录：删除 {delete_count} 条，保留 {max_retention} 条", flush=True)


def _snapshot_path(filename):
    """返回快照文件的绝对路径；非法文件名返回 None。"""
    if not filename:
        return None
    basename = os.path.basename(str(filename).strip())
    if not basename or basename != str(filename).strip():
        return None
    return os.path.join(SNAPSHOT_DIR, basename)


def _write_event_snapshot(event_id, server_name, event_time, content):
    """将事件触发时刻的采集原始输出写入挂载目录 data/event_snapshots/。"""
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)
    safe_server = re.sub(r'[^\w\-.]+', '_', server_name or 'server').strip('_')[:40] or 'server'
    safe_time = re.sub(r'[^\d]', '', event_time or '')[:14] or 'unknown'
    filename = f'{int(event_id)}_{safe_server}_{safe_time}.log'
    path = os.path.join(SNAPSHOT_DIR, filename)
    with open(path, 'w', encoding='utf-8', errors='replace') as f:
        f.write(content if content is not None else '')
    return filename


def _delete_snapshot_files(rows):
    """删除事件对应的快照文件（裁剪时调用）。"""
    for row in rows or []:
        filename = row['snapshot_file'] if isinstance(row, sqlite3.Row) else (row.get('snapshot_file') if isinstance(row, dict) else '')
        path = _snapshot_path(filename)
        if not path:
            continue
        try:
            if os.path.isfile(path):
                os.remove(path)
        except OSError as e:
            print(f"[DB] 删除事件快照失败: {filename}: {e}", flush=True)


def _prune_events(conn, max_retention):
    """按最大保留条数裁剪事件日志（保留最新的），并同步删除对应快照文件。"""
    if not max_retention or max_retention <= 0:
        return
    count_row = conn.execute('SELECT COUNT(*) as c FROM events').fetchone()
    total = count_row['c']
    if total > max_retention:
        delete_count = total - max_retention
        old_rows = conn.execute(
            'SELECT id, snapshot_file FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)',
            (max_retention,)
        ).fetchall()
        conn.execute(
            'DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)',
            (max_retention,)
        )
        _delete_snapshot_files(old_rows)
        print(f"[DB] 裁剪事件日志：删除 {delete_count} 条，保留 {max_retention} 条", flush=True)


def save_scan_record(server_name, server_type, scan_time, online_count,
                     client_ips, client_details, raw_output, status, error_message, duration_ms):
    conn = get_connection()
    try:
        conn.execute('''
            INSERT INTO scan_records (server_name, server_type, scan_time, online_count,
                                      client_ips, client_details, raw_output, status, error_message, duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (server_name, server_type, scan_time, online_count,
              json.dumps(client_ips), json.dumps(client_details), raw_output, status, error_message, duration_ms))
        # 自动裁剪：按 scan_history_retention 上限删除旧记录
        from config_manager import load_config
        cfg = load_config()
        max_retention = int(cfg.get('scan_history_retention', 10000) or 10000)
        _prune_scan_records(conn, max_retention)
        conn.commit()
    finally:
        # 异常路径也必须关闭，否则悬空写事务会长期持锁并加剧 database is locked
        conn.close()


def save_event(event_type, server_name, detail, notified=0, snapshot_content=None, severity='重要'):
    """写入事件日志。snapshot_content 为触发时刻的采集原始输出（如 openvpn-status.log）。"""
    event_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    severity = severity if severity in ('提示', '重要', '紧急') else '重要'
    conn = get_connection()
    try:
        cur = conn.execute('''
            INSERT INTO events (event_time, event_type, server_name, detail, notified, snapshot_file, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (event_time, event_type, server_name, detail, notified, '', severity))
        event_id = cur.lastrowid
        if snapshot_content is not None:
            try:
                snapshot_file = _write_event_snapshot(event_id, server_name, event_time, snapshot_content)
                conn.execute('UPDATE events SET snapshot_file=? WHERE id=?', (snapshot_file, event_id))
            except Exception as e:
                print(f"[DB] 写入事件快照失败: event_id={event_id}: {e}", flush=True)
        # 自动裁剪：按 event_history_retention 上限删除旧记录
        from config_manager import load_config
        cfg = load_config()
        max_retention = int(cfg.get('event_history_retention', 5000) or 5000)
        _prune_events(conn, max_retention)
        conn.commit()
        return event_id
    finally:
        conn.close()


def get_latest_scan_per_server():
    conn = get_connection()
    try:
        rows = conn.execute('''
            SELECT s.* FROM scan_records s
            INNER JOIN (
                SELECT server_name, MAX(id) as max_id FROM scan_records GROUP BY server_name
            ) latest ON s.id = latest.max_id
            ORDER BY s.server_name
        ''').fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def get_recent_events(limit=100):
    conn = get_connection()
    try:
        rows = conn.execute(
            'SELECT * FROM events ORDER BY id DESC LIMIT ?', (limit,)
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def get_events_paginated(page=1, page_size=50):
    """分页查询事件日志，返回 (items, total_count, clamped_page)，自动将越界页码修正为最大有效页"""
    # 入口钳制，避免 page_size=0 除零或非法值直接把接口打成 500
    try:
        page_size = int(page_size)
    except (TypeError, ValueError):
        page_size = 50
    page_size = max(1, min(page_size, 500))
    try:
        page = int(page)
    except (TypeError, ValueError):
        page = 1
    conn = get_connection()
    try:
        total = conn.execute('SELECT COUNT(*) as c FROM events').fetchone()['c']
        total_pages = max(1, (total + page_size - 1) // page_size)
        if page < 1:
            page = 1
        if page > total_pages:
            page = total_pages
        offset = (page - 1) * page_size
        rows = conn.execute(
            'SELECT * FROM events ORDER BY id DESC LIMIT ? OFFSET ?',
            (page_size, offset)
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows], total, page


def get_event_snapshot(event_id):
    """读取指定事件触发时刻保存的原始采集日志快照。
    返回 dict: {event, filename, content}；不存在时返回 None。"""
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        return None
    conn = get_connection()
    try:
        row = conn.execute('SELECT * FROM events WHERE id=?', (event_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    rec = dict(row)
    path = _snapshot_path(rec.get('snapshot_file') or '')
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError:
        return None
    return {
        'event': rec,
        'filename': os.path.basename(path),
        'content': content
    }


def get_known_ips():
    """获取历史出现过的所有 IP"""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT DISTINCT client_ips FROM scan_records WHERE client_ips != '[]' ORDER BY id DESC LIMIT 50"
        ).fetchall()
    finally:
        conn.close()
    all_ips = set()
    for r in rows:
        try:
            ips = json.loads(r['client_ips'])
            all_ips.update(ips)
        except Exception:
            pass
    return list(all_ips)


def db_ping():
    """轻量数据库连通性检查，用于健康检查"""
    conn = None
    try:
        conn = get_connection()
        conn.execute('SELECT 1')
        return True
    except Exception:
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# ==================== 告警/扫描暂停状态持久化 ====================
# 暂停状态存在 config_store（key/value）里而不是内存里：
# 容器重启、进程崩溃自愈重启后暂停仍然有效，不会因为重启把“暂停”悄悄丢掉，
# 从而在维护窗口内突然又开始扫描并弹出告警。
PAUSE_STATE_KEY = 'alert_scan_pause'


def save_pause_state(state):
    """写入（覆盖）暂停状态。

    - state 为 dict 时写入 JSON；为 None 时删除该键（表示恢复）。
    - 返回受影响行数，供调用方判断是否真的落库。
    """
    conn = None
    try:
        conn = get_connection()
        if state is None:
            cursor = conn.execute('DELETE FROM config_store WHERE key=?', (PAUSE_STATE_KEY,))
            affected = cursor.rowcount
            action = '清除暂停状态'
        else:
            cursor = conn.execute(
                'INSERT OR REPLACE INTO config_store (key, value, updated_at) VALUES (?, ?, ?)',
                (PAUSE_STATE_KEY,
                 json.dumps(state, ensure_ascii=False),
                 datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            affected = cursor.rowcount
            action = '写入暂停状态'
        conn.commit()
        print(f"[DB] {action}: key={PAUSE_STATE_KEY} 影响行数={affected} "
              f"内容={json.dumps(state, ensure_ascii=False) if state is not None else '（无）'}", flush=True)
        return affected
    except Exception as exc:
        print(f"[DB] {('清除' if state is None else '写入')}暂停状态失败: {exc}", flush=True)
        return 0
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def load_pause_state():
    """读取暂停状态。

    返回 dict（含 updated_at）或 None（从未暂停过 / 记录损坏 / 读取失败）。
    调用方需要自行判断 pause_until 是否已经过期。
    """
    conn = None
    try:
        conn = get_connection()
        row = conn.execute(
            'SELECT value, updated_at FROM config_store WHERE key=?',
            (PAUSE_STATE_KEY,)
        ).fetchone()
    except Exception as exc:
        print(f"[DB] 读取暂停状态失败: {exc}", flush=True)
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    if row is None:
        return None
    try:
        state = json.loads(row['value'])
    except Exception as exc:
        print(f"[DB] 暂停状态内容损坏，按“未暂停”处理: {exc}", flush=True)
        return None
    if not isinstance(state, dict):
        print(f"[DB] 暂停状态类型异常（{type(state).__name__}），按“未暂停”处理", flush=True)
        return None
    state['updated_at'] = row['updated_at']
    return state


def get_db_stats():
    conn = get_connection()
    try:
        scan_count = conn.execute('SELECT COUNT(*) as c FROM scan_records').fetchone()['c']
        event_count = conn.execute('SELECT COUNT(*) as c FROM events').fetchone()['c']
    finally:
        conn.close()
    return {'scan_count': scan_count, 'event_count': event_count}


def prune_all():
    """
    立即按配置的保留条数裁剪扫描记录和事件日志（互不影响）。
    用于配置保存后立刻清理超出上限的旧数据。
    返回 dict: {scan_deleted, event_deleted}
    """
    from config_manager import load_config
    cfg = load_config()
    max_scan = int(cfg.get('scan_history_retention', 10000) or 10000)
    max_event = int(cfg.get('event_history_retention', 5000) or 5000)

    conn = get_connection()
    result = {'scan_deleted': 0, 'event_deleted': 0}

    try:
        # 裁剪扫描记录
        if max_scan > 0:
            count_row = conn.execute('SELECT COUNT(*) as c FROM scan_records').fetchone()
            total = count_row['c']
            if total > max_scan:
                result['scan_deleted'] = total - max_scan
                conn.execute(
                    'DELETE FROM scan_records WHERE id NOT IN (SELECT id FROM scan_records ORDER BY id DESC LIMIT ?)',
                    (max_scan,)
                )
                print(f"[DB] prune_all: 扫描记录删除 {result['scan_deleted']} 条，保留 {max_scan} 条", flush=True)
    except Exception as e:
        print(f"[DB] prune_all scan error: {e}", flush=True)

    try:
        # 裁剪事件日志
        if max_event > 0:
            count_row = conn.execute('SELECT COUNT(*) as c FROM events').fetchone()
            total = count_row['c']
            if total > max_event:
                result['event_deleted'] = total - max_event
                old_rows = conn.execute(
                    'SELECT id, snapshot_file FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)',
                    (max_event,)
                ).fetchall()
                conn.execute(
                    'DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)',
                    (max_event,)
                )
                _delete_snapshot_files(old_rows)
                print(f"[DB] prune_all: 事件日志删除 {result['event_deleted']} 条，保留 {max_event} 条", flush=True)
    except Exception as e:
        print(f"[DB] prune_all event error: {e}", flush=True)

    conn.commit()
    conn.close()
    return result
