"""
采集器模块 - 通过 SSH 登录远程服务器执行只读命令
支持连接复用：对每个服务器保持长连接，10 秒心跳，自动重连。
"""
import os
import re
import time
import socket
import ipaddress
import threading
from datetime import datetime
import paramiko

DAT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---- 连接缓存（线程安全） ----
_conn_cache = {}       # key -> {'client': SSHClient, 'created_at': float}
_conn_lock = threading.Lock()


class CollectError(Exception):
    pass


def _make_cache_key(server_config):
    """根据服务器配置生成稳定的缓存键"""
    host = str(server_config.get('host', '') or '')
    port = int(server_config.get('port', 22))
    username = str(server_config.get('username', 'root') or 'root')
    return (host, port, username)


def _invalidate_connection(server_config):
    """从缓存中移除并关闭指定服务器的连接"""
    key = _make_cache_key(server_config)
    with _conn_lock:
        entry = _conn_cache.pop(key, None)
    if entry:
        try:
            entry['client'].close()
        except Exception:
            pass


def _get_or_create_connection(server_config, timeout=30):
    """
    从缓存获取可用连接，若不存在或已断开则创建新连接。
    返回 paramiko.SSHClient 实例。
    注意：此函数不关闭连接，由 _invalidate_connection 负责清理。
    """
    key = _make_cache_key(server_config)

    # 先尝试复用缓存中的连接
    with _conn_lock:
        entry = _conn_cache.get(key)
    if entry:
        client = entry['client']
        try:
            transport = client.get_transport()
            if transport is not None and transport.is_active():
                return client
        except Exception:
            pass
        # 连接已失效，移除并关闭
        _invalidate_connection(server_config)

    # 创建新连接
    client = _build_client(server_config, timeout)

    # 设置 SSH 层 keepalive（每 10 秒发送心跳包，防止空闲断开）
    try:
        transport = client.get_transport()
        if transport:
            transport.set_keepalive(10)
    except Exception:
        pass

    # 放入缓存
    with _conn_lock:
        _conn_cache[key] = {'client': client, 'created_at': time.time()}

    return client


def _build_client(server_config, timeout=30):
    """
    根据服务器配置创建并认证 SSHClient（原 collect_server 中的连接逻辑提取）。
    仅在 _get_or_create_connection 内部调用。
    """
    host = server_config.get('host', '')
    port = int(server_config.get('port', 22))
    username = server_config.get('username', 'root')
    password = server_config.get('password', '')
    ssh_key_path = server_config.get('ssh_key_path', '')
    ssh_key_passphrase = server_config.get('ssh_key_passphrase', '')

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # 构建 pkey 对象（如果配置了密钥路径）
    pkey = None
    if ssh_key_path:
        try:
            key_path = os.path.expanduser(ssh_key_path)
            if not os.path.isabs(key_path):
                key_path = os.path.join(DAT_DIR, key_path)
            if os.path.exists(key_path):
                key_loaders = [
                    paramiko.RSAKey,
                    paramiko.Ed25519Key,
                    paramiko.ECDSAKey,
                    paramiko.DSSKey,
                ]
                loaded = False
                for key_cls in key_loaders:
                    try:
                        if ssh_key_passphrase:
                            pkey = key_cls.from_private_key_file(key_path, password=ssh_key_passphrase)
                        else:
                            pkey = key_cls.from_private_key_file(key_path)
                        loaded = True
                        break
                    except paramiko.PasswordRequiredException:
                        continue
                    except Exception:
                        continue
                if not loaded:
                    try:
                        if ssh_key_passphrase:
                            pkey = paramiko.RSAKey.from_private_key_file(key_path, password=ssh_key_passphrase)
                        else:
                            pkey = paramiko.RSAKey.from_private_key_file(key_path)
                    except Exception:
                        pass
        except Exception:
            # 密钥加载失败不在此处报错，留给 connect 阶段处理
            pass

    connect_kwargs = {
        'hostname': host,
        'port': port,
        'username': username,
        'timeout': timeout,
    }
    if pkey is not None:
        connect_kwargs['pkey'] = pkey
        if password:
            connect_kwargs['password'] = password
        connect_kwargs['allow_agent'] = False
        connect_kwargs['look_for_keys'] = False
    elif password:
        connect_kwargs['password'] = password
        connect_kwargs['allow_agent'] = False
        connect_kwargs['look_for_keys'] = False
    else:
        connect_kwargs['allow_agent'] = True
        connect_kwargs['look_for_keys'] = True

    try:
        client.connect(**connect_kwargs)
    except Exception:
        # connect 失败时 paramiko 不会自行关闭，会残留半开 socket 与 transport 线程；
        # 监控场景会周期性重连挂掉的服务器，必须在此显式关闭否则 fd/线程持续累积。
        client.close()
        raise
    return client


def _ssh_exec(client, command, timeout=30):
    """
    执行 SSH 命令。
    注意：原命令中若含 docker exec -it，因 -it 在非交互式 SSH 中会导致
    "the input device is not a TTY" 错误，已在配置中去掉 -it 参数。
    若仍需 TTY，此处分配 PTY 伪终端作为兼容路径。
    """
    if '-it' in command or '-t' in command.split():
        # docker exec -it 需要 TTY（兼容路径）
        chan = client.get_transport().open_session()
        chan.get_pty()
        chan.exec_command(command)
        chan.settimeout(timeout)
        # 循环读取直到 EOF：PTY 分支此前只 recv 一次，超过 64KB 的输出会被静默截断
        chunks = []
        import time as _time
        deadline = _time.time() + timeout
        try:
            while True:
                if chan.recv_ready():
                    data = chan.recv(65536)
                    if not data:
                        break
                    chunks.append(data)
                    deadline = _time.time() + timeout
                    continue
                if chan.exit_status_ready() and not chan.recv_ready():
                    break
                if _time.time() > deadline:
                    # 读取超时：必须抛错，不能退化成空串被上层当成“在线 0 人”的成功
                    raise paramiko.SSHException('命令执行超时')
                _time.sleep(0.05)
        except OSError:
            chan.close()
            raise
        raw_output = b''.join(chunks).decode('utf-8', errors='replace')
        try:
            err = b''
            while chan.recv_stderr_ready():
                part = chan.recv_stderr(4096)
                if not part:
                    break
                err += part
            err = err.decode('utf-8', errors='replace')
        except Exception:
            err = ''
        chan.close()
        if not raw_output.strip() and err.strip():
            raw_output = err
        return raw_output.strip()
    else:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        # 设置读取超时
        stdout.channel.settimeout(timeout)
        stderr.channel.settimeout(timeout)
        try:
            raw_output = stdout.read().decode('utf-8', errors='replace').strip()
        except socket.timeout as e:
            # 超时必须显式报错：退化成空串会让上层写成 “status=success, online_count=0” 的假记录
            raise paramiko.SSHException('命令执行超时') from e
        except OSError:
            raise
        except paramiko.SSHException:
            raise
        except Exception:
            raise
        try:
            err_output = stderr.read().decode('utf-8', errors='replace').strip()
        except socket.timeout:
            err_output = ''
        except OSError:
            raise
        except Exception:
            err_output = ''
        if not raw_output and err_output:
            raw_output = err_output
        return raw_output


def _build_auth_hint(server_config):
    """根据服务器配置生成认证方式提示"""
    has_password = bool(server_config.get('password', ''))
    has_key = bool(server_config.get('ssh_key_path', ''))
    if has_password and has_key:
        return '(同时配置了密码和密钥，优先使用密钥)'
    if has_key:
        return '(使用 SSH 密钥认证)'
    if has_password:
        return '(使用密码认证)'
    return '(未配置密码或密钥)'


def collect_server(server_config, timeout=30):
    """
    通过 SSH 连接服务器，执行只读命令并返回结果。
    支持密码认证和 SSH 密钥认证，复用长连接（心跳 10s）。
    返回 dict: {status, online_count, client_ips, client_details, raw_output, error_message, duration_ms}
    """
    host = server_config.get('host', '')
    port = int(server_config.get('port', 22))
    command = server_config.get('command', '')
    server_type = server_config.get('type', 'unknown')
    # 用户手动配置的排除 IP 列表（例如监控端自己的出口 IP / 堡垒机 IP）
    raw_exclude = server_config.get('exclude_ips') or []
    custom_exclude_ips = {str(item).strip() for item in raw_exclude if str(item).strip()}
    raw_exclude_users = server_config.get('exclude_users') or []
    custom_exclude_users = {str(item).strip() for item in raw_exclude_users if str(item).strip()}

    t0 = time.time()

    # 获取或创建长连接
    try:
        client = _get_or_create_connection(server_config, timeout)
    except paramiko.AuthenticationException as e:
        duration_ms = int((time.time() - t0) * 1000)
        hint = _build_auth_hint(server_config)
        err_msg = f'认证失败: {str(e)}\n可能原因：① 密码错误 ② 目标服务器禁止密码登录(需使用SSH密钥) ③ 密钥权限不正确(应为0600) ④ 密钥类型不受支持\n当前认证方式: {hint}'
        return {
            'status': 'auth_failed',
            'online_count': 0,
            'client_ips': [],
            'client_details': [],
            'raw_output': '',
            'error_message': err_msg,
            'duration_ms': duration_ms
        }
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        err_msg = str(e)
        if 'timeout' in err_msg.lower() or 'timed out' in err_msg.lower():
            err_msg = f'连接超时: 无法在 {timeout} 秒内连接到 {host}:{port}，请检查网络和防火墙'
        elif 'refused' in err_msg.lower() or 'connection refused' in err_msg.lower():
            err_msg = f'连接被拒绝: {host}:{port} SSH 服务未运行或端口被防火墙拦截'
        elif 'name or service not known' in err_msg.lower() or 'getaddrinfo' in err_msg.lower():
            err_msg = f'无法解析主机名: {host}，请检查主机地址是否正确'
        return {
            'status': 'error',
            'online_count': 0,
            'client_ips': [],
            'client_details': [],
            'raw_output': '',
            'error_message': f'连接失败: {err_msg}',
            'duration_ms': duration_ms
        }

    # 执行命令（使用缓存的长连接），失败时自动重试一次（剔除旧连接后新建）
    raw_output = None
    last_error = None
    last_is_ssh_exc = False

    for attempt in (1, 2):
        try:
            raw_output = _ssh_exec(client, command, timeout)
            break
        except paramiko.SSHException as e:
            # SSH 协议级异常 → 连接大概率已损坏，剔除缓存后重试
            last_error = e
            last_is_ssh_exc = True
            _invalidate_connection(server_config)
            if attempt == 1:
                try:
                    client = _get_or_create_connection(server_config, timeout)
                except Exception:
                    pass
            continue
        except Exception as e:
            last_error = e
            last_is_ssh_exc = False
            # 执行失败时检查连接是否存活；不论 is_active 是否 True
            # 都剔除缓存（因为实际 I/O 已失败），然后重试一次
            try:
                _invalidate_connection(server_config)
            except Exception:
                pass
            if attempt == 1:
                try:
                    client = _get_or_create_connection(server_config, timeout)
                except Exception:
                    pass
            continue

    if raw_output is None:
        duration_ms = int((time.time() - t0) * 1000)
        err_msg = str(last_error) if last_error else '未知错误'
        if last_is_ssh_exc:
            return {
                'status': 'error',
                'online_count': 0,
                'client_ips': [],
                'client_details': [],
                'raw_output': '',
                'error_message': f'SSH 会话异常: {err_msg}',
                'duration_ms': duration_ms
            }
        else:
            return {
                'status': 'error',
                'online_count': 0,
                'client_ips': [],
                'client_details': [],
                'raw_output': '',
                'error_message': f'命令执行失败: {err_msg}',
                'duration_ms': duration_ms
            }

    # 解析客户端 IP（根据服务器类型）
    if server_type == 'ikev2':
        client_ips, online_count, client_details = _parse_ikev2(raw_output)
    elif server_type == 'openvpn':
        client_ips, online_count, client_details = _parse_openvpn(raw_output)
    elif server_type == 'ssh_login':
        client_ips, online_count, client_details = _parse_ssh_login(
            raw_output,
            exclude_ips=custom_exclude_ips,
            exclude_users=custom_exclude_users,
        )
    else:
        client_ips, online_count, client_details = _parse_generic(raw_output)

    duration_ms = int((time.time() - t0) * 1000)

    return {
        'status': 'success',
        'online_count': online_count,
        'client_ips': client_ips,
        'client_details': client_details,
        'raw_output': raw_output,
        'error_message': '',
        'duration_ms': duration_ms
    }


def _parse_duration_to_seconds(text):
    total = 0
    patterns = [
        (r'(\d+)\s+days?', 86400),
        (r'(\d+)\s+hours?', 3600),
        (r'(\d+)\s+minutes?', 60),
        (r'(\d+)\s+seconds?', 1)
    ]
    for pattern, multiplier in patterns:
        match = re.search(pattern, text)
        if match:
            total += int(match.group(1)) * multiplier
    return total if total > 0 else None


def _parse_datetime_string(value):
    """解析 OpenVPN 常见时间格式，包括文本、ISO-8601 和 Unix 时间戳。"""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None

    # status-version 2 可能同时提供 Connected Since (time_t)。
    if re.fullmatch(r'-?\d+(?:\.\d+)?', text):
        try:
            return datetime.fromtimestamp(float(text))
        except (OverflowError, OSError, ValueError):
            pass

    for fmt in ('%Y-%m-%d %H:%M:%S', '%a %b %d %H:%M:%S %Y'):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue

    try:
        iso_text = text[:-1] + '+00:00' if text.endswith('Z') else text
        parsed = datetime.fromisoformat(iso_text)
        # 应用内部使用本地时间的 naive datetime，避免 aware/naive 相减报错。
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone().replace(tzinfo=None)
        return parsed
    except ValueError:
        return None


def _parse_ssh_datetime(text):
    """解析 ssh 日志时间，支持 ISO-8601 和 Syslog 格式。"""
    if not text:
        return None
    text = str(text).strip()
    try:
        iso_text = text[:-1] + '+00:00' if text.endswith('Z') else text
        # 兼容 2026-09-15T12:11:37.341542+08:00 / +0800 / Z 等所有 ISO 变体
        if re.match(r'^\d{4}-\d{2}-\d{2}T', iso_text):
            iso_text = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', iso_text)
        parsed = datetime.fromisoformat(iso_text)
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone().replace(tzinfo=None)
        return parsed
    except ValueError:
        pass
    now = datetime.now()
    for fmt in ('%b %d %H:%M:%S', '%b  %d %H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%b %d %H:%M'):
        try:
            parsed = datetime.strptime(text, fmt)
            if fmt.startswith('%b'):
                parsed = parsed.replace(year=now.year)
                # 处理跨年边界
                if (parsed - now).days > 30:
                    parsed = parsed.replace(year=now.year - 1)
            return parsed
        except ValueError:
            continue
    return None


def _build_client_detail(ip, connected_since=None, connected_seconds=None, source=''):
    return {
        'ip': ip,
        'connected_since': connected_since or '',
        'connected_seconds': connected_seconds,
        'source': source
    }


def _is_private_172(ip):
    """检查 IP 是否落在 172.16.0.0/12 私网段（172.16.x.x - 172.31.x.x）。"""
    try:
        parts = ip.split('.')
        if len(parts) == 4 and parts[0] == '172':
            second = int(parts[1])
            return 16 <= second <= 31
    except (ValueError, IndexError):
        pass
    return False


def _parse_ikev2(output):
    """
    解析 strongSwan ipsec statusall 输出，提取客户端 IP。
    实际输出示例（地址为 RFC 5737 文档保留段，非真实 IP）：
      Security Associations (0 up, 0 connecting):
        none
    或带连接时：
      Security Associations (1 up, 0 connecting):
        ikev2-psk[1]: ESTABLISHED 2 minutes ago, 198.51.100.10[id]...203.0.113.20[10.10.10.1]
        ikev2-psk{1}:  INSTALLED, TUNNEL, reqid 1, ...
          10.10.10.0/24 === 0.0.0.0/0

    ESTABLISHED 行格式: <conn>[I]: ESTABLISHED <time> ago, <local_ip>[<local_id>]...<remote_ip>[<remote_id>]
    其中 remote_ip 是客户端的公网 IP，[<remote_id>] 中可能包含虚拟 IP（如 10.10.10.1）。
    需要用排除列表过滤掉内部 IP，才能正确提取客户端公网 IP 并关联 connected_seconds。
    """
    from datetime import datetime as dt_module

    client_ips = set()
    client_details = []
    online_count = 0

    # 排除非客户端 IP（服务器自身、Docker 网桥、VPN 地址池等）
    # 172.16.0.0/12 整段由 _is_private_172() 统一过滤
    exclude_starts = ['0.0.0.', '255.255.', '127.0.', '192.168.4.', '192.168.0.',
                      '10.10.10.']
    exclude_exact = {'0.0.0.0', '255.255.255.255', '127.0.0.1'}

    # 解析 "Security Associations (N up, M connecting):" 中的 N
    sa_match = re.search(r'Security Associations\s*\((\d+)\s+up', output)
    if sa_match:
        online_count = int(sa_match.group(1))

    if online_count == 0:
        return [], 0, []

    seen_detail_ips = set()
    now = dt_module.now()
    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

    for line in output.split('\n'):
        line = line.strip()
        if 'ESTABLISHED' not in line:
            continue
        all_ips_in_line = ip_pattern.findall(line)
        if not all_ips_in_line:
            continue

        duration_seconds = _parse_duration_to_seconds(line)

        # 从 ESTABLISHED 行提取客户端公网 IP：
        # 过滤掉服务器自身和内部 IP，取最后一个剩余 IP 作为客户端公网 IP
        # 如果全部被排除（纯内网场景），回退到最后一个 IP
        candidate_ips = [ip for ip in all_ips_in_line
                         if ip not in exclude_exact
                         and not any(ip.startswith(p) for p in exclude_starts)
                         and not _is_private_172(ip)]
        if candidate_ips:
            client_ip = candidate_ips[-1]
        else:
            # 整行 IP 均在排除范围内（如纯 172.16/12 私网），跳过该行
            continue

        # 计算稳定的 connected_since 时间戳（用于去重，避免每次扫描 marker 变化）
        connected_since = ''
        if duration_seconds is not None and duration_seconds >= 0:
            try:
                connected_since = (now - dt_module.resolution * duration_seconds * 1000000).strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                connected_since = ''

        client_ips.add(client_ip)
        if client_ip not in seen_detail_ips:
            client_details.append(_build_client_detail(
                client_ip,
                connected_since=connected_since,
                connected_seconds=duration_seconds,
                source='ikev2'
            ))
            seen_detail_ips.add(client_ip)

    # 不再对整段输出做兜底 IP 提取：那会把服务器自身公网 IP、网关等也当成客户端，
    # 进而与上一轮扫描做差集时产生虚假的“新客户端上线/下线”事件与告警。
    # 客户端只以 ESTABLISHED 行为准（上面的循环）。
    return list(client_ips), online_count, client_details


def _parse_openvpn(output):
    """解析 OpenVPN 状态日志，并保留每一条可观察到的客户端请求。

    同时兼容旧式 CLIENT LIST/ROUTING TABLE 和 status-version 2 的
    ``CLIENT_LIST,...`` 格式。没有虚拟 IP 的行仍返回给上层，供其记录为“提示”；
    只有能关联到虚拟 IP 的行才计入在线客户端。
    """
    def _normal_key(value):
        return str(value or '').strip().casefold()

    def _row_from_values(values, columns=None):
        values = [str(value or '').strip() for value in values]
        if columns:
            row = {}
            for index, value in enumerate(values):
                if index < len(columns):
                    row[_normal_key(columns[index])] = value
            return row
        # 旧格式的固定字段顺序；即使只有一列也保留，避免静默丢请求。
        return {
            'common name': values[0] if len(values) >= 1 else '',
            'real address': values[1] if len(values) >= 2 else '',
            'bytes received': values[2] if len(values) >= 3 else '',
            'bytes sent': values[3] if len(values) >= 4 else '',
            'connected since': values[4] if len(values) >= 5 else ''
        }

    def _row_from_v2_values(values, columns=None):
        """解析没有 HEADER 行时的 status-version 2 固定前缀字段。"""
        if columns:
            return _row_from_values(values, columns)
        values = [str(value or '').strip() for value in values]
        return {
            'common name': values[0] if len(values) >= 1 else '',
            'real address': values[1] if len(values) >= 2 else '',
            'virtual address': values[2] if len(values) >= 3 else '',
            'bytes received': values[3] if len(values) >= 4 else '',
            'bytes sent': values[4] if len(values) >= 5 else '',
            'connected since': values[5] if len(values) >= 6 else '',
            'connected since (time_t)': values[6] if len(values) >= 7 else ''
        }

    def _route_from_values(values, columns=None):
        """解析没有 HEADER 行时的 ROUTING TABLE 固定字段。"""
        if columns:
            return _row_from_values(values, columns)
        values = [str(value or '').strip() for value in values]
        return {
            'virtual address': values[0] if len(values) >= 1 else '',
            'common name': values[1] if len(values) >= 2 else '',
            'real address': values[2] if len(values) >= 3 else '',
            'last ref': values[3] if len(values) >= 4 else ''
        }

    def _field(row, *names):
        for name in names:
            value = row.get(_normal_key(name), '')
            if value != '':
                return value
        return ''

    def _parse_int(value):
        try:
            return int(str(value or '').strip())
        except (TypeError, ValueError):
            return 0

    def _extract_address(value):
        text = str(value or '').strip()
        if not text:
            return ''
        # OpenVPN 对 IPv6 通常使用 [addr]:port 表示。
        if text.startswith('[') and ']:' in text:
            return text[1:text.index(']:')].strip()
        # IPv4、主机名和 host:port；不拆未加括号的 IPv6。
        if text.count(':') == 1:
            host, port = text.rsplit(':', 1)
            if port.isdigit():
                return host.strip()
        return text.strip('[]').strip()

    def _is_ip(value):
        try:
            ipaddress.ip_address(str(value))
            return True
        except ValueError:
            return False

    client_rows = []
    route_by_real_address = {}
    section = ''
    client_columns = None
    route_columns = None
    updated_at = None

    for raw_line in str(output or '').split('\n'):
        # 去除可能存在的 UTF-8 BOM，兼容不同 OpenVPN/status 脚本输出。
        line = raw_line.strip().lstrip('\ufeff')
        if not line:
            continue
        parts = line.split(',')

        # status-version 2: HEADER,CLIENT_LIST,... / CLIENT_LIST,...
        folded = line.casefold()
        if folded.startswith('header,client_list'):
            client_columns = [part.strip() for part in parts[2:]]
            section = 'v2_clients'
            continue
        if folded.startswith('client_list,'):
            values = parts[1:]
            client_rows.append(_row_from_v2_values(values, client_columns))
            continue
        if folded.startswith('header,routing_table'):
            route_columns = [part.strip() for part in parts[2:]]
            section = 'v2_routes'
            continue
        if folded.startswith('routing_table,'):
            values = parts[1:]
            route = _route_from_values(values, route_columns)
            virtual_ip = _field(route, 'Virtual Address', 'Virtual IP')
            real_address = _field(route, 'Real Address')
            if virtual_ip and real_address:
                route_by_real_address[real_address] = virtual_ip
            continue

        if folded.startswith('updated'):
            updated_parts = line.split(',', 1)
            updated_at = _parse_datetime_string(updated_parts[1] if len(updated_parts) > 1 else '')
            continue
        if folded.startswith('routing table'):
            route_columns = None
            section = 'routes'
            continue
        if folded.startswith('common name') and 'real address' in folded:
            client_columns = [part.strip() for part in parts]
            section = 'clients'
            continue
        if folded.startswith('virtual address'):
            route_columns = [part.strip() for part in parts]
            section = 'routes'
            continue
        if folded.startswith('global stats') or folded.startswith('global_stats') or folded == 'end':
            section = ''
            continue
        # 标题行后即使标准 CLIENT LIST 表头缺失，也保留后续行作为请求。
        if folded.startswith('openvpn client list') or folded == 'client list':
            client_columns = None
            section = 'clients'
            continue
        if folded.startswith('openvpn') or folded.startswith('title') or folded.startswith('time'):
            continue

        if section in ('clients', 'v2_clients'):
            row_builder = _row_from_values if section == 'clients' else _row_from_v2_values
            client_rows.append(row_builder(parts, client_columns))
        elif section in ('routes', 'v2_routes') and len(parts) >= 3:
            row_builder = _row_from_values if section == 'routes' else _row_from_v2_values
            route = row_builder(parts, route_columns)
            virtual_ip = _field(route, 'Virtual Address', 'Virtual IP')
            real_address = _field(route, 'Real Address')
            if virtual_ip and real_address:
                route_by_real_address[real_address] = virtual_ip

    client_ips = set()
    client_details = []
    online_count = 0
    seen_sessions = set()

    for row_index, row in enumerate(client_rows):
        common_name = _field(row, 'Common Name', 'Common_Name') or '未知'
        real_address = _field(row, 'Real Address', 'Real_Address')
        addr = _extract_address(real_address) or '未知'
        connected_since = _field(row, 'Connected Since', 'Connected_Since')
        connected_since_epoch = _field(row, 'Connected Since (time_t)', 'Connected_Since (time_t)')
        time_value = connected_since or connected_since_epoch
        connected_since_dt = _parse_datetime_string(time_value)
        connected_seconds = None
        if updated_at and connected_since_dt:
            connected_seconds = max(0, int((updated_at - connected_since_dt).total_seconds()))

        bytes_received = _parse_int(_field(row, 'Bytes Received', 'Bytes_Received'))
        bytes_sent = _parse_int(_field(row, 'Bytes Sent', 'Bytes_Sent'))
        # status-version 2 可能直接在 CLIENT_LIST 中给出 Virtual Address。
        virtual_ip = _field(row, 'Virtual Address', 'Virtual IP', 'Virtual_Address', 'Virtual_IP')
        if not virtual_ip:
            virtual_ip = route_by_real_address.get(real_address, '')
        authenticated = bool(virtual_ip) and common_name.upper() != 'UNDEF'

        # 完整字段相同时去重；地址、时间和 CN 都缺失时用行号，避免丢掉后续请求。
        dedupe_key = (common_name, real_address, time_value, virtual_ip)
        if not (real_address or time_value or common_name not in ('', '未知')):
            dedupe_key = ('row', row_index)
        if dedupe_key in seen_sessions:
            continue
        seen_sessions.add(dedupe_key)

        if authenticated:
            if _is_ip(addr):
                client_ips.add(addr)
            online_count += 1
        detail = _build_client_detail(
            addr,
            connected_since=connected_since or connected_since_epoch,
            connected_seconds=connected_seconds,
            source='openvpn'
        )
        detail.update({
            'common_name': common_name,
            'real_address': real_address,
            'virtual_ip': virtual_ip,
            'bytes_received': bytes_received,
            'bytes_sent': bytes_sent,
            'authenticated': authenticated,
            'observed_request': True
        })
        client_details.append(detail)

    return list(client_ips), online_count, client_details


def _parse_generic(output):
    """通用 IP 提取"""
    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    all_ips = ip_pattern.findall(output)
    exclude_patterns = {'0.0.0.0', '255.255.255.255', '127.0.0.1'}
    # 去重 + 校验合法 IP：重复出现会导致在线数虚高，非法串（999.1.1.1）不应算作客户端
    seen = set()
    client_ips = []
    for ip in all_ips:
        if ip in exclude_patterns or ip in seen:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        seen.add(ip)
        client_ips.append(ip)
    client_details = [_build_client_detail(ip, source='generic') for ip in client_ips]
    return client_ips, len(client_ips), client_details


def _parse_ssh_login(output, exclude_ips=None, exclude_users=None):
    """
    解析 SSH 登录状态与日志。
    支持复合输出：
      ===CURRENT_WHO=== (who 命令输出，反映此时真正存活的在线会话终端)
      ===SSH_LOGS===    (journalctl/auth.log 日志，用于增量告警与安全审计)
    若无分隔符，则向下兼容纯日志输出。
    exclude_ips: 用户手动配置的排除 IP 集合。
    exclude_users: 用户手动配置的排除用户集合（如监控专用账号）。

    返回值 online_count 只代表「当前活跃终端数」（来自 who）；
    日志解析出的登录/失败属于事件流，全部保留在 client_details 中但不计入在线数。

    注意：命中排除规则的记录「不会被屏蔽」，仍会完整保留在结果中，
    仅在每条 detail 上打 'excluded': True 标记，交由上层把其告警等级降为「提示」
    （只写事件日志、不发送任何通知）。
    """
    exclude_ip_set = {str(item).strip() for item in (exclude_ips or []) if str(item).strip()}
    exclude_user_set = {str(item).strip() for item in (exclude_users or []) if str(item).strip()}
    # 时间戳统一用「懒惰前缀 + 主机名 + sshd 进程」定位，兼容以下全部格式：
    #   2026-09-15T12:11:37.341542+08:00  (rsyslog 高精度 ISO，带微秒)
    #   2026-09-14T23:56:57+0800         (journalctl -o short-iso)
    #   Sep 15 12:11:37                  (传统 syslog)
    _ts = r'(?P<time_str>.*?)'
    _tail = r'\s+\S+\s+sshd(?:-session)?\[\d+\]:\s+'
    accepted_re = re.compile(
        _ts + _tail +
        r'Accepted\s+(?P<auth_method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)'
    )
    failed_re = re.compile(
        _ts + _tail +
        r'Failed\s+(?P<auth_method>\S+)\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)'
    )

    def _is_ip(val):
        try:
            ipaddress.ip_address(str(val).strip())
            return True
        except ValueError:
            return False

    def _parse_who_line(line_str):
        line_str = str(line_str or '').strip()
        if not line_str.endswith(')'):
            return None
        r_idx = line_str.rfind('(')
        if r_idx <= 0:
            return None
        host = line_str[r_idx+1:-1].strip()
        if not host or not (_is_ip(host) or host.startswith(':') or re.match(r'^[a-zA-Z0-9.-]+$', host)):
            return None
        left = line_str[:r_idx].strip()
        parts = left.split()
        if len(parts) < 3:
            return None
        user = parts[0]
        if ':' in user or '[' in user or user.startswith('202') or user.startswith('199'):
            return None
        terminal = parts[1]
        if not (terminal.startswith('pts') or terminal.startswith('tty') or terminal.startswith('sshd') or terminal.startswith('seat')):
            return None

        date_str = ""
        for i in range(1, len(parts)):
            sub = " ".join(parts[i:i+2])
            sub3 = " ".join(parts[i:i+3])
            if re.match(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}', sub):
                date_str = sub
                break
            elif re.match(r'^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}', sub3):
                date_str = sub3
                break
            elif re.match(r'^\d{4}-\d{2}-\d{2}$', parts[i]):
                date_str = parts[i]
                break
        if not date_str:
            return None
        # terminal（pts/0、pts/1、tty1…）是会话的唯一标识：
        # 同一公网 IP 上可以并存多个终端，必须保留终端名才能区分它们。
        return {'user': user, 'date': date_str, 'host': host, 'terminal': terminal}

    raw_str = str(output or '')
    who_section = ""
    log_section = ""

    has_markers = ('===CURRENT_WHO===' in raw_str or '===SSH_LOGS===' in raw_str)
    if has_markers:
        parts = raw_str.split('===SSH_LOGS===')
        log_section = parts[1] if len(parts) > 1 else ""
        who_part = parts[0]
        if '===CURRENT_WHO===' in who_part:
            who_section = who_part.split('===CURRENT_WHO===')[1]
        else:
            who_section = who_part

    now = datetime.now()
    active_ips = set()
    active_details = []
    log_details = []

    # 如果有明确的分隔符，按分段解析；若没有，直接逐行自适应匹配 who 终端行与日志行
    lines_to_process = (who_section.splitlines() + log_section.splitlines()) if has_markers else raw_str.splitlines()

    for raw_line in lines_to_process:
        line = raw_line.strip().lstrip('\ufeff')
        if not line:
            continue

        # 优先尝试作为 who 活跃会话识别
        parsed_who = _parse_who_line(line)
        if parsed_who:
            host = parsed_who['host']
            user = parsed_who['user']
            if host in (':0', ':0.0') or host.startswith(':'):
                continue
            excluded = bool(host in exclude_ip_set or user in exclude_user_set)
            if _is_ip(host):
                active_ips.add(host)
            dt = _parse_ssh_datetime(parsed_who['date'])
            conn_since = dt.strftime('%Y-%m-%d %H:%M:%S') if dt else parsed_who['date']
            conn_sec = max(0, int((now - dt).total_seconds())) if dt else None

            active_details.append({
                'ip': host,
                'terminal': parsed_who.get('terminal', ''),
                'connected_since': conn_since,
                'connected_seconds': conn_sec,
                'source': 'ssh_login',
                'common_name': user,
                'user': user,
                'port': '',
                'auth_method': '',
                'status_type': 'active_session',
                'authenticated': True,
                'observed_request': False,
                'excluded': excluded
            })
            continue

        m_acc = accepted_re.search(line)
        if m_acc:
            data = m_acc.groupdict()
            ip = data['ip'].strip()
            user = data['user'].strip()
            port = data['port'].strip()
            excluded = bool(ip in exclude_ip_set or user in exclude_user_set)
            auth = data['auth_method'].strip()
            t_str = data['time_str'].strip()
            dt = _parse_ssh_datetime(t_str)
            conn_since = dt.strftime('%Y-%m-%d %H:%M:%S') if dt else t_str
            conn_sec = max(0, int((now - dt).total_seconds())) if dt else None

            detail = _build_client_detail(
                ip,
                connected_since=conn_since,
                connected_seconds=conn_sec,
                source='ssh_login'
            )
            detail.update({
                'common_name': user,
                'user': user,
                'port': port,
                'auth_method': auth,
                'status_type': 'accepted',
                'authenticated': True,
                'observed_request': True,
                'excluded': excluded
            })
            log_details.append(detail)
            continue

        m_fail = failed_re.search(line)
        if m_fail:
            data = m_fail.groupdict()
            ip = data['ip'].strip()
            user = data['user'].strip()
            port = data['port'].strip()
            excluded = bool(ip in exclude_ip_set or user in exclude_user_set)
            auth = data['auth_method'].strip()
            t_str = data['time_str'].strip()
            dt = _parse_ssh_datetime(t_str)
            conn_since = dt.strftime('%Y-%m-%d %H:%M:%S') if dt else t_str
            conn_sec = max(0, int((now - dt).total_seconds())) if dt else None

            detail = _build_client_detail(
                ip,
                connected_since=conn_since,
                connected_seconds=conn_sec,
                source='ssh_login'
            )
            detail.update({
                'common_name': user,
                'user': user,
                'port': port,
                'auth_method': auth,
                'status_type': 'failed',
                'authenticated': False,
                'observed_request': True,
                'excluded': excluded
            })
            log_details.append(detail)

    # 同一台机器可能同时配了 auth.log 与 journalctl 两个日志源（互为兜底），
    # 此时同一条登录会被解析两次。按「状态+用户+IP+时间+端口」去重，避免重复展示与重复告警。
    _seen_log = set()
    _dedup_logs = []
    for d in log_details:
        key = (d.get('status_type'), d.get('user'), d.get('ip'),
               d.get('connected_since'), d.get('port'))
        if key in _seen_log:
            continue
        _seen_log.add(key)
        _dedup_logs.append(d)
    # 最近的登录事件排在最前
    _dedup_logs.sort(key=lambda x: str(x.get('connected_since') or ''), reverse=True)
    log_details = _dedup_logs

    # 在线数按「who 给出的活跃终端会话数」统计，而不是按唯一 IP 统计。
    # 同一公网 IP 下同时存在 pts/0、pts/1 时，应计为两个在线终端。
    online_count = len(active_details)
    client_details = active_details + log_details

    return list(active_ips), online_count, client_details
