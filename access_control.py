"""
访问控制模块 - 基于 IP / CIDR 白名单限制 Web 端访问。

规则说明：
  - 支持单个 IP（192.168.1.10、2001:db8::1）与网段（192.168.1.0/24、10.8.0.0/24、2001:db8::/32）。
  - 兼容用户手写的“主机地址 + 掩码”（如 192.168.1.1/24），会自动收敛为 192.168.1.0/24。
  - 回环地址（127.0.0.0/8 与 ::1）永远允许：既保证本机管理入口不被锁死，
    也保证容器内置 HEALTHCHECK（从 127.0.0.1 请求 /healthz）始终可用。
  - 默认白名单只包含 127.0.0.1，且该规则不可删除。

本模块刻意不依赖 Flask：仅接收请求对象（鸭子类型），便于单独测试。
"""
import ipaddress

# 永远允许、不可删除的内置规则
PERMANENT_RULES = ('127.0.0.1',)

# 访问控制总开关的默认值（默认关闭：不开启则不拦截任何访问）
DEFAULT_ENABLED = False

# 是否采信反向代理转发头（X-Forwarded-For / X-Real-IP / Forwarded），默认不采信
DEFAULT_TRUST_PROXY = False


def coerce_bool(value, default=False):
    """把任意输入（bool / 'true' / '0' / None ...）安全地转换为布尔值。"""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().casefold()
    if text in ('', 'false', '0', 'no', 'off', 'none', 'null', 'undefined'):
        return False
    if text in ('true', '1', 'yes', 'on'):
        return True
    return bool(text)


class RuleError(ValueError):
    """规则格式非法"""


def normalize_rule(rule):
    """把一条用户输入规范化为标准规则字符串；非法时抛 RuleError。

    返回值示例：'127.0.0.1' / '10.8.0.0/24' / '2001:db8::/32'
    """
    if rule is None:
        raise RuleError('规则为空')
    text = str(rule).strip()
    if not text:
        raise RuleError('规则为空')
    if '/' in text:
        try:
            # strict=False：把 192.168.1.1/24 这类“主机地址 + 掩码”自动收敛为 192.168.1.0/24
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise RuleError(f'非法的网段: {text}')
        return str(net)
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise RuleError(f'非法的 IP 地址: {text}')


def _net_key(rule):
    """用于去重/比较的网络键：把 127.0.0.1 与 127.0.0.1/32 视为同一规则。"""
    return str(ipaddress.ip_network(str(rule).strip(), strict=False))


def _as_rule_list(items):
    """把配置里的白名单归一成列表：兼容 "a,b" 字符串写法。"""
    if isinstance(items, str):
        return [part.strip() for part in items.replace('，', ',').split(',')]
    return list(items or [])


def normalize_allowlist(items):
    """规范化整个白名单：过滤非法项、去重，并强制包含内置规则。"""
    result = []
    seen = set()
    for item in _as_rule_list(items):
        try:
            rule = normalize_rule(item)
        except RuleError:
            continue
        key = _net_key(rule)
        if key in seen:
            continue
        seen.add(key)
        result.append(rule)
    for rule in PERMANENT_RULES:
        key = _net_key(rule)
        if key not in seen:
            seen.add(key)
            result.append(rule)
    return result


def is_permanent_rule(rule):
    """该规则是否为不可删除的内置规则。"""
    try:
        return _net_key(rule) in {_net_key(item) for item in PERMANENT_RULES}
    except ValueError:
        return False


def _client_address(ip_text):
    """把客户端地址文本转成 ipaddress 对象，并把 IPv4-mapped IPv6 还原为 IPv4。"""
    addr = ipaddress.ip_address(str(ip_text).strip())
    mapped = getattr(addr, 'ipv4_mapped', None)
    return mapped if mapped is not None else addr


def is_allowed(ip_text, rules):
    """判断客户端 IP 是否命中白名单。回环地址恒为允许。"""
    if is_loopback_address(ip_text):
        return True
    return matches_rules(ip_text, rules)


def matches_rules(ip_text, rules):
    """纯规则匹配：只与给定规则比对，不注入任何隐式/内置规则。

    注意与 is_allowed 的区别——is_allowed 会对回环地址直接放行，
    而本函数不做任何特判，供"可信代理""伪造防护"等场景使用。
    """
    text = str(ip_text or '').strip()
    if not text:
        return False
    try:
        addr = _client_address(text)
    except ValueError:
        return False
    for rule in _as_rule_list(rules):
        try:
            net = ipaddress.ip_network(str(rule).strip(), strict=False)
        except ValueError:
            continue
        if addr.version != net.version:
            continue
        if addr in net:
            return True
    return False


def is_loopback_address(ip_text):
    """判断是否为回环地址（127.0.0.0/8 或 ::1）。"""
    try:
        return _client_address(ip_text).is_loopback
    except (ValueError, TypeError):
        return False


def normalize_trusted_proxies(items):
    """规范化可信代理地址列表（IP 或 CIDR）。非法项丢弃，不注入内置规则。"""
    result = []
    seen = set()
    for item in _as_rule_list(items):
        try:
            rule = normalize_rule(item)
        except RuleError:
            continue
        key = _net_key(rule)
        if key in seen:
            continue
        seen.add(key)
        result.append(rule)
    return result


def _parse_forwarded_header(value):
    """解析 RFC 7239 的 Forwarded 头，提取其中的 for= 地址。"""
    ips = []
    for element in str(value or '').split(','):
        for token in element.split(';'):
            token = token.strip()
            if not token.lower().startswith('for='):
                continue
            ip = token[4:].strip().strip('"')
            if ip.startswith('['):                      # [2001:db8::1]:port
                end = ip.find(']')
                ip = ip[1:end] if end > 0 else ip
            elif ip.count(':') == 1:                    # 1.2.3.4:5678
                host, _, port = ip.rpartition(':')
                if port.isdigit():
                    ip = host
            if ip and _is_valid_ip(ip):
                ips.append(ip)
    return ips


def _is_valid_ip(value):
    """判断字符串是否为合法 IP（含 IPv6），非法值一律剔除。"""
    text = str(value or '').strip()
    if not text:
        return False
    # 去掉可能的 IPv6 端口形式 [::1]:port
    if text.startswith('['):
        end = text.find(']')
        if end > 0:
            text = text[1:end]
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _forwarded_chain(req):
    """按优先级提取代理链：X-Forwarded-For → X-Real-IP → Forwarded。"""
    headers = getattr(req, 'headers', None) or {}
    xff = headers.get('X-Forwarded-For') or ''
    chain = [part.strip() for part in str(xff).split(',') if part.strip()]
    # 只保留合法 IP：这些值来自客户端可控的请求头，非法串（含 HTML/脚本）必须丢弃，
    # 否则会被原样回显到页面形成反射型 XSS。
    chain = [ip for ip in chain if _is_valid_ip(ip)]
    if not chain:
        real_ip = str(headers.get('X-Real-IP') or '').strip()
        if real_ip and _is_valid_ip(real_ip):
            chain = [real_ip]
    if not chain:
        chain = _parse_forwarded_header(headers.get('Forwarded'))
    return chain


def resolve_client_ip(req, cfg=None):
    """解析真实客户端 IP，区分"TCP 对端"与"真实客户端"。

    返回 dict:
      peer      —— TCP 直连来源（容器里就是 request.remote_addr）
      client    —— 最终用于判定的客户端 IP
      forwarded —— 原始转发链文本（未采信时为空）
      source    —— 'socket' | 'forwarded' | 'forwarded-ignored'

    规则：
      1. 未开启 trust_proxy → 一律使用 peer（不采信任何可伪造的头）。
      2. 开启 trust_proxy 但未配置可信代理 → 仍使用 peer（安全回退）。
      3. peer 不在可信代理列表 → 忽略转发头（防伪造），使用 peer。
      4. peer 可信 → 从右往左跳过可信代理，取第一个非可信地址为真实客户端。
    """
    cfg = cfg or {}
    peer = str(getattr(req, 'remote_addr', '') or '').strip()
    info = {'peer': peer, 'client': peer, 'forwarded': '', 'source': 'socket'}
    if not coerce_bool(cfg.get('trust_proxy'), default=DEFAULT_TRUST_PROXY):
        return info
    trusted = normalize_trusted_proxies(cfg.get('trusted_proxies'))
    if not trusted or not matches_rules(peer, trusted):
        info['source'] = 'forwarded-ignored'
        return info
    chain = _forwarded_chain(req)
    if not chain:
        return info
    info['forwarded'] = ', '.join(chain)
    hops = list(chain) + [peer]
    for ip in reversed(hops):
        if matches_rules(ip, trusted):
            continue
        info['client'] = ip
        info['source'] = 'forwarded'
        return info
    # 整条链都是可信代理 → 取最左（最早）的一个
    info['client'] = hops[0]
    info['source'] = 'forwarded'
    return info


def check_request_access(req, cfg=None):
    """统一的访问判定入口，返回 (allowed: bool, info: dict)。

    关键安全点：
      * "回环恒放行"只对 peer 生效 —— 即只有真的从本机连过来才放行。
        远端直连时，即使转发头声称自己是 127.0.0.1，也一律判为伪造并拒绝。
      * 判定使用 matches_rules（不注入内置规则），避免 127.0.0.1 被顺带放行。
    """
    cfg = cfg or {}
    info = resolve_client_ip(req, cfg)
    info['allowed'] = False
    info['reason'] = ''
    info['matched_rule'] = ''

    # 只有"未经代理改写"的本机直连才恒放行。
    # 若 peer 是回环地址但它是可信代理（source == 'forwarded'），说明真实客户端在转发链里，
    # 此时必须继续按真实客户端判定 —— 否则代理跑在 127.0.0.1 上会让白名单被整体绕过。
    if is_loopback_address(info['peer']) and info['source'] != 'forwarded':
        info['allowed'] = True
        info['reason'] = '本机(回环)直连，恒放行'
        return True, info

    client = info['client']
    if is_loopback_address(client):
        # 远端连接不可能来自回环地址 → 判定为伪造
        info['reason'] = '来源声称是回环地址，判定为伪造，拒绝'
        return False, info

    rules = _as_rule_list(cfg.get('allowed_ips'))
    if matches_rules(client, rules):
        info['allowed'] = True
        info['reason'] = '命中白名单'
        for rule in rules:
            if matches_rules(client, [rule]):
                info['matched_rule'] = str(rule).strip()
                break
        return True, info

    info['reason'] = '不在白名单'
    return False, info


def get_client_ip(req):
    """从 Flask request 对象取客户端 IP。"""
    try:
        return str(getattr(req, 'remote_addr', '') or '').strip()
    except Exception:
        return ''
