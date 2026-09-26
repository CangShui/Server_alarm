"""
城市解析器模块 - 可插拔 IP 地理位置查询

支持：
  1. LocalFileResolver — 本地 MaxMind GeoLite2-City.mmdb 数据库
  2. OnlineAPIResolver — 在线 API（预留）

默认使用 GeoLite2-City.mmdb。
"""

import os
import json
import ipaddress
from abc import ABC, abstractmethod

DAT_DIR = os.path.dirname(os.path.abspath(__file__))
MMDB_PATH = os.path.join(DAT_DIR, 'GeoLite2-City.mmdb')


class GeoResolverBase(ABC):
    """城市解析器抽象基类"""

    @property
    @abstractmethod
    def name(self):
        pass

    @abstractmethod
    def resolve(self, ip: str) -> dict:
        """返回 {city, country, region, isp, source, error}"""
        pass

    @abstractmethod
    def status(self) -> dict:
        """返回解析器状态信息"""
        pass


class LocalFileResolver(GeoResolverBase):
    """本地文件解析器 — 使用 MaxMind GeoLite2-City.mmdb"""

    @property
    def name(self):
        return "本地文件解析器"

    def __init__(self, filepath=MMDB_PATH):
        self.filepath = filepath
        self._available = False
        self._error = ""
        self._reader = None
        self._check()

    def _check(self):
        if not os.path.exists(self.filepath):
            self._error = (f"文件不存在: {self.filepath}\n"
                          f"请确认文件路径是否正确。可从以下地址下载:\n"
                          f"  https://github.com/P3TERX/GeoLite.mmdb\n"
                          f"  https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
            return

        try:
            import maxminddb
            self._reader = maxminddb.open_database(self.filepath)
            self._available = True
            self._error = ""
        except ImportError:
            self._error = "缺少 maxminddb 库，请执行: pip install maxminddb"
        except Exception as e:
            err_str = str(e)
            file_size = -1
            try:
                file_size = os.path.getsize(self.filepath)
            except Exception:
                pass

            # 提供更友好的错误诊断
            import_error_type = type(e).__name__
            if ('InvalidDatabaseError' in import_error_type
                    or 'invalid' in err_str.lower()
                    or '格式' in err_str
                    or 'format' in err_str.lower()
                    or 'unknown' in err_str.lower()):
                self._error = (
                    f"无法打开 MaxMind 数据库: {err_str}\n"
                    f"文件路径: {self.filepath}\n"
                    f"文件大小: {file_size} 字节\n"
                    f"可能原因：\n"
                    f"  ① 文件损坏或不完整(重新下载即可)\n"
                    f"  ② 文件不是有效的 .mmdb 格式\n"
                    f"  ③ maxminddb 库版本过旧 (当前需要 >=2.0.0)\n"
                    f"  ④ 文件为旧版 .dat 格式，需转换为 .mmdb\n"
                    f"下载地址: https://github.com/P3TERX/GeoLite.mmdb"
                )
            else:
                self._error = f"打开数据库失败: {err_str}\n文件: {self.filepath}"

    def resolve(self, ip: str) -> dict:
        if not self._available or self._reader is None:
            return {
                'city': '-',
                'country': '-',
                'region': '-',
                'isp': '-',
                'source': self.name,
                'error': self._error
            }
        try:
            import maxminddb
            record = self._reader.get(ip)
            if record is None:
                return {
                    'city': '-',
                    'country': '-',
                    'region': '-',
                    'isp': '-',
                    'source': self.name,
                    'error': f'未找到 {ip} 的地理信息'
                }
            city = record.get('city', {})
            country = record.get('country', {})
            subdivisions = record.get('subdivisions', [])
            continent = record.get('continent', {})

            def _best_name(names_dict):
                if not isinstance(names_dict, dict):
                    return '-'
                for lang in ('zh-CN', 'en',):
                    if lang in names_dict:
                        return names_dict[lang]
                first = next(iter(names_dict.values()), None)
                return first if first else '-'

            return {
                'city': _best_name(city.get('names', {})),
                'country': _best_name(country.get('names', {})),
                'region': _best_name(subdivisions[0].get('names', {})) if subdivisions else '-',
                'isp': '-',
                'source': self.name,
                'error': ''
            }
        except Exception as e:
            return {
                'city': '-',
                'country': '-',
                'region': '-',
                'isp': '-',
                'source': self.name,
                'error': f'查询失败: {str(e)}'
            }

    def status(self) -> dict:
        return {
            'name': self.name,
            'available': self._available,
            'file': self.filepath,
            'error': self._error
        }


class OnlineAPIResolver(GeoResolverBase):
    """
    在线 API 解析器（预留实现）
    可接入 ip-api.com, ipinfo.io 等免费 API
    注意：在线 API 有速率限制，不建议高频调用
    """

    @property
    def name(self):
        return "在线API解析器（未启用）"

    def __init__(self, enabled=False):
        self._enabled = enabled

    def resolve(self, ip: str) -> dict:
        if not self._enabled:
            return {
                'city': '-',
                'country': '-',
                'region': '-',
                'isp': '-',
                'source': self.name,
                'error': '在线API解析器未启用'
            }
        # 预留：调用 http://ip-api.com/json/{ip}
        return {
            'city': '-',
            'country': '-',
            'region': '-',
            'isp': '-',
            'source': self.name,
            'error': 'API 调用未实现'
        }

    def status(self) -> dict:
        return {
            'name': self.name,
            'available': self._enabled,
            'error': '在线API解析器未启用' if not self._enabled else ''
        }


# ---- 全局解析器实例 ----
# 按优先级尝试：本地文件 -> (预留在线API) -> 无
_resolvers = []


def init_resolvers():
    """初始化解析器链，支持从配置中读取自定义文件路径"""
    global _resolvers
    _resolvers = []

    # 从配置读取自定义路径
    from config_manager import load_config
    cfg = load_config()
    custom_path = cfg.get('geo_file_path', '').strip()
    if custom_path:
        # 解析相对路径：相对于项目目录
        if not os.path.isabs(custom_path):
            abs_custom = os.path.join(DAT_DIR, custom_path)
        else:
            abs_custom = custom_path

        # 如果自定义路径存在则使用，否则回退到默认路径并给出提示
        if os.path.exists(abs_custom):
            filepath = abs_custom
        else:
            print(f"[WARN] 配置的 GeoIP 文件路径不存在: {abs_custom}，回退使用默认路径")
            filepath = MMDB_PATH
    else:
        # 未显式配置时使用默认的 GeoLite2-City.mmdb
        filepath = MMDB_PATH

    # 当默认路径也不存在时给出明确提示
    if not os.path.exists(filepath):
        print(f"[WARN] GeoIP 数据库文件未找到: {filepath}")
        print(f"  请将 GeoLite2-City.mmdb 放在项目目录下，或在设置页配置正确路径。")
        print(f"  下载地址: https://github.com/P3TERX/GeoLite.mmdb 或 https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")

    # 本地文件解析器
    local = LocalFileResolver(filepath)
    _resolvers.append(local)


def get_active_resolver():
    """获取第一个可用的解析器"""
    for r in _resolvers:
        if r.status().get('available'):
            return r
    return _resolvers[0] if _resolvers else None


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip or '').strip())
        mapped = getattr(addr, 'ipv4_mapped', None)
        if mapped is not None:
            addr = mapped
        return bool(addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)
    except ValueError:
        return False


def resolve_ip(ip: str) -> dict:
    """解析单个 IP 的城市信息。内网/保留地址不走 GeoLite2，直接标记为内网。"""
    if _is_private_ip(ip):
        return {
            'city': '内网',
            'country': '-',
            'region': '局域网',
            'isp': '-',
            'source': '内网地址',
            'error': '',
            'is_private': True
        }
    resolver = get_active_resolver()
    if resolver is None:
        return {'city': '-', 'country': '-', 'region': '-', 'isp': '-', 'source': '无解析器', 'error': '没有配置任何解析器', 'is_private': False}
    result = resolver.resolve(ip)
    result['is_private'] = False
    return result


def resolve_ips(ips: list) -> dict:
    """批量解析 IP"""
    result = {}
    for ip in ips:
        result[ip] = resolve_ip(ip)
    return result


def get_resolver_status() -> dict:
    """获取所有解析器的状态"""
    return [r.status() for r in _resolvers]
