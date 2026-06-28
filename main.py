import asyncio
import aiohttp
import json
import os
import re
import base64
import shutil
import ipaddress
import socket
import sys
import logging
import time
import copy
import glob as glob_mod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Any
from urllib.parse import urlparse, parse_qs, urlencode, unquote, quote
from datetime import datetime, timezone
from collections import defaultdict
import geoip2.database

try:
    import yaml
except ImportError:
    yaml = None

# --- Configuration & Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Feature #11: Configuration File Support ---
DEFAULT_CONFIG = {
    'limits': {'lite': 2, 'normal': 6},
    'timeouts': {'http': 15, 'tcp': 2, 'dns': 10},
    'workers': {'dns': 100, 'tcp': 500, 'logo': 20},
    'retry': {'max_attempts': 3, 'backoff_base': 2},
    'rate_limit': {'max_requests_per_domain': 50, 'window_seconds': 60},
    'dedup': {'cache_file': 'seen_fps.json', 'max_age_days': 7},
    'source_discovery': {'enabled': True, 'max_depth': 1},
    'ai_domains': ['openai.com', 'chatgpt.com', 'claude.com', 'claude.ai'],
    'fake_names': ['#همکاری_ملی', '#جاویدشاه', '#KingRezaPahlavi'],
    'github': {'user': 'itsyebekhe', 'repo': 'PSG', 'branch': 'main'},
    'cloudflare_cidrs': [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32",
        "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
        "2a06:98c0::/29", "2c0f:f248::/32"
    ],
    'validation': {
        'enabled': True,
        'required_vless_reality': ['pbk', 'sid'],
        'required_vmess_fields': ['id', 'add'],
        'required_trojan_fields': ['sni'],
        'required_ss_fields': ['method', 'password']
    }
}


def load_config() -> Dict[str, Any]:
    config_path = os.path.join(BASE_DIR, 'config.yaml')
    config = DEFAULT_CONFIG.copy()
    if os.path.exists(config_path):
        if yaml:
            with open(config_path, 'r', encoding='utf-8') as f:
                user_cfg = yaml.safe_load(f)
            if user_cfg:
                config = _deep_merge(config, user_cfg)
            logger.info(f"Loaded config from {config_path}")
        else:
            json_path = os.path.join(BASE_DIR, 'config.json')
            if os.path.exists(json_path):
                with open(json_path, 'r', encoding='utf-8') as f:
                    user_cfg = json.load(f)
                config = _deep_merge(config, user_cfg)
                logger.info(f"Loaded config from {json_path}")
            else:
                logger.warning("PyYAML not installed. Place config.json next to main.py or install PyYAML.")
    return config


def _deep_merge(base: Dict, override: Dict) -> Dict:
    result = base.copy()
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


CFG = load_config()

PATHS = {
    'INPUT': os.path.join(BASE_DIR, 'channelsData', 'channelsAssets.json'),
    'TEMP': os.path.join(BASE_DIR, 'temp_build'),
    'FINAL_ASSETS': os.path.join(BASE_DIR, 'channelsData'),
    'GEOIP': os.path.join(BASE_DIR, 'Country.mmdb'),
    'API': os.path.join(BASE_DIR, 'api'),
    'OUTPUT_SUBS': os.path.join(BASE_DIR, 'subscriptions'),
    'OUTPUT_LITE': os.path.join(BASE_DIR, 'lite', 'subscriptions'),
    'CONFIG_TXT': os.path.join(BASE_DIR, 'config.txt'),
    'SEEN_FPS': os.path.join(BASE_DIR, CFG['dedup']['cache_file']),
    'DISCOVERED': os.path.join(BASE_DIR, 'discovered_sources.json'),
    'CHANNEL_ACTIVITY': os.path.join(BASE_DIR, 'channel_activity.json')
}

URLS = {
    'GEOIP': "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
    'GITHUB_LOGO': f"https://raw.githubusercontent.com/{CFG['github']['user']}/{CFG['github']['repo']}/main/channelsData/logos",
    'IP_API': 'http://ip-api.com/json/{}',
    'DOH_GOOGLE': 'https://dns.google/resolve?name={}&type=A',
    'DOH_CLOUDFLARE': 'https://1.1.1.1/dns-query?name={}&type=A'
}

CONSTANTS = {
    'LITE_LIMIT': CFG['limits']['lite'],
    'NORMAL_LIMIT': CFG['limits']['normal'],
    'TIMEOUT': CFG['timeouts']['http'],
    'DNS_WORKERS': CFG['workers']['dns'],
    'TCP_WORKERS': CFG['workers']['tcp'],
    'TCP_TIMEOUT': CFG['timeouts']['tcp'],
    'LOGO_WORKERS': CFG['workers']['logo'],
    'MAX_RETRIES': CFG['retry']['max_attempts'],
    'RETRY_BACKOFF_BASE': CFG['retry']['backoff_base'],
    'FAKE_NAMES': CFG['fake_names'],
    'CLOUDFLARE_CIDRS': CFG['cloudflare_cidrs'],
    'AI_DOMAINS': CFG['ai_domains'],
    'CDN_DOMAINS': CFG.get('cdn_domains', []),
    'GITHUB_USER': CFG['github']['user'],
    'GITHUB_REPO': CFG['github']['repo'],
    'GITHUB_BRANCH': CFG['github']['branch'],
    'RATE_LIMIT_MAX': CFG['rate_limit']['max_requests_per_domain'],
    'RATE_LIMIT_WINDOW': CFG['rate_limit']['window_seconds'],
    'SEEN_FP_MAX_AGE': CFG['dedup']['max_age_days'],
    'SOURCE_DISCOVERY': CFG['source_discovery']['enabled'],
    'SOURCE_DISCOVERY_DEPTH': CFG['source_discovery']['max_depth'],
    'VALIDATION_ENABLED': CFG['validation']['enabled']
}

# Pre-compile Regex and Networks
PROTOCOL_REGEX = re.compile(r'(?:vmess|vless|trojan|ss|tuic|hy2|hysteria2?):\/\/[^\s"\']+(?=\s|<|>|$)', re.IGNORECASE)
TELEGRAM_MSG_REGEX = re.compile(r'<div class="tgme_widget_message_text[^"]*">(.*?)</div>', re.DOTALL)
TELEGRAM_CHANNEL_REGEX = re.compile(r't\.me/s/([a-zA-Z0-9_]{5,})', re.IGNORECASE)
CLOUDFLARE_NETWORKS = [ipaddress.ip_network(cidr) for cidr in CONSTANTS['CLOUDFLARE_CIDRS']]


# --- Data Classes ---

@dataclass
class EnrichedConfig:
    fp: str
    orig: str
    parsed: Dict[str, Any]
    chan: str
    ip: str
    country_code: str
    is_cf: bool
    flag: str
    latency_ms: float = 0.0
    speed_tier: str = "unknown"


# --- Feature #3: Protocol-Specific Validation ---

class ConfigValidator:
    @staticmethod
    def validate(parsed: Dict[str, Any], raw: str) -> Tuple[bool, str]:
        if not CONSTANTS['VALIDATION_ENABLED']:
            return True, ""
        ctype = parsed.get('type', '')
        if ctype == 'vless':
            return ConfigValidator._validate_vless(parsed, raw)
        if ctype == 'vmess':
            return ConfigValidator._validate_vmess(parsed)
        if ctype == 'trojan':
            return ConfigValidator._validate_trojan(parsed)
        if ctype == 'ss':
            return ConfigValidator._validate_ss(parsed)
        return True, ""

    @staticmethod
    def _validate_vless(parsed: Dict, raw: str) -> Tuple[bool, str]:
        host = parsed.get('host', '')
        if not host:
            return False, "vless: missing host"
        port = parsed.get('port', '')
        if not port:
            return False, "vless: missing port"
        user = parsed.get('user', '')
        if not user:
            return False, "vless: missing uuid"
        params = parsed.get('params', {})
        if 'security=reality' in raw:
            missing = [f for f in CFG['validation']['required_vless_reality'] if f not in params]
            if missing:
                return False, f"vless reality: missing {', '.join(missing)}"
        return True, ""

    @staticmethod
    def _validate_vmess(parsed: Dict) -> Tuple[bool, str]:
        missing = [f for f in CFG['validation']['required_vmess_fields'] if not parsed.get(f)]
        if missing:
            return False, f"vmess: missing {', '.join(missing)}"
        port = parsed.get('port', '')
        try:
            p = int(port)
            if not (1 <= p <= 65535):
                return False, f"vmess: invalid port {port}"
        except (ValueError, TypeError):
            return False, f"vmess: non-numeric port '{port}'"
        scy = parsed.get('scy', 'auto')
        valid_ciphers = ['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none', 'aes-128-cfb', 'aes-256-cfb', 'chacha20-ietf']
        if scy not in valid_ciphers:
            return False, f"vmess: invalid cipher '{scy}'"
        return True, ""

    @staticmethod
    def _validate_trojan(parsed: Dict) -> Tuple[bool, str]:
        missing = [f for f in CFG['validation']['required_trojan_fields'] if not parsed.get(f) and not parsed.get('params', {}).get(f)]
        if missing:
            return False, f"trojan: missing {', '.join(missing)}"
        if not parsed.get('password'):
            return False, "trojan: missing password"
        return True, ""

    @staticmethod
    def _validate_ss(parsed: Dict) -> Tuple[bool, str]:
        missing = [f for f in CFG['validation']['required_ss_fields'] if not parsed.get(f)]
        if missing:
            return False, f"ss: missing {', '.join(missing)}"
        return True, ""


# --- ConfigUtils & ConfigParser ---

class ConfigUtils:
    @staticmethod
    def decode_base64(s: str) -> str:
        if not s: return ""
        s = s.strip().replace(' ', '+')
        s = s.replace('-', '+').replace('_', '/')
        padding = len(s) % 4
        if padding:
            s += '=' * (4 - padding)
        try:
            return base64.b64decode(s).decode('utf-8', errors='ignore')
        except Exception:
            return ""

    @staticmethod
    def detect_type(config: str) -> Optional[str]:
        lower = config[:20].lower()
        if lower.startswith('vmess://'): return 'vmess'
        if lower.startswith('vless://'): return 'vless'
        if lower.startswith('trojan://'): return 'trojan'
        if lower.startswith('ss://'): return 'ss'
        if lower.startswith('tuic://'): return 'tuic'
        if lower.startswith(('hy2://', 'hysteria2://')): return 'hy2'
        if lower.startswith('hysteria://'): return 'hysteria'
        return None

    @staticmethod
    def is_ipv6(host: str) -> bool:
        host = host.strip('[]')
        try:
            return isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address)
        except ValueError:
            return False

    @staticmethod
    def get_address_type(host: str) -> str:
        host = host.strip('[]')
        try:
            ip = ipaddress.ip_address(host)
            return 'ipv6' if isinstance(ip, ipaddress.IPv6Address) else 'ipv4'
        except ValueError:
            return 'domain'

    @staticmethod
    def is_cloudflare(ip_str: str) -> bool:
        if not ip_str: return False
        try:
            clean_ip = ip_str.strip('[]')
            ip_obj = ipaddress.ip_address(clean_ip)
            return any(ip_obj in net for net in CLOUDFLARE_NETWORKS)
        except ValueError:
            return False

    @staticmethod
    def is_reality(config: str) -> bool:
        return 'security=reality' in config and config.lower().startswith('vless://')

    @staticmethod
    def is_xhttp(config: str) -> bool:
        return 'type=xhttp' in config

    @staticmethod
    def create_fake_config(name: str) -> str:
        encoded_name = quote(name.lstrip('#'))
        return f"vless://00000000-0000-0000-0000-000000000000@127.0.0.1:443?security=none&type=ws&path=/#{encoded_name}"

    @staticmethod
    def generate_header(title: str) -> str:
        b64_title = base64.b64encode(title.encode()).decode()
        return (
            f"#profile-title: base64:{b64_title}\n"
            "#profile-update-interval: 1\n"
            "#subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531\n"
            "#support-url: https://t.me/yebekhe\n"
            f"#profile-web-page-url: https://github.com/{CONSTANTS['GITHUB_USER']}/{CONSTANTS['GITHUB_REPO']}\n\n"
        )

    @staticmethod
    def safe_base64_decode(text: str) -> str:
        try:
            return ConfigUtils.decode_base64(text)
        except:
            return text


class ConfigParser:
    @staticmethod
    def parse(config_str: str) -> Optional[Dict[str, Any]]:
        ctype = ConfigUtils.detect_type(config_str)
        if not ctype: return None

        try:
            if ctype == 'vmess':
                return ConfigParser._parse_vmess(config_str)
            elif ctype == 'ss':
                return ConfigParser._parse_ss(config_str)
            else:
                return ConfigParser._parse_generic(config_str, ctype)
        except Exception:
            return None

    @staticmethod
    def _parse_vmess(config_str: str) -> Optional[Dict]:
        try:
            prefix_len = 8
            b64 = config_str[prefix_len:]
            json_str = ConfigUtils.decode_base64(b64)
            if not json_str: return None

            data = json.loads(json_str)

            return {
                'type': 'vmess',
                'ps': data.get('ps', ''),
                'add': data.get('add', ''),
                'port': str(data.get('port', '')),
                'id': data.get('id', ''),
                'net': data.get('net', 'tcp'),
                'type_transport': data.get('type', 'none'),
                'host': data.get('host', ''),
                'path': data.get('path', ''),
                'tls': data.get('tls', ''),
                'sni': data.get('sni', ''),
                'scy': data.get('scy', 'auto'),
                'full_data': data
            }
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _parse_ss(config_str: str) -> Optional[Dict]:
        parsed = urlparse(config_str)
        user_info = parsed.netloc
        host_port = ""

        if '@' in user_info:
            user_pass_b64, host_port = user_info.rsplit('@', 1)
            try:
                decoded = ConfigUtils.decode_base64(user_pass_b64)
                if ':' in decoded:
                    method, password = decoded.split(':', 1)
                else:
                    method = "auto"
                    password = decoded
            except:
                if ':' in user_pass_b64:
                    method, password = user_pass_b64.split(':', 1)
                else:
                    return None
        else:
            decoded_full = ConfigUtils.decode_base64(user_info)
            if '@' in decoded_full:
                method_pass, host_port = decoded_full.rsplit('@', 1)
                if ':' in method_pass:
                    method, password = method_pass.split(':', 1)
                else:
                    return None
            else:
                return None

        host = ""
        port = ""
        if ']:' in host_port:
            host_part, port_part = host_port.rsplit(':', 1)
            host = host_part.strip('[]')
            port = port_part
        elif ':' in host_port:
            host, port = host_port.rsplit(':', 1)
        else:
            host = host_port

        return {
            'type': 'ss',
            'name': unquote(parsed.fragment),
            'host': host,
            'port': port,
            'method': method,
            'password': password
        }

    @staticmethod
    def _parse_generic(config_str: str, ctype: str) -> Dict:
        parsed = urlparse(config_str)
        params = parse_qs(parsed.query)
        clean_params = {k: v[0] for k, v in params.items() if v}

        return {
            'type': ctype,
            'hash': unquote(parsed.fragment),
            'user': unquote(parsed.username) if parsed.username else '',
            'password': unquote(parsed.password) if parsed.password else '',
            'host': parsed.hostname if parsed.hostname else '',
            'port': str(parsed.port) if parsed.port else '',
            'params': clean_params,
            'path': parsed.path
        }

    @staticmethod
    def reassemble(parsed: Dict, new_tag: str = None) -> Optional[str]:
        if not parsed: return None
        ctype = parsed.get('type')

        if ctype == 'vmess':
            data = parsed.get('full_data', {}).copy()
            if new_tag: data['ps'] = new_tag
            if not data.get('add'): data['add'] = '127.0.0.1'
            if not data.get('port'): data['port'] = 443
            if not data.get('id'): data['id'] = 'uuid'
            json_str = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
            return 'vmess://' + base64.b64encode(json_str.encode()).decode()

        elif ctype == 'ss':
            method = parsed.get('method', 'chacha20-ietf-poly1305')
            password = parsed.get('password', '')
            user_pass = f"{method}:{password}"
            b64_user = base64.b64encode(user_pass.encode()).decode()

            host = parsed.get('host', '')
            if ConfigUtils.is_ipv6(host): host = f"[{host}]"

            uri = f"ss://{b64_user}@{host}:{parsed.get('port', '')}"
            name = new_tag if new_tag else parsed.get('name', '')
            return f"{uri}#{quote(name)}"

        else:
            user = parsed.get('user', '')
            password = parsed.get('password', '')
            userinfo = quote(user)
            if password: userinfo += f":{quote(password)}"

            host = parsed.get('host', '')
            if ConfigUtils.is_ipv6(host): host = f"[{host}]"

            netloc = f"{userinfo}@{host}:{parsed.get('port', '')}"
            query_params = parsed.get('params', {}).copy()
            path = parsed.get('path', '')

            full_path_str = ""
            if ctype in ['vless', 'trojan']:
                 full_path_str = path
                 if query_params: full_path_str += "?" + urlencode(query_params, doseq=True, safe='/')
            else:
                 if path and path != '/': query_params['path'] = path
                 if query_params: full_path_str = "?" + urlencode(query_params, doseq=True, safe='/')

            name = new_tag if new_tag else parsed.get('hash', '')
            return f"{ctype}://{netloc}{full_path_str}#{quote(name)}"

    @staticmethod
    def get_fingerprint(parsed: Dict) -> str:
        ctype = parsed.get('type')
        if not ctype: return "invalid"

        def norm(s): return str(s).strip().lower()

        components = [ctype]

        if ctype == 'vmess':
            keys = ['add', 'port', 'id', 'net', 'type_transport', 'path', 'host', 'sni', 'tls', 'scy']
            for k in keys:
                components.append(norm(parsed.get(k, '')))

        elif ctype == 'ss':
            keys = ['host', 'port', 'method', 'password']
            for k in keys:
                components.append(norm(parsed.get(k, '')))

        else:
            components.append(norm(parsed.get('user', '')))
            components.append(norm(parsed.get('host', '')))
            components.append(norm(parsed.get('port', '')))
            components.append(norm(parsed.get('path', '')))

            ignored_params = ['name', 'remarks', 'ps', 'plugin', 'spiders', 'hash']
            params = parsed.get('params', {})
            sorted_keys = sorted(params.keys())
            for k in sorted_keys:
                if k.lower() in ignored_params: continue
                components.append(f"{k.lower()}={norm(params[k])}")

        return "|".join(components)

# --- Main Processor ---

class SubscriptionProcessor:
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.dns_cache: Dict[str, Optional[str]] = {}
        self.geo_reader: Optional[geoip2.database.Reader] = None
        self.channel_assets: Dict[str, Dict[str, Any]] = {}
        self.all_configs: List[Tuple[str, str]] = []
        self.dns_semaphore = asyncio.Semaphore(CONSTANTS['DNS_WORKERS'])
        self.tcp_semaphore = asyncio.Semaphore(CONSTANTS['TCP_WORKERS'])
        self.logo_semaphore = asyncio.Semaphore(CONSTANTS['LOGO_WORKERS'])
        self._seen_fps: Dict[str, float] = {}
        self._discovered_sources: Set[str] = set()
        self._geo_fallback_cache: Dict[str, str] = {}
        self._channel_activity: Dict[str, Dict[str, Any]] = {}

    async def initialize(self):
        self.session = aiohttp.ClientSession(headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
        })

        dirs_to_clean = [
            PATHS['TEMP'],
            PATHS['OUTPUT_SUBS'],
            PATHS['OUTPUT_LITE']
        ]

        logger.info("Cleaning up old directories...")
        for d in dirs_to_clean:
            if os.path.exists(d):
                try:
                    shutil.rmtree(d, ignore_errors=True)
                except Exception as e:
                    logger.warning(f"Could not remove {d}: {e}")

        for path in [PATHS['TEMP'], PATHS['FINAL_ASSETS'], PATHS['API'],
                     os.path.join(PATHS['TEMP'], 'logos'),
                     os.path.join(PATHS['TEMP'], 'html_cache')]:
            os.makedirs(path, exist_ok=True)

        await self._setup_geoip()
        self._load_seen_fps()
        self._load_discovered_sources()
        self._load_channel_activity()

    async def cleanup(self):
        if self.session:
            await self.session.close()
            self.session = None
        if self.geo_reader:
            self.geo_reader.close()
        self._save_seen_fps()
        self._save_discovered_sources()
        self._save_channel_activity()

    # --- Feature #5: Rate Limiting ---

    async def _fetch_url(self, url: str) -> Optional[bytes]:
        if not self.session: return None
        for attempt in range(CONSTANTS['MAX_RETRIES']):
            try:
                async with self.session.get(url, timeout=CONSTANTS['TIMEOUT']) as response:
                    if response.status == 200:
                        return await response.read()
                    if response.status == 429:
                        wait = CONSTANTS['RETRY_BACKOFF_BASE'] ** attempt
                        logger.warning(f"Rate limited ({response.status}) on {url}, retrying in {wait}s...")
                        await asyncio.sleep(wait)
                        continue
                    if response.status >= 500:
                        wait = CONSTANTS['RETRY_BACKOFF_BASE'] ** attempt
                        logger.warning(f"Server error ({response.status}) on {url}, retrying in {wait}s...")
                        await asyncio.sleep(wait)
                        continue
                    return None
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt < CONSTANTS['MAX_RETRIES'] - 1:
                    wait = CONSTANTS['RETRY_BACKOFF_BASE'] ** attempt
                    await asyncio.sleep(wait)
                    continue
                logger.warning(f"Failed to fetch {url} after {CONSTANTS['MAX_RETRIES']} attempts")
                return None
            except Exception:
                return None
        return None

    # --- Feature #12: Graceful Degradation (GeoIP + DoH) ---

    async def _setup_geoip(self):
        db_path = PATHS['GEOIP']
        if not os.path.exists(db_path) or (datetime.now().timestamp() - os.path.getmtime(db_path) > 86400):
            logger.info("Downloading GeoIP Database...")
            geoip_urls = [
                URLS['GEOIP'],
                "https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@download/GeoLite2-Country.mmdb",
                "https://git.io/GeoLite2-Country.mmdb"
            ]
            data = None
            for url in geoip_urls:
                data = await self._fetch_url(url)
                if data:
                    break
                logger.info(f"  Trying next GeoIP mirror...")
            if data:
                with open(db_path, 'wb') as f: f.write(data)
            else:
                logger.warning("Failed to download GeoIP from all mirrors.")

        try:
            self.geo_reader = geoip2.database.Reader(db_path)
        except Exception:
            logger.warning("Could not load GeoIP database. Falling back to ip-api.com for geo lookups.")

    async def _geo_ip_api_fallback(self, ip: str) -> str:
        if ip in self._geo_fallback_cache:
            return self._geo_fallback_cache[ip]
        try:
            url = URLS['IP_API'].format(ip)
            data = await self._fetch_url(url)
            if data:
                info = json.loads(data)
                code = info.get('countryCode', 'XX')
                self._geo_fallback_cache[ip] = code
                return code
        except Exception:
            pass
        self._geo_fallback_cache[ip] = 'XX'
        return 'XX'

    async def _dns_doh_fallback(self, host: str) -> Optional[str]:
        for doh_url_template in [URLS['DOH_GOOGLE'], URLS['DOH_CLOUDFLARE']]:
            try:
                url = doh_url_template.format(host)
                data = await self._fetch_url(url)
                if data:
                    result = json.loads(data)
                    answers = result.get('Answer', [])
                    for ans in answers:
                        if ans.get('type') == 1:
                            return ans['data']
            except Exception:
                continue
        return None

    async def resolve_ip(self, host: str) -> Optional[str]:
        if not host: return None
        if host in self.dns_cache: return self.dns_cache[host]

        try:
            ipaddress.ip_address(host.strip('[]'))
            self.dns_cache[host] = host.strip('[]')
            return self.dns_cache[host]
        except ValueError:
            pass

        async with self.dns_semaphore:
            try:
                loop = asyncio.get_running_loop()
                results = await loop.getaddrinfo(
                    host, None,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM
                )
                if results:
                    ip = results[0][4][0]
                    self.dns_cache[host] = ip
                    return ip
            except Exception:
                pass

            # Feature #12: DoH fallback
            doh_ip = await self._dns_doh_fallback(host)
            if doh_ip:
                self.dns_cache[host] = doh_ip
                return doh_ip

            self.dns_cache[host] = None
            return None

    async def check_reachability(self, ip: str, port: int) -> Tuple[bool, float]:
        if not ip or not port: return False, 0.0
        target_ip = ip.strip('[]')
        start = time.monotonic()
        async with self.tcp_semaphore:
            try:
                future = asyncio.open_connection(target_ip, port)
                reader, writer = await asyncio.wait_for(future, timeout=CONSTANTS['TCP_TIMEOUT'])
                elapsed_ms = (time.monotonic() - start) * 1000
                writer.close()
                await writer.wait_closed()
                return True, elapsed_ms
            except (OSError, asyncio.TimeoutError):
                return False, 0.0
            except Exception:
                return False, 0.0

    def get_geo_code(self, ip: str) -> str:
        if not ip: return "XX"
        if self.geo_reader:
            try:
                return self.geo_reader.country(ip).country.iso_code or "XX"
            except:
                pass
        return "XX"

    @staticmethod
    def get_flag(code: str) -> str:
        if not code or len(code) != 2: return "🏳️"
        return chr(127397 + ord(code[0])) + chr(127397 + ord(code[1]))

    @staticmethod
    def _speed_tier(latency_ms: float) -> str:
        if latency_ms <= 0: return "unknown"
        if latency_ms < 200: return "fast"
        if latency_ms < 500: return "medium"
        return "slow"

    # --- Feature #4: Cross-Session Dedup Cache ---

    def _load_seen_fps(self):
        cache_path = PATHS['SEEN_FPS']
        if not os.path.exists(cache_path):
            return
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            max_age = CONSTANTS['SEEN_FP_MAX_AGE'] * 86400
            now = time.time()
            self._seen_fps = {fp: ts for fp, ts in data.items() if now - ts < max_age}
            logger.info(f"Loaded {len(self._seen_fps)} fingerprints from cache (expired pruned)")
        except Exception as e:
            logger.warning(f"Could not load seen fps cache: {e}")

    def _save_seen_fps(self):
        try:
            with open(PATHS['SEEN_FPS'], 'w', encoding='utf-8') as f:
                json.dump(self._seen_fps, f)
        except Exception as e:
            logger.warning(f"Could not save seen fps cache: {e}")

    def _load_discovered_sources(self):
        if not os.path.exists(PATHS['DISCOVERED']):
            return
        try:
            with open(PATHS['DISCOVERED'], 'r', encoding='utf-8') as f:
                data = json.load(f)
            self._discovered_sources = set(data.get('sources', []))
            logger.info(f"Loaded {len(self._discovered_sources)} discovered sources")
        except Exception:
            pass

    def _save_discovered_sources(self):
        try:
            with open(PATHS['DISCOVERED'], 'w', encoding='utf-8') as f:
                json.dump({'sources': sorted(self._discovered_sources)}, f, indent=2)
        except Exception:
            pass

    def _load_channel_activity(self):
        if not os.path.exists(PATHS['CHANNEL_ACTIVITY']):
            return
        try:
            with open(PATHS['CHANNEL_ACTIVITY'], 'r', encoding='utf-8') as f:
                self._channel_activity = json.load(f)
        except Exception:
            pass

    def _save_channel_activity(self):
        try:
            with open(PATHS['CHANNEL_ACTIVITY'], 'w', encoding='utf-8') as f:
                json.dump(self._channel_activity, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def _is_channel_stale(self, key: str) -> bool:
        """Check if a channel has had 0 configs for 3+ days."""
        STALE_DAYS = 3
        entry = self._channel_activity.get(key)
        if not entry:
            return False
        last_config_count = entry.get('config_count', 0)
        last_seen = entry.get('last_seen', 0)
        days_since = (time.time() - last_seen) / 86400
        if last_config_count == 0 and days_since >= STALE_DAYS:
            return True
        return False

    def _update_channel_activity(self, key: str, config_count: int):
        """Update channel activity tracker."""
        self._channel_activity[key] = {
            'config_count': config_count,
            'last_seen': time.time()
        }

    # --- Feature #8: Automatic Source Discovery ---

    def _extract_discovered_channels(self, text: str, depth: int) -> List[str]:
        if not CONSTANTS['SOURCE_DISCOVERY'] or depth >= CONSTANTS['SOURCE_DISCOVERY_DEPTH']:
            return []
        found = set()
        for match in TELEGRAM_CHANNEL_REGEX.finditer(text):
            ch = match.group(1)
            if ch not in self._discovered_sources and ch not in self.channel_assets:
                found.add(ch)
        return sorted(found)

    async def process_sources(self):
        try:
            with open(PATHS['INPUT'], 'r', encoding='utf-8') as f:
                raw_input = json.load(f)
        except FileNotFoundError:
            logger.error("Input file not found.")
            return

        # Normalize input: support multiple formats
        sources = self._normalize_sources(raw_input)

        # Merge discovered sources
        for disc in self._discovered_sources:
            if disc not in sources:
                sources[disc] = {}

        # Single-pass: fetch each channel once, extract everything
        logger.info("Fetching channels (single-pass)...")
        results = await self._fetch_all_sources(sources)

        logos_to_fetch = {}
        new_discoveries = set()
        for key, configs, logo_url, discovered in results:
            if logo_url: logos_to_fetch[key] = logo_url
            for c in configs: self.all_configs.append((c, key))
            for d in discovered:
                if d not in self._discovered_sources:
                    new_discoveries.add(d)
                    self._discovered_sources.add(d)

        if new_discoveries:
            logger.info(f"Discovered {len(new_discoveries)} new sources: {sorted(new_discoveries)[:10]}")

        logo_tasks = [self._fetch_and_save_logo(k, u) for k, u in logos_to_fetch.items()]
        if logo_tasks: await asyncio.gather(*logo_tasks, return_exceptions=True)

    async def _fetch_all_sources(self, sources: Dict[str, Dict]) -> List[Tuple[str, List[str], Optional[str], List[str]]]:
        """Fetch each channel once, extract subscriber count + configs + metadata, then sort by subscribers."""
        sub_count_regex = re.compile(r'count[^>]*>([\d,\.]+[KkMm]?)<')
        FETCH_DELAY = 0.3
        keys = list(sources.keys())
        total = len(keys)
        results_with_counts = []
        skipped_stale = 0

        for i, key in enumerate(keys):
            # Skip channels with 0 configs for 3+ days
            if self._is_channel_stale(key):
                skipped_stale += 1
                continue

            if (i + 1) % 20 == 0 or i == 0:
                logger.info(f"  Fetching: {i + 1}/{total} (skipped {skipped_stale} stale)")

            data = sources[key]
            url = data.get('subscription_url') or f"https://t.me/s/{key}"
            content = await self._fetch_url(url)

            configs = []
            logo = None
            types = set()
            title = data.get('title', key)
            discovered = []
            sub_count = 0

            if content:
                text = content.decode('utf-8', errors='ignore')

                # Extract subscriber count
                count_match = sub_count_regex.search(text)
                if count_match:
                    raw = count_match.group(1).replace(',', '').replace('.', '')
                    try:
                        if raw.endswith(('K', 'k')):
                            sub_count = int(float(raw[:-1]) * 1000)
                        elif raw.endswith(('M', 'm')):
                            sub_count = int(float(raw[:-1]) * 1000000)
                        else:
                            sub_count = int(raw)
                    except (ValueError, IndexError):
                        sub_count = 0

                # Extract configs
                if data.get('subscription_url'):
                    try:
                        decoded = ConfigUtils.safe_base64_decode(text)
                        if 'vmess://' in decoded or 'vless://' in decoded:
                            text = decoded
                    except: pass

                if 't.me' in url and not data.get('subscription_url'):
                    msg_bodies = TELEGRAM_MSG_REGEX.findall(text)
                    if msg_bodies:
                        text = '\n'.join(msg_bodies)
                    discovered = self._extract_discovered_channels(text, 0)

                configs = PROTOCOL_REGEX.findall(text)
                for c in configs:
                    ct = ConfigUtils.detect_type(c)
                    if ct: types.add(ct)

                # Extract metadata
                t_match = re.search(r'<meta property="twitter:title" content="(.*?)">', text)
                i_match = re.search(r'<meta property="twitter:image" content="(.*?)">', text)
                if t_match: title = t_match.group(1)
                if i_match: logo = i_match.group(1)

            # Update activity tracker
            self._update_channel_activity(key, len(configs))

            self.channel_assets[key] = {
                'title': title,
                'logo': URLS['GITHUB_LOGO'] + f"/{key}.jpg" if logo else data.get('logo', ''),
                'types': sorted(list(types))
            }

            results_with_counts.append((key, configs, logo, discovered, sub_count))
            await asyncio.sleep(FETCH_DELAY)

        if skipped_stale:
            logger.info(f"Skipped {skipped_stale} stale channels (0 configs for 3+ days)")

        # Sort by subscriber count descending
        results_with_counts.sort(key=lambda x: x[4], reverse=True)
        top3 = [(r[0], r[4]) for r in results_with_counts[:3] if r[4] > 0]
        if top3:
            top_str = ", ".join(f"{k} ({c:,})" for k, c in top3)
            logger.info(f"Top channels by subscribers: {top_str}")

        # Return without counts
        return [(r[0], r[1], r[2], r[3]) for r in results_with_counts]

    def _normalize_sources(self, raw: Any) -> Dict[str, Dict]:
        """Accept multiple input formats and normalize to {key: {data}}."""
        # Format 1: Old format — dict of dicts with full metadata
        # {"ChannelName": {"title": "...", "logo": "...", "types": [...], "subscription_url": "..."}}
        if isinstance(raw, dict):
            first_val = next(iter(raw.values()), None) if raw else None
            if isinstance(first_val, dict):
                return raw
            # Format 2: Simple dict — {"ChannelName": numeric_id, ...}
            # Just use the keys as channel names
            return {k: {} for k in raw.keys()}

        # Format 3: Array — ["ChannelName1", "ChannelName2", ...]
        if isinstance(raw, list):
            return {str(item): {} for item in raw if item}

        logger.warning("Unknown input format. Expected dict or list.")
        return {}

    async def _fetch_and_save_logo(self, key, url):
        async with self.logo_semaphore:
            data = await self._fetch_url(url)
            if data:
                try:
                    with open(os.path.join(PATHS['TEMP'], 'logos', f"{key}.jpg"), 'wb') as f:
                        f.write(data)
                except: pass

    def deduplicate_configs(self) -> Dict[str, Tuple[str, Dict, str]]:
        unique_map = {}
        skipped_invalid = 0
        for conf_str, chan in self.all_configs:
            parsed = ConfigParser.parse(conf_str)
            if not parsed: continue

            # Feature #3: Protocol-specific validation
            valid, reason = ConfigValidator.validate(parsed, conf_str)
            if not valid:
                skipped_invalid += 1
                logger.debug(f"Rejected config from {chan}: {reason}")
                continue

            fp = ConfigParser.get_fingerprint(parsed)
            orig_name = parsed.get('ps') or parsed.get('name') or parsed.get('hash', '')

            if fp not in unique_map:
                unique_map[fp] = (orig_name, parsed, chan)

        # Feature #4: Mark fingerprints as seen
        now = time.time()
        for fp in unique_map:
            self._seen_fps[fp] = now

        self.all_configs.clear()
        if skipped_invalid:
            logger.info(f"Validation rejected {skipped_invalid} invalid configs")
        return unique_map

    async def _process_config_parallel(self, fp: str, orig: str, parsed: Dict, chan: str) -> Optional[EnrichedConfig]:
        raw_port = parsed.get('port')
        if not raw_port: return None
        try:
            port = int(raw_port)
        except ValueError:
            return None

        host = parsed.get('host') or parsed.get('add', '')
        sni = parsed.get('sni') or parsed.get('params', {}).get('sni') or parsed.get('params', {}).get('host')
        if (not host or host == '127.0.0.1') and sni:
            host = sni

        if not host: return None

        ip = await self.resolve_ip(host)
        if not ip: return None

        is_reachable, latency_ms = await self.check_reachability(ip, port)
        if not is_reachable: return None

        is_cf = ConfigUtils.is_cloudflare(ip)
        country_code = self.get_geo_code(ip)
        if country_code == "XX" and not is_cf:
            country_code = await self._geo_ip_api_fallback(ip)
        flag = self.get_flag(country_code)

        return EnrichedConfig(
            fp=fp,
            orig=orig,
            parsed=parsed,
            chan=chan,
            ip=ip,
            country_code=country_code,
            is_cf=is_cf,
            flag=flag,
            latency_ms=round(latency_ms, 1),
            speed_tier=self._speed_tier(latency_ms)
        )

    async def enrich_and_tag(self, unique_map: Dict):
        final_list = []
        lite_list = []
        api_data = []
        groups: Dict[str, Any] = {'channels': defaultdict(list), 'locations': defaultdict(list), 'ai': []}

        lite_channel_counts: Dict[str, int] = defaultdict(int)
        normal_channel_counts: Dict[str, int] = defaultdict(int)
        channel_name_counter: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

        total = len(unique_map)
        logger.info(f"Processing {total} configs (Mass Parallel Check)...")

        tasks = []
        for fp, (orig, parsed, chan) in unique_map.items():
            tasks.append(self._process_config_parallel(fp, orig, parsed, chan))

        results = await asyncio.gather(*tasks)

        logger.info("Checks complete. Formatting results...")

        reachable_count = 0
        for res in results:
            if not res: continue
            reachable_count += 1

            parsed = res.parsed
            chan = res.chan
            country_code = res.country_code
            flag = res.flag
            is_cf = res.is_cf

            clean_chan = chan.strip().lstrip('@')
            ctype_disp = parsed.get('type', 'UNK').upper()

            combo_key = f"{country_code}_{ctype_disp}"
            channel_name_counter[clean_chan][combo_key] += 1
            count_idx = channel_name_counter[clean_chan][combo_key]

            speed_badge = f" [{res.speed_tier}]" if res.speed_tier != "unknown" else ""
            new_tag = f"{flag} {country_code} | {ctype_disp} | @{clean_chan} #{count_idx}{speed_badge}"

            final_str = ConfigParser.reassemble(parsed, new_tag)
            if not final_str: continue

            if normal_channel_counts[clean_chan] < CONSTANTS['NORMAL_LIMIT']:
                final_list.append(final_str)
                groups['channels'][clean_chan].append(final_str)
                groups['locations'][country_code].append(final_str)
                if is_cf:
                    groups['locations']['CF'].append(final_str)

                if is_cf and parsed['type'] == 'vless':
                    sni = parsed.get('sni') or parsed.get('params', {}).get('sni') or ''
                    check_host = parsed.get('host') or parsed.get('add') or ''
                    is_ai_config = any(domain in sni or domain in check_host for domain in CONSTANTS['AI_DOMAINS'])
                    if is_ai_config:
                        groups['ai'].append(final_str)

                normal_channel_counts[clean_chan] += 1

            if lite_channel_counts[clean_chan] < CONSTANTS['LITE_LIMIT']:
                lite_list.append(final_str)
                lite_channel_counts[clean_chan] += 1

            eff_type = parsed['type']
            if eff_type == 'vless' and 'security=reality' in final_str: eff_type = 'reality'
            assets = self.channel_assets.get(clean_chan, {})

            if normal_channel_counts[clean_chan] <= CONSTANTS['NORMAL_LIMIT']:
                api_data.append({
                    'channel': {'username': clean_chan, 'title': assets.get('title', ''), 'logo': assets.get('logo', '')},
                    'country': country_code, 'flag': flag, 'type': eff_type, 'config': final_str,
                    'is_cf': is_cf, 'latency_ms': res.latency_ms, 'speed_tier': res.speed_tier
                })

        logger.info(f"Processing complete. Reachable: {reachable_count}/{total}, Normal: {len(final_list)}, Lite: {len(lite_list)}")
        return final_list, lite_list, groups, api_data

    def write_output(self, final_list, lite_list, groups, api_data):
        sorted_assets = dict(sorted(self.channel_assets.items()))
        with open(os.path.join(PATHS['TEMP'], 'channelsAssets.json'), 'w', encoding='utf-8') as f:
            json.dump(sorted_assets, f, indent=4, ensure_ascii=False)

        if os.path.exists(PATHS['FINAL_ASSETS']): shutil.rmtree(PATHS['FINAL_ASSETS'], ignore_errors=True)
        shutil.copytree(PATHS['TEMP'], PATHS['FINAL_ASSETS'])

        def write_subscription_package(configs: List[str], base_dir: str, title_prefix: str, ai_configs: List[str] = None):
            proto_groups: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
            fake_configs = [ConfigUtils.create_fake_config(n) for n in CONSTANTS['FAKE_NAMES']]

            for c in configs:
                ct = ConfigUtils.detect_type(c)
                if not ct: continue
                parsed = ConfigParser.parse(c)
                host = ""
                if parsed:
                    host = parsed.get('host') or parsed.get('add', '') or parsed.get('host', '')
                addr_type = ConfigUtils.get_address_type(host) if host else 'domain'
                proto_groups[ct][addr_type].append(c)
                if ct == 'vless' and ConfigUtils.is_reality(c):
                    proto_groups['reality'][addr_type].append(c)
                if ConfigUtils.is_xhttp(c):
                    proto_groups['xhttp'][addr_type].append(c)

            self._write_files(base_dir, 'mix', configs, f"{title_prefix} | MIX", fake_configs)

            if ai_configs:
                self._write_files(base_dir, 'openai', ai_configs, f"{title_prefix} | OpenAI/Claude", fake_configs)

            for proto, addr_groups in proto_groups.items():
                all_proto_configs = []
                for at, confs in addr_groups.items():
                    if not confs: continue
                    filename = f"{proto}_{at}"
                    header_title = f"{title_prefix} | {proto.upper()} {at.upper()}"
                    self._write_files(base_dir, filename, confs, header_title, fake_configs)
                    all_proto_configs.extend(confs)
                if all_proto_configs:
                    header_title = f"{title_prefix} | {proto.upper()}"
                    self._write_files(base_dir, proto, all_proto_configs, header_title, fake_configs)

        logger.info("Writing files...")
        write_subscription_package(final_list, os.path.join(PATHS['OUTPUT_SUBS'], 'xray'), "PSG", groups['ai'])
        write_subscription_package(lite_list, os.path.join(PATHS['OUTPUT_LITE'], 'xray'), "PSG Lite", groups['ai'])

        for loc, confs in groups['locations'].items():
            safe_name = re.sub(r'[^a-zA-Z0-9]', '', loc) or "XX"
            path = os.path.join(PATHS['OUTPUT_SUBS'], 'locations')
            self._write_files(path, safe_name, confs, f"PSG | Location {loc}")

        for chan, confs in groups['channels'].items():
            safe_chan = re.sub(r'[^a-zA-Z0-9_.-]', '_', chan)
            path = os.path.join(PATHS['OUTPUT_SUBS'], 'channels', safe_chan)
            self._write_files(path, 'list', confs, f"PSG | @{chan}")

        with open(PATHS['CONFIG_TXT'], 'w', encoding='utf-8') as f:
            f.write('\n'.join(final_list))

        with open(os.path.join(PATHS['API'], 'allConfigs.json'), 'w', encoding='utf-8') as f:
            json.dump(api_data, f, indent=4, ensure_ascii=False)

    def _write_files(self, directory: str, filename: str, configs: List[str], title: str, prepends: List[str] = None):
        os.makedirs(os.path.join(directory, 'normal'), exist_ok=True)
        os.makedirs(os.path.join(directory, 'base64'), exist_ok=True)

        merged = (prepends or []) + configs
        content = ConfigUtils.generate_header(title) + '\n'.join(merged)
        b64_content = base64.b64encode(content.encode()).decode()

        try:
            with open(os.path.join(directory, 'normal', filename), 'w', encoding='utf-8') as f:
                f.write(content)
            with open(os.path.join(directory, 'base64', filename), 'w', encoding='utf-8') as f:
                f.write(b64_content)
        except IOError as e:
            logger.error(f"Failed to write {filename} in {directory}: {e}")

    async def send_telegram_notification(self, total_normal: int, total_lite: int):
        token = os.getenv('TG_TOKEN')
        chat_id = os.getenv('TG_CHAT_ID')

        if not token or not chat_id:
            logger.warning("Telegram Credentials not found. Skipping notification.")
            return

        base_url = f"https://raw.githubusercontent.com/{CONSTANTS['GITHUB_USER']}/{CONSTANTS['GITHUB_REPO']}/{CONSTANTS['GITHUB_BRANCH']}"

        message = (
            f"<b>🚀 بروزرسانی PSG تکمیل شد</b>\n"
            f"📅 <i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>\n\n"
            f"📊 <b>آمار:</b>\n"
            f"• کانفیگ‌های عادی: {total_normal}\n"
            f"• کانفیگ‌های سبک: {total_lite}\n"
            f"• منابع کشف شده: {len(self._discovered_sources)}\n\n"
            f"🔗 <b>لینک‌های اشتراک (Base64):</b>\n\n"
            f"🌍 <b>اشتراک عادی (میکس):</b>\n"
            f"<code>{base_url}/subscriptions/xray/base64/mix</code>\n\n"
            f"🚀 <b>اشتراک سبک (میکس):</b>\n"
            f"<code>{base_url}/lite/subscriptions/xray/base64/mix</code>\n\n"
            f"🤖 <b>API جیسون:</b>\n"
            f"<code>{base_url}/api/allConfigs.json</code>\n\n"
            f"📱 <b>کلاینت‌های پیشنهادی:</b>\n"
            f"• Android: <b>v2rayNG</b>, <b>Hiddify</b>\n"
            f"• iOS: <b>Streisand</b>, <b>V2Box</b>, <b>Shadowrocket</b>\n"
            f"• Windows/Mac: <b>v2rayN</b>, <b>Hiddify</b>\n\n"
            f"#Update #Proxy #V2ray"
        )

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            'chat_id': chat_id,
            'text': message,
            'parse_mode': 'HTML',
            'disable_web_page_preview': True
        }

        try:
            async with self.session.post(url, json=payload) as response:
                if response.status == 200:
                    logger.info("Telegram notification sent successfully.")
                else:
                    logger.error(f"Failed to send Telegram notification: {await response.text()}")
        except Exception as e:
            logger.error(f"Error sending Telegram notification: {e}")

    async def generate_cdn_configs(self, final_list: List[str]) -> List[str]:
        """Take all CF WS configs, replace their server address with resolved CDN domain IPs."""
        cdn_domains = CONSTANTS['CDN_DOMAINS']
        if not cdn_domains:
            return []

        # Resolve all CDN domain IPs (skip raw IPs)
        all_ips: List[str] = []
        for domain in cdn_domains:
            try:
                ipaddress.ip_address(domain)
                logger.info(f"  CDN {domain} (raw IP, no resolution needed)")
                all_ips.append(domain)
                continue
            except ValueError:
                pass
            ips = await self._resolve_all_ips(domain)
            if ips:
                logger.info(f"  CDN {domain} → {', '.join(ips)}")
                all_ips.extend(ips)

        if not all_ips:
            logger.warning("  No IPs resolved for any CDN domain")
            return []

        # Find all CF WS configs
        cf_ws_configs = []
        for config_str in final_list:
            if not config_str.startswith('vless://'):
                continue
            if 'type=ws' not in config_str:
                continue
            parsed = ConfigParser.parse(config_str)
            if not parsed:
                continue
            cf_ws_configs.append((config_str, parsed))

        if not cf_ws_configs:
            logger.info("  No CF WS configs found")
            return []

        logger.info(f"  Replacing addresses in {len(cf_ws_configs)} CF WS configs with {len(all_ips)} CDN IPs")

        # For each CF WS config, replace server address with each CDN IP
        configs = []
        for config_str, parsed in cf_ws_configs:
            user = parsed.get('user', '')
            port = parsed.get('port', '443')
            params = parsed.get('params', {})

            for ip in all_ips:
                query = '&'.join(f"{k}={quote(str(v))}" for k, v in params.items())
                name = f"CDN {ip}"
                config = f"vless://{user}@{ip}:{port}?{query}#{quote(name)}"
                configs.append(config)

        logger.info(f"  Generated {len(configs)} CDN configs")
        return configs

    async def _resolve_all_ips(self, domain: str) -> List[str]:
        """Resolve a domain to all its A records."""
        ips = []
        try:
            loop = asyncio.get_running_loop()
            results = await loop.getaddrinfo(
                domain, None,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM
            )
            seen = set()
            for r in results:
                ip = r[4][0]
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
        except Exception as e:
            logger.warning(f"  DNS resolution failed for {domain}: {e}")
        return ips

    def generate_readmes(self, final_list: List[str], lite_list: List[str], groups: Dict, api_data: List):
        logger.info("7. Generating README files...")
        base_url = f"https://raw.githubusercontent.com/{CONSTANTS['GITHUB_USER']}/{CONSTANTS['GITHUB_REPO']}/{CONSTANTS['GITHUB_BRANCH']}"

        protocol_counts: Dict[str, int] = defaultdict(int)
        country_counts: Dict[str, int] = defaultdict(int)
        channel_counts: Dict[str, int] = defaultdict(int)
        speed_tiers = {'fast': 0, 'medium': 0, 'slow': 0, 'unknown': 0}
        cf_count = 0

        for item in api_data:
            protocol_counts[item['type']] += 1
            country_counts[item['country']] += 1
            channel_counts[item['channel']['username']] += 1
            if item.get('is_cf'): cf_count += 1
            tier = item.get('speed_tier', 'unknown')
            speed_tiers[tier] = speed_tiers.get(tier, 0) + 1

        total = len(final_list)
        total_lite = len(lite_list)
        total_channels = len(channel_counts)
        total_countries = len(country_counts)
        total_protocols = len(protocol_counts)

        sorted_protocols = sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)
        sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        sorted_channels = sorted(channel_counts.items(), key=lambda x: x[1], reverse=True)[:30]

        def clean_title(title: str) -> str:
            title = re.sub(r'<[^>]+>', '', title)
            title = re.sub(r'[^\w\s\-@#.!?]', '', title)
            title = re.sub(r'\s+', ' ', title).strip()
            return title[:35] if title else ''

        def country_flag(code: str) -> str:
            if not code or len(code) != 2: return ""
            return chr(127397 + ord(code[0])) + chr(127397 + ord(code[1]))

        def protocol_emoji(p: str) -> str:
            return {'vless': '🔒', 'vmess': '🛡️', 'trojan': '🐴', 'ss': '🔑', 'reality': '⚡', 'xhttp': '🚀', 'tuic': '🎯', 'hy2': '🌊'}.get(p, '📡')

        def bar_chart(count: int, max_count: int, width: int = 20) -> str:
            if max_count == 0: return ""
            filled = int((count / max_count) * width)
            return "█" * filled + "░" * (width - filled)

        now = datetime.now().strftime('%Y-%m-%d %H:%M UTC')

        # Protocol chart
        max_proto = sorted_protocols[0][1] if sorted_protocols else 1
        proto_chart_rows = []
        for proto, count in sorted_protocols:
            emoji = protocol_emoji(proto)
            pct = (count / total * 100) if total else 0
            chart = bar_chart(count, max_proto)
            proto_chart_rows.append(f"> {emoji} **{proto.upper()}** — {count:,} ({pct:.1f}%)\n> `{chart}`\n")
        proto_chart = "\n".join(proto_chart_rows)

        # Country chart
        max_country = sorted_countries[0][1] if sorted_countries else 1
        country_chart_rows = []
        for code, count in sorted_countries[:15]:
            flag = country_flag(code)
            pct = (count / total * 100) if total else 0
            chart = bar_chart(count, max_country, 15)
            country_chart_rows.append(f"> {flag} **{code}** — {count:,} ({pct:.1f}%)\n> `{chart}`\n")
        country_chart = "\n".join(country_chart_rows)

        # Channel list
        channel_items = []
        for i, (chan, count) in enumerate(sorted_channels, 1):
            assets = self.channel_assets.get(chan, {})
            title = clean_title(assets.get('title', ''))
            channel_items.append(f"{i}. **@{chan}** — {count} configs {'— ' + title if title else ''}")
        channel_list = "\n".join(channel_items)

        # CDN domains
        cdn_domains = CONSTANTS['CDN_DOMAINS']
        cdn_section = ""
        if cdn_domains:
            cdn_domain_list = ", ".join(cdn_domains)
            cdn_section = f"""
## 🌐 CDN Domain Configs

Configs for **{cdn_domain_list}** — resolved IPs with WebSocket transport:

> 🔗 [Base64 Normal]({base_url}/subscriptions/xray/base64/cdn) · [Base64 Lite]({base_url}/lite/subscriptions/xray/base64/cdn)
> ⚡ [Clash Normal]({base_url}/subscriptions/clash/cdn) · [Clash Lite]({base_url}/lite/subscriptions/clash/cdn)
> 📦 [Sing-box Normal]({base_url}/subscriptions/singbox/cdn.json) · [Sing-box Lite]({base_url}/lite/subscriptions/singbox/cdn.json)
"""

        # === ENGLISH README ===
        readme_en = f"""# 🛡️ PSG — Premium Subscription Generator

<p align="center">
  <img src="https://img.shields.io/badge/Configs-{total}-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Lite-{total_lite}-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Channels-{total_channels}-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Countries-{total_countries}-purple?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Updated-{now}-red?style=for-the-badge" />
</p>

<p align="center"><a href="README.fa.md">🇮🇷 نسخه فارسی</a></p>

---

## 📊 Network Statistics

> 🔢 **{total:,}** configs · 🪶 **{total_lite:,}** lite · 📡 **{total_channels}** channels · 🌍 **{total_countries}** countries · ☁️ **{cf_count:,}** Cloudflare

### ⚡ Protocol Distribution

{proto_chart}

### 🌍 Top Countries

{country_chart}

### 🚀 Speed Distribution

> ⚡ **Fast** — {speed_tiers['fast']:,} (< 200ms)
> 🟡 **Medium** — {speed_tiers['medium']:,} (200-500ms)
> 🐢 **Slow** — {speed_tiers['slow']:,} (> 500ms)

---

## 🔗 Subscription Links

### 📌 Main Subscriptions

| Format | Normal | Lite |
|:---|:---|:---|
| 🔗 Base64 | [mix]({base_url}/subscriptions/xray/base64/mix) | [mix]({base_url}/lite/subscriptions/xray/base64/mix) |
| ⚡ Clash | [mix]({base_url}/subscriptions/clash/mix) | [mix]({base_url}/lite/subscriptions/clash/mix) |
| 🧠 Clash.Meta | [mix]({base_url}/subscriptions/meta/mix) | [mix]({base_url}/lite/subscriptions/meta/mix) |
| 🏄 Surfboard | [mix]({base_url}/subscriptions/surfboard/mix) | [mix]({base_url}/lite/subscriptions/surfboard/mix) |
| 📦 Sing-box | [mix.json]({base_url}/subscriptions/singbox/mix.json) | [mix.json]({base_url}/lite/subscriptions/singbox/mix.json) |
| 🐱 Nekobox | [mix.json]({base_url}/subscriptions/nekobox/mix.json) | [mix.json]({base_url}/lite/subscriptions/nekobox/mix.json) |

### 🔌 By Protocol

| Protocol | Normal | Lite |
|:---|:---|:---|
| 🔒 VLESS | [vless]({base_url}/subscriptions/xray/base64/vless) | [vless]({base_url}/lite/subscriptions/xray/base64/vless) |
| 🛡️ VMess | [vmess]({base_url}/subscriptions/xray/base64/vmess) | [vmess]({base_url}/lite/subscriptions/xray/base64/vmess) |
| 🐴 Trojan | [trojan]({base_url}/subscriptions/xray/base64/trojan) | [trojan]({base_url}/lite/subscriptions/xray/base64/trojan) |
| 🔑 Shadowsocks | [ss]({base_url}/subscriptions/xray/base64/ss) | [ss]({base_url}/lite/subscriptions/xray/base64/ss) |
| ⚡ Reality | [reality]({base_url}/subscriptions/xray/base64/reality) | [reality]({base_url}/lite/subscriptions/xray/base64/reality) |
| 🚀 XHTTP | [xhttp]({base_url}/subscriptions/xray/base64/xhttp) | [xhttp]({base_url}/lite/subscriptions/xray/base64/xhttp) |

{cdn_section}
### 🌍 By Country (Top 20)

| Country | Link |
|:---|:---|
| 🇺🇸 US | [US]({base_url}/subscriptions/locations/base64/US) |
| 🇩🇪 DE | [DE]({base_url}/subscriptions/locations/base64/DE) |
| 🇳🇱 NL | [NL]({base_url}/subscriptions/locations/base64/NL) |
| 🇬🇧 GB | [GB]({base_url}/subscriptions/locations/base64/GB) |
| 🇫🇷 FR | [FR]({base_url}/subscriptions/locations/base64/FR) |
| 🇯🇵 JP | [JP]({base_url}/subscriptions/locations/base64/JP) |
| 🇸🇬 SG | [SG]({base_url}/subscriptions/locations/base64/SG) |
| 🇭🇰 HK | [HK]({base_url}/subscriptions/locations/base64/HK) |
| 🇨🇦 CA | [CA]({base_url}/subscriptions/locations/base64/CA) |
| 🇦🇺 AU | [AU]({base_url}/subscriptions/locations/base64/AU) |

> More countries available in [locations/base64/]({base_url}/subscriptions/locations/base64/)

---

## 📡 Active Channels ({total_channels})

{channel_list}

---

## 📱 Recommended Clients

| Platform | Client |
|:---|:---|
| 🤖 Android | [v2rayNG](https://github.com/2dust/v2rayNG) · [Hiddify](https://github.com/hiddify/hiddify-app) |
| 🍎 iOS | [Streisand](https://github.com/nickinchina/streisand) · [V2Box](https://github.com/nickinchina/v2box) · [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932740345) |
| 🪟 Windows | [v2rayN](https://github.com/2dust/v2rayN) · [Hiddify](https://github.com/hiddify/hiddify-app) |
| 🍏 macOS | [V2Box](https://github.com/nickinchina/v2box) · [Hiddify](https://github.com/hiddify/hiddify-app) |
| 🐧 Linux | [Nekoray](https://github.com/MatsuriDayo/nekoray) · [Hiddify](https://github.com/hiddify/hiddify-app) |

---

<div align="center">

**Auto-updated every 6 hours** · Built with ❤️ by [PSG](https://github.com/itsyebekhe/PSG)

</div>
"""

        # === FARSI README ===
        readme_fa = f"""# 🛡️ PSG — سازنده اشتراک پروکسی

<p align="center">
  <img src="https://img.shields.io/badge/کانفیگ-{total:,}-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/سبک-{total_lite:,}-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/کانال-{total_channels}-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/کشور-{total_countries}-purple?style=for-the-badge" />
  <img src="https://img.shields.io/badge/بروزرسانی-{now}-red?style=for-the-badge" />
</p>

<p align="center"><a href="README.md">🇬🇧 English Version</a></p>

---

## 📊 آمار شبکه

> 🔢 **{total:,}** کانفیگ · 🪶 **{total_lite:,}** سبک · 📡 **{total_channels}** کانال · 🌍 **{total_countries}** کشور · ☁️ **{cf_count:,}** کلودفلر

### ⚡ توزیع پروتکل‌ها

{proto_chart}

### 🌍 برترین کشورها

{country_chart}

### 🚀 توزیع سرعت

> ⚡ **سریع** — {speed_tiers['fast']:,} (کمتر از ۲۰۰ms)
> 🟡 **متوسط** — {speed_tiers['medium']:,} (۲۰۰-۵۰۰ms)
> 🐢 **کند** — {speed_tiers['slow']:,} (بیش از ۵۰۰ms)

---

## 🔗 لینک‌های اشتراک

### 📌 اشتراک اصلی

| فرمت | عادی | سبک |
|:---|:---|:---|
| 🔗 Base64 | [mix]({base_url}/subscriptions/xray/base64/mix) | [mix]({base_url}/lite/subscriptions/xray/base64/mix) |
| ⚡ Clash | [mix]({base_url}/subscriptions/clash/mix) | [mix]({base_url}/lite/subscriptions/clash/mix) |
| 🧠 Clash.Meta | [mix]({base_url}/subscriptions/meta/mix) | [mix]({base_url}/lite/subscriptions/meta/mix) |
| 🏄 Surfboard | [mix]({base_url}/subscriptions/surfboard/mix) | [mix]({base_url}/lite/subscriptions/surfboard/mix) |
| 📦 Sing-box | [mix.json]({base_url}/subscriptions/singbox/mix.json) | [mix.json]({base_url}/lite/subscriptions/singbox/mix.json) |
| 🐱 Nekobox | [mix.json]({base_url}/subscriptions/nekobox/mix.json) | [mix.json]({base_url}/lite/subscriptions/nekobox/mix.json) |

### 🔌 بر اساس پروتکل

| پروتکل | عادی | سبک |
|:---|:---|:---|
| 🔒 VLESS | [vless]({base_url}/subscriptions/xray/base64/vless) | [vless]({base_url}/lite/subscriptions/xray/base64/vless) |
| 🛡️ VMess | [vmess]({base_url}/subscriptions/xray/base64/vmess) | [vmess]({base_url}/lite/subscriptions/xray/base64/vmess) |
| 🐴 Trojan | [trojan]({base_url}/subscriptions/xray/base64/trojan) | [trojan]({base_url}/lite/subscriptions/xray/base64/trojan) |
| 🔑 Shadowsocks | [ss]({base_url}/subscriptions/xray/base64/ss) | [ss]({base_url}/lite/subscriptions/xray/base64/ss) |
| ⚡ Reality | [reality]({base_url}/subscriptions/xray/base64/reality) | [reality]({base_url}/lite/subscriptions/xray/base64/reality) |
| 🚀 XHTTP | [xhttp]({base_url}/subscriptions/xray/base64/xhttp) | [xhttp]({base_url}/lite/subscriptions/xray/base64/xhttp) |

{cdn_section.replace('CDN Domain Configs', 'کانفیگ‌های دامنه CDN').replace('resolved IPs with WebSocket transport', 'IPهای رزولو شده با انتقال WebSocket') if cdn_section else ''}
### 🌍 بر اساس کشور (۲۰ کشور برتر)

| کشور | لینک |
|:---|:---|
| 🇺🇸 US | [US]({base_url}/subscriptions/locations/base64/US) |
| 🇩🇪 DE | [DE]({base_url}/subscriptions/locations/base64/DE) |
| 🇳🇱 NL | [NL]({base_url}/subscriptions/locations/base64/NL) |
| 🇬🇧 GB | [GB]({base_url}/subscriptions/locations/base64/GB) |
| 🇫🇷 FR | [FR]({base_url}/subscriptions/locations/base64/FR) |
| 🇯🇵 JP | [JP]({base_url}/subscriptions/locations/base64/JP) |
| 🇸🇬 SG | [SG]({base_url}/subscriptions/locations/base64/SG) |
| 🇭🇰 HK | [HK]({base_url}/subscriptions/locations/base64/HK) |
| 🇨🇦 CA | [CA]({base_url}/subscriptions/locations/base64/CA) |
| 🇦🇺 AU | [AU]({base_url}/subscriptions/locations/base64/AU) |

> کشورهای بیشتر در [locations/base64/]({base_url}/subscriptions/locations/base64/)

---

## 📡 کانال‌های فعال ({total_channels})

{channel_list}

---

## 📱 کلاینت‌های پیشنهادی

| پلتفرم | کلاینت |
|:---|:---|
| 🤖 اندروید | [v2rayNG](https://github.com/2dust/v2rayNG) · [Hiddify](https://github.com/hiddify/hiddify-app) |
| 🍎 آیفون | [Streisand](https://github.com/nickinchina/streisand) · [V2Box](https://github.com/nickinchina/v2box) · [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932740345) |
| 🪟 ویندوز | [v2rayN](https://github.com/2dust/v2rayN) · [Hiddify](https://github.com/hiddify/hiddify-app) |
| 🍏 مک | [V2Box](https://github.com/nickinchina/v2box) · [Hiddify](https://github.com/hiddify/hiddify-app) |
| 🐧 لینوکس | [Nekoray](https://github.com/MatsuriDayo/nekoray) · [Hiddify](https://github.com/hiddify/hiddify-app) |

---

<div align="center">

**بروزرسانی خودکار هر ۶ ساعت** · ساخته شده با ❤️ توسط [PSG](https://github.com/itsyebekhe/PSG)

</div>
"""

        with open(os.path.join(BASE_DIR, 'README.md'), 'w', encoding='utf-8') as f:
            f.write(readme_en)
        with open(os.path.join(BASE_DIR, 'README.fa.md'), 'w', encoding='utf-8') as f:
            f.write(readme_fa)
        logger.info("README.md and README.fa.md generated.")

# --- Feature #6: Configuration Format Converter ---

ALLOWED_SS_METHODS = ["chacha20-ietf-poly1305", "aes-256-gcm", "2022-blake3-aes-256-gcm", "aes-128-gcm", "chacha20-ietf"]


class ConfigConverter:
    SINGBOX_TEMPLATE = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "google", "address": "https://8.8.8.8/dns-query"},
                {"tag": "local", "address": "local"}
            ],
            "rules": [{"server": "local", "domain_suffix": ["ir"]}]
        },
        "inbounds": [
            {"tag": "mixed-in", "type": "mixed", "listen": "127.0.0.1", "listen_port": 2080}
        ],
        "outbounds": [
            {"tag": "DIRECT", "type": "direct"},
            {"tag": "BLOCK", "type": "block"},
            {"tag": "REJECT", "type": "reject"}
        ]
    }

    NEKOBOX_TEMPLATE = {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"tag": "google", "address": "https://8.8.8.8/dns-query"},
                {"tag": "local", "address": "local"}
            ]
        },
        "inbounds": [
            {"tag": "mixed-in", "type": "mixed", "listen": "127.0.0.1", "listen_port": 2080}
        ],
        "outbounds": [
            {"tag": "DIRECT", "type": "direct"},
            {"tag": "BLOCK", "type": "block"}
        ]
    }

    CLASH_TEMPLATE = """mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
proxies:
##PROXIES##
proxy-groups:
  - name: "PROXY"
    type: select
    proxies:
##PROXY_NAMES##
      - DIRECT
  - name: "Auto"
    type: url-test
    proxies:
##PROXY_NAMES##
rules:
  - GEOIP,IR,DIRECT
  - MATCH,PROXY
"""

    SURFBOARD_TEMPLATE = """[General]
loglevel = notify
skip-proxy = 127.0.0.1, localhost, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.*, 10.*, 172.16.*, 172.17.*, 172.18.*, 172.19.*, 172.20.*, 172.21.*, 172.22.*, 172.23.*, 172.24.*, 172.25.*, 172.26.*, 172.27.*, 172.28.*, 172.29.*, 172.30.*, 172.31.*, localhost, *.local, e.crashlynatics.com
dns-server = 8.8.8.8, 8.8.4.4
[Proxy]
##PROXIES##
[Proxy Group]
PROXY = select, ##PROXY_NAMES##
[Rule]
GEOSITE,category-ads-all,REJECT
GEOIP,LAN,DIRECT
GEOIP,CN,DIRECT
MATCH,PROXY
"""

    @staticmethod
    def _parse_config_for_export(config_str: str) -> Optional[Dict[str, Any]]:
        ctype = ConfigUtils.detect_type(config_str)
        if not ctype:
            return None
        try:
            if ctype == 'vmess':
                b64 = config_str[8:]
                data = json.loads(ConfigUtils.decode_base64(b64))
                return {
                    'type': 'vmess',
                    'name': data.get('ps', 'VMess'),
                    'server': data.get('add', ''),
                    'port': int(data.get('port', 443)),
                    'uuid': data.get('id', ''),
                    'alterId': int(data.get('aid', 0)),
                    'cipher': data.get('scy', 'auto'),
                    'network': data.get('net', 'tcp'),
                    'type_header': data.get('type', 'none'),
                    'host': data.get('host', ''),
                    'path': data.get('path', ''),
                    'tls': data.get('tls', '') == 'tls',
                    'sni': data.get('sni', ''),
                    'fp': data.get('fp', ''),
                    'alpn': data.get('alpn', ''),
                }
            elif ctype == 'ss':
                parsed = urlparse(config_str)
                user_info = parsed.username
                if not user_info and '@' in parsed.netloc:
                    try:
                        b64part = parsed.netloc.split('@')[0]
                        decoded = ConfigUtils.decode_base64(b64part)
                        method, password = decoded.split(':', 1)
                    except Exception:
                        return None
                else:
                    method = parsed.username
                    password = parsed.password
                return {
                    'type': 'ss',
                    'name': unquote(parsed.fragment),
                    'server': parsed.hostname,
                    'port': parsed.port,
                    'method': method,
                    'password': password
                }
            else:
                parsed = urlparse(config_str)
                params = parse_qs(parsed.query)
                clean_params = {k: v[0] for k, v in params.items()}
                return {
                    'type': ctype,
                    'name': unquote(parsed.fragment),
                    'server': parsed.hostname,
                    'port': parsed.port,
                    'uuid': parsed.username,
                    'password': parsed.username,
                    'params': clean_params,
                    'path': parsed.path
                }
        except Exception:
            return None

    @staticmethod
    def _to_clash_proxy(data: Dict, is_meta: bool = False) -> Optional[Dict]:
        ctype = data['type']
        proxy = {
            "name": data['name'],
            "server": data['server'],
            "port": data['port'],
            "type": ctype,
            "skip-cert-verify": True
        }

        if ctype == 'vmess':
            proxy.update({
                "uuid": data['uuid'],
                "alterId": data.get('alterId', 0),
                "cipher": data.get('cipher', 'auto'),
                "network": data.get('network', 'tcp'),
                "tls": data.get('tls', False)
            })
            if data.get('network') == 'ws':
                proxy['ws-opts'] = {
                    "path": data.get('path', '/'),
                    "headers": {"Host": data.get('host') or data['server']}
                }
            elif data.get('network') == 'grpc':
                proxy['grpc-opts'] = {"grpc-service-name": data.get('path', '')}
                if not proxy['tls']:
                    proxy['tls'] = True

        elif ctype == 'vless':
            if not is_meta:
                return None
            params = data.get('params', {})
            proxy.update({
                "uuid": data['uuid'],
                "network": params.get('type', 'tcp'),
                "tls": params.get('security') in ['tls', 'reality'],
                "udp": True,
                "client-fingerprint": params.get('fp', 'chrome')
            })
            if params.get('flow'):
                proxy['flow'] = 'xtls-rprx-vision'
            if params.get('sni'):
                proxy['servername'] = params['sni']
            if proxy['network'] == 'ws':
                proxy['ws-opts'] = {
                    "path": data.get('path', '/'),
                    "headers": {"Host": params.get('host', data['server'])}
                }
            elif proxy['network'] == 'grpc':
                proxy['grpc-opts'] = {"grpc-service-name": params.get('serviceName', '')}
            if params.get('security') == 'reality':
                proxy['client-fingerprint'] = params.get('fp', 'chrome')
                proxy['reality-opts'] = {
                    "public-key": params.get('pbk', ''),
                    "short-id": params.get('sid', '')
                }

        elif ctype == 'trojan':
            proxy['password'] = data.get('password', '')
            proxy['skip-cert-verify'] = data.get('params', {}).get('allowInsecure') == '1'
            if data.get('params', {}).get('sni'):
                proxy['sni'] = data['params']['sni']

        elif ctype == 'ss':
            if data.get('method') not in ALLOWED_SS_METHODS:
                return None
            proxy['cipher'] = data['method']
            proxy['password'] = data.get('password', '')
        else:
            return None

        return proxy

    @staticmethod
    def _to_surfboard_proxy(data: Dict) -> Optional[str]:
        ctype = data['type']
        if ctype not in ['vmess', 'trojan', 'ss']:
            return None
        name = data['name'].replace(',', ' ')
        parts = [f"{name} = {ctype}", data['server'], str(data['port'])]

        if ctype == 'vmess':
            parts.append(f"username = {data['uuid']}")
            parts.append(f"ws = {'true' if data.get('network') == 'ws' else 'false'}")
            parts.append(f"tls = {'true' if data.get('tls') else 'false'}")
            if data.get('network') == 'ws':
                parts.append(f"ws-path = {data.get('path', '/')}")
                host = data.get('host') or data['server']
                parts.append(f'ws-headers = Host:"{host}"')
        elif ctype == 'trojan':
            parts.append(f"password = {data.get('password', '')}")
            parts.append("skip-cert-verify = true")
            if data.get('params', {}).get('sni'):
                parts.append(f"sni = {data['params']['sni']}")
        elif ctype == 'ss':
            if data.get('method') not in ALLOWED_SS_METHODS:
                return None
            parts.append(f"encrypt-method = {data['method']}")
            parts.append(f"password = {data.get('password', '')}")

        return ", ".join(parts)

    @staticmethod
    def _to_singbox_outbound(data: Dict) -> Optional[Dict]:
        ctype = data['type']
        out = {
            "tag": data['name'],
            "type": ctype,
            "server": data['server'],
            "server_port": data['port']
        }

        def get_tls(sni, insecure=True, fp='chrome', alpn=None, reality=None):
            tls = {
                "enabled": True,
                "server_name": sni,
                "insecure": insecure,
                "utls": {"enabled": True, "fingerprint": fp}
            }
            if alpn:
                tls['alpn'] = alpn if isinstance(alpn, list) else [alpn]
            if reality:
                tls['reality'] = reality
                tls['reality']['enabled'] = True
            return tls

        def get_transport(net, path, host, service_name):
            if net == 'ws':
                return {"type": "ws", "path": path, "headers": {"Host": host}}
            if net == 'grpc':
                return {"type": "grpc", "service_name": service_name}
            if net == 'http':
                return {"type": "http", "host": [host], "path": path}
            return None

        if ctype == 'vmess':
            out.update({
                "uuid": data['uuid'],
                "security": "auto",
                "alter_id": data.get('alterId', 0)
            })
            if data.get('port') == 443 or data.get('tls'):
                out['tls'] = get_tls(data.get('sni') or data.get('host', ''))
            net = data.get('network', 'tcp')
            if net in ['ws', 'grpc', 'http']:
                out['transport'] = get_transport(net, data.get('path', ''), data.get('host', ''), data.get('path', ''))

        elif ctype == 'vless':
            params = data.get('params', {})
            out.update({
                "uuid": data['uuid'],
                "packet_encoding": "xudp"
            })
            if params.get('flow'):
                out['flow'] = "xtls-rprx-vision"
            security = params.get('security', '')
            if data.get('port') == 443 or security in ['tls', 'reality']:
                reality = None
                if security == 'reality':
                    reality = {"public_key": params.get('pbk', ''), "short_id": params.get('sid', '')}
                out['tls'] = get_tls(params.get('sni', ''), reality=reality, fp=params.get('fp', 'chrome'))
            net = params.get('type', 'tcp')
            if net in ['ws', 'grpc', 'http']:
                out['transport'] = get_transport(net, data.get('path', ''), params.get('host', ''), params.get('serviceName', ''))

        elif ctype == 'trojan':
            out['password'] = data.get('password', '')
            if data.get('port') == 443 or data.get('params', {}).get('security') == 'tls':
                out['tls'] = get_tls(data.get('params', {}).get('sni', ''))

        elif ctype == 'ss':
            out['type'] = "shadowsocks"
            out['method'] = data.get('method', 'aes-256-gcm')
            out['password'] = data.get('password', '')

        elif ctype == 'tuic':
            params = data.get('params', {})
            out.update({
                "uuid": data['uuid'],
                "password": data.get('password', ''),
                "congestion_control": params.get('congestion_control', 'bbr'),
                "udp_relay_mode": params.get('udp_relay_mode', 'native'),
                "tls": {
                    "enabled": True,
                    "server_name": params.get('sni', ''),
                    "insecure": params.get('allow_insecure') == '1',
                    "alpn": params.get('alpn', '').split(',') if params.get('alpn') else None
                }
            })

        elif ctype == 'hy2':
            out['type'] = 'hysteria2'
            params = data.get('params', {})
            if not params.get('obfs-password'):
                return None
            out.update({
                "password": data.get('password', ''),
                "obfs": {"type": params.get('obfs', 'salamander'), "password": params.get('obfs-password', '')},
                "tls": {
                    "enabled": True,
                    "server_name": params.get('sni', ''),
                    "insecure": params.get('insecure') == '1',
                    "alpn": ["h3"]
                }
            })
        else:
            return None

        return out

    def convert_outputs(self, output_subs: str, output_lite: str):
        logger.info("6. Converting outputs to Clash/Meta/Surfboard/Singbox formats...")
        datasets = [
            {
                "name": "MAIN",
                "input_dir": os.path.join(output_subs, 'xray', 'base64'),
                "output_root": output_subs,
                "url_path": "subscriptions/surfboard"
            },
            {
                "name": "LITE",
                "input_dir": os.path.join(output_lite, 'xray', 'base64'),
                "output_root": output_lite,
                "url_path": "lite/subscriptions/surfboard"
            },
            {
                "name": "LOCATIONS",
                "input_dir": os.path.join(output_subs, 'locations', 'base64'),
                "output_root": output_subs,
                "url_path": "subscriptions/locations/surfboard"
            }
        ]

        for dataset in datasets:
            self._process_dataset(
                dataset['name'],
                dataset['input_dir'],
                dataset['output_root'],
                dataset['url_path']
            )

        logger.info("Format conversion complete.")

    def _process_dataset(self, name: str, input_dir: str, output_root: str, url_path: str):
        logger.info(f"  Converting {name} datasets...")

        for out_type in ['clash', 'meta', 'surfboard']:
            os.makedirs(os.path.join(output_root, out_type), exist_ok=True)

        os.makedirs(os.path.join(output_root, 'singbox'), exist_ok=True)
        os.makedirs(os.path.join(output_root, 'nekobox'), exist_ok=True)

        input_files = [f for f in glob_mod.glob(os.path.join(input_dir, '*')) if os.path.isfile(f)]
        if not input_files:
            logger.info(f"    No files found in {input_dir}")
            return

        for filepath in input_files:
            filename = os.path.basename(filepath)
            with open(filepath, 'r', encoding='utf-8') as f:
                b64_content = f.read().strip()
            decoded_content = ConfigUtils.decode_base64(b64_content)
            config_lines = decoded_content.splitlines()

            parsed_proxies = []
            for line in config_lines:
                if not line.strip():
                    continue
                parsed = self._parse_config_for_export(line)
                if parsed:
                    parsed_proxies.append(parsed)

            if not parsed_proxies:
                continue

            self._write_clash_configs(parsed_proxies, filename, output_root)
            self._write_surfboard_config(parsed_proxies, filename, output_root, url_path)
            self._write_singbox_configs(parsed_proxies, filename, output_root)

    def _write_clash_configs(self, proxies: List[Dict], filename: str, output_root: str):
        for out_type in ['clash', 'meta']:
            is_meta = (out_type == 'meta')
            proxy_lines = []
            proxy_names = []

            for p in proxies:
                res = self._to_clash_proxy(p, is_meta)
                if res:
                    json_str = json.dumps(res, ensure_ascii=False)
                    proxy_lines.append(f"  - {json_str}")
                    safe_name = p['name'].replace("'", "''")
                    proxy_names.append(f"      - '{safe_name}'")

            if proxy_lines:
                content = self.CLASH_TEMPLATE
                content = content.replace('##PROXIES##', '\n'.join(proxy_lines))
                content = content.replace('##PROXY_NAMES##', '\n'.join(proxy_names))
                out_path = os.path.join(output_root, out_type, filename)
                with open(out_path, 'w', encoding='utf-8') as f:
                    f.write(content)

    def _write_surfboard_config(self, proxies: List[Dict], filename: str, output_root: str, url_path: str):
        surf_lines = []
        proxy_names = []
        for p in proxies:
            res = self._to_surfboard_proxy(p)
            if res:
                surf_lines.append(res)
                proxy_names.append(p['name'].replace(',', ' '))

        if surf_lines:
            content = self.SURFBOARD_TEMPLATE
            content = content.replace('##PROXIES##', '\n'.join(surf_lines))
            content = content.replace('##PROXY_NAMES##', ', '.join(proxy_names))
            out_path = os.path.join(output_root, 'surfboard', filename)
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(content)

    def _write_singbox_configs(self, proxies: List[Dict], filename: str, output_root: str):
        for task, base_template in [('singbox', self.SINGBOX_TEMPLATE), ('nekobox', self.NEKOBOX_TEMPLATE)]:
            structure = copy.deepcopy(base_template)
            tags_added = []

            for p in proxies:
                outbound = self._to_singbox_outbound(p)
                if outbound:
                    structure['outbounds'].append(outbound)
                    tags_added.append(outbound['tag'])

            if tags_added:
                structure['outbounds'][0]['outbounds'] = tags_added

            if task == 'singbox':
                b64_title = base64.b64encode(f"PSG | {filename.upper()}".encode()).decode()
                header = (
                    f"//profile-title: base64:{b64_title}\n"
                    "//profile-update-interval: 1\n"
                    "//subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531\n"
                    "//support-url: https://t.me/yebekhe\n"
                    f"//profile-web-page-url: https://github.com/{CONSTANTS['GITHUB_USER']}/{CONSTANTS['GITHUB_REPO']}\n\n"
                )
                final_content = header + json.dumps(structure, indent=2, ensure_ascii=False)
            else:
                final_content = json.dumps(structure, indent=2, ensure_ascii=False)

            out_path = os.path.join(output_root, task, f"{filename}.json")
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(final_content)


# --- Entry Point ---

async def main():
    processor = SubscriptionProcessor()
    try:
        await processor.initialize()

        logger.info("1. Fetching Sources")
        await processor.process_sources()

        logger.info("2. Deduplicating & Validating")
        unique_map = processor.deduplicate_configs()

        logger.info("3. Enriching and Tagging (Mass Parallel Check)")
        final, lite, groups, api_data = await processor.enrich_and_tag(unique_map)

        logger.info("4. Writing Outputs")
        processor.write_output(final, lite, groups, api_data)

        logger.info("5. Generating CDN Configs")
        cdn_configs = await processor.generate_cdn_configs(final)
        if cdn_configs:
            cdn_dir = os.path.join(PATHS['OUTPUT_SUBS'], 'xray', 'base64')
            processor._write_files(cdn_dir, 'cdn', cdn_configs, "PSG | CDN Domains")
            cdn_lite_dir = os.path.join(PATHS['OUTPUT_LITE'], 'xray', 'base64')
            processor._write_files(cdn_lite_dir, 'cdn', cdn_configs, "PSG Lite | CDN Domains")
            logger.info(f"  Generated {len(cdn_configs)} CDN configs")

        logger.info("6. Converting to Export Formats")
        converter = ConfigConverter()
        converter.convert_outputs(PATHS['OUTPUT_SUBS'], PATHS['OUTPUT_LITE'])

        logger.info("7. Generating READMEs")
        processor.generate_readmes(final, lite, groups, api_data)

        logger.info("8. Sending Notification")
        await processor.send_telegram_notification(len(final), len(lite))

    finally:
        await processor.cleanup()
        logger.info("Cleanup done.")

if __name__ == "__main__":
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(main())
