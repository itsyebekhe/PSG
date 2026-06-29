#!/usr/bin/env python3
"""
Proxy URL to sing-box Config Converter
Converts vmess:// vless:// trojan:// ss:// hysteria2:// tuic:// etc. to sing-box client config.
"""

import base64
import json
import re
import sys
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class ProxyNode:
    type: str = ""
    tag: str = ""
    server: str = ""
    port: int = 0
    uuid: str = ""
    alter_id: int = 0
    security: str = "auto"
    method: str = ""
    password: str = ""
    plugin: str = ""
    plugin_opts: str = ""
    flow: str = ""
    network: str = "tcp"
    tls_enabled: bool = True
    tls_server_name: str = ""
    tls_insecure: bool = False
    tls_alpn: list = field(default_factory=list)
    tls_utls_fingerprint: str = ""
    tls_reality_enabled: bool = False
    tls_reality_public_key: str = ""
    tls_reality_short_id: str = ""
    transport_type: str = ""
    transport_path: str = ""
    transport_host: list = field(default_factory=list)
    transport_headers: dict = field(default_factory=dict)
    transport_max_early_data: int = 0
    transport_early_data_header_name: str = ""
    transport_service_name: str = ""
    obfs_type: str = ""
    obfs_password: str = ""
    congestion_control: str = "cubic"
    up_mbps: int = 0
    down_mbps: int = 0
    username: str = ""
    packet_encoding: str = ""
    server_ports: list = field(default_factory=list)
    hop_interval: str = ""


def b64_decode(s: str) -> str:
    s = s.strip()
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    try:
        return base64.b64decode(s).decode("utf-8", errors="replace")
    except Exception:
        return ""


def parse_url_params(query: str) -> dict:
    params = {}
    if not query:
        return params
    for part in query.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            params[k] = urllib.parse.unquote(v)
    return params


def parse_vmess(url: str) -> Optional[ProxyNode]:
    raw = url[len("vmess://"):]
    try:
        data = json.loads(b64_decode(raw))
    except Exception:
        return None

    node = ProxyNode(type="vmess")
    node.tag = data.get("ps", "") or data.get("add", "vmess")
    node.server = data.get("add", "")
    try:
        node.port = int(data.get("port", 0))
    except (ValueError, TypeError):
        return None
    node.uuid = data.get("id", "")
    node.alter_id = int(data.get("aid", 0))
    node.security = data.get("scy", "auto") or "auto"
    node.network = data.get("net", "tcp") or "tcp"

    tls = data.get("tls", "")
    node.tls_enabled = tls == "tls"
    node.tls_server_name = data.get("sni", "") or data.get("host", "")
    node.tls_insecure = str(data.get("allowInsecure", "0")) == "1"

    host = data.get("host", "")
    path = data.get("path", "")
    net = node.network

    if net == "ws":
        node.transport_type = "ws"
        node.transport_path = path
        if host:
            node.transport_host = [host]
    elif net == "grpc":
        node.transport_type = "grpc"
        node.transport_service_name = path or "grpc"
    elif net == "h2" or net == "http":
        node.transport_type = "http"
        node.transport_path = path
        if host:
            node.transport_host = [host] if isinstance(host, str) else host
    elif net == "quic":
        node.transport_type = "quic"

    if not node.tls_server_name and host:
        node.tls_server_name = host

    return node


def parse_vless(url: str) -> Optional[ProxyNode]:
    node = ProxyNode(type="vless")
    raw = url[len("vless://"):]
    main, _, fragment = raw.partition("#")
    node.tag = urllib.parse.unquote(fragment) if fragment else "vless"

    userinfo, _, hostinfo = main.partition("@")
    node.uuid = urllib.parse.unquote(userinfo)

    if "?" in hostinfo:
        hostport, query = hostinfo.split("?", 1)
    else:
        hostport, query = hostinfo, ""

    if ":" in hostport:
        parts = hostport.rsplit(":", 1)
        node.server = parts[0]
        try:
            node.port = int(parts[1])
        except ValueError:
            return None
    else:
        return None

    params = parse_url_params(query)
    node.flow = params.get("flow", "")
    node.security = params.get("security", "tls")
    node.tls_enabled = node.security in ("tls", "reality")
    node.tls_server_name = params.get("sni", "") or params.get("host", "")
    node.tls_insecure = params.get("allowInsecure", "0") == "1"

    fp = params.get("fp", "")
    if fp:
        node.tls_utls_fingerprint = fp

    if params.get("pbk"):
        node.tls_reality_enabled = True
        node.tls_reality_public_key = params.get("pbk", "")
        node.tls_reality_short_id = params.get("sid", "")

    alpn = params.get("alpn", "")
    if alpn:
        node.tls_alpn = alpn.split(",")

    node.network = params.get("type", "tcp") or "tcp"
    transport = params.get("type", "tcp")

    if transport == "ws":
        node.transport_type = "ws"
        node.transport_path = params.get("path", "")
        host = params.get("host", "")
        if host:
            node.transport_host = [host]
    elif transport == "grpc":
        node.transport_type = "grpc"
        node.transport_service_name = params.get("serviceName", "grpc")
    elif transport == "h2" or transport == "http":
        node.transport_type = "http"
        node.transport_path = params.get("path", "")
        host = params.get("host", "")
        if host:
            node.transport_host = [h.strip() for h in host.split(",")]
    elif transport == "quic":
        node.transport_type = "quic"

    node.packet_encoding = params.get("packetEncoding", "xudp")

    if not node.tls_server_name:
        node.tls_server_name = params.get("host", "")

    return node


def parse_trojan(url: str) -> Optional[ProxyNode]:
    node = ProxyNode(type="trojan")
    raw = url[len("trojan://"):]
    main, _, fragment = raw.partition("#")
    node.tag = urllib.parse.unquote(fragment) if fragment else "trojan"

    userinfo, _, hostinfo = main.partition("@")
    node.password = urllib.parse.unquote(userinfo)

    if "?" in hostinfo:
        hostport, query = hostinfo.split("?", 1)
    else:
        hostport, query = hostinfo, ""

    if ":" in hostport:
        parts = hostport.rsplit(":", 1)
        node.server = parts[0]
        try:
            node.port = int(parts[1])
        except ValueError:
            return None
    else:
        return None

    params = parse_url_params(query)
    node.security = params.get("security", "tls")
    node.tls_enabled = node.security == "tls"
    node.tls_server_name = params.get("sni", "") or params.get("host", "")
    node.tls_insecure = params.get("allowInsecure", "0") == "1"

    fp = params.get("fp", "")
    if fp:
        node.tls_utls_fingerprint = fp

    alpn = params.get("alpn", "")
    if alpn:
        node.tls_alpn = alpn.split(",")

    node.network = params.get("type", "tcp") or "tcp"
    transport = params.get("type", "tcp")

    if transport == "ws":
        node.transport_type = "ws"
        node.transport_path = params.get("path", "")
        host = params.get("host", "")
        if host:
            node.transport_host = [host]
    elif transport == "grpc":
        node.transport_type = "grpc"
        node.transport_service_name = params.get("serviceName", "grpc")
    elif transport == "h2" or transport == "http":
        node.transport_type = "http"
        node.transport_path = params.get("path", "")
        host = params.get("host", "")
        if host:
            node.transport_host = [host]
    elif transport == "quic":
        node.transport_type = "quic"
    elif transport == "httpupgrade":
        node.transport_type = "httpupgrade"
        node.transport_path = params.get("path", "")
        host = params.get("host", "")
        if host:
            node.transport_host = [host]

    if not node.tls_server_name:
        node.tls_server_name = params.get("host", "")

    return node


def parse_shadowsocks(url: str) -> Optional[ProxyNode]:
    node = ProxyNode(type="shadowsocks")
    raw = url[len("ss://"):]
    main, _, fragment = raw.partition("#")
    node.tag = urllib.parse.unquote(fragment) if fragment else "ss"

    query = ""
    hostport = ""

    if "@" in main:
        userinfo, _, hostinfo = main.partition("@")
        decoded = urllib.parse.unquote(userinfo)
        try:
            decoded = b64_decode(decoded)
        except Exception:
            pass
        if ":" in decoded:
            node.method, node.password = decoded.split(":", 1)
        else:
            node.method = decoded
        if "?" in hostinfo:
            hostport, query = hostinfo.split("?", 1)
        else:
            hostport = hostinfo
    else:
        decoded = b64_decode(urllib.parse.unquote(main))
        if not decoded:
            return None
        if "@" in decoded:
            userinfo, _, hostport = decoded.partition("@")
            if ":" in userinfo:
                node.method, node.password = userinfo.split(":", 1)
            else:
                node.method = userinfo
        else:
            try:
                decoded_json = json.loads(decoded)
                return parse_shadowsocks_json(decoded_json, node.tag)
            except Exception:
                return None
        if "?" in main:
            _, query = main.rsplit("?", 1)

    if hostport and ":" in hostport:
        parts = hostport.rsplit(":", 1)
        node.server = parts[0]
        try:
            node.port = int(parts[1])
        except ValueError:
            return None

    params = parse_url_params(query)
    plugin = params.get("plugin", "")
    if plugin:
        node.plugin = plugin
        node.plugin_opts = params.get("plugin-opts", "")

    return node


def parse_shadowsocks_json(data: dict, tag: str = "ss") -> Optional[ProxyNode]:
    node = ProxyNode(type="shadowsocks")
    node.tag = tag
    node.server = data.get("server", "")
    node.port = int(data.get("server_port", 0))
    node.method = data.get("method", "")
    node.password = data.get("password", "")
    node.plugin = data.get("plugin", "")
    node.plugin_opts = data.get("plugin_opts", "")
    return node


def parse_hysteria2(url: str) -> Optional[ProxyNode]:
    node = ProxyNode(type="hysteria2")
    raw = url.replace("hysteria2://", "").replace("hy2://", "")
    main, _, fragment = raw.partition("#")
    node.tag = urllib.parse.unquote(fragment) if fragment else "hy2"

    userinfo, _, hostinfo = main.partition("@")
    node.password = urllib.parse.unquote(userinfo)

    if "?" in hostinfo:
        hostport, query = hostinfo.split("?", 1)
    else:
        hostport, query = hostinfo, ""

    if ":" in hostport:
        parts = hostport.rsplit(":", 1)
        node.server = parts[0]
        try:
            node.port = int(parts[1])
        except ValueError:
            return None

    params = parse_url_params(query)
    node.tls_enabled = True
    node.tls_server_name = params.get("sni", "")
    node.tls_insecure = params.get("insecure", "0") == "1"

    fp = params.get("obfs", "")
    if fp:
        node.obfs_type = "salamander"
        node.obfs_password = fp

    alpn = params.get("alpn", "")
    if alpn:
        node.tls_alpn = alpn.split(",")

    if params.get("up_mbps"):
        node.up_mbps = int(params["up_mbps"])
    if params.get("down_mbps"):
        node.down_mbps = int(params["down_mbps"])

    ports = params.get("mport", "") or params.get("ports", "")
    if ports:
        node.server_ports = [ports]

    return node


def parse_tuic(url: str) -> Optional[ProxyNode]:
    node = ProxyNode(type="tuic")
    raw = url[len("tuic://"):]
    main, _, fragment = raw.partition("#")
    node.tag = urllib.parse.unquote(fragment) if fragment else "tuic"

    userinfo, _, hostinfo = main.partition("@")
    userinfo = urllib.parse.unquote(userinfo)

    if ":" in userinfo:
        node.uuid, node.password = userinfo.split(":", 1)
    else:
        node.uuid = userinfo

    if "?" in hostinfo:
        hostport, query = hostinfo.split("?", 1)
    else:
        hostport, query = hostinfo, ""

    if ":" in hostport:
        parts = hostport.rsplit(":", 1)
        node.server = parts[0]
        try:
            node.port = int(parts[1])
        except ValueError:
            return None

    params = parse_url_params(query)
    if params.get("password") and not node.password:
        node.password = params["password"]
    node.congestion_control = params.get("congestion_control", "cubic")
    node.tls_enabled = True
    node.tls_server_name = params.get("sni", "")
    node.tls_insecure = params.get("allowInsecure", "0") == "1"

    alpn = params.get("alpn", "")
    if alpn:
        node.tls_alpn = alpn.split(",")

    return node


def parse_wireguard(url: str) -> Optional[ProxyNode]:
    node = ProxyNode(type="wireguard")
    raw = url[len("wireguard://"):]
    main, _, fragment = raw.partition("#")
    node.tag = urllib.parse.unquote(fragment) if fragment else "wg"

    if "?" in main:
        hostpart, query = main.split("?", 1)
    else:
        hostpart, query = main, ""

    parts = hostpart.split("@")
    if len(parts) >= 2:
        node.uuid = parts[0]
        host_port = parts[1]
        if ":" in host_port:
            host, port = host_port.rsplit(":", 1)
            node.server = host
            try:
                node.port = int(port)
            except ValueError:
                pass

    params = parse_url_params(query)
    if params.get("privateKey"):
        node.password = params["privateKey"]
    if params.get("peerPublicKey"):
        node.uuid = params["peerPublicKey"]

    return node


def parse_proxy_url(url: str) -> Optional[ProxyNode]:
    url = url.strip()
    if url.startswith("vmess://"):
        return parse_vmess(url)
    elif url.startswith("vless://"):
        return parse_vless(url)
    elif url.startswith("trojan://"):
        return parse_trojan(url)
    elif url.startswith("ss://"):
        return parse_shadowsocks(url)
    elif url.startswith("hysteria2://") or url.startswith("hy2://"):
        return parse_hysteria2(url)
    elif url.startswith("tuic://"):
        return parse_tuic(url)
    elif url.startswith("wireguard://") or url.startswith("wg://"):
        return parse_wireguard(url)
    return None


def build_outbound(node: ProxyNode) -> dict:
    ob = {}
    ob["type"] = node.type
    ob["tag"] = node.tag
    ob["server"] = node.server
    ob["server_port"] = node.port

    if node.type == "vmess":
        ob["uuid"] = node.uuid
        ob["security"] = node.security
        ob["alter_id"] = node.alter_id
        ob["global_padding"] = False
        ob["authenticated_length"] = True
        ob["network"] = node.network
        ob["packet_encoding"] = node.packet_encoding or ""

    elif node.type == "vless":
        ob["uuid"] = node.uuid
        if node.flow:
            ob["flow"] = node.flow
        ob["network"] = node.network
        ob["packet_encoding"] = node.packet_encoding or "xudp"

    elif node.type == "trojan":
        ob["password"] = node.password
        ob["network"] = node.network

    elif node.type == "shadowsocks":
        ob["method"] = node.method
        ob["password"] = node.password
        ob["network"] = node.network or "tcp"
        if node.plugin:
            ob["plugin"] = node.plugin
            ob["plugin_opts"] = node.plugin_opts

    elif node.type == "hysteria2":
        ob["password"] = node.password
        if node.up_mbps:
            ob["up_mbps"] = node.up_mbps
        if node.down_mbps:
            ob["down_mbps"] = node.down_mbps
        if node.obfs_type:
            ob["obfs"] = {"type": node.obfs_type, "password": node.obfs_password}
        if node.server_ports:
            ob["server_ports"] = node.server_ports

    elif node.type == "hysteria":
        ob["auth_str"] = node.password
        if node.up_mbps:
            ob["up_mbps"] = node.up_mbps
        if node.down_mbps:
            ob["down_mbps"] = node.down_mbps
        if node.obfs_password:
            ob["obfs"] = node.obfs_password

    elif node.type == "tuic":
        ob["uuid"] = node.uuid
        if node.password:
            ob["password"] = node.password
        ob["congestion_control"] = node.congestion_control
        ob["udp_relay_mode"] = "native"
        ob["zero_rtt_handshake"] = False
        ob["heartbeat"] = "10s"

    elif node.type == "wireguard":
        ob["local_address"] = ["10.0.0.2/32"]
        ob["private_key"] = node.password
        ob["peer_public_key"] = node.uuid
        ob["reserved"] = [0, 0, 0]
        ob["mtu"] = 1408

    tls = {}
    if node.tls_enabled:
        tls["enabled"] = True
        if node.tls_server_name:
            tls["server_name"] = node.tls_server_name
        if node.tls_insecure:
            tls["insecure"] = True
        if node.tls_alpn:
            tls["alpn"] = node.tls_alpn
        if node.tls_utls_fingerprint:
            tls["utls"] = {"enabled": True, "fingerprint": node.tls_utls_fingerprint}
        if node.tls_reality_enabled:
            tls["reality"] = {
                "enabled": True,
                "public_key": node.tls_reality_public_key,
                "short_id": node.tls_reality_short_id,
            }

    if tls and node.type not in ("hysteria2", "hysteria", "tuic"):
        ob["tls"] = tls
    elif node.type in ("hysteria2", "hysteria", "tuic"):
        if tls:
            ob["tls"] = tls
        else:
            ob["tls"] = {"enabled": True}

    transport = {}
    if node.transport_type:
        transport["type"] = node.transport_type
        if node.transport_type == "ws":
            if node.transport_path:
                transport["path"] = node.transport_path
            if node.transport_host:
                transport["headers"] = {"Host": node.transport_host[0]}
        elif node.transport_type == "grpc":
            transport["service_name"] = node.transport_service_name or "grpc"
        elif node.transport_type == "http":
            if node.transport_host:
                transport["host"] = node.transport_host
            if node.transport_path:
                transport["path"] = node.transport_path
        elif node.transport_type == "httpupgrade":
            if node.transport_host:
                transport["host"] = node.transport_host[0]
            if node.transport_path:
                transport["path"] = node.transport_path

    if transport and node.type in ("vmess", "vless", "trojan"):
        ob["transport"] = transport

    return ob


def build_singbox_config(
    outbounds: list,
    listen: str = "127.0.0.1",
    mixed_port: int = 2080,
    tun_enabled: bool = False,
    dns_servers: list = None,
    experimental: bool = True,
) -> dict:
    proxy_tags = [ob["tag"] for ob in outbounds]
    auto_outbounds = [t for t in proxy_tags if t not in ("direct", "block", "dns-out")]

    config = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "google", "address": "tls://8.8.8.8", "detour": "select"},
                {"tag": "local", "address": "223.5.5.5", "detour": "direct"},
            ],
            "rules": [
                {"outbound": ["any"], "server": "local"},
            ],
            "final": "google",
            "strategy": "prefer_ipv4",
            "optimistic": True,
            "reverse_mapping": True,
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": listen,
                "listen_port": mixed_port,
                "set_system_proxy": False,
            }
        ],
        "outbounds": [
            {
                "type": "selector",
                "tag": "select",
                "outbounds": ["auto"] + auto_outbounds + ["direct"],
                "default": "auto",
            },
        ] + outbounds + [
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {"type": "dns", "tag": "dns-out"},
        ],
        "route": {
            "rules": [
                {"ip_is_private": True, "outbound": "direct"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"action": "route", "outbound": "select"},
            ],
            "final": "select",
            "auto_detect_interface": True,
        },
    }

    if auto_outbounds:
        config["outbounds"].insert(1, {
            "type": "urltest",
            "tag": "auto",
            "outbounds": auto_outbounds,
            "url": "https://www.gstatic.com/generate_204",
            "interval": "3m",
            "tolerance": 50,
            "idle_timeout": "30m",
        })

    if tun_enabled:
        config["inbounds"].insert(0, {
            "type": "tun",
            "tag": "tun-in",
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": 9000,
            "auto_route": True,
            "strict_route": True,
            "stack": "system",
            "dns_mode": "hijack",
            "dns_address": ["172.19.0.2", "fdfe:dcba:9876::2"],
        })

    if experimental:
        config["experimental"] = {
            "cache_file": {"enabled": True, "path": "cache.db", "store_dns": True},
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "access_control_allow_origin": ["*"],
                "access_control_allow_private_network": True,
            },
        }

    if dns_servers:
        config["dns"]["servers"] = dns_servers

    return config


def convert_from_url_list(
    urls: list,
    listen: str = "127.0.0.1",
    mixed_port: int = 2080,
    tun_enabled: bool = False,
    output: str = "",
) -> dict:
    outbounds = []
    errors = []
    seen_tags = set()

    for url in urls:
        url = url.strip()
        if not url or url.startswith("#"):
            continue
        node = parse_proxy_url(url)
        if node is None:
            errors.append(f"Failed to parse: {url[:80]}...")
            continue

        ob = build_outbound(node)

        tag = ob["tag"]
        base_tag = tag
        counter = 1
        while tag in seen_tags:
            tag = f"{base_tag}-{counter}"
            counter += 1
        ob["tag"] = tag
        seen_tags.add(tag)

        outbounds.append(ob)

    if errors:
        print(f"Warnings ({len(errors)} failed):", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)

    config = build_singbox_config(
        outbounds=outbounds,
        listen=listen,
        mixed_port=mixed_port,
        tun_enabled=tun_enabled,
    )

    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        print(f"Written to {output} ({len(outbounds)} outbounds)", file=sys.stderr)
    else:
        print(json.dumps(config, indent=2, ensure_ascii=False))

    return config


def convert_from_file(
    filepath: str,
    listen: str = "127.0.0.1",
    mixed_port: int = 2080,
    tun_enabled: bool = False,
    output: str = "",
) -> dict:
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read().strip()

    lines = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("http://") or line.startswith("https://"):
            try:
                import urllib.request
                resp = urllib.request.urlopen(line, timeout=10)
                data = resp.read().decode("utf-8")
                decoded = b64_decode(data.strip())
                if decoded:
                    for subline in decoded.splitlines():
                        subline = subline.strip()
                        if subline:
                            lines.append(subline)
                else:
                    for subline in data.splitlines():
                        subline = subline.strip()
                        if subline:
                            lines.append(subline)
            except Exception as e:
                print(f"Failed to fetch {line}: {e}", file=sys.stderr)
            continue
        if re.match(r"^[a-z]+://", line):
            lines.append(line)

    return convert_from_url_list(lines, listen, mixed_port, tun_enabled, output)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Convert proxy subscription URLs to sing-box client config"
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Input file with proxy URLs (one per line) or a single subscription URL",
    )
    parser.add_argument("-o", "--output", default="", help="Output JSON file path")
    parser.add_argument("--listen", default="127.0.0.1", help="Listen address")
    parser.add_argument("--port", type=int, default=2080, help="Mixed proxy port")
    parser.add_argument("--tun", action="store_true", help="Enable TUN inbound")
    args = parser.parse_args()

    if args.input:
        convert_from_file(
            args.input,
            listen=args.listen,
            mixed_port=args.port,
            tun_enabled=args.tun,
            output=args.output,
        )
    else:
        print("Reading from stdin... (Ctrl+D to finish)", file=sys.stderr)
        content = sys.stdin.read().strip()
        lines = [l.strip() for l in content.splitlines() if l.strip()]
        convert_from_url_list(
            lines,
            listen=args.listen,
            mixed_port=args.port,
            tun_enabled=args.tun,
            output=args.output,
        )


if __name__ == "__main__":
    main()
