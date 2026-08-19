# -*- coding: utf-8 -*-
"""TLS record/handshake parsing (ClientHello / ServerHello) + JA3."""
import hashlib

# GREASE values per RFC 8701 - excluded from JA3 per convention
GREASE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}


def _dedupe_grease(values):
    return [v for v in values if v not in GREASE]


def build_ja3(version_int, ciphers, ext_types, groups, ec_formats):
    try:
        c = "-".join(str(x) for x in _dedupe_grease(ciphers))
        e = "-".join(str(x) for x in _dedupe_grease(ext_types))
        g = "-".join(str(x) for x in _dedupe_grease(groups))
        f = "-".join(str(x) for x in ec_formats)
        ja3_str = f"{version_int},{c},{e},{g},{f}"
        return hashlib.md5(ja3_str.encode()).hexdigest(), ja3_str
    except Exception:
        return None, None


def parse_client_hello(b):
    try:
        i = 0
        client_version = int.from_bytes(b[i:i + 2], "big")
        i += 2
        i += 32  # random
        sess_len = b[i]
        i += 1 + sess_len
        cs_len = int.from_bytes(b[i:i + 2], "big")
        i += 2
        cipher_suites = [int.from_bytes(b[i + j:i + j + 2], "big") for j in range(0, cs_len, 2)]
        i += cs_len
        comp_len = b[i]
        i += 1 + comp_len

        sni = None
        alpn = []
        groups = []
        ec_formats = []
        ext_types = []

        if i + 2 <= len(b):
            ext_total = int.from_bytes(b[i:i + 2], "big")
            i += 2
            end = min(i + ext_total, len(b))
            while i + 4 <= end:
                etype = int.from_bytes(b[i:i + 2], "big")
                elen = int.from_bytes(b[i + 2:i + 4], "big")
                edata = b[i + 4:i + 4 + elen]
                ext_types.append(etype)
                if etype == 0x00 and len(edata) > 5:
                    name_len = int.from_bytes(edata[3:5], "big")
                    sni = edata[5:5 + name_len].decode("utf-8", errors="ignore")
                elif etype == 0x10 and len(edata) > 2:  # ALPN
                    pos = 2
                    while pos < len(edata):
                        plen = edata[pos]
                        pos += 1
                        alpn.append(edata[pos:pos + plen].decode("utf-8", errors="ignore"))
                        pos += plen
                elif etype == 0x0a and len(edata) > 2:  # supported_groups
                    vals = edata[2:]
                    groups = [int.from_bytes(vals[k:k + 2], "big") for k in range(0, len(vals) - 1, 2)]
                elif etype == 0x0b and len(edata) > 1:  # ec_point_formats
                    ec_formats = list(edata[1:])
                i += 4 + elen

        ja3, ja3_str = build_ja3(client_version, cipher_suites, ext_types, groups, ec_formats)
        return {
            "type": "ClientHello",
            "version": client_version,
            "ciphers": cipher_suites,
            "sni": sni,
            "alpn": alpn,
            "ja3": ja3,
            "ja3_str": ja3_str,
        }
    except Exception:
        return None


def parse_server_hello(b):
    try:
        i = 0
        version = int.from_bytes(b[i:i + 2], "big")
        i += 2
        i += 32
        sess_len = b[i]
        i += 1 + sess_len
        cipher = int.from_bytes(b[i:i + 2], "big")
        i += 2
        alpn = None
        i += 1  # compression method
        if i + 2 <= len(b):
            ext_total = int.from_bytes(b[i:i + 2], "big")
            i += 2
            end = min(i + ext_total, len(b))
            while i + 4 <= end:
                etype = int.from_bytes(b[i:i + 2], "big")
                elen = int.from_bytes(b[i + 2:i + 4], "big")
                edata = b[i + 4:i + 4 + elen]
                if etype == 0x10 and len(edata) > 2:
                    pos = 2
                    if pos < len(edata):
                        plen = edata[pos]
                        pos += 1
                        alpn = edata[pos:pos + plen].decode("utf-8", errors="ignore")
                i += 4 + elen
        return {"type": "ServerHello", "version": version, "cipher": cipher, "alpn": alpn}
    except Exception:
        return None


TLS_VERSION_NAMES = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


def tls_version_name(v):
    return TLS_VERSION_NAMES.get(v, f"0x{v:04x}")


def parse_tls_record(payload):
    """Parse the first handshake message in a single TLS record. Returns dict or None."""
    if len(payload) < 5 or payload[0] != 0x16:
        return None
    rec_len = int.from_bytes(payload[3:5], "big")
    body = payload[5:5 + rec_len]
    if len(body) < 4:
        return None
    hs_type = body[0]
    hs_len = int.from_bytes(body[1:4], "big")
    hs_body = body[4:4 + hs_len]
    if hs_type == 0x01:
        return parse_client_hello(hs_body)
    elif hs_type == 0x02:
        return parse_server_hello(hs_body)
    return None
