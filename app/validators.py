"""Format validation for user-supplied fields that feed subprocess arguments
(nmap host/port-range) or outbound network calls (Palo Alto hostname) —
narrow, targeted checks, not a general-purpose form-validation framework."""
import re
import ipaddress

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_PORT_RANGE_RE = re.compile(r"^[\d\s,\-]+$")


def is_valid_host(value):
    """Accept an IP address, a CIDR network (subnet-type targets scan a whole
    range), or an RFC-1123-shaped hostname/domain."""
    value = (value or "").strip()
    if not value or len(value) > 253:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(value))


def is_valid_port_range(value):
    """Accept nmap-style port specs: '1-1024', '22,80,443', '1-100,443', etc."""
    value = (value or "").strip()
    if not value or len(value) > 200 or not _PORT_RANGE_RE.match(value):
        return False
    for part in value.split(","):
        part = part.strip()
        if not part:
            return False
        if "-" in part:
            lo, _, hi = part.partition("-")
            lo, hi = lo.strip(), hi.strip()
            if not (lo.isdigit() and hi.isdigit()):
                return False
            lo, hi = int(lo), int(hi)
            if not (0 <= lo <= 65535 and 0 <= hi <= 65535 and lo <= hi):
                return False
        else:
            if not part.isdigit() or not (0 <= int(part) <= 65535):
                return False
    return True
