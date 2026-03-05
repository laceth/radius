import re


def normalize_mac(mac: str) -> str:
    """
    Normalize a MAC address to bare lowercase hex (e.g. ``98f2b301a055``).

    Accepts any common delimiter format: colons, dashes, dots, or none.
    ``fstool devinfo`` uses this format as the record key.
    """
    return re.sub(r'[-:.]', '', mac).replace('0x', '').lower()

