import random
import re

# Matches common MAC formats: aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff, aabbccddeeff
_MAC_RE = re.compile(r'^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$|^[0-9a-fA-F]{12}$')


def is_valid_mac(value: str) -> bool:
    """Return True if *value* looks like a MAC address.

    Accepts colon-separated (``aa:bb:cc:dd:ee:ff``), dash-separated
    (``aa-bb-cc-dd-ee-ff``), or bare 12-hex-char (``aabbccddeeff``) formats.

    Example::

        >>> is_valid_mac("aa:bb:cc:dd:ee:ff")
        True
        >>> is_valid_mac("not-a-mac")
        False
    """
    return bool(_MAC_RE.match(value))


def normalize_mac(mac: str) -> str:
    """
    Normalize a MAC address to bare lowercase hex (e.g. ``98f2b301a055``).

    Accepts any common delimiter format: colons, dashes, dots, or none.
    ``fstool devinfo`` uses this format as the record key.
    """
    return re.sub(r'[-:.]', '', mac).replace('0x', '').lower()


def generate_random_mac() -> str:
    """Generate a random MAC address as bare lowercase hex (12 chars).

    Example::

        >>> generate_random_mac()
        'a1b2c3d4e5f6'
    """
    return "".join(f"{random.randint(0, 255):02x}" for _ in range(6))


def generate_unique_random_macs(count: int) -> list[str]:
    """Generate *count* unique random MAC addresses as bare lowercase hex.

    Example::

        >>> generate_unique_random_macs(3)
        ['a1b2c3d4e5f6', '112233445566', 'deadbeef0123']
    """
    seen: set[str] = set()
    macs: list[str] = []
    while len(macs) < count:
        mac = generate_random_mac()
        if mac not in seen:
            seen.add(mac)
            macs.append(mac)
    return macs


