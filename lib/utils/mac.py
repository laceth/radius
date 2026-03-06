import random
import re


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


