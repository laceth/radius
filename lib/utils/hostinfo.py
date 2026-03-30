"""
Utilities for parsing ``fstool hostinfo`` output lines.

The ``fstool hostinfo <id> | grep <field>,`` command produces lines of the form::

    <host_id>, <timestamp>, <field_name>, <value>, (<plugin>@…), …

These helpers are used by the CA property-check layer and can be reused by
anything else that reads hostinfo output (e.g. log parsers, diagnostic scripts).
"""
from typing import Optional


def parse_property_value(output: str) -> Optional[str]:
    """
    Parse the value field out of a ``fstool hostinfo … | grep <field>,`` line.

    Forescout renders an empty/blank property value as ``???`` in hostinfo output.
    This function normalises that sentinel to ``""`` so callers always receive
    ``""`` for empty and ``None`` for truly absent / irresolvable.

    Args:
        output: Raw stdout line from ``fstool hostinfo <id> | grep <field>,``.
                May be an empty string when grep found no match.

    Returns:
        ``""``   – property resolved but empty (Forescout returned ``???``)
        ``str``  – the resolved, non-empty value
        ``None`` – property not present in output (grep returned nothing)

    Example::

        >>> parse_property_value(
        ...     "10.0.0.1, 0,Thu Jan 01 00:00:00 UTC 1970, dot1x_mar_comment, ???, (dot1x@123)"
        ... )
        ''
        >>> parse_property_value(
        ...     "10.0.0.1, 0,Thu Jan 01 00:00:00 UTC 1970, dot1x_mar_comment, 802.1x Authorization, (dot1x@123)"
        ... )
        '802.1x Authorization'
        >>> parse_property_value("") is None
        True
    """
    parts = output.split(", ")
    if len(parts) <= 3:
        return None
    raw = parts[3]
    return "" if raw == "???" else raw

