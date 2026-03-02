"""
Configuration dataclasses for RADIUS MAB (MAC Authentication Bypass) setup.
"""
from dataclasses import dataclass


@dataclass
class MABConfig:
    """
    Configuration for MAB (MAC Authentication Bypass) setup on Windows endpoint.

    MAB is used for endpoints that don't have 802.1X supplicants.
    The switch authenticates the endpoint based on its MAC address.

    Usage:
        config = MABConfig()
    """
    # Remote Windows paths
    profiles_path: str = r'C:\Profiles'

    # NIC configuration
    nicname: str = 'pciPassthru0'


