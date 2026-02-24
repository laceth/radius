"""
Configuration dataclasses for RADIUS MAB (MAC Authentication Bypass) setup.
"""
from dataclasses import dataclass
from pathlib import Path

from lib.passthrough.enums import AuthNicProfile


@dataclass
class MABConfig:
    """
    Configuration for MAB (MAC Authentication Bypass) setup on Windows endpoint.

    MAB is used for endpoints that don't have 802.1X supplicants.
    The switch authenticates the endpoint based on its MAC address.

    Usage:
        config = MABConfig()  # Uses all defaults
    """
    # Remote Windows paths
    profiles_path: str = r'C:\Profiles'

    # NIC configuration
    auth_nic_profile: AuthNicProfile = AuthNicProfile.MAB
    nicname: str = 'pciPassthru0'

    @property
    def lan_profile_filename(self) -> str:
        return self.auth_nic_profile.value

    @property
    def local_lan_profile_path(self) -> str:
        return _find_resource(self.lan_profile_filename)


def _find_resource(filename: str) -> str:
    """
    Find resource file in known locations.
    Searches in order: nic_profiles directory, scripts directory.
    """
    # Try nic_profiles first (for LAN profile XMLs)
    nic_profiles_path = Path(__file__).parent.parent.parent.parent.parent / 'resources' / 'radius' / 'nic_profiles' / filename
    if nic_profiles_path.exists():
        return str(nic_profiles_path)

    # Try scripts directory
    scripts_path = Path(__file__).parent.parent.parent.parent.parent / 'scripts' / filename
    if scripts_path.exists():
        return str(scripts_path)

    raise FileNotFoundError(f"Resource not found: {filename}")

