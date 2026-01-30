"""
Configuration dataclasses for RADIUS PEAP setup.
"""
from dataclasses import dataclass
from pathlib import Path

from lib.passthrough.enums import AuthNicProfile


@dataclass
class PEAPCredentialsConfig:
    """
    Configuration for PEAP credentials setup on Windows endpoint.

    Usage:
        config = PEAPCredentialsConfig()  # Uses all defaults
        config = PEAPCredentialsConfig(auth_nic_profile=AuthNicProfile.EAP_TLS)
    """
    # Remote Windows paths
    scripts_path: str = r'C:\Scripts'
    logs_path: str = r'C:\Logs'
    pstools_path: str = r'C:\PSTools'
    profiles_path: str = r'C:\Profiles'

    # Script/execution configuration
    peap_script_filename: str = 'radius_nic_PEAP_credentials_config.ps1'
    execution_policy: str = 'Bypass'
    auth_nic_profile: AuthNicProfile = AuthNicProfile.PEAP
    nicname: str = 'pciPassthru0'

    # PEAP credentials
    peap_domain: str = 'txqalab'
    peap_user: str = 'dotonex'
    peap_password: str = 'aristo'

    @property
    def lan_profile_filename(self) -> str:
        return self.auth_nic_profile.value

    @property
    def psexec_path(self) -> str:
        return f'{self.pstools_path}\\PsExec.exe'

    @property
    def peap_username(self) -> str:
        """Full PEAP username in domain\\user format."""
        return f'{self.peap_domain}\\{self.peap_user}' if self.peap_domain else self.peap_user

    @property
    def local_script_path(self) -> str:
        return _find_resource(self.peap_script_filename)

    @property
    def local_lan_profile_path(self) -> str:
        return _find_resource(self.lan_profile_filename)

    def validate(self):
        """Validate that required files exist."""
        if not Path(self.local_script_path).exists():
            raise FileNotFoundError(f"PEAP script not found: {self.local_script_path}")


@dataclass
class LauncherScriptConfig:
    """Configuration for rendering the PEAP launcher script."""
    session_id: str
    log_filename: str
    psexec_path: str
    execution_policy: str
    scripts_path: str
    peap_script_filename: str
    nicname: str
    logs_path: str
    peap_username: str
    peap_password: str

    @classmethod
    def from_peap_config(cls, config: 'PEAPCredentialsConfig', session_id: str,
                         log_filename: str) -> 'LauncherScriptConfig':
        """Create from PEAPCredentialsConfig."""
        return cls(
            session_id=session_id,
            log_filename=log_filename,
            psexec_path=config.psexec_path,
            execution_policy=config.execution_policy,
            scripts_path=config.scripts_path,
            peap_script_filename=config.peap_script_filename,
            nicname=config.nicname,
            logs_path=config.logs_path,
            peap_username=config.peap_username,
            peap_password=config.peap_password
        )


# =============================================================================
# Private: Resource path utilities
# =============================================================================

_PROJECT_ROOT = Path(__file__).resolve().parents[4]
_SCRIPTS_DIR = _PROJECT_ROOT / 'scripts'
_RESOURCES_DIR = _PROJECT_ROOT / 'resources'
_NIC_PROFILES_DIR = _RESOURCES_DIR / 'radius' / 'nic_profiles'


def _find_resource(filename: str) -> str:
    for directory in [_SCRIPTS_DIR, _RESOURCES_DIR, _NIC_PROFILES_DIR]:
        path = directory / filename
        if path.exists():
            return str(path)
    return str(_SCRIPTS_DIR / filename)

