"""
Configuration dataclasses for RADIUS PEAP setup.
"""
from dataclasses import dataclass
import os


@dataclass
class PEAPCredentialsConfig:
    """
    Configuration for PEAP credentials setup on Windows endpoint.

    This class encapsulates all parameters needed for PEAP credentials configuration,
    making method signatures cleaner and configuration easier to manage.

    Most parameters have sensible defaults and only need to be overridden for special cases.

    Usage:
        # Minimal - uses all defaults
        config = PEAPCredentialsConfig()

        # Override specific values
        config = PEAPCredentialsConfig(nicname='Wi-Fi', peap_username='domain\\\\user')
    """
    # Remote paths (defaults to standard locations)
    scripts_path: str = r'C:\Scripts'
    logs_path: str = r'C:\Logs'
    pstools_path: str = r'C:\PSTools'

    # Script configuration (defaults provided)
    peap_script_filename: str = 'radius_nic_PEAP_credentials_config.ps1'
    execution_policy: str = 'Bypass'

    # Network configuration (default NIC name)
    nicname: str = 'pciPassthru0'

    # PEAP authentication credentials (defaults for txqalab environment)
    peap_domain: str = 'txqalab'
    peap_user: str = 'dotonex'
    peap_password: str = 'aristo'

    # Local script path (auto-detected if not provided)
    local_script_path: str = None

    @property
    def psexec_path(self) -> str:
        """Full path to PsExec.exe."""
        return os.path.join(self.pstools_path, 'PsExec.exe')

    @property
    def peap_username(self) -> str:
        """Full PEAP username in domain\\user format."""
        return f'{self.peap_domain}\\{self.peap_user}'

    def __post_init__(self):
        """Initialize and validate configuration."""
        # Auto-detect local script path if not provided
        if not self.local_script_path:
            self.local_script_path = self._find_script_path()

    def _find_script_path(self) -> str:
        """Find the PEAP script in the project's scripts directory."""
        possible_paths = [
            # From current working directory
            os.path.join(os.getcwd(), 'scripts', self.peap_script_filename),
            # From project root (detected by markers)
            os.path.join(self._find_project_root(), 'scripts', self.peap_script_filename),
        ]

        for path in possible_paths:
            if os.path.exists(path):
                return path

        # Return default path even if not found (validation happens at runtime)
        return possible_paths[0]

    @staticmethod
    def _find_project_root() -> str:
        """
        Find the project root directory by looking for known project markers.

        Searches upward from the current file's location for directories containing
        typical project root markers like pyproject.toml, setup.py, or .git.
        """
        markers = ['pyproject.toml', 'setup.py', '.git', 'requirements.txt']

        current_dir = os.path.dirname(os.path.abspath(__file__))

        # Walk up the directory tree
        while current_dir != os.path.dirname(current_dir):  # Stop at filesystem root
            for marker in markers:
                if os.path.exists(os.path.join(current_dir, marker)):
                    return current_dir
            current_dir = os.path.dirname(current_dir)

        # Fallback to current working directory
        return os.getcwd()

    def validate(self):
        """Validate that all required files exist. Call before use."""
        if not os.path.exists(self.local_script_path):
            raise FileNotFoundError(f"PEAP script not found: {self.local_script_path}")


@dataclass
class LauncherScriptConfig:
    """
    Configuration for rendering the PEAP launcher script.

    This dataclass holds all parameters needed to render the PowerShell launcher
    script that executes PsExec with the PEAP configuration script.
    """
    session_id: str
    log_filename: str
    psexec_path: str = None
    execution_policy: str = 'Bypass'
    scripts_path: str = r'C:\Scripts'
    peap_script_filename: str = 'radius_nic_PEAP_credentials_config.ps1'
    nicname: str = 'pciPassthru0'
    logs_path: str = r'C:\Logs'
    peap_username: str = None
    peap_password: str = None

    @classmethod
    def from_peap_config(cls, peap_config: 'PEAPCredentialsConfig', session_id: str,
                         log_filename: str) -> 'LauncherScriptConfig':
        """
        Create LauncherScriptConfig from PEAPCredentialsConfig.

        Args:
            peap_config: PEAPCredentialsConfig to copy values from
            session_id: Windows session ID for the script
            log_filename: Log file name for script output

        Returns:
            LauncherScriptConfig with values from peap_config
        """
        return cls(
            session_id=session_id,
            log_filename=log_filename,
            psexec_path=peap_config.psexec_path,
            execution_policy=peap_config.execution_policy,
            scripts_path=peap_config.scripts_path,
            peap_script_filename=peap_config.peap_script_filename,
            nicname=peap_config.nicname,
            logs_path=peap_config.logs_path,
            peap_username=peap_config.peap_username,
            peap_password=peap_config.peap_password
        )
