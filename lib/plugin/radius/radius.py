import time
from framework.log.logger import log
from lib.plugin.radius.models.peap_config import LauncherScriptConfig
from lib.plugin.radius.radius_base import RadiusBase


class Radius(RadiusBase):

    def exec_cmd(self, command: str, timeout: int = 15) -> str:
        return self.platform.exec_command(command, timeout)

    def dot1x_plugin_running(self) -> bool:
        log.info("Checking if 802.1X plugin is running on RADIUS server")
        status_output = self.exec_cmd("fstool dot1x status")
        if "is running" in status_output:
            log.info("RADIUS server is running")
            return True
        else:
            log.error("RADIUS server is not running")
            return False

    def restart_dot1x_plugin(self, timeout: int = 60, interval: int = 5) -> None:
        log.info("Restarting 802.1X plugin on RADIUS server")
        self.exec_cmd("fstool dot1x restart")
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.dot1x_plugin_running():
                log.info("802.1X plugin restarted successfully and is running")
                return
            log.info(f"Waiting for plugin to start... Retrying in {interval} seconds")
            time.sleep(interval)

        log.error("802.1X plugin failed to restart within the timeout period")

    def render_peap_configuration_launcher_script(self, passthrough, config: LauncherScriptConfig) -> str:
        """
        Render the PowerShell launcher script that will execute the PEAP configuration script.

        Args:
            passthrough: WindowsPassthrough instance for accessing credentials
            config: LauncherScriptConfig object containing all script parameters

        Returns:
            Rendered script content
        """
        # Use PEAP credentials if provided, otherwise use Windows credentials
        peap_user = config.peap_username if config.peap_username else passthrough.username
        peap_pass = config.peap_password if config.peap_password else passthrough.password

        # Render the launcher script template
        # PsExec uses Windows credentials (passthrough.username/password)
        # PowerShell script receives PEAP credentials (peap_user/peap_pass)
        template = (
            f"{config.psexec_path} -accepteula -u \"{passthrough.username}\" -p \"{passthrough.password}\" "
            f"-i {config.session_id} -h -d powershell.exe -ExecutionPolicy {config.execution_policy} "
            f"-File \"{config.scripts_path}\\{config.peap_script_filename}\" "
            f"-username \"{peap_user}\" "
            f"-password \"{peap_pass}\" "
            f"-nicname \"{config.nicname}\" "
            f"-logfile \"{config.logs_path}\\{config.log_filename}\""
        )
        return template


