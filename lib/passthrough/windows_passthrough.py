from framework.log.logger import log
from lib.passthrough.passthrough_base import PassthroughBase
import winrm


class WindowsPassthrough(PassthroughBase):
    def __init__(self, ip: str, user_name: str, password: str, mac: str) -> None:
        super().__init__(ip, user_name, password, mac)
        self.session = winrm.Session(self.ip, auth=(self.username, self.password), transport='ntlm')

    def execute_command(self, command, is_ps=True):
        try:
            log.info(f"Executing command on WindowsPassthrough: {command}")
            out = self.session.run_ps(command) if is_ps else self.session.run_cmd(command)
        except Exception as e:
            raise RuntimeError(f"Failed to execute command '{command}': {str(e)}")
        stdout = out.std_out.decode("utf-8", errors="replace").strip()
        stderr = out.std_err.decode("utf-8", errors="replace").strip()

        rc = out.status_code
        ok = (rc == 0)

        if not ok:
            msg = f"Command failed (code={rc})\nSTDERR:\n{stderr or '<empty>'}\n"
            raise RuntimeError(msg)
        return stdout
