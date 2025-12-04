from abc import abstractmethod
from framework.connection.connection_client import ConnectionClientBase


class WinRMClient(ConnectionClientBase):
    @abstractmethod
    def get_conn_key(self):
        """Unique key for the connection in the pool."""
        pass

    @abstractmethod
    def _create_connection(self):
        """Create and return the underlying connection object."""
        pass

    @abstractmethod
    def _execute(self, cmd, timeout=30):
        """Run the command using the internal connection."""
        pass

    @abstractmethod
    def exec_command(self, cmd, timeout=30):
        """Acquire connection from pool, execute command, and return result."""
        pass
