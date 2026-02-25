from framework.log.logger import log


class ConnectionPool:
    def __init__(self):
        self._pools = {}

    def get(self, key, creator=None):
        """Get a connection from the pool by key. If the connection is not alive, it will be removed and recreated."""
        if key in self._pools:
            connection = self._pools[key]
            try:
                # TODO: compromised way to check if connection is alive, better way is to abstract connections
                if hasattr(connection, "is_alive"):
                    # Netmiko connection
                    if not connection.is_alive():
                        connection.disconnect()
                        raise ConnectionError("Netmiko connection is down")
                elif hasattr(connection, "get_transport"):
                    # Paramiko connection
                    if not connection.get_transport() or not connection.get_transport().is_active():
                        connection.close()
                        raise ConnectionError("Paramiko connection is down")
                else:
                    raise TypeError("Unsupported connection type")
            except ConnectionError:
                del self._pools[key]
                log.info(f"[POOL] Removed broken connection for key: {key}")
        if key not in self._pools:
            if creator is None:
                raise ValueError(f"No connection for key: {key} and no creator provided")
            log.debug(f"[POOL] Creating connection for key: {key}")
            self._pools[key] = creator()
        return self._pools[key]

    def close_all(self):
        log.info("Closing all connections")
        for conn in self._pools.values():
            try:
                conn.close()
            except Exception:
                pass
        self._pools.clear()


CONNECTION_POOL = ConnectionPool()
