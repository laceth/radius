from framework.log.logger import log
import time


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
            last_exc = None
            for attempt in range(3):
                try:
                    self._pools[key] = creator()
                    break
                except Exception as e:
                    last_exc = e
                    if attempt < 2:
                        wait = 5 * (attempt + 1)  # 5s then 10s
                        log.warning(
                            f"[POOL] Connection creation failed for key {key!r} "
                            f"(attempt {attempt + 1}/3), retrying in {wait}s: {e!r}"
                        )
                        time.sleep(wait)
                    else:
                        raise last_exc
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
