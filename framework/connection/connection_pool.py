from framework.log.logger import log


class ConnectionPool:
    def __init__(self):
        self._pools = {}

    def get(self, key, creator=None):
        if key in self._pools:
            connection = self._pools[key]
            try:
                if not connection.is_alive():
                    log.debug(f"[POOL] Connection for key: {key} is down. Reconnecting...")
                    connection.close()
                    raise Exception("Connection is down")
            except Exception:
                del self._pools[key]
                log.debug(f"[POOL] Removed broken connection for key: {key}")

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
