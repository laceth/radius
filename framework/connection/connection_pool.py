from framework.log.logger import log


class ConnectionPool:
    def __init__(self):
        self._pools = {}

    def get(self, key, creator):
        if key not in self._pools:
            log.debug(f"[POOL] Creating connection for key: {key}")
            self._pools[key] = creator()
        else:
            log.debug(f"[POOL] Reusing connection for key: {key}")
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
