"""
Base class for RADIUS plugin.
"""


class RadiusBase:
    """Base class for RADIUS plugin implementations."""

    version = "1.0.0"
    platform = None

    def __init__(self, platform, version="1.0.0", username=None, password=None):
        self.platform = platform
        self.version = version
        self.username = username
        self.password = password

