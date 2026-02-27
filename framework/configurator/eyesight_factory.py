import importlib
from lib.external_servers.ocsp_server import OcspServer
from lib.passthrough.windows_passthrough import WindowsPassthrough
from lib.switch.cisco_ios import CiscoIOS

PLUGIN_MAPPING = {
    "ca": "lib.ca.ca.CouterActAppliance",
    "em": "lib.ca.em.EnterpriseManager",
    "radius": "lib.plugin.radius.radius.Radius"
}


class EyesightFactory:

    def __init__(self, config):
        self.config = config

    def get_ca(self, is_em=False):
        role = "ca"
        if is_em:
            role = "em"
        cls = PLUGIN_MAPPING.get(role)
        module_name, class_name = cls.rsplit(".", 1)
        module = importlib.import_module(module_name)
        cls = getattr(module, class_name)
        ins = cls(**self.config.get(role, {}))
        return ins

    def get_switch(self, switch_config):
        # need to be replaced with switch factory
        return CiscoIOS(**switch_config)

    def get_passthrough(self, passthrough_config):
        return WindowsPassthrough(**passthrough_config)

    def get_plugin(self, ca_instance, plugin_name, plugin_config):
        cls = PLUGIN_MAPPING.get(plugin_name)
        module_name, class_name = cls.rsplit(".", 1)
        module = importlib.import_module(module_name)
        cls = getattr(module, class_name)
        ins = cls(ca_instance, **plugin_config)
        return ins

    def get_external_server(self, ocsp_config):
        """Currently only OCSP server is supported as external server, if more needed to support variant of tests, need to be a generic method
        """
        return OcspServer(**ocsp_config)
