import inspect
import yaml
from framework.configurator.eyesight_factory import EyesightFactory


CONTEXTMAPPING = {
    'ca': 'lib.ca.ca_common_base.CounterActBase',
    'em': 'lib.em.em_common_base.CounterActBase',
    'radius': 'lib.plugin.radius.radius.Radius',
    'switch': 'lib.plugin.switch.cisco_ios.CiscoIOS'
}

PLUGIN_LIST = ["radius"]
class Configurator:
    def __init__(self, config_path):
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

    def get_dependencies(self):
        if "ca" in self.config:
            return self.eyesight_config()
        raise NotImplementedError("Missing ca config, Only Eyesight CA is supported for now.")

    def eyesight_config(self):
        ef = EyesightFactory(self.config)
        instances = {}
        ca = ef.get_ca()
        instances["ca"] = ca
        if "em" in self.config:
            em = ef.get_ca(is_em=True)
            instances["em"] = em
        if "switch" in self.config:
            switch = ef.get_switch(self.config.get("switch"))
            instances["switch"] = switch
        if "passthrough" in self.config:
            passthrough = ef.get_passthrough(self.config.get("passthrough"))
            instances["passthrough"] = passthrough
        if "ocsp" in self.config:
            ocsp = ef.get_external_server(self.config.get("ocsp"))
            instances["ocsp"] = ocsp
        for key in self.config:
            if key not in PLUGIN_LIST:
                continue
            plugin = ef.get_plugin(ca, key, self.config.get(key))
            instances[key] = plugin
        return instances

    def inject(self, cls, dependencies):
        sig = inspect.signature(cls.__init__)

        valid_params = {
            name for name in sig.parameters
            if name != "self"
        }

        kwargs = {
            key: value
            for key, value in dependencies.items()
            if key in valid_params
        }

        missing = [
            name for name, p in sig.parameters.items()
            if name != "self"
               and p.default is p.empty
               and name not in kwargs
        ]
        if missing:
            raise ValueError(f"Missing required config keys: {missing}")

        return cls(**kwargs)

