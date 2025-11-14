import yaml
from lib.ca.ca_common_base import CounterActBase
from lib.plugin.radius import Radius

CONTEXTMAPPING = {
    'ca': 'lib.ca.ca_common_base.CounterActBase',
    'em': 'lib.em.em_common_base.CounterActBase',
    'radius': 'lib.plugin.radius.Radius'
}

class Configurator:
    def __init__(self, config_path):
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)
        self.instances = {}
    # dummy impl to enabling radius testcases run, need to be replaced with actual DI implementation
    def eyesight_config(self):
        ca = CounterActBase(**self.config.get('ca', {}))
        dot1x = Radius(ca, **self.config.get('radius', {}))
        return ca, dot1x

