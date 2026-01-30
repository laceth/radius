from enum import Enum


class Action(str, Enum):
    SETUP = "setup"
    TEARDOWN = "teardown"
