def component(required: list[str]):
    def wrapper(cls):
        cls._required_fields = required
        return cls
    return wrapper