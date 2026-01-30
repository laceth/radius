def requires(*deps):
    def wrapper(cls):
        base_reqs = []
        for base in cls.__mro__[1:]:
            base_reqs.extend(getattr(base, "__requires__", []))
        cls.__requires__ = tuple(set(base_reqs + list(deps)))
        return cls
    return wrapper