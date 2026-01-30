def parametrize(arg_names, arg_values_list):
    """
    Decorator for class or function parametrization.
    If applied to class, stores parameters for the test runner.
    use test_params dict in the test class instance to reference params. e.g. self.test_params.get("param_name")
    """
    def wrapper(target):
        names = [n.strip() for n in arg_names.split(",")]
        setattr(target, "_parametrize_args", (names, arg_values_list))
        return target
    return wrapper
