def _get_version():
    import pkg_resources

    return pkg_resources.get_distribution(__name__).version
