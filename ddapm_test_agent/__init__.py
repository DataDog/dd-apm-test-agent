def _get_version():
    import pkg_resources  # type: ignore[import-untyped]

    return pkg_resources.get_distribution(__name__).version
