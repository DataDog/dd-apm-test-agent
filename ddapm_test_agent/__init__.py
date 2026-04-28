def _get_version() -> str:
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version

    try:
        return version(__name__)
    except PackageNotFoundError:
        import pkg_resources

        return str(pkg_resources.get_distribution(__name__).version)
