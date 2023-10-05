class Integration:
    def __init__(self, integration_name: str, integration_version: str, dependency_name: str, version_sent: bool):
        self.integration_name = integration_name
        self.integration_version = integration_version
        self.dependency_name = dependency_name
        self.version_sent = version_sent
