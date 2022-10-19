class InvalidURLList(Exception):
    pass


class DockerfileParseError(Exception):
    pass


class SymlinkFoundError(Exception):
    pass


class ORASDownloadError(Exception):
    pass


class MaxRetriesException(Exception):
    pass


class GenericSubprocessError(Exception):
    pass
