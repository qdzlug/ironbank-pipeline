class InvalidURLList(Exception):
    pass


class DockerfileParseError(Exception):
    pass


class SymlinkFoundError(Exception):
    pass


class CosignDownloadError(Exception):
    pass


class MaxRetriesException(Exception):
    pass


class GenericSubprocessError(Exception):
    pass


class RepoTypeNotSupported(Exception):
    pass
