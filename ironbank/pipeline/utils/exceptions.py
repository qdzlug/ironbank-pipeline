class ArtifactNotFound(Exception):
    """ArtifactNotFound Exception."""


class InvalidURLList(Exception):
    """InvalidURLList Exception."""


class DockerfileParseError(Exception):
    """DockerfileParseError Exception."""


class SymlinkFoundError(Exception):
    """SymlinkFoundError Exception."""


class CosignDownloadError(Exception):
    """CosignDownloadError Exception."""


class MaxRetriesException(Exception):
    """MaxRetriesException( Exception."""


class GenericSubprocessError(Exception):
    """GenericSubprocessError Exception."""


class RepoTypeNotSupported(Exception):
    """RepoTypeNotSupported( Exception."""


class NoMatchingOvalUrl(Exception):
    """NoMatchingOvalUrl Exception."""


class OvalDefinitionDownloadFailure(Exception):
    """OvalDefinitionDownloadFailure Exception."""
