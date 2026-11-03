"""Public domain errors, deliberately independent of the HTTP framework."""


class ThreatNotFound(Exception):
    """No record exists for the supplied normalized MD5."""


class ThreatAlreadyExists(Exception):
    """A record already exists for the supplied normalized MD5."""
