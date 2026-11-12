"""Container images: a CycloneDX SBOM of a built image, and a vulnerability scan of it."""


class ContainerError(RuntimeError):
    """A scanner could not be installed or run, or the scan found what it may not pass."""
