"""Signing a product's modules with a key held in Azure Key Vault."""


class SigningError(RuntimeError):
    """A signing or provisioning step could not be completed."""
