"""CycloneDX validation shared by ecosystem adapters."""

from __future__ import annotations


def validate_json(serialized_bom: str, spec_version: str) -> None:
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    schema_versions = {
        "1.6": SchemaVersion.V1_6,
        "1.7": SchemaVersion.V1_7,
    }
    try:
        schema = schema_versions[spec_version]
    except KeyError as exc:
        raise ValueError(f"unsupported CycloneDX specification version: {spec_version}") from exc
    validation_error = JsonStrictValidator(schema).validate_str(serialized_bom)
    if validation_error is not None:
        raise ValueError(f"CycloneDX schema validation failed: {validation_error}")

