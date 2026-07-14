"""Configuration parsing and validation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib
from typing import Any


class ConfigError(ValueError):
    """Invalid build tooling configuration."""


@dataclass(frozen=True)
class Organization:
    name: str
    website: str | None = None


@dataclass(frozen=True)
class Product:
    id: str
    name: str
    repository: str | None = None
    website: str | None = None
    license_id: str | None = None
    license_name: str | None = None
    component_type: str = "application"


@dataclass(frozen=True)
class RequirementGroup:
    name: str
    lock: Path
    input: Path | None = None


@dataclass(frozen=True)
class PythonEcosystem:
    version: str
    requirements: tuple[RequirementGroup, ...]

    def requirement(self, name: str) -> RequirementGroup:
        for group in self.requirements:
            if group.name == name:
                return group
        names = ", ".join(group.name for group in self.requirements)
        raise ConfigError(f"unknown requirement group {name!r}; configured: {names}")


@dataclass(frozen=True)
class Config:
    project: Path
    path: Path
    organization: Organization
    products: dict[str, Product]
    python: PythonEcosystem

    def product(self, product_id: str | None) -> Product:
        if product_id is None:
            if len(self.products) == 1:
                return next(iter(self.products.values()))
            raise ConfigError("--product is required when multiple products are configured")
        try:
            return self.products[product_id]
        except KeyError as exc:
            names = ", ".join(self.products)
            raise ConfigError(f"unknown product {product_id!r}; configured: {names}") from exc


def _table(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be a table")
    return value


def _keys(table: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise ConfigError(f"unknown {label} key(s): {', '.join(unknown)}")


def _required_string(table: dict[str, Any], key: str, label: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label}.{key} must be a non-empty string")
    return value


def _optional_string(table: dict[str, Any], key: str, label: str) -> str | None:
    value = table.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label}.{key} must be a non-empty string")
    return value


def _project_path(project: Path, value: str, label: str, *, must_exist: bool) -> Path:
    configured = Path(value)
    if configured.is_absolute():
        raise ConfigError(f"{label} must be relative to project root")
    resolved = (project / configured).resolve()
    if not resolved.is_relative_to(project):
        raise ConfigError(f"{label} escapes project root: {value}")
    if must_exist and not resolved.is_file():
        raise ConfigError(f"{label} does not exist: {value}")
    return resolved


def load_config(
    project: str | Path = ".",
    config_path: str | Path = "build-tooling.toml",
    *,
    require_lock_files: bool = True,
) -> Config:
    project_root = Path(project).resolve()
    path_arg = Path(config_path)
    path = path_arg.resolve() if path_arg.is_absolute() else (project_root / path_arg).resolve()
    if not path.is_file():
        raise ConfigError(f"configuration does not exist: {path}")

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc

    _keys(data, {"schema-version", "organization", "products", "ecosystems"}, "top-level")
    if data.get("schema-version") != 1:
        raise ConfigError(f"unsupported schema-version: {data.get('schema-version')!r}")

    organization_data = _table(data.get("organization"), "organization")
    _keys(organization_data, {"name", "website"}, "organization")
    organization = Organization(
        name=_required_string(organization_data, "name", "organization"),
        website=_optional_string(organization_data, "website", "organization"),
    )

    products_data = _table(data.get("products"), "products")
    if not products_data:
        raise ConfigError("at least one product must be configured")
    products: dict[str, Product] = {}
    product_keys = {
        "name", "repository", "website", "license-id", "license-name", "component-type"
    }
    for product_id, raw_product in products_data.items():
        label = f"products.{product_id}"
        product_data = _table(raw_product, label)
        _keys(product_data, product_keys, label)
        license_id = _optional_string(product_data, "license-id", label)
        license_name = _optional_string(product_data, "license-name", label)
        if license_id and license_name:
            raise ConfigError(f"{label} cannot define both license-id and license-name")
        component_type = _optional_string(product_data, "component-type", label) or "application"
        if component_type not in {"application", "firmware", "library"}:
            raise ConfigError(f"{label}.component-type is invalid: {component_type}")
        products[product_id] = Product(
            id=product_id,
            name=_required_string(product_data, "name", label),
            repository=_optional_string(product_data, "repository", label),
            website=_optional_string(product_data, "website", label),
            license_id=license_id,
            license_name=license_name,
            component_type=component_type,
        )

    ecosystems_data = _table(data.get("ecosystems"), "ecosystems")
    _keys(ecosystems_data, {"python"}, "ecosystems")
    python_data = _table(ecosystems_data.get("python"), "ecosystems.python")
    _keys(python_data, {"version", "requirements"}, "ecosystems.python")
    version = _required_string(python_data, "version", "ecosystems.python")
    raw_groups = python_data.get("requirements")
    if not isinstance(raw_groups, list) or not raw_groups:
        raise ConfigError("ecosystems.python.requirements must be a non-empty array")

    groups: list[RequirementGroup] = []
    names: set[str] = set()
    for index, raw_group in enumerate(raw_groups):
        label = f"ecosystems.python.requirements[{index}]"
        group_data = _table(raw_group, label)
        _keys(group_data, {"name", "input", "lock"}, label)
        name = _required_string(group_data, "name", label)
        if name in names:
            raise ConfigError(f"duplicate requirement group: {name}")
        names.add(name)
        lock_value = _required_string(group_data, "lock", label)
        input_value = _optional_string(group_data, "input", label)
        groups.append(
            RequirementGroup(
                name=name,
                lock=_project_path(
                    project_root,
                    lock_value,
                    f"{label}.lock",
                    must_exist=require_lock_files,
                ),
                input=(
                    _project_path(project_root, input_value, f"{label}.input", must_exist=True)
                    if input_value is not None
                    else None
                ),
            )
        )

    return Config(
        project=project_root,
        path=path,
        organization=organization,
        products=products,
        python=PythonEcosystem(version=version, requirements=tuple(groups)),
    )

