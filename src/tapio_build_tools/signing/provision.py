"""Set up module signing for one product in a shared Azure Key Vault.

One vault holds every product's keys; each product gets its own::

    <product>-<generation>a   the active key, the only one its pipeline may use
    <product>-<generation>b   a standby, pinned by the product but disabled in
                              the vault until the active key has to be retired

and its own signing identity: an app registration whose one federated
credential is a single GitHub environment in the product's repository, and
whose one role is Key Vault Crypto User on the product's active key. A key per
product is what keeps a leak of one product's pipeline from signing modules
another product would load - the signing context a product prefixes cannot do
that, because whoever signs chooses it.

Everything is looked up before it is made, so running this twice changes
nothing the second time, and ``dry_run`` performs the lookups and prints every
change instead of making it. Nothing about a particular deployment lives here:
subscription, vault, repository and reviewers are all arguments.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

from tapio_build_tools.downloads.package import Runner, _subprocess_runner
from tapio_build_tools.signing import SigningError
from tapio_build_tools.signing.sign import sign_and_pack

PRODUCT_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
TOKEN_AUDIENCE = "api://AzureADTokenExchange"
OFFICER_ROLE = "Key Vault Crypto Officer"
USER_ROLE = "Key Vault Crypto User"
#: A role assignment can take minutes to reach the vault's data plane.
PERMISSION_WAIT_SECONDS = 600
PERMISSION_POLL_SECONDS = 15

Sleep = Callable[[float], None]


@dataclass(frozen=True)
class Canary:
    """A module that does nothing, signed once by each key the product pins."""

    builder: tuple[str, ...]
    source: Path
    directory: Path
    created: str | None = None
    #: The product's signed-file extension, with its dot: canaries are kept as
    #: <key><extension>, which is where the product's key test looks for them.
    extension: str = ".tpp"

    def __post_init__(self) -> None:
        # A file name's ending, nothing that could step out of the directory.
        if not re.fullmatch(r"\.[a-z0-9]+", self.extension):
            raise SigningError(f"canary extension {self.extension!r} is not a dot and "
                               f"lowercase letters or digits, e.g. .tpp")


@dataclass(frozen=True)
class Request:
    subscription: str
    resource_group: str
    location: str
    vault: str
    product: str
    repository: str
    reviewers: tuple[str, ...]
    environment: str = "module-signing"
    branch: str = "main"
    generation: str = field(default_factory=lambda: str(datetime.now(timezone.utc).year))
    canary: Canary | None = None
    keep_admin: bool = False
    #: Off only while a new setup is tried out: purge protection cannot be
    #: turned off once on, and a run without this turns it on.
    purge_protection: bool = True
    #: Without a reviewer, anyone who can push to the branch can sign; that has
    #: to be asked for, not arrived at by leaving the reviewers out.
    require_reviewer: bool = True

    @property
    def active_key(self) -> str:
        return f"{self.product}-{self.generation}a"

    @property
    def standby_key(self) -> str:
        return f"{self.product}-{self.generation}b"

    @property
    def app_name(self) -> str:
        return f"github-{self.product}-module-signing"

    @property
    def subject(self) -> str:
        return f"repo:{self.repository}:environment:{self.environment}"

    def validate(self) -> None:
        if not PRODUCT_PATTERN.match(self.product):
            raise SigningError(f"product {self.product!r} must be lowercase letters, digits and hyphens")
        if not REPOSITORY_PATTERN.match(self.repository):
            raise SigningError(f"repository {self.repository!r} must be owner/name")
        if not self.reviewers and self.require_reviewer:
            raise SigningError("name a reviewer to approve signing runs, or ask for none "
                               "explicitly")
        if not re.fullmatch(r"[0-9]{4}", self.generation):
            raise SigningError(f"generation {self.generation!r} must be a year, such as 2026")


@dataclass
class Result:
    public_keys: dict[str, str] = field(default_factory=dict)
    canaries: list[Path] = field(default_factory=list)
    changes: list[str] = field(default_factory=list)

    def trusted_keys(self) -> str:
        """The lines to paste into the product's key table."""
        return "".join(f'    "{key_id}": "{value}",\n' for key_id, value in self.public_keys.items())


class _NotFound(Exception):
    pass


class _Forbidden(Exception):
    pass


_NOT_FOUND = ("KeyNotFound", "was not found", "could not be found", "ResourceNotFound",
              "(NotFound)", "HTTP 404")
_FORBIDDEN = ("ForbiddenByRbac", "Forbidden", "does not have authorization", "AuthorizationFailed")


class Provisioner:
    def __init__(
        self,
        request: Request,
        *,
        runner: Runner = _subprocess_runner,
        dry_run: bool = False,
        sleep: Sleep = time.sleep,
        log: Callable[[str], None] = lambda line: print(line, file=sys.stderr),
    ) -> None:
        request.validate()
        self.request = request
        self.runner = runner
        self.dry_run = dry_run
        self.sleep = sleep
        self.log = log
        self.result = Result()
        #: False only in a dry run that would create the vault: there is
        #: nothing yet to look keys up in.
        self.vault_exists = True

    # ---------------------------------------------------------------- running

    def _call(self, args: list[str]) -> str:
        try:
            return self.runner(args).stdout or ""
        except FileNotFoundError as exc:
            raise SigningError(f"{args[0]} is not installed") from exc
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or "").strip() if isinstance(exc.stderr, str) else ""
            if any(marker in detail for marker in _NOT_FOUND):
                raise _NotFound(detail) from exc
            if any(marker in detail for marker in _FORBIDDEN):
                raise _Forbidden(detail) from exc
            raise SigningError(f"{' '.join(args)} failed: {detail or exc}") from exc

    def query(self, args: list[str]) -> str:
        """A lookup. Runs in a dry run too; it changes nothing."""
        return self._call(args).strip()

    def change(self, description: str, args: list[str]) -> str:
        """A change. Printed, not run, in a dry run."""
        self.result.changes.append(description)
        if self.dry_run:
            self.log(f"would {description}: {' '.join(args)}")
            return ""
        self.log(f"{description}")
        return self._call(args).strip()

    def az(self, *args: str, subscription: bool = True) -> list[str]:
        command = ["az", *args]
        if subscription:
            command += ["--subscription", self.request.subscription]
        return command

    # ------------------------------------------------------------- the vault

    def ensure_provider(self) -> None:
        state = self.query(self.az("provider", "show", "--namespace", "Microsoft.KeyVault",
                                   "--query", "registrationState", "--output", "tsv"))
        if state != "Registered":
            self.change("register the Microsoft.KeyVault provider",
                        self.az("provider", "register", "--namespace", "Microsoft.KeyVault", "--wait"))

    def ensure_group(self) -> bool:
        """Whether the group exists after this, or would in a dry run."""
        request = self.request
        exists = self.query(self.az("group", "exists", "--name", request.resource_group)) == "true"
        if not exists:
            self.change(f"create resource group {request.resource_group}",
                        self.az("group", "create", "--name", request.resource_group,
                                "--location", request.location, "--output", "none"))
        return exists

    def vault_id(self) -> str:
        request = self.request
        return (f"/subscriptions/{request.subscription}/resourceGroups/{request.resource_group}"
                f"/providers/Microsoft.KeyVault/vaults/{request.vault}")

    def ensure_vault(self, group_existed: bool) -> None:
        """A vault keys can be scoped in, whose keys cannot be purged by mistake.

        Access is by Azure role, not by access policy: a role can be assigned on
        a single key, and that is what keeps each product's identity to its own
        key. Purge protection cannot be turned off again once on, which is the
        point: a deleted key stays recoverable for the retention period.
        """
        request = self.request
        found = ""
        if group_existed:
            found = self.query(self.az(
                "keyvault", "list", "--resource-group", request.resource_group,
                "--query", f"[?name=='{request.vault}'].name", "--output", "tsv"))
        if not found:
            self.vault_exists = not self.dry_run
            create = self.az("keyvault", "create", "--name", request.vault,
                             "--resource-group", request.resource_group, "--location", request.location,
                             "--sku", "standard", "--enable-rbac-authorization", "true",
                             "--retention-days", "90", "--output", "none")
            if request.purge_protection:
                create += ["--enable-purge-protection", "true"]
                description = (f"create vault {request.vault} (Standard, Azure RBAC, purge protection, "
                               f"90-day soft delete; purge protection cannot be turned off)")
            else:
                description = (f"create vault {request.vault} (Standard, Azure RBAC, 90-day soft "
                               f"delete; purge protection left off for now)")
            self.change(description, create)
            self._warn_unprotected()
            return
        settings = json.loads(self.query(self.az(
            "keyvault", "show", "--name", request.vault, "--resource-group", request.resource_group,
            "--query", "{rbac: properties.enableRbacAuthorization, "
                       "purge: properties.enablePurgeProtection}",
            "--output", "json")))
        if not settings.get("rbac"):
            raise SigningError(
                f"vault {request.vault} uses access policies, not Azure RBAC; "
                f"a role cannot be scoped to one key there")
        if settings.get("purge"):
            if not request.purge_protection:
                self.log(f"vault {request.vault} already has purge protection, which cannot "
                         f"be turned off; leaving it on")
        elif request.purge_protection:
            self.change(f"turn on purge protection on {request.vault} (cannot be turned off)",
                        self.az("keyvault", "update", "--name", request.vault,
                                "--resource-group", request.resource_group,
                                "--enable-purge-protection", "true", "--output", "none"))
        else:
            self._warn_unprotected()

    def _warn_unprotected(self) -> None:
        if not self.request.purge_protection:
            self.log(f"WARNING: purge protection is off on {self.request.vault}: a deleted key "
                     f"can be purged for good. Run again without --no-purge-protection to "
                     f"turn it on once the setup works.")

    # ---------------------------------------------------------------- roles

    def _has_role(self, assignee: str, role: str, scope: str) -> bool:
        # Azure answers a scope that does not exist yet - a vault a dry run
        # would create - with an error, not an empty list.
        try:
            return bool(self.query(self.az(
                "role", "assignment", "list", "--assignee", assignee, "--role", role,
                "--scope", scope, "--query", "[].id", "--output", "tsv")))
        except _NotFound:
            return False

    def ensure_role(self, assignee: str, principal_type: str, role: str, scope: str,
                    description: str) -> bool:
        """Whether this run had to assign it."""
        if not self.dry_run or not assignee.startswith("<"):
            if self._has_role(assignee, role, scope):
                return False
        self.change(description, self.az(
            "role", "assignment", "create", "--assignee-object-id", assignee,
            "--assignee-principal-type", principal_type, "--role", role,
            "--scope", scope, "--output", "none"))
        return True

    # ------------------------------------------------------------------ keys

    def wait_for_key_access(self) -> None:
        """A role just assigned takes a while to reach the vault's data plane."""
        if self.dry_run:
            return
        waited = 0
        while True:
            try:
                self.query(self.az("keyvault", "key", "list", "--vault-name", self.request.vault,
                                   "--query", "length(@)", "--output", "tsv", subscription=False))
                return
            except _Forbidden:
                if waited >= PERMISSION_WAIT_SECONDS:
                    raise SigningError(
                        f"still not permitted to use keys in {self.request.vault} after "
                        f"{PERMISSION_WAIT_SECONDS} seconds")
                self.log(f"waiting for the role to reach {self.request.vault}...")
                self.sleep(PERMISSION_POLL_SECONDS)
                waited += PERMISSION_POLL_SECONDS

    def key_state(self, name: str) -> bool | None:
        """True if enabled, False if disabled, None if there is no such key.

        Read from the vault's key list: a disabled key cannot be read on its
        own. In a dry run the caller may not yet hold a role on the vault, and
        the vault may not exist yet; a key it cannot see is reported missing.
        """
        if not self.vault_exists:
            return None
        try:
            enabled = self.query(self.az(
                "keyvault", "key", "list", "--vault-name", self.request.vault,
                "--query", f"[?name=='{name}'].attributes.enabled | [0]", "--output", "tsv",
                subscription=False))
        except _Forbidden:
            if self.dry_run:
                return None
            raise
        if enabled == "":
            return None
        return enabled == "true"

    def ensure_key(self, name: str) -> None:
        if self.key_state(name) is not None:
            return
        self.change(f"create key {name} (EC P-256, sign and verify only, not exportable)",
                    self.az("keyvault", "key", "create", "--vault-name", self.request.vault,
                            "--name", name, "--kty", "EC", "--curve", "P-256",
                            "--ops", "sign", "verify", "--output", "none", subscription=False))

    def set_enabled(self, name: str, enabled: bool) -> None:
        self.change(f"{'enable' if enabled else 'disable'} key {name}",
                    self.az("keyvault", "key", "set-attributes", "--vault-name", self.request.vault,
                            "--name", name, "--enabled", "true" if enabled else "false",
                            "--output", "none", subscription=False))

    @contextmanager
    def enabled(self, name: str):
        """A disabled key cannot be read or used; enable it for the block only."""
        was = self.key_state(name)
        if was is False:
            self.set_enabled(name, True)
        try:
            yield
        finally:
            if was is False:
                self.set_enabled(name, False)

    def public_key(self, name: str) -> str:
        """Base64 of the SubjectPublicKeyInfo DER, as a product's key table holds it."""
        if self.dry_run and self.key_state(name) is not True:
            return f"<public key of {name}>"
        with tempfile.TemporaryDirectory(prefix="tapio-key-") as work:
            target = Path(work) / f"{name}.der"
            self.query(self.az("keyvault", "key", "download", "--vault-name", self.request.vault,
                               "--name", name, "--encoding", "DER", "--file", str(target),
                               subscription=False))
            return base64.b64encode(target.read_bytes()).decode("ascii")

    def sign_canary(self, name: str) -> None:
        canary = self.request.canary
        target = canary.directory / f"{name}{canary.extension}"
        if target.exists():
            return
        self.result.changes.append(f"sign canary {target.name}")
        if self.dry_run:
            self.log(f"would sign canary {target} with {name}")
            return
        self.log(f"sign canary {target.name}")
        sign_and_pack(builder=canary.builder, source=canary.source, output=target,
                      vault=self.request.vault, key_name=name, key_id=name,
                      created=canary.created, runner=self.runner)
        self.result.canaries.append(target)

    # -------------------------------------------------------------- identity

    def ensure_app(self) -> tuple[str, str, bool]:
        """The app registration and its service principal.

        Returns the app id, the principal's object id, and whether the app
        was made by this run.
        """
        name = self.request.app_name
        app_ids = self.query(self.az("ad", "app", "list", "--display-name", name,
                                     "--query", "[].appId", "--output", "tsv",
                                     subscription=False)).split()
        if len(app_ids) > 1:
            raise SigningError(f"{len(app_ids)} app registrations are called {name}")
        created = not app_ids
        if app_ids:
            app_id = app_ids[0]
        else:
            app_id = self.change(f"create app registration {name}",
                                 self.az("ad", "app", "create", "--display-name", name,
                                         "--sign-in-audience", "AzureADMyOrg",
                                         "--query", "appId", "--output", "tsv",
                                         subscription=False)) or f"<app id of {name}>"
        principal = ""
        if not app_id.startswith("<"):
            principal = self.query(self.az("ad", "sp", "list", "--filter", f"appId eq '{app_id}'",
                                           "--query", "[].id", "--output", "tsv",
                                           subscription=False))
        if not principal:
            principal = self.change(f"create the service principal of {name}",
                                    self.az("ad", "sp", "create", "--id", app_id,
                                            "--query", "id", "--output", "tsv",
                                            subscription=False)) or f"<principal of {name}>"
        return app_id, principal, created

    def ensure_federated_credential(self, app_id: str) -> None:
        """The one way to act as the app: a job in the product's environment."""
        subject = self.request.subject
        if not app_id.startswith("<"):
            existing = self.query(self.az(
                "ad", "app", "federated-credential", "list", "--id", app_id,
                "--query", "[].subject", "--output", "json", subscription=False))
            subjects = json.loads(existing or "[]")
            if subject in subjects:
                return
            if subjects:
                raise SigningError(
                    f"{self.request.app_name} already trusts {subjects}; it is meant to "
                    f"trust {subject} alone")
        repository = self.request.repository.split("/", 1)[1]
        parameters = {
            "name": f"{repository}-{self.request.environment}",
            "issuer": GITHUB_ISSUER,
            "subject": subject,
            "audiences": [TOKEN_AUDIENCE],
        }
        self.change(f"trust {subject} as {self.request.app_name}",
                    self.az("ad", "app", "federated-credential", "create", "--id", app_id,
                            "--parameters", json.dumps(parameters), "--output", "none",
                            subscription=False))

    # ---------------------------------------------------------------- GitHub

    def gh(self, *args: str) -> list[str]:
        return ["gh", *args]

    def ensure_environment(self, app_id: str, app_created: bool) -> None:
        """Usable from one branch, after a named reviewer approves the run.

        With no reviewer asked for, from one branch only: anyone who can push
        to it can sign.
        """
        request = self.request
        repo, environment = request.repository, request.environment
        if not request.reviewers:
            self.log(f"WARNING: {environment} in {repo} has no reviewer; anyone who can push "
                     f"to {request.branch} can sign")
        reviewer_ids = sorted(int(self.query(self.gh("api", f"users/{login}", "--jq", ".id")))
                              for login in request.reviewers)

        try:
            current = json.loads(self.query(self.gh("api", f"repos/{repo}/environments/{environment}")))
        except _NotFound:
            current = None
        current_reviewers = sorted(
            reviewer["reviewer"]["id"]
            for rule in (current or {}).get("protection_rules", [])
            if rule.get("type") == "required_reviewers"
            for reviewer in rule.get("reviewers", []))
        policy = (current or {}).get("deployment_branch_policy") or {}
        if (current is None or current_reviewers != reviewer_ids
                or policy.get("custom_branch_policies") is not True
                or policy.get("protected_branches") is not False):
            body = {
                "deployment_branch_policy": {"protected_branches": False,
                                             "custom_branch_policies": True},
            }
            if reviewer_ids:
                body["reviewers"] = [{"type": "User", "id": user_id} for user_id in reviewer_ids]
            with tempfile.TemporaryDirectory(prefix="tapio-env-") as work:
                body_file = Path(work) / "environment.json"
                body_file.write_text(json.dumps(body), encoding="utf-8")
                reviewers = ", ".join(request.reviewers) or "none"
                self.change(f"set environment {environment} in {repo}: reviewers "
                            f"{reviewers}, chosen branches only",
                            self.gh("api", "--method", "PUT",
                                    f"repos/{repo}/environments/{environment}",
                                    "--input", str(body_file)))

        branches: list[str] = []
        if current is not None:
            branches = self.query(self.gh(
                "api", f"repos/{repo}/environments/{environment}/deployment-branch-policies",
                "--jq", '.branch_policies[] | .name + " " + .type')).splitlines()
        wanted = f"{request.branch} branch"
        for allowed in branches:
            if allowed != wanted:
                raise SigningError(
                    f"environment {environment} in {repo} also allows {allowed!r}; "
                    f"remove it so only {request.branch} can sign")
        if wanted not in branches:
            self.change(f"limit {environment} to {request.branch}",
                        self.gh("api", "--method", "POST",
                                f"repos/{repo}/environments/{environment}/deployment-branch-policies",
                                "-f", f"name={request.branch}", "-f", "type=branch"))

        # Secrets cannot be read back. One already there is left alone unless
        # the app it names was made by this run.
        secrets: list[str] = []
        if current is not None:
            secrets = self.query(self.gh("secret", "list", "--repo", repo, "--env", environment,
                                         "--json", "name", "--jq", ".[].name")).split()
        tenant = self.query(self.az("account", "show", "--query", "tenantId", "--output", "tsv"))
        for name, value in (("AZURE_CLIENT_ID", app_id), ("AZURE_TENANT_ID", tenant),
                            ("AZURE_SUBSCRIPTION_ID", request.subscription)):
            if name not in secrets or (app_created and name == "AZURE_CLIENT_ID"):
                self.change(f"set secret {name} on {environment}",
                            self.gh("secret", "set", name, "--repo", repo, "--env", environment,
                                    "--body", value))

        variables: dict[str, str] = {}
        if current is not None:
            listed = self.query(self.gh("variable", "list", "--repo", repo, "--env", environment,
                                        "--json", "name,value"))
            variables = {item["name"]: item["value"] for item in json.loads(listed or "[]")}
        for name, value in (("SIGNING_VAULT", request.vault),
                            ("SIGNING_KEY_NAME", request.active_key)):
            if variables.get(name) != value:
                self.change(f"set variable {name} on {environment}",
                            self.gh("variable", "set", name, "--repo", repo, "--env", environment,
                                    "--body", value))

    # ---------------------------------------------------------------- all of it

    def run(self) -> Result:
        request = self.request
        self.ensure_provider()
        group_existed = self.ensure_group()
        self.ensure_vault(group_existed)
        vault_id = self.vault_id()

        caller = self.query(self.az("ad", "signed-in-user", "show", "--query", "id",
                                    "--output", "tsv", subscription=False))
        granted = self.ensure_role(
            caller, "User", OFFICER_ROLE, vault_id,
            f"give the signed-in user {OFFICER_ROLE} on {request.vault} for this run")
        try:
            self.wait_for_key_access()
            for name in (request.active_key, request.standby_key):
                self.ensure_key(name)
            for name in (request.active_key, request.standby_key):
                with self.enabled(name):
                    self.result.public_keys[name] = self.public_key(name)
                    if request.canary is not None:
                        self.sign_canary(name)
            if self.key_state(request.standby_key) is not False:
                self.set_enabled(request.standby_key, False)

            app_id, principal, app_created = self.ensure_app()
            self.ensure_federated_credential(app_id)
            self.ensure_role(principal, "ServicePrincipal", USER_ROLE,
                             f"{vault_id}/keys/{request.active_key}",
                             f"let {request.app_name} sign with {request.active_key} and nothing else")
            self.ensure_environment(app_id, app_created)
        finally:
            if granted and not request.keep_admin:
                self.change(f"remove the signed-in user's {OFFICER_ROLE} on {request.vault}",
                            self.az("role", "assignment", "delete", "--assignee", caller,
                                    "--role", OFFICER_ROLE, "--scope", vault_id))
        return self.result


def provision(request: Request, **kwargs) -> Result:
    try:
        return Provisioner(request, **kwargs).run()
    except (_NotFound, _Forbidden) as exc:
        raise SigningError(str(exc)) from exc
