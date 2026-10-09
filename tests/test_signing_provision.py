import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from tapio_build_tools.signing import SigningError
from tapio_build_tools.signing.provision import OFFICER_ROLE, USER_ROLE, Canary, Request, provision

SUBSCRIPTION = "00000000-0000-0000-0000-000000000001"
VAULT_ID = (f"/subscriptions/{SUBSCRIPTION}/resourceGroups/signing"
            f"/providers/Microsoft.KeyVault/vaults/example-vault")
USER = "user-object-id"


def request(**overrides) -> Request:
    options = {
        "subscription": SUBSCRIPTION, "resource_group": "signing", "location": "northeurope",
        "vault": "example-vault", "product": "gadget", "repository": "example-org/gadget",
        "reviewers": ("alice",), "generation": "2026",
    }
    options.update(overrides)
    return Request(**options)


def fail(args, stderr):
    raise subprocess.CalledProcessError(1, args, stderr=stderr)


class FakeCloud:
    """Azure and GitHub as the az and gh command lines show them.

    Holds the state a provisioning run reads and changes, answers the commands
    it uses, and refuses what the real services refuse: key operations without
    a role on the vault, and reading or signing with a disabled key. A role
    on the vault reaches the data plane only after *propagation* key lookups.
    """

    def __init__(self, *, propagation: int = 0) -> None:
        self.registered = False
        self.groups: set[str] = set()
        self.vaults: dict[str, dict] = {}
        self.keys: dict[str, dict] = {}
        self.roles: set[tuple[str, str, str]] = set()
        self.apps: dict[str, dict] = {}
        self.users = {"alice": 101, "bob": 102}
        self.environments: dict[str, dict] = {}
        self.propagation = propagation
        self._pending = 0
        self.mutations: list[list[str]] = []
        self.commands: list[list[str]] = []

    # -------------------------------------------------------------- plumbing

    def state(self):
        return copy.deepcopy((self.registered, self.groups, self.vaults, self.keys,
                              self.roles, self.apps, self.environments))

    @staticmethod
    def value(args, flag):
        for index, arg in enumerate(args):
            if arg == flag:
                return args[index + 1]
            if arg.startswith(flag + "="):
                return arg.split("=", 1)[1]
        return None

    def done(self, args, stdout=""):
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

    def __call__(self, args):
        self.commands.append(list(args))
        if args[0] == "builder":
            return self.builder(args)
        words = [arg for arg in args if not arg.startswith("-")]
        for size in (5, 4, 3, 2):
            handler = getattr(self, "_".join(words[:size]).replace("-", "_"), None)
            if handler is not None:
                return handler(args)
        raise AssertionError(f"unexpected command: {args}")

    def mutated(self, args):
        self.mutations.append(list(args))

    def data_plane(self, args):
        if not self.vaults:
            fail(args, "(VaultNotFound)")
        if (USER, OFFICER_ROLE, VAULT_ID) not in self.roles:
            fail(args, "(Forbidden) Caller is not authorized. ForbiddenByRbac")
        if self._pending:
            self._pending -= 1
            fail(args, "(Forbidden) ForbiddenByRbac")

    # ------------------------------------------------------------------- az

    def az_provider_show(self, args):
        return self.done(args, "Registered\n" if self.registered else "NotRegistered\n")

    def az_provider_register(self, args):
        self.mutated(args)
        self.registered = True
        return self.done(args)

    def az_group_exists(self, args):
        return self.done(args, "true\n" if self.value(args, "--name") in self.groups else "false\n")

    def az_group_create(self, args):
        self.mutated(args)
        self.groups.add(self.value(args, "--name"))
        return self.done(args)

    def az_keyvault_list(self, args):
        name = re.search(r"name=='([^']+)'", self.value(args, "--query")).group(1)
        return self.done(args, name + "\n" if name in self.vaults else "")

    def az_keyvault_create(self, args):
        self.mutated(args)
        assert self.value(args, "--enable-rbac-authorization") == "true"
        assert self.value(args, "--sku") == "standard"
        self.vaults[self.value(args, "--name")] = {
            "rbac": True, "purge": self.value(args, "--enable-purge-protection") == "true"}
        return self.done(args)

    def az_keyvault_update(self, args):
        self.mutated(args)
        assert self.value(args, "--enable-purge-protection") == "true", "it cannot be turned off"
        self.vaults[self.value(args, "--name")]["purge"] = True
        return self.done(args)

    def az_keyvault_show(self, args):
        return self.done(args, json.dumps(self.vaults[self.value(args, "--name")]))

    def az_ad_signed_in_user_show(self, args):
        return self.done(args, USER + "\n")

    def az_role_assignment_list(self, args):
        # As Azure answers it: a scope that does not exist yet is an error,
        # not an empty list.
        scope = self.value(args, "--scope")
        group = re.search(r"/resourceGroups/([^/]+)", scope)
        if group and group.group(1) not in self.groups:
            fail(args, f"(ResourceGroupNotFound) Resource group '{group.group(1)}' could not be found.")
        vault = re.search(r"/vaults/([^/]+)", scope)
        if vault and vault.group(1) not in self.vaults:
            fail(args, f"(ResourceNotFound) The Resource '{vault.group(1)}' was not found.")
        key = (self.value(args, "--assignee"), self.value(args, "--role"), scope)
        return self.done(args, "assignment-id\n" if key in self.roles else "")

    def az_role_assignment_create(self, args):
        self.mutated(args)
        self.roles.add((self.value(args, "--assignee-object-id"), self.value(args, "--role"),
                        self.value(args, "--scope")))
        if self.value(args, "--assignee-object-id") == USER:
            self._pending = self.propagation
        return self.done(args)

    def az_role_assignment_delete(self, args):
        self.mutated(args)
        self.roles.discard((self.value(args, "--assignee"), self.value(args, "--role"),
                            self.value(args, "--scope")))
        return self.done(args)

    def az_keyvault_key_list(self, args):
        self.data_plane(args)
        query = self.value(args, "--query")
        if query == "length(@)":
            return self.done(args, f"{len(self.keys)}\n")
        name = re.search(r"name=='([^']+)'", query).group(1)
        if name not in self.keys:
            return self.done(args, "")
        return self.done(args, "true\n" if self.keys[name]["enabled"] else "false\n")

    def az_keyvault_key_create(self, args):
        self.data_plane(args)
        self.mutated(args)
        assert self.value(args, "--kty") == "EC" and self.value(args, "--curve") == "P-256"
        name = self.value(args, "--name")
        self.keys[name] = {"enabled": True, "der": hashlib.sha256(name.encode()).digest()}
        return self.done(args)

    def az_keyvault_key_set_attributes(self, args):
        self.data_plane(args)
        self.mutated(args)
        self.keys[self.value(args, "--name")]["enabled"] = self.value(args, "--enabled") == "true"
        return self.done(args)

    def usable_key(self, args):
        self.data_plane(args)
        key = self.keys[self.value(args, "--name")]
        if not key["enabled"]:
            fail(args, "(Forbidden) Operation get is not allowed on a disabled key.")
        return key

    def az_keyvault_key_download(self, args):
        key = self.usable_key(args)
        Path(self.value(args, "--file")).write_bytes(key["der"])
        return self.done(args)

    def az_keyvault_key_sign(self, args):
        self.usable_key(args)
        digest = base64.b64decode(self.value(args, "--digest").encode("utf-8"))
        signature = hashlib.sha512(self.value(args, "--name").encode() + digest).digest()
        return self.done(args, base64.b64encode(signature).decode() + "\n")

    def az_ad_app_list(self, args):
        app = self.apps.get(self.value(args, "--display-name"))
        return self.done(args, app["appId"] + "\n" if app else "")

    def az_ad_app_create(self, args):
        self.mutated(args)
        name = self.value(args, "--display-name")
        self.apps[name] = {"appId": f"app-{len(self.apps) + 1}", "sp": None, "subjects": []}
        return self.done(args, self.apps[name]["appId"] + "\n")

    def app_by_id(self, app_id):
        return next(app for app in self.apps.values() if app["appId"] == app_id)

    def az_ad_sp_list(self, args):
        app_id = re.search(r"appId eq '([^']+)'", self.value(args, "--filter")).group(1)
        sp = self.app_by_id(app_id)["sp"]
        return self.done(args, sp + "\n" if sp else "")

    def az_ad_sp_create(self, args):
        self.mutated(args)
        app = self.app_by_id(self.value(args, "--id"))
        app["sp"] = "sp-" + app["appId"]
        return self.done(args, app["sp"] + "\n")

    def az_ad_app_federated_credential_list(self, args):
        return self.done(args, json.dumps(self.app_by_id(self.value(args, "--id"))["subjects"]))

    def az_ad_app_federated_credential_create(self, args):
        self.mutated(args)
        parameters = json.loads(self.value(args, "--parameters"))
        assert parameters["issuer"] == "https://token.actions.githubusercontent.com"
        assert parameters["audiences"] == ["api://AzureADTokenExchange"]
        self.app_by_id(self.value(args, "--id"))["subjects"].append(parameters["subject"])
        return self.done(args)

    def az_account_show(self, args):
        return self.done(args, "tenant-id\n")

    # ------------------------------------------------------------------- gh

    def environment(self, path):
        match = re.fullmatch(r"repos/[^/]+/[^/]+/environments/([^/]+)(/.*)?", path)
        return match.group(1), match.group(2) or ""

    def gh_api(self, args):
        path = next(arg for arg in args[2:] if not arg.startswith("-")
                    and args[args.index(arg) - 1] not in ("--method", "--jq", "--input", "-f"))
        method = self.value(args, "--method") or "GET"
        if path.startswith("users/"):
            return self.done(args, f"{self.users[path.split('/')[1]]}\n")
        name, rest = self.environment(path)
        environment = self.environments.get(name)
        if rest == "" and method == "GET":
            if environment is None:
                fail(args, "gh: Not Found (HTTP 404)")
            rules = [{"type": "required_reviewers",
                      "reviewers": [{"type": "User", "reviewer": {"id": uid}}
                                    for uid in environment["reviewers"]]}]
            return self.done(args, json.dumps({
                "protection_rules": rules,
                "deployment_branch_policy": {"protected_branches": environment["protected"],
                                             "custom_branch_policies": environment["custom"]}}))
        if rest == "" and method == "PUT":
            self.mutated(args)
            body = json.loads(Path(self.value(args, "--input")).read_text(encoding="utf-8"))
            environment = self.environments.setdefault(
                name, {"branches": [], "secrets": set(), "variables": {}})
            environment["reviewers"] = [reviewer["id"] for reviewer in body.get("reviewers", [])]
            environment["protected"] = body["deployment_branch_policy"]["protected_branches"]
            environment["custom"] = body["deployment_branch_policy"]["custom_branch_policies"]
            return self.done(args)
        if rest == "/deployment-branch-policies" and method == "GET":
            return self.done(args, "".join(f"{n} {t}\n" for n, t in environment["branches"]))
        if rest == "/deployment-branch-policies" and method == "POST":
            self.mutated(args)
            fields = dict(arg.split("=", 1) for arg in args if "=" in arg and not arg.startswith("-"))
            environment["branches"].append((fields["name"], fields["type"]))
            return self.done(args)
        raise AssertionError(f"unexpected gh api call: {args}")

    def gh_secret_list(self, args):
        return self.done(args, "".join(f"{name}\n" for name in
                                       sorted(self.environments[self.value(args, "--env")]["secrets"])))

    def gh_secret_set(self, args):
        self.mutated(args)
        self.environments[self.value(args, "--env")]["secrets"].add(args[3])
        return self.done(args)

    def gh_variable_list(self, args):
        variables = self.environments[self.value(args, "--env")]["variables"]
        return self.done(args, json.dumps([{"name": n, "value": v} for n, v in variables.items()]))

    def gh_variable_set(self, args):
        self.mutated(args)
        self.environments[self.value(args, "--env")]["variables"][args[3]] = self.value(args, "--body")
        return self.done(args)

    # -------------------------------------------------------------- builder

    def builder(self, args):
        command = args[1]
        if command == "manifest":
            Path(self.value(args, "--out")).write_bytes(b'{"id": "com.example.canary"}\n')
            return self.done(args)
        if command == "digest":
            digest = hashlib.sha256(Path(self.value(args, "--manifest")).read_bytes()).digest()
            return self.done(args, base64.b64encode(digest).decode() + "\n")
        if command == "pack":
            Path(self.value(args, "--out")).write_text(self.value(args, "--key-id"), encoding="utf-8")
            return self.done(args)
        raise AssertionError(f"unexpected builder call: {args}")


class ProvisionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.canaries = Path(temporary.name) / "canaries"
        self.slept: list[float] = []
        self.logged: list[str] = []

    def run_against(self, cloud, req=None, **options):
        return provision(req or request(), runner=cloud, sleep=self.slept.append,
                         log=self.logged.append, **options)

    def test_a_first_run_sets_up_the_vault_the_keys_and_the_identity(self) -> None:
        cloud = FakeCloud()
        canary = Canary(builder=("builder",), source=Path("canary"), directory=self.canaries,
                        created="2026-01-01T00:00:00Z")
        result = self.run_against(cloud, request(canary=canary))

        self.assertTrue(cloud.registered)
        self.assertEqual(cloud.groups, {"signing"})
        self.assertIn("example-vault", cloud.vaults)
        self.assertEqual({name: key["enabled"] for name, key in cloud.keys.items()},
                         {"gadget-2026a": True, "gadget-2026b": False})
        self.assertEqual(sorted(result.public_keys), ["gadget-2026a", "gadget-2026b"])
        self.assertEqual(result.public_keys["gadget-2026a"],
                         base64.b64encode(cloud.keys["gadget-2026a"]["der"]).decode())
        self.assertEqual(sorted(path.name for path in self.canaries.iterdir()),
                         ["gadget-2026a.tpp", "gadget-2026b.tpp"])

        app = cloud.apps["github-gadget-module-signing"]
        self.assertEqual(app["subjects"], ["repo:example-org/gadget:environment:module-signing"])
        self.assertEqual(cloud.roles, {(app["sp"], USER_ROLE, f"{VAULT_ID}/keys/gadget-2026a")},
                         "the identity has one role, on the active key, and the user none")

        environment = cloud.environments["module-signing"]
        self.assertEqual(environment["reviewers"], [101])
        self.assertEqual(environment["branches"], [("main", "branch")])
        self.assertEqual(environment["secrets"],
                         {"AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID"})
        self.assertEqual(environment["variables"],
                         {"SIGNING_VAULT": "example-vault", "SIGNING_KEY_NAME": "gadget-2026a"})
        self.assertIn('"gadget-2026a": "', result.trusted_keys())

    def test_a_second_run_only_borrows_and_returns_what_it_needs(self) -> None:
        """The vault role for the run, and the standby enabled to read it."""
        cloud = FakeCloud()
        self.run_against(cloud)
        before = cloud.state()

        result = self.run_against(cloud)

        self.assertEqual(cloud.state(), before)
        self.assertEqual(result.changes, [
            f"give the signed-in user {OFFICER_ROLE} on example-vault for this run",
            "enable key gadget-2026b",
            "disable key gadget-2026b",
            f"remove the signed-in user's {OFFICER_ROLE} on example-vault",
        ])

    def test_a_dry_run_changes_nothing_and_says_everything(self) -> None:
        cloud = FakeCloud()
        result = self.run_against(cloud, dry_run=True)

        self.assertEqual(cloud.mutations, [])
        self.assertIn("create vault example-vault (Standard, Azure RBAC, purge protection, "
                      "90-day soft delete; purge protection cannot be turned off)", result.changes)
        self.assertIn("create key gadget-2026a (EC P-256, sign and verify only, not exportable)",
                      result.changes)
        self.assertEqual(result.public_keys["gadget-2026a"], "<public key of gadget-2026a>")
        self.assertTrue(all(line.startswith("would ") for line in self.logged))

    def test_a_dry_run_against_a_finished_setup_reports_its_real_keys(self) -> None:
        """With the vault role kept, a dry run can read what is there."""
        cloud = FakeCloud()
        self.run_against(cloud, request(keep_admin=True))
        made = len(cloud.mutations)

        result = self.run_against(cloud, request(keep_admin=True), dry_run=True)

        self.assertEqual(len(cloud.mutations), made)
        self.assertEqual(result.public_keys["gadget-2026a"],
                         base64.b64encode(cloud.keys["gadget-2026a"]["der"]).decode())
        self.assertEqual(result.public_keys["gadget-2026b"], "<public key of gadget-2026b>",
                         "the standby is disabled, and a dry run does not enable it to look")

    def test_it_waits_for_the_role_to_reach_the_vault(self) -> None:
        self.run_against(FakeCloud(propagation=2))
        self.assertEqual(len(self.slept), 2)

    def test_the_borrowed_role_is_returned_when_a_step_fails(self) -> None:
        cloud = FakeCloud()
        cloud.apps["github-gadget-module-signing"] = {"appId": "app-1", "sp": "sp-app-1",
                                                      "subjects": ["repo:example-org/other:ref:refs/heads/main"]}
        with self.assertRaisesRegex(SigningError, "it is meant to trust .* alone"):
            self.run_against(cloud)
        self.assertNotIn((USER, OFFICER_ROLE, VAULT_ID), cloud.roles)

    def test_a_setup_can_be_tried_without_purge_protection_and_protected_later(self) -> None:
        cloud = FakeCloud()
        self.run_against(cloud, request(purge_protection=False))
        self.assertFalse(cloud.vaults["example-vault"]["purge"])
        self.assertTrue(any("WARNING: purge protection is off" in line for line in self.logged))

        self.run_against(cloud, request(purge_protection=False))
        self.assertFalse(cloud.vaults["example-vault"]["purge"], "asked again to leave it off")

        result = self.run_against(cloud)
        self.assertTrue(cloud.vaults["example-vault"]["purge"])
        self.assertIn("turn on purge protection on example-vault (cannot be turned off)",
                      result.changes)

    def test_asking_to_leave_it_off_cannot_turn_it_off(self) -> None:
        cloud = FakeCloud()
        self.run_against(cloud)
        self.run_against(cloud, request(purge_protection=False))
        self.assertTrue(cloud.vaults["example-vault"]["purge"])

    def test_no_reviewer_must_be_asked_for_and_is_warned_about(self) -> None:
        cloud = FakeCloud()
        self.run_against(cloud, request(reviewers=(), require_reviewer=False))

        environment = cloud.environments["module-signing"]
        self.assertEqual(environment["reviewers"], [])
        self.assertEqual(environment["branches"], [("main", "branch")])
        self.assertTrue(any("has no reviewer; anyone who can push to main can sign" in line
                            for line in self.logged))

        before = cloud.state()
        self.run_against(cloud, request(reviewers=(), require_reviewer=False))
        self.assertEqual(cloud.state(), before)

    def test_a_vault_on_access_policies_is_refused(self) -> None:
        cloud = FakeCloud()
        cloud.registered = True
        cloud.groups.add("signing")
        cloud.vaults["example-vault"] = {"rbac": False, "purge": True}
        with self.assertRaisesRegex(SigningError, "a role cannot be scoped to one key"):
            self.run_against(cloud)

    def test_an_environment_open_to_another_branch_is_refused(self) -> None:
        cloud = FakeCloud()
        self.run_against(cloud)
        cloud.environments["module-signing"]["branches"].append(("feature/*", "branch"))
        with self.assertRaisesRegex(SigningError, "also allows 'feature/\\* branch'"):
            self.run_against(cloud)

    def test_changing_the_reviewers_updates_the_environment(self) -> None:
        cloud = FakeCloud()
        self.run_against(cloud)
        self.run_against(cloud, request(reviewers=("alice", "bob")))
        self.assertEqual(cloud.environments["module-signing"]["reviewers"], [101, 102])

    def test_a_request_that_could_not_be_what_was_meant_is_refused(self) -> None:
        for overrides, message in (
            ({"product": "Gadget"}, "lowercase"),
            ({"repository": "gadget"}, "owner/name"),
            ({"reviewers": ()}, "name a reviewer"),
            ({"generation": "26"}, "must be a year"),
        ):
            with self.subTest(**{k: str(v) for k, v in overrides.items()}):
                with self.assertRaisesRegex(SigningError, message):
                    provision(request(**overrides), runner=FakeCloud())


if __name__ == "__main__":
    unittest.main()
