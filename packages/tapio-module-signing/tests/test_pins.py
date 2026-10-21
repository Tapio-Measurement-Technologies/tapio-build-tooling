"""The key-table and canary checks, run against tables and canaries made to be wrong.

A product runs these against its shipped table, where with the vault's keys
they pass; here each is shown to catch what it is for.
"""

import os
import shutil
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from support import PROFILE
from tapio_module_signing.pins import canary_problems, key_table_problems
from tapio_module_signing.testing import build_vault_style, generate_key, public_b64, trusting

CANARY_CREATED = "2026-01-01T00:00:00Z"


class TheChecksTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="module-signing-canary-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.canaries = os.path.join(self.tmp, "canaries")
        os.makedirs(self.canaries)
        self.source = os.path.join(self.tmp, "source")
        os.makedirs(self.source)
        with open(os.path.join(self.source, "canary.py"), "w", encoding="utf-8") as handle:
            handle.write("")
        with open(os.path.join(self.source, "gadget.toml"), "w", encoding="utf-8") as handle:
            handle.write('id = "com.example.signing-canary"\nversion = "1"\nmodule = "canary.py"\n')
        self.key = generate_key()
        self.other_key = generate_key()

    def trust(self, table):
        trust = trusting(PROFILE, table)
        trust.__enter__()
        self.addCleanup(trust.__exit__, None, None, None)

    def canary(self, key_id, key, name=None):
        out = os.path.join(self.canaries, (name or key_id) + PROFILE.extension)
        return build_vault_style(self.source, out, key_id, key, profile=PROFILE,
                                 created=CANARY_CREATED)

    def test_a_canary_signed_the_way_the_vault_signs_passes(self):
        self.trust({"gadget-test": public_b64(self.key)})
        self.canary("gadget-test", self.key)

        self.assertEqual(key_table_problems(profile=PROFILE), [])
        self.assertEqual(canary_problems(self.canaries, profile=PROFILE), [])

    def test_a_pinned_key_that_is_not_the_vault_key_is_caught(self):
        """What the canaries are for: the table and the vault disagree."""
        self.trust({"gadget-test": public_b64(self.other_key)})
        self.canary("gadget-test", self.key)

        self.assertEqual(key_table_problems(profile=PROFILE), [])
        [problem] = canary_problems(self.canaries, profile=PROFILE)
        self.assertIn("does not verify", problem)

    def test_a_trusted_key_without_a_canary_is_caught(self):
        self.trust({"gadget-test": public_b64(self.key)})

        [problem] = canary_problems(self.canaries, profile=PROFILE)
        self.assertIn("has no gadget-test.tgm canary", problem)

    def test_a_canary_left_behind_by_a_retired_key_is_caught(self):
        self.trust({"gadget-old": public_b64(self.key)})
        self.canary("gadget-old", self.key)
        self.trust({})

        [problem] = canary_problems(self.canaries, profile=PROFILE)
        self.assertIn("not trusted", problem)

    def test_a_canary_signed_by_another_trusted_key_is_caught(self):
        """It verifies, and says nothing about the key it is named for."""
        self.trust({"gadget-a": public_b64(self.key),
                    "gadget-b": public_b64(self.other_key)})
        self.canary("gadget-a", self.key)
        self.canary("gadget-a", self.key, name="gadget-b")

        [problem] = canary_problems(self.canaries, profile=PROFILE)
        self.assertIn("gadget-b.tgm is signed with 'gadget-a'", problem)

    def test_the_same_key_pasted_under_two_ids_is_caught(self):
        """An active key and a standby that is the same key are one key."""
        self.trust({"gadget-a": public_b64(self.key), "gadget-b": public_b64(self.key)})

        [problem] = key_table_problems(profile=PROFILE)
        self.assertIn("same key", problem)

    def test_a_key_that_is_not_p256_is_caught(self):
        wrong = {
            "p384": ec.generate_private_key(ec.SECP384R1()),
            "rsa": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        }
        self.trust({key_id: public_b64(key) for key_id, key in wrong.items()})

        problems = key_table_problems(profile=PROFILE)
        self.assertEqual(len(problems), 2, problems)
        for problem in problems:
            self.assertIn("not an ECDSA P-256 key", problem)

    def test_a_key_cut_short_when_pasted_is_caught(self):
        self.trust({"gadget-test": public_b64(self.key)[:-12]})

        [problem] = key_table_problems(profile=PROFILE)
        self.assertIn("gadget-test", problem)
