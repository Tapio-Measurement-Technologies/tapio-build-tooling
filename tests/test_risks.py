from datetime import date
import unittest

from tapio_build_tools.config import AcceptedRisk
from tapio_build_tools.risks import Finding, assess


TODAY = date(2026, 11, 12)


def risk(advisory: str, package: str, ecosystem: str = "container") -> AcceptedRisk:
    return AcceptedRisk(advisory, package, "Reason.", date(2027, 1, 31), f"{ecosystem}.accepted-risks[0]",
                        ecosystem)


class AssessTests(unittest.TestCase):
    def test_an_unaccepted_finding_the_predicate_lets_through_passes(self) -> None:
        low = Finding("curl", "8.0.0", "CVE-2026-1", "rpm", severity="Low")
        high = Finding("glibc", "2.34", "CVE-2026-2", "rpm", severity="High")
        assessment = assess([low, high], [], on=TODAY, fails=lambda finding: finding.severity == "High")
        self.assertEqual(assessment.passed, (low,))
        self.assertEqual(assessment.open, (high,))
        self.assertTrue(assessment.failed)

    def test_an_accepted_finding_is_accepted_whether_or_not_it_would_fail(self) -> None:
        low = Finding("curl", "8.0.0", "CVE-2026-1", "rpm", severity="Low")
        entry = risk("CVE-2026-1", "curl")
        assessment = assess([low], [entry], on=TODAY, fails=lambda finding: False)
        self.assertEqual(assessment.accepted, ((low, entry),))
        self.assertEqual(assessment.passed, ())

    def test_only_entries_it_judges_are_called_stale(self) -> None:
        own, other = risk("CVE-2026-1", "curl"), risk("GHSA-2222-3333-4444", "requests", "python")
        assessment = assess([], [own, other], on=TODAY, judges=lambda entry: entry.ecosystem == "container")
        self.assertEqual(assessment.stale, (own,))

    def test_an_expired_entry_on_a_finding_that_passes_anyway_does_not_fail(self) -> None:
        low = Finding("curl", "8.0.0", "CVE-2026-1", "rpm", severity="Low")
        entry = risk("CVE-2026-1", "curl")
        assessment = assess([low], [entry], on=date(2027, 2, 1), fails=lambda finding: False)
        self.assertEqual(assessment.passed, (low,))
        self.assertEqual(assessment.expired, ())
        self.assertEqual(assessment.stale, ())


if __name__ == "__main__":
    unittest.main()
