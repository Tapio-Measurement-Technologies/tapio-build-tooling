from dataclasses import replace
from pathlib import Path
import re
import tempfile
import unittest

from tapio_build_tools.downloads.manifest import Asset, Release, empty_manifest, merge_release
from tapio_build_tools.downloads.render import render_program_pages, render_root_page
from tests.downloads_support import GPL_CONFIG, RELEASED, write_project


def asset(kind: str, version: str, name: str, *, os: str | None = None, arch: str | None = None) -> Asset:
    return Asset(
        kind=kind, os=os, arch=arch, file=name, key=f"demo/{version}/{name}",
        url=f"https://example.invalid/demo/{version}/{name}", size=3 * 1024 * 1024, sha256="ab" * 32,
    )


def release(version: str, *, released: str = RELEASED, source: bool = True, sbom: bool = True) -> Release:
    assets = [
        asset("binary", version, f"demo-{version}-windows-x86_64.zip", os="windows", arch="x86_64"),
        asset("binary", version, f"demo-{version}-linux-x86_64.tar.gz", os="linux", arch="x86_64"),
    ]
    if sbom:
        assets.append(asset("sbom", version, f"demo-{version}-windows-x86_64.cdx.json", os="windows", arch="x86_64"))
    if source:
        assets.append(asset("source", version, f"demo-{version}-source.tar.gz"))
    return Release(version=version, released=released, commit="c", assets=tuple(assets))


class RenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.config = write_project(Path(self.temporary.name))
        self.program = self.config.require_downloads().program("demo")
        manifest = merge_release(empty_manifest(self.program, RELEASED), release("v1.2.0", released="2026-08-01T09:00:00Z"))
        self.manifest = merge_release(manifest, release("v1.3.0", source=False, sbom=False))
        self.pages = {
            page.key: page.html
            for page in render_program_pages(self.program, self.manifest, "Example Oy", self.config.downloads.logo)
        }

    def test_writes_the_permanent_page_one_per_version_and_the_list(self) -> None:
        self.assertEqual(
            sorted(self.pages),
            ["demo/index.html", "demo/v1.2.0/index.html", "demo/v1.3.0/index.html", "demo/versions/index.html"],
        )

    def test_the_permanent_page_offers_the_latest_release_for_every_system(self) -> None:
        page = self.pages["demo/index.html"]
        self.assertIn("<h1>Demo Program</h1>", page)
        self.assertIn("Version v1.3.0, released 16 September 2026", page)
        self.assertIn('data-os="windows" href="v1.3.0/demo-v1.3.0-windows-x86_64.zip"><svg class="icon"', page)
        self.assertIn('<span>Download for Windows</span></a>', page)
        self.assertIn('data-os="linux" href="v1.3.0/demo-v1.3.0-linux-x86_64.tar.gz"><svg class="icon"', page)
        self.assertIn('<span>Download for Linux</span></a>', page)
        self.assertIn("3.0 MB", page)
        self.assertIn("ab" * 32, page)
        self.assertIn('href="versions/index.html">All versions</a>', page)
        self.assertIn("always offers the latest release of Demo Program", page)
        self.assertNotIn("newer version", page)

    def test_an_older_version_page_points_at_the_newer_one(self) -> None:
        page = self.pages["demo/v1.2.0/index.html"]
        self.assertIn("Version v1.2.0, released 1 August 2026", page)
        self.assertIn('A newer version, v1.3.0, is available. <a href="../index.html">', page)
        self.assertIn('href="demo-v1.2.0-windows-x86_64.zip"', page)
        self.assertNotIn("newer version", self.pages["demo/v1.3.0/index.html"])

    def test_a_copyleft_release_offers_its_source_and_says_so(self) -> None:
        page = self.pages["demo/v1.2.0/index.html"]
        self.assertIn('href="demo-v1.2.0-source.tar.gz">Source code (GPL-3.0-or-later)</a>', page)
        self.assertIn("free software under the GPL-3.0-or-later licence", page)
        self.assertIn("complete corresponding source code", page)
        self.assertIn('href="demo-v1.2.0-windows-x86_64.cdx.json"', page)
        self.assertIn("SBOM", page)
        without = self.pages["demo/v1.3.0/index.html"]
        self.assertNotIn("Source code", without)
        self.assertNotIn("SBOM", without)

    def test_the_versions_page_lists_newest_first(self) -> None:
        page = self.pages["demo/versions/index.html"]
        self.assertLess(page.index("v1.3.0"), page.index("v1.2.0"))
        self.assertIn('href="../v1.2.0/index.html">v1.2.0</a>', page)
        self.assertIn("v1.3.0</a> (latest)", page)
        self.assertIn("Windows, Linux, source, SBOM", page)
        self.assertIn('href="../index.html">Latest release: v1.3.0</a>', page)

    def test_nothing_is_loaded_from_anywhere_else(self) -> None:
        """Behind a proxy that blocks fonts and stylesheets the page is whole."""
        for key, page in self.pages.items():
            with self.subTest(page=key):
                references = re.findall(r'(?:src|href)="([^"]*)"', page)
                self.assertTrue(references)
                for reference in references:
                    self.assertFalse(
                        reference.startswith(("http:", "https:", "//")) or not reference,
                        f"{key} reaches out to {reference}",
                    )
                self.assertNotIn("@import", page)
                self.assertNotIn("url(", page)
                self.assertNotIn("http", page.split("<script>")[-1].split("</script>")[0])

    def test_every_link_spells_out_index_html(self) -> None:
        for key, page in self.pages.items():
            for reference in re.findall(r'href="([^"]*)"', page):
                if reference.startswith(("mailto:", "data:")) or "." in reference.rsplit("/", 1)[-1]:
                    continue
                self.fail(f"{key} links to a directory: {reference}")

    def test_search_engines_are_told_to_leave_it_alone_unless_asked_in(self) -> None:
        robots = '<meta name="robots" content="noindex, nofollow, noarchive">'
        for page in self.pages.values():
            self.assertIn(robots, page)
        indexable = write_project(
            Path(self.temporary.name), GPL_CONFIG.replace('slug = "demo"', 'slug = "demo"\nindexable = true')
        ).require_downloads().program("demo")
        for page in render_program_pages(indexable, self.manifest, "Example Oy"):
            self.assertNotIn(robots, page.html)

    def test_what_it_is_given_cannot_become_markup(self) -> None:
        page = self.pages["demo/index.html"]
        self.assertIn("Second &lt;paragraph&gt;.", page)
        self.assertNotIn("<paragraph>", page)
        hostile = write_project(
            Path(self.temporary.name), GPL_CONFIG.replace('name = "Demo Program"', 'name = "Demo <script>alert(1)</script>"')
        ).require_downloads().program("demo")
        rendered = render_program_pages(hostile, self.manifest, "Example & Co")[0].html
        self.assertNotIn("<script>alert", rendered)
        self.assertIn("Demo &lt;script&gt;", rendered)
        self.assertIn("Example &amp; Co", rendered)

    def test_release_notes_are_shown_on_the_version_and_latest_pages(self) -> None:
        noted = replace(self.manifest, releases=tuple(
            replace(r, notes="## Fixed\n- <b>bold</b> is text\n") if r.version == "v1.3.0" else r
            for r in self.manifest.releases
        ))
        pages = {p.key: p.html for p in render_program_pages(self.program, noted, "Example Oy")}
        for key in ("demo/index.html", "demo/v1.3.0/index.html"):
            self.assertIn('<details class="notes">\n<summary>Release notes</summary>', pages[key])
            self.assertNotIn("<details open", pages[key])
            self.assertIn("&lt;b&gt;bold&lt;/b&gt; is text", pages[key])
        self.assertNotIn("Release notes", pages["demo/v1.2.0/index.html"])
        self.assertNotIn("Release notes", self.pages["demo/index.html"])

    def test_the_logo_is_inlined_when_configured(self) -> None:
        self.assertIn('src="data:image/png;base64,', self.pages["demo/index.html"])
        plain = render_program_pages(self.program, self.manifest, "Example Oy")[0].html
        self.assertNotIn("<img", plain)

    def test_the_javascript_only_reorders_buttons(self) -> None:
        page = self.pages["demo/index.html"]
        self.assertIn("navigator.platform", page)
        self.assertIn('querySelector(".downloads")', page)
        self.assertNotIn("<script", self.pages["demo/versions/index.html"])

    def test_the_root_page_lists_every_listed_program(self) -> None:
        other = empty_manifest(self.program, RELEASED)
        hidden = replace(self.manifest, slug="hidden", name="Hidden Program", listed=False)
        page = render_root_page([self.manifest, other, hidden], "Example Oy").html
        self.assertIn("<title>Downloads</title>", page)
        self.assertIn("<h1>Downloads</h1>", page)
        self.assertIn('<p class="eyebrow">Example Oy</p>', page)
        self.assertIn('<a href="demo/index.html">Demo Program</a></td><td>v1.3.0</td>', page)
        self.assertNotIn("Hidden Program", page)
        self.assertEqual(page.count("<tr>"), 2)  # header row plus one program; empty and unlisted are left out


if __name__ == "__main__":
    unittest.main()
