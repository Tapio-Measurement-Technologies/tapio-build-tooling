import unittest

from tapio_build_tools.downloads.markdown import render_markdown


class MarkdownTests(unittest.TestCase):
    def test_blocks(self) -> None:
        html = render_markdown("# Title\n\nFirst line\nsame paragraph.\n\n- one\n- two\n\n1. a\n2) b\n\n```\nx < y\n```\n")
        self.assertIn("<h3>Title</h3>", html)
        self.assertIn("<p>First line same paragraph.</p>", html)
        self.assertIn("<ul><li>one</li><li>two</li></ul>", html)
        self.assertIn("<ol><li>a</li><li>b</li></ol>", html)
        self.assertIn("<pre><code>x &lt; y</code></pre>", html)
        self.assertIn("<h4>", render_markdown("### deep"))

    def test_inline(self) -> None:
        html = render_markdown("**bold** and *it* and _it_ and `co**de**` and [t](https://e.com/a?b=1&c=2) x")
        self.assertIn("<strong>bold</strong>", html)
        self.assertEqual(html.count("<em>it</em>"), 2)
        self.assertIn("<code>co**de**</code>", html)
        self.assertIn('<a href="https://e.com/a?b=1&amp;c=2">t</a>', html)

    def test_bare_urls_stop_before_punctuation(self) -> None:
        html = render_markdown("See https://example.com/path. Then (https://example.com/x), done.")
        self.assertIn('<a href="https://example.com/path">https://example.com/path</a>.', html)
        self.assertIn('(<a href="https://example.com/x">https://example.com/x</a>),', html)

    def test_markup_and_unsafe_links_are_shown_not_run(self) -> None:
        html = render_markdown('<script>alert(1)</script> [x](javascript:alert(1)) <a href="https://e">y</a>')
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn('href="javascript', html)
        self.assertIn("[x](javascript:alert(1))", html)
        self.assertNotIn('<a href="https://e">y</a>', html)

    def test_empty_input(self) -> None:
        self.assertEqual(render_markdown("\n\n"), "")


if __name__ == "__main__":
    unittest.main()
