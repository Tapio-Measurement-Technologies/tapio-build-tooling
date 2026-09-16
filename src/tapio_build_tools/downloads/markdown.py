"""Release notes, from the Markdown written on a GitHub release to HTML.

Only what release notes use: headings, paragraphs, bullet and numbered
lists, fenced code, and inline emphasis, code and links. Everything passes
through html.escape first, so markup in the source is shown, not run, and
a link is only a link when it points at http(s) or mailto. Nested lists are
flattened; anything else unrecognised is a paragraph.
"""

from __future__ import annotations

import html
import re


_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_BULLET = re.compile(r"^\s*[-*+]\s+(.*)$")
_NUMBERED = re.compile(r"^\s*\d+[.)]\s+(.*)$")
_FENCE = re.compile(r"^\s*```")
_CODE_SPAN = re.compile(r"(`+)(.+?)\1")
_LINK = re.compile(r"\[([^\]]+)\]\(((?:https?:|mailto:)[^)\s]+)\)")
_BARE_URL = re.compile(r"(?<![\"'>=\w])(https?://[^\s<)]+?)(?=[.,;:!?]*(?:\s|$|<|\)))")
_STRONG = re.compile(r"\*\*(?=\S)(.+?)(?<=\S)\*\*|__(?=\S)(.+?)(?<=\S)__")
_EMPHASIS = re.compile(r"(?<![\w*])\*(?=\S)(.+?)(?<=\S)\*(?![\w*])|(?<!\w)_(?=\S)(.+?)(?<=\S)_(?!\w)")


def _inline(text: str) -> str:
    parts: list[str] = []
    position = 0
    for match in _CODE_SPAN.finditer(text):
        parts.append(_formatted(text[position:match.start()]))
        parts.append(f"<code>{html.escape(match.group(2).strip())}</code>")
        position = match.end()
    parts.append(_formatted(text[position:]))
    return "".join(parts)


def _formatted(text: str) -> str:
    escaped = html.escape(text, quote=True)
    escaped = _LINK.sub(lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>', escaped)
    escaped = _BARE_URL.sub(lambda m: f'<a href="{m.group(1)}">{m.group(1)}</a>', escaped)
    escaped = _STRONG.sub(lambda m: f"<strong>{m.group(1) or m.group(2)}</strong>", escaped)
    escaped = _EMPHASIS.sub(lambda m: f"<em>{m.group(1) or m.group(2)}</em>", escaped)
    return escaped


def render_markdown(text: str) -> str:
    lines = text.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        if _FENCE.match(line):
            index += 1
            code: list[str] = []
            while index < len(lines) and not _FENCE.match(lines[index]):
                code.append(lines[index])
                index += 1
            index += 1
            out.append(f"<pre><code>{html.escape(chr(10).join(code))}</code></pre>")
            continue
        heading = _HEADING.match(line)
        if heading:
            level = 3 if len(heading.group(1)) <= 2 else 4
            out.append(f"<h{level}>{_inline(heading.group(2))}</h{level}>")
            index += 1
            continue
        for pattern, tag in ((_BULLET, "ul"), (_NUMBERED, "ol")):
            if pattern.match(line):
                items: list[str] = []
                while index < len(lines) and (match := pattern.match(lines[index])):
                    items.append(f"<li>{_inline(match.group(1))}</li>")
                    index += 1
                out.append(f"<{tag}>" + "".join(items) + f"</{tag}>")
                break
        else:
            paragraph: list[str] = []
            while index < len(lines) and lines[index].strip() and not _is_block_start(lines[index]):
                paragraph.append(lines[index].strip())
                index += 1
            out.append(f"<p>{_inline(' '.join(paragraph))}</p>")
    return "\n".join(out)


def _is_block_start(line: str) -> bool:
    return bool(_FENCE.match(line) or _HEADING.match(line) or _BULLET.match(line) or _NUMBERED.match(line))
