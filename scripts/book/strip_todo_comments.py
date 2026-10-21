#!/usr/bin/env python3

# mdBook preprocessor that removes `<!-- TODO... -->` comments from chapters.
# They are notes for maintainers and must not reach the HTML source or the search index.

import json
import re
import sys

TODO_COMMENT = re.compile(r"[ \t]*<!--\s*TODO.*?-->[ \t]*\n?", re.DOTALL)


def strip(items):
    for item in items:
        chapter = item.get("Chapter") if isinstance(item, dict) else None
        if chapter is None:
            continue
        chapter["content"] = TODO_COMMENT.sub("", chapter["content"])
        strip(chapter["sub_items"])


if len(sys.argv) > 1 and sys.argv[1] == "supports":
    sys.exit(0)

_context, book = json.load(sys.stdin)
strip(book["sections"])
json.dump(book, sys.stdout)
