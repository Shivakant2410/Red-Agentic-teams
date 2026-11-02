"""Blogment — tiny blog engine fixture for the red-team benchmark.

Surfaces (HTML-only target: no /openapi.json, no JSON API beyond error bodies):
  GET /                          HTML index of 3 posts + footer "Blogment 1.2.0"
  GET /post/{id}                 HTML page; title/body/comments ALWAYS html.escape()d.
                                 Post 1 ships a seeded comment containing <b>guidelines</b>
                                 as the always-escaped oracle (escaping here is NOT a flaw).
  GET /search?q={term}           HTML "Results for {q}" heading + <li> list of matching
                                 post titles (case-insensitive substring over titles+bodies)
  GET /robots.txt                points crawlers at /backup/ (recon breadcrumb)
  GET /backup/blogment-2024.sql  fabricated SQL dump; 404 unless the backup profile is on
  POST (any path)                405

Flaw profiles (env vars, one per flaw, DEFAULT BENIGN when unset):
  BLOGMENT_REFLECT_PROFILE=raw     /search renders the RAW q value UNESCAPED in the
                                   heading — the reflected-XSS sink (CWE-79)
  BLOGMENT_BACKUP_PROFILE=exposed  /backup/blogment-2024.sql returns 200 text/plain with
                                   a fake dump containing credential material (CWE-200)

Everything below is deterministic stdlib-only fakery: no randomness, no command
execution, no network egress. The SQL dump is invented fixture data — the bcrypt-style
hash and the "first pet name" hint are inert strings, not live credentials.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import json
import os
import sys
from urllib.parse import parse_qs, urlsplit

POSTS = {"1": {"title": "Welcome to Blogment", "body": "Thanks for installing Blogment 1.2.0."},
         "2": {"title": "Writing your first post", "body": "Use the editor toolbar to format markdown."},
         "3": {"title": "Moderation policy", "body": "Comments are reviewed before publication."}}

# Post 1's seeded comment embeds raw HTML on purpose: the page must always escape it,
# so "&lt;b&gt;guidelines&lt;/b&gt;" in the response is the escaping oracle.
COMMENTS = {"1": [("admin", "Please read the <b>guidelines</b> before posting.")]}

BACKUP_FILE = "/backup/blogment-2024.sql"

# Fabricated dump: header + CREATE/INSERT for users (with credential material) + 3 posts.
# Exactly 28 lines including the trailing newline.
SQL_DUMP = """-- Blogment backup 2024

SET FOREIGN_KEY_CHECKS = 0;

CREATE TABLE users (
  id INT PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  password_hint VARCHAR(255),
  created_at DATETIME
);

INSERT INTO users (id, email, password_hash, password_hint, created_at) VALUES
  (1, 'admin@blogment.local', '$2y$10$e0MYzXyjpJS7Pd0RVvHwHe1HlCkAmVjuLjCvYE5YVEMkGpGbhPRvi', 'first pet name', '2024-01-15 09:30:00');

CREATE TABLE posts (
  id INT PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  body TEXT
);

INSERT INTO posts (id, title, body) VALUES
  (1, 'Welcome to Blogment', 'Thanks for installing Blogment 1.2.0.'),
  (2, 'Writing your first post', 'Use the editor toolbar to format markdown.'),
  (3, 'Moderation policy', 'Comments are reviewed before publication.');

SET FOREIGN_KEY_CHECKS = 1;
-- End of backup
"""


class Handler(BaseHTTPRequestHandler):
    # -- helpers ----------------------------------------------------------------

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        # Bodies MUST be bytes: writing str into wfile has caused IncompleteRead
        # in a prior fixture. Every caller encodes before reaching here.
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def _html(self, status: int, markup: str) -> None:
        self._send(status, markup.encode(), "text/html; charset=utf-8")

    # -- routes -------------------------------------------------------------------

    def do_POST(self):
        # Consume any request body so the socket stays coherent, then refuse:
        # this is a read-only blog engine, every POST is a 405.
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        return self._json(405, {"error": "method_not_allowed"})

    def do_GET(self):
        path = urlsplit(self.path).path

        if path == "/":
            items = "".join(
                f'<li><a href="/post/{pid}">{html.escape(p["title"])}</a></li>'
                for pid, p in POSTS.items())
            return self._html(200, "<html><head><title>Blogment</title></head>"
                                   "<body><h1>Blogment</h1><ul>" + items + "</ul>"
                                   '<form action="/search" method="get">'
                                   '<input name="q" placeholder="search posts"></form>'
                                   "<footer>Blogment 1.2.0</footer></body></html>")

        if path.startswith("/post/"):
            pid = path[len("/post/"):]
            if pid not in POSTS:
                return self._json(404, {"error": "no_post"})
            post = POSTS[pid]
            parts = [f'<html><head><title>{html.escape(post["title"])}</title></head>',
                     f'<body><h1>{html.escape(post["title"])}</h1>',
                     f'<div class="body">{html.escape(post["body"])}</div>',
                     "<h2>Comments</h2>"]
            comments = COMMENTS.get(pid, [])
            if comments:
                for author, text in comments:
                    # Always escaped — including the seeded <b>guidelines</b> oracle.
                    parts.append(f'<div class="comment" data-author="{html.escape(author)}">'
                                 f'{html.escape(text)}</div>')
            else:
                parts.append("<p>No comments yet.</p>")
            parts.append('<a href="/">Back to index</a></body></html>')
            return self._html(200, "".join(parts))

        if path == "/search":
            q = (parse_qs(urlsplit(self.path).query).get("q") or [""])[0]
            # FLAW 1 (CWE-79): with BLOGMENT_REFLECT_PROFILE=raw the q value goes
            # into the heading UNESCAPED. Default behaviour escapes it.
            heading_q = q if os.getenv("BLOGMENT_REFLECT_PROFILE") == "raw" else html.escape(q)
            term = q.lower()
            matches = [p for p in POSTS.values()
                       if term in p["title"].lower() or term in p["body"].lower()]
            if matches:
                hits = "".join(f'<li><a href="/post/{pid}">{html.escape(p["title"])}</a></li>'
                               for pid, p in POSTS.items() if p in matches)
                listing = f"<ul>{hits}</ul>"
            else:
                listing = "<p>No matches.</p>"
            return self._html(200, "<html><head><title>Search - Blogment</title></head>"
                                   f"<body><h2>Results for {heading_q}</h2>"
                                   f"{listing}"
                                   '<a href="/">Back to index</a></body></html>')

        if path == "/robots.txt":
            return self._send(200, b"User-agent: *\nDisallow: /backup/\n", "text/plain")

        if path.startswith("/backup/"):
            # FLAW 2 (CWE-200): with BLOGMENT_BACKUP_PROFILE=exposed the SQL dump
            # (credential material) is served. Default behaviour: 404 like any
            # other unknown /backup/ path.
            if path == BACKUP_FILE and os.getenv("BLOGMENT_BACKUP_PROFILE") == "exposed":
                return self._send(200, SQL_DUMP.encode(), "text/plain")
            return self._json(404, {"error": "not found"})

        return self._json(404, {"error": "not found"})

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8895
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
