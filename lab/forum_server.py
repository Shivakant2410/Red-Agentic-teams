"""Invision-style community fixture for the forum engagement dry-run.

Surfaces shaped like the real target class (forum.1win.io per the program scope):
  POST /login              {"username","password"} -> {"token","user"}   (JSON)
  GET  /openapi.json       documents the API paths (deterministic recon reads this)
  GET  /                   HTML index of forums (forum 5 = restricted staff area)
  GET  /forum/{id}         topic list; forum 5 is staff-only unless
                           FORUM_ACL_PROFILE=member-readable
  GET  /topic/{id}         HTML page; replies rendered RAW (unescaped) only when
                           FORUM_XSS_PROFILE=raw-echo — the stored-XSS sink
  POST /topic/{id}/reply   form field `content`; any valid member token
  GET  /pm/{id}            private message; owner-only unless FORUM_PM_PROFILE=open

All profiles default BENIGN (escaped rendering, staff-only forum, owner-only
PMs); the dry-run runner turns the flaws on explicitly. Fixed tokens keep the
fixture deterministic across proof replays (k-of-n needs stable credentials).
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import json
import os
import sys
from urllib.parse import parse_qs, urlsplit

USERS = {"member-a": ("pw-a", "tok-a"),
         "member-b": ("pw-b", "tok-b"),
         "staff": ("pw-s", "tok-staff")}
TOKENS = {tok: user for user, (_, tok) in USERS.items()}

FORUMS = {"1": "General Discussion", "5": "Staff Announcements"}
TOPICS = {"7": {"title": "Welcome & feedback", "forum": 1},
          "9": {"title": "Internal roadmap", "forum": 5}}
REPLIES = {"7": [("member-a", "Welcome to the community! Please follow the rules.")],
           "9": [("staff", "Roadmap draft — staff eyes only.")]}


class Handler(BaseHTTPRequestHandler):
    # -- helpers ----------------------------------------------------------------

    def _token_user(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        return TOKENS.get(auth.removeprefix("Bearer ").strip())

    def _send(self, status: int, body: bytes, ctype: str) -> None:
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
        path = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""

        if path == "/login":
            try:
                creds = json.loads(raw or "{}")
            except json.JSONDecodeError:
                return self._json(400, {"error": "bad_json"})
            entry = USERS.get(creds.get("username", ""))
            if entry and entry[0] == creds.get("password", ""):
                return self._json(200, {"token": entry[1], "user": creds["username"]})
            return self._json(401, {"error": "bad_credentials"})

        if path.startswith("/topic/") and path.endswith("/reply"):
            user = self._token_user()
            if user is None:
                return self._json(401, {"error": "unauthorized"})
            tid = path[len("/topic/"):-len("/reply")]
            if tid not in TOPICS:
                return self._json(404, {"error": "no_topic"})
            content = (parse_qs(raw).get("content") or [""])[0]
            REPLIES.setdefault(tid, []).append((user, content))
            return self._json(200, {"ok": True, "stored_chars": len(content)})

        return self._json(404, {"error": "not found"})

    def do_GET(self):
        path = urlsplit(self.path).path

        if path == "/openapi.json":
            return self._json(200, {
                "openapi": "3.0.0",
                "info": {"title": "Community API", "version": "1.0.0"},
                "paths": {
                    "/login": {"post": {"summary": "Exchange credentials for a bearer token"}},
                    "/forum/{forum_id}": {"get": {"summary": "Topic list for a forum"}},
                    "/topic/{topic_id}": {"get": {"summary": "HTML page of a topic and replies"}},
                    "/topic/{topic_id}/reply": {"post": {"summary": "Post a reply (form: content)"}},
                    "/pm/{pm_id}": {"get": {"summary": "Read a private message"}},
                },
            })

        if path == "/":
            items = "".join(
                f'<li><a href="/forum/{fid}">{name}</a>'
                + (" (restricted)" if fid == 5 else "") + "</li>"
                for fid, name in FORUMS.items())
            return self._html(200, f"<html><head><title>Community</title></head>"
                                   f"<body><h1>Forums</h1><ul>{items}</ul></body></html>")

        if path.startswith("/forum/"):
            fid = path[len("/forum/"):]
            if fid not in FORUMS:
                return self._json(404, {"error": "no_forum"})
            user = self._token_user()
            if fid == "5":
                staff_ok = user == "staff"
                member_ok = (user is not None
                             and os.getenv("FORUM_ACL_PROFILE") == "member-readable")
                if not (staff_ok or member_ok):
                    return self._json(403, {"error": "staff_only"})
            topics = "".join(
                f'<li><a href="/topic/{tid}">{t["title"]}</a></li>'
                for tid, t in TOPICS.items() if t["forum"] == int(fid))
            return self._html(200, f"<html><body><h1>{FORUMS[fid]}</h1>"
                                   f'<ul>{topics or "<li>(no topics)</li>"}</ul></body></html>')

        if path.startswith("/topic/") and path.endswith("/reply"):
            return self._json(405, {"error": "use_post"})

        if path.startswith("/topic/"):
            tid = path[len("/topic/"):]
            if tid not in TOPICS:
                return self._json(404, {"error": "no_topic"})
            raw_echo = os.getenv("FORUM_XSS_PROFILE") == "raw-echo"
            parts = [f"<html><head><title>{TOPICS[tid]['title']}</title></head>",
                     f"<body><h1>{html.escape(TOPICS[tid]['title'])}</h1>"]
            for author, content in REPLIES.get(tid, []):
                body = content if raw_echo else html.escape(content)
                parts.append(f'<div class="reply" data-author="{author}">{body}</div>')
            parts.append("</body></html>")
            return self._html(200, "".join(parts))

        if path.startswith("/pm/"):
            pid = path[len("/pm/"):]
            user = self._token_user()
            owner = "member-a"          # pm/1 belongs to member-a
            if user is None:
                return self._json(401, {"error": "unauthorized"})
            if user != owner and os.getenv("FORUM_PM_PROFILE") != "open":
                return self._json(403, {"error": "not_your_pm"})
            return self._json(200, {"pm_id": pid, "to": owner,
                                    "body": "Reset link: https://community.example/reset/xyz"})

        return self._json(404, {"error": "not found"})

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8898
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
