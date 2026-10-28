"""Persistent, semantic memory backend for ExperienceStore — HelixDB (graph+vector).

Closes the real gap a flat tag-matched JSON store has: `redteam/memory.py`'s
ExperienceStore learns vuln-CLASS tradecraft ("how to prove CWE-639 in general") but has
no representation of APP-SHAPE patterns ("this app uses a two-step login: POST username
alone, then password keyed by username in the URL") because that needs similarity recall,
not exact tag overlap — two differently-worded descriptions of the same app shape never
share a tag. HelixDB gives semantic (vector) recall plus real graph relationships between
lessons/patterns, so a new target that merely RESEMBLES a past one in embedding space
still surfaces what worked there, instead of the agent starting blind on every new app.

Lifecycle (same pattern as sandbox/docker_kali.py — a managed local Docker service):

    server = HelixServer()
    server.start()                      # pull/run the container, wait for it to answer
    backend = HelixBackend(server.client, embedder)
    store = ExperienceStore(backend=backend)
    ...
    server.stop()
"""
