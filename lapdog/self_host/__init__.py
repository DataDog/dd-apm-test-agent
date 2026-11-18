"""``lapdog server``: a self-managed, ClickHouse-backed LLM Observability server.

Unlike ``lapdog start`` (a single-user laptop tool), the server is meant to be
reachable over the network by a team. It only ingests LLMObs spans and serves
the Event Platform query API: no terminal, no file serving, no coding-agent
hooks. Spans are stored in a ClickHouse server that lapdog runs and supervises
as a child process, with retention and max-disk limits.
"""
