#!/usr/bin/env python3
"""The Agents Rule of Two (4.16.0): one agent that reads untrusted input, reaches sensitive data and can act.

Meta's "Agents Rule of Two" (October 2025) and Simon Willison's "lethal trifecta" (June 2025) name the same danger:
an agent that combines

  [A] untrustworthy input: text anyone can write (web pages, email, chat, public issues, an open webhook);
  [B] sensitive systems or private data: databases, private repositories, a developer's files and credentials;
  [C] a way to change state or communicate externally: write tools, a shell, fetching any URL (what the agent
      puts in the URL leaves with it), sending messages;

can be steered by a prompt injection in [A] to read [B] and send or change it through [C]. Holding all three needs
a person to approve the steps that act. The harm happens at [C], so supervision is judged there: an agent is
unsupervised when some tool that provides [C] runs without approval.

What a repository shows is configuration, not a session: a configuration that grants all three is reported,
whatever one session uses. Server capabilities come from each server's own documentation (`MCP_SERVERS`); a server
not in the table is listed as of unknown capability and counts for nothing. A capability that depends on what the
configuration does not show (which repositories a GitHub token reaches, and whether they are public) is
"possible": it counts, and lowers the finding's confidence, not its verdict.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

import jh_agent

YES, POSSIBLE = "yes", "possible"
RANK = {"": 0, POSSIBLE: 1, YES: 2}
PROPS = ("A", "B", "C")
WORDS = {"A": "untrusted input", "B": "sensitive data", "C": "a way to act"}

# (pattern over command, args and URL; label; A; B; C; what it gives the agent), from each server's README.
MCP_SERVERS: List[Tuple[str, str, str, str, str, str]] = [
    (r"@modelcontextprotocol/server-github|github-mcp-server|api\.githubcopilot\.com/mcp", "GitHub",
     POSSIBLE, POSSIBLE, YES, "issues and comments others write, private repositories when its token reaches them, "
     "and opening issues and pull requests"),
    (r"@modelcontextprotocol/server-gitlab", "GitLab", POSSIBLE, POSSIBLE, YES,
     "issues others write, private projects when its token reaches them, and changes to projects"),
    (r"mcp-server-fetch|@modelcontextprotocol/server-fetch", "Fetch", YES, "", YES,
     "any web page, and a request to any address (what it puts in the URL leaves with it)"),
    (r"@modelcontextprotocol/server-puppeteer|@playwright/mcp|playwright-mcp|puppeteer-mcp", "browser", YES, "", YES,
     "any web page, and filling in and submitting forms"),
    (r"@modelcontextprotocol/server-brave-search|@brave/brave-search-mcp-server", "Brave Search", YES, "", "",
     "web search results"),
    (r"@modelcontextprotocol/server-slack|slack-mcp-server", "Slack", YES, YES, YES,
     "messages others write, the workspace's channels, and posting messages"),
    (r"@modelcontextprotocol/server-postgres", "PostgreSQL", "", YES, "", "read-only queries on the database"),
    (r"mcp-server-sqlite|@modelcontextprotocol/server-sqlite", "SQLite", "", YES, YES, "reading and writing the database"),
    (r"@modelcontextprotocol/server-redis", "Redis", "", YES, YES, "reading and writing the key-value store"),
    (r"@modelcontextprotocol/server-gdrive", "Google Drive", "", YES, "", "reading and searching Drive files"),
    (r"@modelcontextprotocol/server-sentry|mcp-server-sentry", "Sentry", POSSIBLE, YES, "",
     "error reports, which can carry text users supplied"),
    (r"mcp-server-git(?![\w-])|@modelcontextprotocol/server-git(?![\w-])", "Git", "", POSSIBLE, YES,
     "the repository's history, and making commits"),
    (r"@modelcontextprotocol/server-filesystem", "Filesystem", "", "path", YES,
     "reading and writing files under the folders it is given"),
    (r"@modelcontextprotocol/server-memory|@modelcontextprotocol/server-sequential-thinking|mcp-server-time"
     r"|@modelcontextprotocol/server-everything", "local helper", "", "", "", "no outside input, data or actions"),
    # vendors' own servers, from their documentation
    (r"mcp\.supabase\.com|@supabase/mcp-server-supabase", "Supabase", POSSIBLE, YES, YES,
     "the project's database (rows its users wrote can carry instructions), and SQL and migrations that change it"),
    (r"mcp\.neon\.tech|@neondatabase/mcp-server-neon", "Neon", POSSIBLE, YES, YES,
     "the project's databases (rows its users wrote can carry instructions), and SQL that changes them"),
    (r"mcp\.linear\.app", "Linear", POSSIBLE, YES, YES,
     "issues and comments others write, the workspace's private projects, and creating and changing issues"),
    (r"mcp\.atlassian\.com", "Atlassian", POSSIBLE, YES, YES,
     "Jira issues and Confluence pages others write, the site's private content, and creating and changing them"),
    (r"mcp\.notion\.com|@notionhq/notion-mcp-server", "Notion", POSSIBLE, YES, YES,
     "pages others write or share, the workspace's private pages, and creating and changing pages"),
    (r"mcp\.stripe\.com|@stripe/mcp", "Stripe", "", YES, YES,
     "the account's customers and payments, and creating payments, refunds and links"),
    (r"mcp\.resend\.com|resend-mcp", "Resend", "", POSSIBLE, YES, "the account's contacts, and sending email"),
    (r"@auth0/auth0-mcp-server", "Auth0", "", YES, YES, "the tenant's applications and settings, and changing them"),
    (r"mcp\.context7\.com|@upstash/context7-mcp", "Context7", YES, "", "", "library documentation anyone can publish"),
    (r"firecrawl-mcp|mcp\.firecrawl\.dev", "Firecrawl", YES, "", YES, "any web page, and a request to any address"),
    (r"tavily-mcp|mcp\.tavily\.com", "Tavily", YES, "", "", "web search results and page contents"),
    (r"exa-mcp-server|mcp\.exa\.ai", "Exa", YES, "", "", "web search results and page contents"),
    (r"chrome-devtools-mcp", "Chrome DevTools", YES, "", YES, "any page in a browser, and acting in it"),
    (r"mcp-reddit", "Reddit", YES, "", "", "posts and comments anyone writes"),
]
_MCP_RE = [(re.compile(p, re.I),) + tuple(rest) for p, *rest in MCP_SERVERS]
# The tools that act, for servers whose tool lists are documented (their READMEs): denying all of them in Claude
# Code takes away that server's way to act. Fetch has one tool, so denying it also takes away what it reads.
ACTING_TOOLS = {
    "Fetch": {"fetch"},
    "Slack": {"slack_post_message", "slack_reply_to_thread", "slack_add_reaction"},
    "Filesystem": {"write_file", "edit_file", "create_directory", "move_file", "append_file", "copy_file"},
    "Git": {"git_add", "git_commit", "git_reset", "git_create_branch", "git_checkout", "git_merge", "git_remote"},
    "SQLite": {"write_query", "create_table", "append_insight"},
}

_SENSITIVE_PATH = re.compile(r"^(?:/|~(?:/.*)?|\$\{?HOME\}?(?:/.*)?|%USERPROFILE%.*|[A-Za-z]:\\Users\\[^\\]+\\?|"
                             r"/(?:home|Users)/[^/]+/?|/root/?)$|(?:^|[/\\])\.(?:ssh|aws|config|kube|gnupg|docker)(?:$|[/\\])")


def _path_sensitivity(args: Sequence[str]) -> str:
    """[B] for a filesystem server, from the folders it is given: a home folder, the root or a credential folder is
    sensitive; the project's own folder (relative paths, ${workspaceFolder}) is not; another absolute path may be."""
    paths = [a for a in args if a and not a.startswith("-") and "server-filesystem" not in a]
    if any(_SENSITIVE_PATH.search(p) for p in paths):
        return YES
    if any(p.startswith(("/", "\\")) or re.match(r"[A-Za-z]:\\", p) for p in paths):
        return POSSIBLE
    return ""


def server_capability(server: jh_agent.McpServer) -> Optional[Dict[str, str]]:
    """{label, A, B, C, what} for a server in the table, else None (unknown capability)."""
    hay = " ".join([server.command] + list(server.args) + [server.url])
    for rx, label, a, b, c, what in _MCP_RE:
        if rx.search(hay):
            if label == "GitHub" and read_only_github(server):
                c, what = "", "issues and comments others write, and private repositories when its token reaches " \
                    "them (read-only mode: it cannot open issues or pull requests)"
            elif label in ("Supabase", "Neon") and ("--read-only" in server.args
                                                    or re.search(r"[?&]read_?only=true\b", server.url, re.I)):
                c, what = "", what.split(", and")[0] + " (read-only mode)"
            return {"label": label, "A": a, "B": _path_sensitivity(server.args) if b == "path" else b, "C": c,
                    "what": what}
    return None


def read_only_github(server: jh_agent.McpServer) -> bool:
    """GitHub's MCP server in read-only mode: --read-only, GITHUB_READ_ONLY=1, the /readonly remote URL, or the
    X-MCP-Readonly header (github/github-mcp-server README)."""
    truthy = ("1", "true", "yes")
    return ("--read-only" in server.args or str(server.env.get("GITHUB_READ_ONLY", "")).lower() in truthy
            or re.search(r"/mcp/(?:x/[\w-]+/)?readonly\b", server.url) is not None
            or any(k.lower() == "x-mcp-readonly" and str(v).lower() in truthy for k, v in server.headers.items()))


# ---------------------------------------------------------------- approvals

_ACT_WORDS = {"create", "post", "send", "write", "push", "update", "delete", "remove", "merge", "comment", "fetch",
              "navigate", "click", "fill", "submit", "execute", "exec", "run", "commit", "insert", "edit", "move",
              "upload", "publish", "reply", "forward", "put", "patch", "add", "set", "evaluate", "type", "close",
              "fork", "assign", "label", "request", "drop", "alter", "invite", "archive", "transfer"}


def acting_tool(name: str) -> bool:
    """True when a tool's name says it changes something or reaches out (create_pull_request, fetch,
    post_message); False for get/list/read/search/query names."""
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name.split("__")[-1]).lower().replace("-", "_").split("_")
    return any(w in _ACT_WORDS for w in words)


def _approved(names: Sequence[str], server: str, bare: bool) -> Optional[str]:
    """'all' when a list pre-approves every tool of a server, the first acting tool it pre-approves, else None.
    Claude Code's lists name MCP tools mcp__<server>[__<tool>|__*] (a bare name there is a built-in tool such as
    WebFetch); a client's per-server autoApprove or alwaysAllow list also uses bare tool names (bare=True)."""
    for n in names:
        if n in ("mcp__%s" % server, "mcp__%s__*" % server) or (bare and n == "*"):
            return "all"
        m = re.fullmatch(r"mcp__(.+?)__(.+)", n)
        if (m and m.group(1) != server) or (not m and not bare):
            continue
        tool = m.group(2) if m else n
        if acting_tool(tool):
            return tool
    return None


def _json(path: str, root: str) -> Any:
    """A JSON(C) file inside root (symlinks resolved), else None."""
    real, top = os.path.realpath(path), os.path.realpath(root)
    if not (real.startswith(top.rstrip(os.sep) + os.sep) and os.path.isfile(real)):
        return None
    try:
        with open(real, encoding="utf-8", errors="replace") as fh:
            return jh_agent.loads_jsonc(fh.read(262144))
    except (OSError, ValueError, RecursionError):
        return None


def claude_settings(project: str) -> Dict[str, Any]:
    """Claude Code's project settings (.claude/settings.json, then settings.local.json): whether permissions are
    bypassed, what is pre-approved, which project servers are switched off, and the first file read."""
    out: Dict[str, Any] = {"bypass": False, "allow": [], "deny": [], "disabled": [], "file": "", "line": 1}
    for name in ("settings.json", "settings.local.json") if project else ():
        doc = _json(os.path.join(project, ".claude", name), project)
        if not isinstance(doc, dict):
            continue
        out["file"] = out["file"] or ".claude/" + name
        perms = doc.get("permissions") if isinstance(doc.get("permissions"), dict) else {}
        if perms.get("defaultMode") == "bypassPermissions":
            out["bypass"] = True
        out["allow"] += [x for x in perms.get("allow") or [] if isinstance(x, str)]
        out["deny"] += [x for x in perms.get("deny") or [] if isinstance(x, str)]
        out["disabled"] += [x for x in doc.get("disabledMcpjsonServers") or [] if isinstance(x, str)]
    return out


def vscode_auto_approve(project: str) -> bool:
    doc = _json(os.path.join(project, ".vscode", "settings.json"), project)
    return isinstance(doc, dict) and any(doc.get(k) is True for k in ("chat.tools.autoApprove",
                                                                     "chat.tools.global.autoApprove"))


_BROAD_BASH = {"Bash", "Bash(*)", "Bash(:*)", "Bash(**)"}


def _webfetch_any(allow: Sequence[str]) -> bool:
    """WebFetch pre-approved for any address (WebFetch(domain:docs.example.com) is one site, not a way out)."""
    return any(a in ("WebFetch", "WebFetch(*)", "WebFetch(domain:*)") for a in allow)


# ---------------------------------------------------------------- one agent

def assess(parts: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """parts: [{source, A, B, C, supervised, why, ...}] -> verdict K3 (all three, and some part that acts runs
    without approval), K4 (all three, every acting part approved) or none; certain when no property rests only
    on a 'possible'."""
    best = {k: max((RANK[p[k]] for p in parts), default=0) for k in PROPS}
    out: Dict[str, Any] = {"verdict": "none", "parts": list(parts), "best": best}
    if all(best.values()):
        unsupervised = [p for p in parts if p["C"] and not p["supervised"]]
        out.update(verdict="K3" if unsupervised else "K4", certain=all(v == RANK[YES] for v in best.values()),
                   acting=unsupervised or [p for p in parts if p["C"]])
    return out


def _project_of(abspath: str) -> str:
    folder = os.path.dirname(abspath)
    return os.path.dirname(folder) if os.path.basename(folder) in (".vscode", ".cursor", ".claude", ".roo",
                                                                    ".kilocode", ".codex", ".gemini") else folder


def mcp_agent(rel: str, text: str, abspath: str) -> Optional[Dict[str, Any]]:
    """The agent an MCP client configuration file defines, with the Claude Code or VS Code settings beside it;
    None when the file defines no enabled server."""
    try:
        servers = [s for s in jh_agent.mcp_servers(rel, text) if not s.disabled]
        raw = jh_agent.loads_jsonc(text) if not rel.lower().endswith(".toml") else {}
    except (ValueError, RecursionError):
        return None
    posix = rel.replace(os.sep, "/").lower()
    project = _project_of(abspath)
    claude = claude_settings(project if os.path.basename(posix) == ".mcp.json" else "")
    # Claude Code applies deny rules even when permissions are bypassed
    servers = [s for s in servers if s.name not in claude["disabled"]
               and not {"mcp__%s" % s.name, "mcp__%s__*" % s.name} & set(claude["deny"])]
    if not servers:
        return None
    container: Dict[str, Any] = {}
    if isinstance(raw, dict):
        for key in ("mcpServers", "servers", "mcp"):
            if isinstance(raw.get(key), dict):
                container = raw[key]
                break
    everything = claude["bypass"] or (posix.endswith(".vscode/mcp.json") and vscode_auto_approve(project)) \
        or (posix.endswith(".toml") and re.search(r'(?m)^\s*approval_policy\s*=\s*"never"', text) is not None)
    parts, unknown = [], []
    for s in servers:
        cap = server_capability(s)
        if cap is None:
            unknown.append(s.name)
            continue
        denied = {d.split("__", 2)[2] for d in claude["deny"] if d.startswith("mcp__%s__" % s.name)}
        if cap["label"] in ACTING_TOOLS and ACTING_TOOLS[cap["label"]] <= denied:
            cap = dict(cap, C="", A="" if cap["label"] == "Fetch" else cap["A"],
                       what=cap["what"] + " (its acting tools are denied)")
        spec = container.get(s.name) if isinstance(container.get(s.name), dict) else {}
        listed = [x for k in ("autoApprove", "alwaysAllow") for x in (spec.get(k) or []) if isinstance(x, str)]
        approved = "all" if everything else (_approved(claude["allow"], s.name, False)
                                             or _approved(listed, s.name, True))
        why = ("permissions are bypassed" if claude["bypass"] else "every tool call is auto-approved") if everything \
            else ("every tool of '%s' is pre-approved" % s.name if approved == "all"
                  else "'%s' is pre-approved" % approved if approved else "")
        parts.append({"source": "%s server '%s'" % (cap["label"], s.name), "file": rel, "line": s.line,
                      "A": cap["A"], "B": cap["B"], "C": cap["C"], "what": cap["what"],
                      "supervised": not approved, "why": why})
    if claude["file"]:
        if (claude["bypass"] or _webfetch_any(claude["allow"])) and "WebFetch" not in claude["deny"]:
            parts.append({"source": "Claude Code WebFetch", "file": claude["file"], "line": claude["line"],
                          "A": YES, "B": "", "C": YES, "what": "any web page, and a request to any address",
                          "supervised": False, "why": "permissions are bypassed" if claude["bypass"]
                          else "WebFetch is pre-approved for any address"})
        if (claude["bypass"] or any(a in _BROAD_BASH for a in claude["allow"])) \
                and not _BROAD_BASH & set(claude["deny"]):
            parts.append({"source": "Claude Code shell", "file": claude["file"], "line": claude["line"],
                          "A": "", "B": POSSIBLE, "C": YES, "what": "any command, with the developer's files and "
                          "credentials", "supervised": False, "why": "permissions are bypassed" if claude["bypass"]
                          else "any shell command is pre-approved"})
    out = assess(parts)
    out["unknown"] = unknown
    return out


# ---------------------------------------------------------------- n8n AI Agent nodes

# n8n tool nodes by type after the package prefix: (label, A, B, C, kind). kind "db": [C] only for a writing
# operation (unknown operation: possible); "msg": a reading operation drops [C], a writing one [A] and [B];
# "http": [A] and [C] when the AI picks the address, [C] for a writing method to a fixed address.
N8N_TOOLS: Dict[str, Tuple[str, str, str, str, str]] = {
    "httpRequestTool": ("HTTP Request", YES, "", YES, "http"), "toolHttpRequest": ("HTTP Request", YES, "", YES, "http"),
    "toolSerpApi": ("SerpAPI search", YES, "", "", ""), "toolWikipedia": ("Wikipedia", YES, "", "", ""),
    "toolSearXng": ("SearXNG search", YES, "", "", ""),
    "gmailTool": ("Gmail", YES, YES, YES, "msg"), "microsoftOutlookTool": ("Outlook", YES, YES, YES, "msg"),
    "slackTool": ("Slack", YES, YES, YES, "msg"), "telegramTool": ("Telegram", YES, POSSIBLE, YES, "msg"),
    "githubTool": ("GitHub", POSSIBLE, POSSIBLE, YES, "msg"), "gitlabTool": ("GitLab", POSSIBLE, POSSIBLE, YES, "msg"),
    "postgresTool": ("Postgres", "", YES, POSSIBLE, "db"), "mySqlTool": ("MySQL", "", YES, POSSIBLE, "db"),
    "microsoftSqlTool": ("Microsoft SQL", "", YES, POSSIBLE, "db"), "mongoDbTool": ("MongoDB", "", YES, POSSIBLE, "db"),
    "supabaseTool": ("Supabase", "", YES, POSSIBLE, "db"), "redisTool": ("Redis", "", YES, POSSIBLE, "db"),
    "googleSheetsTool": ("Google Sheets", "", YES, POSSIBLE, "db"), "airtableTool": ("Airtable", "", YES, POSSIBLE, "db"),
    "googleDriveTool": ("Google Drive", "", YES, POSSIBLE, "db"), "notionTool": ("Notion", POSSIBLE, YES, POSSIBLE, "db"),
    "sendEmailTool": ("Send Email", "", "", YES, ""), "emailSendTool": ("Send Email", "", "", YES, ""),
}
_READ_OP = re.compile(r"(?i)^(?:get|list|read|search|select|find|lookup|history|replies)")
_WRITE_OP = re.compile(r"(?i)^(?:insert|update|upsert|delete|executeQuery|append|create|clear|remove|send|post|reply|"
                       r"edit|lock)")
_UNTRUSTED_TRIGGERS = {"emailReadImap": "email", "gmailTrigger": "Gmail", "microsoftOutlookTrigger": "Outlook",
                       "telegramTrigger": "Telegram", "slackTrigger": "Slack", "githubTrigger": "GitHub",
                       "rssFeedReadTrigger": "RSS feed"}


def n8n_tool(node: Dict[str, Any]) -> Optional[Tuple[str, str, str, str]]:
    """(label, A, B, C) for an n8n tool node in the table, else None."""
    import jh_n8n
    short = jh_n8n._short(node) or ""
    if short not in N8N_TOOLS:
        return None
    label, a, b, c, kind = N8N_TOOLS[short]
    p = node.get("parameters") if isinstance(node.get("parameters"), dict) else {}
    op = str(p.get("operation", ""))
    if kind == "msg" and not op and str(p.get("resource", "message")) in ("message", "issue"):
        op = "send"     # an export leaves out defaults: these nodes default to sending a message or creating an issue
    if kind == "db":
        c = YES if _WRITE_OP.match(op) else "" if _READ_OP.match(op) else POSSIBLE
    elif kind == "msg" and op:
        if _READ_OP.match(op):
            c = ""
        elif _WRITE_OP.match(op):
            a = b = ""          # a node fixed to sending or creating reads neither others' text nor private data
    elif kind == "http":
        url, method = p.get("url"), str(p.get("method") or p.get("requestMethod") or "GET").upper()
        if isinstance(url, str) and url and not jh_n8n.dynamic(url):
            a, c = "", (YES if method not in ("GET", "HEAD") else "")
    return label, a, b, c


def n8n_agents(sf: Any) -> List[Dict[str, Any]]:
    """Every enabled LangChain AI Agent node in a workflow export, assessed. A tool that reaches the agent through
    a human review node (n8n's <service>HitlTool) is supervised; any other tool runs as the model decides."""
    import jh_n8n
    out = []
    for flow in jh_n8n.flows(sf):
        raw = {n["raw"]["id"]: n["raw"] for n in flow["nodes"]}
        fed = jh_n8n._fed(flow)
        ups: Dict[str, List[str]] = {}
        tools_of: Dict[str, List[str]] = {}
        for src, dst, channel in flow["edges"]:
            if channel == "main":
                ups.setdefault(dst, []).append(src)
            elif channel == "ai_tool":
                tools_of.setdefault(dst, []).append(src)
        for nid, node in sorted(raw.items()):
            if node.get("type") != "@n8n/n8n-nodes-langchain.agent" or node.get("disabled") is True:
                continue
            parts = []
            if nid in fed:
                kind, name = fed[nid]
                parts.append({"source": "open %s trigger '%s'" % (kind, name), "node": name, "A": YES, "B": "",
                              "C": "", "supervised": True, "why": "", "what": "anyone with the URL writes its input"})
            seen, todo = set(), list(ups.get(nid, ()))
            while todo:
                cur = todo.pop()
                if cur in seen or cur not in raw:
                    continue
                seen.add(cur)
                short = jh_n8n._short(raw[cur]) or ""
                if short in _UNTRUSTED_TRIGGERS and raw[cur].get("disabled") is not True:
                    parts.append({"source": "%s trigger '%s'" % (_UNTRUSTED_TRIGGERS[short], raw[cur]["name"]),
                                  "node": raw[cur]["name"], "A": YES, "B": "", "C": "", "supervised": True,
                                  "why": "", "what": "messages anyone can send become its input"})
                todo.extend(ups.get(cur, ()))
            for src in sorted(set(tools_of.get(nid, ()))):
                if src not in raw or raw[src].get("disabled") is True:
                    continue
                gate = str(raw[src].get("type", "")).endswith("HitlTool")
                for tid in (sorted(set(tools_of.get(src, ()))) if gate else [src]):
                    if tid not in raw or raw[tid].get("disabled") is True:
                        continue
                    cap = n8n_tool(raw[tid])
                    if cap is None:
                        continue
                    label, a, b, c = cap
                    parts.append({"source": "%s tool '%s'" % (label, raw[tid]["name"]), "node": raw[tid]["name"],
                                  "A": a, "B": b, "C": c, "supervised": gate, "what": "",
                                  "why": "" if gate else "n8n runs an agent's tools without asking"})
            verdict = assess(parts)
            verdict.update(agent=node["name"], unknown=[], raw=node)
            out.append(verdict)
    return out


def sources(verdict: Dict[str, Any], prop: str, limit: int = 3) -> str:
    names = sorted({p["source"] for p in verdict["parts"] if p[prop]})
    return ", ".join(names[:limit]) + (" and %d more" % (len(names) - limit) if len(names) > limit else "")
