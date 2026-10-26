#!/usr/bin/env python3
"""Offline connectivity discovery for `jankhunt42 map` (What can it hurt?).

Adapters read repository text (from the working tree or from git objects;
both arrive as (path, text) pairs) and emit typed nodes and edges into
jh_graph.Graph with a sanitized receipt for every claim. Nothing is
executed, resolved, probed, or connected to. Every adapter is line- or
structure-based and bounded.

Evidence states used here:
  observed  - the artifact directly contains the statement (a literal
              client endpoint, an SQL verb in a string, an HTTP call)
  declared  - configuration or manifest says so (env value, k8s spec,
              workflow permissions, IaC role assignment)
  inferred  - heuristic only (an SDK import, a manifest dependency, an
              endpoint resolved through an environment-variable name)
  provider-verified - only from an operator-supplied inventory that lives
              outside the scanned repository
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import jh_agent
import jh_egress
import jh_graph as G
import jh_yaml
from jh_core import (TOOL, VERSION, run_git, DEFAULT_SKIP_DIRS, discover_files, is_mcp_config, is_test_path,
                     safe_text, sanitize, detect_lang, _is_skipped_file)


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

@dataclass
class Item:
    rel: str
    text: str

    def __post_init__(self) -> None:
        # A UTF-8 byte-order mark (common in .NET appsettings.json) is not content.
        if self.text.startswith("\ufeff"):
            self.text = self.text[1:]


@dataclass
class Collected:
    items: List[Item] = field(default_factory=list)
    considered: int = 0
    skipped: Dict[str, int] = field(default_factory=dict)
    skipped_paths: List[str] = field(default_factory=list)
    max_files_reached: bool = False

    def skip(self, reason: str, rel: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1
        if len(self.skipped_paths) < 5000:
            self.skipped_paths.append(rel)


def _decode(raw: bytes) -> Optional[str]:
    if b"\x00" in raw[:8192]:
        return None
    return raw.decode("utf-8", "replace")


def collect_worktree(root: str, paths: Sequence[str], excludes: Sequence[str],
                     max_files: int, max_bytes: int) -> Tuple[str, Collected]:
    base, files = discover_files(paths or [root], excludes=excludes, max_files=max_files,
                                 max_bytes=max_bytes)
    col = Collected(considered=len(files), max_files_reached=len(files) >= max_files)
    for p in files:
        rel = os.path.relpath(str(p), str(base)).replace(os.sep, "/")
        try:
            raw = p.read_bytes()
        except OSError:
            col.skip("unreadable", rel)
            continue
        text = _decode(raw)
        if text is None:
            col.skip("binary", rel)
            continue
        col.items.append(Item(rel, text))
    return str(base), col


class GitError(Exception):
    pass


def _git(root: str, args: Sequence[str], data: Optional[bytes] = None, timeout: int = 60) -> bytes:
    try:
        proc = run_git(["git", "-C", root] + list(args), input=data, capture_output=True,
                              timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise GitError(str(exc))
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise GitError(msg[0] if msg else "git %s failed" % args[0])
    return proc.stdout


def git_toplevel(path: str) -> Optional[str]:
    try:
        return _git(path, ["rev-parse", "--show-toplevel"]).decode().strip()
    except GitError:
        return None


def git_revision(path: str, rev: str = "HEAD") -> Optional[str]:
    try:
        return _git(path, ["rev-parse", "--verify", "--quiet", rev + "^{commit}"]).decode().strip() or None
    except GitError:
        return None


def git_dirty(path: str) -> Optional[bool]:
    try:
        out = _git(path, ["status", "--porcelain", "--untracked-files=normal"])
    except GitError:
        return None
    return bool(out.strip())


def collect_git(root: str, rev: str, excludes: Sequence[str], max_files: int,
                max_bytes: int, prefix: str = "") -> Collected:
    """Read a committed tree from git objects only. The working tree is never
    consulted, so dirty or untracked files cannot leak into a --base diff."""
    listing = _git(root, ["ls-tree", "-r", "-z", "--long", rev] + ([prefix] if prefix else []))
    col = Collected()
    wanted: List[Tuple[str, str]] = []
    pats = list(excludes) + ["*.min.js", "*.min.css", "*.map", "*.snap", "*.lock"]
    for entry in listing.decode("utf-8", "replace").split("\0"):
        if not entry:
            continue
        meta, _, rel = entry.partition("\t")
        parts = meta.split()
        if len(parts) < 4:
            continue
        mode, otype, sha_, size = parts[0], parts[1], parts[2], parts[3]
        col.considered += 1
        if otype != "blob" or mode in ("120000", "160000"):
            col.skip("symlink-or-submodule", rel)
            continue
        segs = rel.split("/")
        if any(s in DEFAULT_SKIP_DIRS for s in segs[:-1]):
            col.skip("excluded", rel)
            continue
        if any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(segs[-1], p) for p in pats) \
                or _is_skipped_file(Path(rel)):
            col.skip("excluded", rel)
            continue
        try:
            if int(size) > max_bytes:
                col.skip("too-large", rel)
                continue
        except ValueError:
            size = "unknown"  # unexpected ls-tree size field: read it; the byte cap still applies on load
        if len(wanted) >= max_files:
            col.max_files_reached = True
            col.skip("file-cap", rel)
            continue
        wanted.append((rel, sha_))
    if not wanted:
        return col
    out = _git(root, ["cat-file", "--batch"], data="".join(s + "\n" for _, s in wanted).encode(), timeout=120)
    pos = 0
    for rel, _ in wanted:
        nl = out.index(b"\n", pos)
        header = out[pos:nl].split()
        size = int(header[2])
        body = out[nl + 1: nl + 1 + size]
        pos = nl + 1 + size + 1
        text = _decode(body)
        if text is None:
            col.skip("binary", rel)
            continue
        col.items.append(Item(rel, text))
    return col


# ---------------------------------------------------------------------------
# Context shared by adapters
# ---------------------------------------------------------------------------

_ENDPOINTISH = re.compile(r"(?i)(URL|URI|DSN|CONN|DATABASE|(^|_)DB($|_)|HOST|ENDPOINT|BROKER|REDIS|MONGO|"
                          r"POSTGRES|PG|MYSQL|AMQP|KAFKA|BUCKET|STORAGE|QUEUE|SERVICE_BUS|COSMOS|API_BASE|BASE_ADDRESS)")
_SECRETISH = re.compile(r"(?i)(PASSWORD|PASSWD|SECRET|TOKEN|(^|_)KEY($|_)|APIKEY|USER(NAME)?$|PWD|CREDENTIAL)")
MAX_LINE = 4000


def endpointish(name: str) -> bool:
    return bool(_ENDPOINTISH.search(name)) and not _SECRETISH.search(name)


SECRET_STORES = ("azure-keyvault",)


class Ctx:
    def __init__(self, graph: G.Graph, app_name: str):
        self.g = graph
        self.app = graph.add_node("application", ["repository"], app_name, trust_domain="internal",
                                  attributes={"role": "repository code"})
        self.g.nodes[self.app]["classification_source"] = "assumption"
        # env/config definitions: NAME -> [(endpoint, evidence id, env hint, path)]
        self.defs: Dict[str, List[Tuple[Dict[str, Any], str, str, str]]] = {}
        # code-side env usages: (NAME, path, line, families in file)
        self.uses: List[Tuple[str, str, int, Set[Tuple[str, str]], str]] = []
        self.families_seen: Set[Tuple[str, str]] = set()
        self.k8s_roles: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
        self.k8s_bindings: List[Tuple[Dict[str, Any], str, int]] = []
        self.manifest_deps: List[Tuple[Tuple[str, str], str, int, str]] = []
        self.openapi: List[Tuple[str, List[Dict[str, Any]], List[str]]] = []
        # azurerm/azuread resource and data blocks, resolved across files
        self.tf_azure: List[Dict[str, Any]] = []
        # NAME -> distinct string values assigned anywhere in Python code
        self.str_vars: Dict[str, Set[str]] = {}
        self.parse_failures: List[Dict[str, str]] = []
        self.templates: List[str] = []
        self.by_adapter: Dict[str, int] = {}
        self.inspected: List[str] = []
        self.warnings: List[str] = []

    def endpoint_node(self, ep: Dict[str, Any], env_hint: str = "unknown", unresolved_hint: str = "",
                      evidence: Optional[str] = None, label_suffix: str = "") -> Optional[str]:
        nid = self._endpoint_node(ep, env_hint, unresolved_hint, evidence, label_suffix)
        if nid and self.g.nodes[nid]["attributes"].get("engine") in SECRET_STORES \
                and self.g.nodes[nid]["sensitivity"] == "unknown":
            # a secret store holds credentials, like a Kubernetes Secret
            self.g.nodes[nid]["sensitivity"] = "restricted"
            self.g.nodes[nid]["classification_source"] = "resource-type: credentials"
        return nid

    def _endpoint_node(self, ep: Dict[str, Any], env_hint: str, unresolved_hint: str,
                       evidence: Optional[str], label_suffix: str) -> Optional[str]:
        kind = ep["kind"]
        engine = ep.get("engine") or kind
        if ep.get("resolved"):
            env = G.infer_environment(ep.get("host", ""), ep.get("path", ""))
            if env == "unknown":
                env = env_hint
            host = ep.get("host", "")
            td = G.trust_domain_for_host(host, engine)
            key = [engine, host, ep.get("port") or "", env]
            attrs: Dict[str, Any] = {"engine": engine}
            if host:
                attrs["host"] = host
            if str(ep.get("port") or "").isdigit() and 0 < int(ep["port"]) < 65536:
                attrs["port"] = int(ep["port"])
            if ep.get("path"):
                attrs["databases" if kind == "database" else "paths"] = [ep["path"]]
            label = G.endpoint_label({**ep, "path": ""}) if kind == "database" else G.endpoint_label(ep)
            return self.g.add_node(kind, key, label + label_suffix, trust_domain=td, environment=env,
                                   attributes=attrs, evidence=evidence)
        hint = unresolved_hint or "unresolved"
        label = "%s (unresolved target%s)" % (engine, ": " + hint if unresolved_hint else "")
        return self.g.add_node(kind, [engine, "unresolved", hint], label, trust_domain="unknown",
                               environment=env_hint,
                               attributes={"engine": engine, "unresolved": True,
                                           **({"via": [unresolved_hint]} if unresolved_hint else {})},
                               evidence=evidence)

    def define(self, name: str, ep: Dict[str, Any], ev: str, env_hint: str, path: str) -> None:
        for n in {name, name.upper(), name.replace(":", "__"), name.split(":")[-1]}:
            self.defs.setdefault(n, []).append((ep, ev, env_hint, path))


def _file_env(rel: str) -> str:
    base = rel.lower()
    return G.infer_environment(*re.split(r"[/\\]", base))


# ---------------------------------------------------------------------------
# Language adapters (Python, JS/TS, .NET)
# ---------------------------------------------------------------------------

# module/package -> (kind, engine, known host or "")
PY_IMPORTS = {
    "psycopg": ("database", "postgresql", ""), "psycopg2": ("database", "postgresql", ""),
    "asyncpg": ("database", "postgresql", ""), "pg8000": ("database", "postgresql", ""),
    "pymysql": ("database", "mysql", ""), "MySQLdb": ("database", "mysql", ""),
    "mysql.connector": ("database", "mysql", ""), "aiomysql": ("database", "mysql", ""),
    "pyodbc": ("database", "sqlserver", ""), "pymssql": ("database", "sqlserver", ""),
    "sqlite3": ("database", "sqlite", ""), "aiosqlite": ("database", "sqlite", ""),
    "pymongo": ("database", "mongodb", ""), "motor": ("database", "mongodb", ""),
    "redis": ("database", "redis", ""), "aioredis": ("database", "redis", ""),
    "cassandra": ("database", "cassandra", ""), "neo4j": ("database", "neo4j", ""),
    "databricks": ("database", "databricks", ""), "snowflake": ("database", "snowflake", ""),
    "google.cloud.bigquery": ("database", "bigquery", ""),
    "azure.cosmos": ("database", "cosmos", ""),
    "boto3": ("external", "aws", ""), "botocore": ("external", "aws", ""),
    "azure.storage.blob": ("storage", "azure-blob", ""), "azure.servicebus": ("queue", "servicebus", ""),
    "google.cloud.storage": ("storage", "gcs", ""), "google.cloud.pubsub": ("queue", "pubsub", ""),
    "pika": ("queue", "amqp", ""), "aio_pika": ("queue", "amqp", ""), "kafka": ("queue", "kafka", ""),
    "confluent_kafka": ("queue", "kafka", ""), "aiokafka": ("queue", "kafka", ""),
    "openai": ("external", "openai", "api.openai.com"),
    "anthropic": ("external", "anthropic", "api.anthropic.com"),
    "smtplib": ("external", "smtp", ""),
    # The stack AI app builders reach for: hosted databases, spreadsheets as
    # databases, payments, messaging, and model APIs.
    "supabase": ("database", "supabase", ""), "firebase_admin": ("database", "firestore", ""),
    "gspread": ("database", "google-sheets", "sheets.googleapis.com"),
    "pygsheets": ("database", "google-sheets", "sheets.googleapis.com"),
    "pyairtable": ("database", "airtable", "api.airtable.com"),
    "notion_client": ("external", "notion", "api.notion.com"),
    "slack_sdk": ("external", "slack", "slack.com"),
    "stripe": ("external", "stripe", "api.stripe.com"),
    "twilio": ("external", "twilio", "api.twilio.com"),
    "sendgrid": ("external", "sendgrid", "api.sendgrid.com"),
    "resend": ("external", "resend", "api.resend.com"),
    "google.generativeai": ("external", "google-ai", "generativelanguage.googleapis.com"),
    "google.genai": ("external", "google-ai", "generativelanguage.googleapis.com"),
    "groq": ("external", "groq", "api.groq.com"),
    "mistralai": ("external", "mistral", "api.mistral.ai"),
    "cohere": ("external", "cohere", "api.cohere.com"),
    "replicate": ("external", "replicate", "api.replicate.com"),
    "huggingface_hub": ("external", "huggingface", "api-inference.huggingface.co"),
    "together": ("external", "together", "api.together.xyz"),
    "vertexai": ("external", "vertex-ai", ""),
    "langchain_openai": ("external", "openai", "api.openai.com"),
    "langchain_anthropic": ("external", "anthropic", "api.anthropic.com"),
    "langchain_google_genai": ("external", "google-ai", "generativelanguage.googleapis.com"),
    "langchain_mistralai": ("external", "mistral", "api.mistral.ai"),
    "langchain_groq": ("external", "groq", "api.groq.com"),
    "pyspark": ("database", "spark", ""), "delta": ("database", "spark", ""),
    "databricks.sdk": ("external", "databricks-api", ""), "snowflake.connector": ("database", "snowflake", ""),
    "pyodbc": ("database", "sql", ""), "pymssql": ("database", "sqlserver", ""), "oracledb": ("database", "oracle", ""),
    "azure.data.tables": ("database", "azure-table", ""), "azure.keyvault.secrets": ("storage", "azure-keyvault", ""),
    "azure.storage.filedatalake": ("storage", "azure-blob", ""), "azure.eventhub": ("queue", "eventhub", ""),
    "azure.kusto.data": ("database", "kusto", ""), "azure.search.documents": ("database", "azure-search", ""),
}
JS_IMPORTS = {
    "pg": ("database", "postgresql", ""), "postgres": ("database", "postgresql", ""),
    "pg-promise": ("database", "postgresql", ""), "mysql": ("database", "mysql", ""),
    "mysql2": ("database", "mysql", ""), "mssql": ("database", "sqlserver", ""),
    "tedious": ("database", "sqlserver", ""), "mongodb": ("database", "mongodb", ""),
    "mongoose": ("database", "mongodb", ""), "redis": ("database", "redis", ""),
    "ioredis": ("database", "redis", ""), "better-sqlite3": ("database", "sqlite", ""),
    "sqlite3": ("database", "sqlite", ""), "@prisma/client": ("database", "sql", ""),
    "typeorm": ("database", "sql", ""), "sequelize": ("database", "sql", ""),
    "knex": ("database", "sql", ""), "@aws-sdk/client-s3": ("storage", "s3", ""),
    "@aws-sdk/client-sqs": ("queue", "sqs", ""), "@aws-sdk/client-dynamodb": ("database", "dynamodb", ""),
    "aws-sdk": ("external", "aws", ""), "@azure/storage-blob": ("storage", "azure-blob", ""),
    "@azure/service-bus": ("queue", "servicebus", ""), "@azure/cosmos": ("database", "cosmos", ""),
    "@google-cloud/storage": ("storage", "gcs", ""), "@google-cloud/pubsub": ("queue", "pubsub", ""),
    "kafkajs": ("queue", "kafka", ""), "amqplib": ("queue", "amqp", ""),
    "openai": ("external", "openai", "api.openai.com"),
    "@anthropic-ai/sdk": ("external", "anthropic", "api.anthropic.com"),
    "nodemailer": ("external", "smtp", ""),
    "@supabase/supabase-js": ("database", "supabase", ""), "@supabase/ssr": ("database", "supabase", ""),
    "firebase/firestore": ("database", "firestore", ""), "firebase/database": ("database", "firebase-rtdb", ""),
    "firebase/storage": ("storage", "firebase-storage", ""), "firebase-admin": ("database", "firestore", ""),
    "@vercel/postgres": ("database", "postgresql", ""), "@neondatabase/serverless": ("database", "postgresql", ""),
    "@planetscale/database": ("database", "mysql", ""), "@upstash/redis": ("database", "redis", ""),
    "@libsql/client": ("database", "sqlite", ""), "drizzle-orm": ("database", "sql", ""),
    "airtable": ("database", "airtable", "api.airtable.com"),
    "@notionhq/client": ("external", "notion", "api.notion.com"),
    "@slack/web-api": ("external", "slack", "slack.com"),
    "stripe": ("external", "stripe", "api.stripe.com"),
    "twilio": ("external", "twilio", "api.twilio.com"),
    "@sendgrid/mail": ("external", "sendgrid", "api.sendgrid.com"),
    "resend": ("external", "resend", "api.resend.com"),
    "@google/generative-ai": ("external", "google-ai", "generativelanguage.googleapis.com"),
    "@google/genai": ("external", "google-ai", "generativelanguage.googleapis.com"),
    "groq-sdk": ("external", "groq", "api.groq.com"),
    "@mistralai/mistralai": ("external", "mistral", "api.mistral.ai"),
    "@ai-sdk/openai": ("external", "openai", "api.openai.com"),
    "@ai-sdk/anthropic": ("external", "anthropic", "api.anthropic.com"),
    "@ai-sdk/google": ("external", "google-ai", "generativelanguage.googleapis.com"),
    "@ai-sdk/google-vertex": ("external", "vertex-ai", ""),
    "@ai-sdk/azure": ("external", "azure-openai", ""),
    "@ai-sdk/amazon-bedrock": ("external", "bedrock", ""),
    "@ai-sdk/mistral": ("external", "mistral", "api.mistral.ai"),
    "@ai-sdk/groq": ("external", "groq", "api.groq.com"),
    "@ai-sdk/xai": ("external", "xai", "api.x.ai"),
    "@ai-sdk/deepseek": ("external", "deepseek", "api.deepseek.com"),
    "@ai-sdk/cohere": ("external", "cohere", "api.cohere.com"),
    "@ai-sdk/togetherai": ("external", "together", "api.together.xyz"),
    "@ai-sdk/perplexity": ("external", "perplexity", "api.perplexity.ai"),
    "@ai-sdk/gateway": ("external", "vercel-ai-gateway", "ai-gateway.vercel.sh"),
    "@openrouter/ai-sdk-provider": ("external", "openrouter", "openrouter.ai"),
    "@aws-sdk/client-bedrock-runtime": ("external", "bedrock", ""),
    "cohere-ai": ("external", "cohere", "api.cohere.com"),
    "replicate": ("external", "replicate", "api.replicate.com"),
    "@huggingface/inference": ("external", "huggingface", "api-inference.huggingface.co"),
    "together-ai": ("external", "together", "api.together.xyz"),
}
GO_IMPORTS = {
    "github.com/lib/pq": ("database", "postgresql", ""), "github.com/jackc/pgx": ("database", "postgresql", ""),
    "github.com/go-sql-driver/mysql": ("database", "mysql", ""),
    "github.com/denisenkom/go-mssqldb": ("database", "sqlserver", ""),
    "github.com/microsoft/go-mssqldb": ("database", "sqlserver", ""),
    "go.mongodb.org/mongo-driver": ("database", "mongodb", ""), "github.com/redis/go-redis": ("database", "redis", ""),
    "github.com/go-redis/redis": ("database", "redis", ""), "github.com/mattn/go-sqlite3": ("database", "sqlite", ""),
    "modernc.org/sqlite": ("database", "sqlite", ""), "github.com/databricks/databricks-sql-go": ("database", "databricks", ""),
    "github.com/snowflakedb/gosnowflake": ("database", "snowflake", ""),
    "github.com/aws/aws-sdk-go-v2/service/s3": ("storage", "s3", ""), "github.com/aws/aws-sdk-go/service/s3": ("storage", "s3", ""),
    "github.com/aws/aws-sdk-go-v2/service/dynamodb": ("database", "dynamodb", ""),
    "github.com/aws/aws-sdk-go-v2/service/sqs": ("queue", "sqs", ""), "cloud.google.com/go/storage": ("storage", "gcs", ""),
    "cloud.google.com/go/bigquery": ("database", "bigquery", ""), "cloud.google.com/go/pubsub": ("queue", "pubsub", ""),
    "github.com/Azure/azure-sdk-for-go/sdk/storage/azblob": ("storage", "azure-blob", ""),
    "github.com/Azure/azure-sdk-for-go/sdk/data/azcosmos": ("database", "cosmos", ""),
    "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets": ("storage", "azure-keyvault", ""),
    "github.com/Azure/azure-sdk-for-go/sdk/messaging/azservicebus": ("queue", "servicebus", ""),
    "github.com/segmentio/kafka-go": ("queue", "kafka", ""), "github.com/rabbitmq/amqp091-go": ("queue", "amqp", ""),
    "github.com/sashabaranov/go-openai": ("external", "openai", "api.openai.com"),
    "github.com/openai/openai-go": ("external", "openai", "api.openai.com"),
    "github.com/anthropics/anthropic-sdk-go": ("external", "anthropic", "api.anthropic.com"),
    "google.golang.org/genai": ("external", "google-ai", "generativelanguage.googleapis.com"),
}
RUST_IMPORTS = {
    "sqlx": ("database", "sql", ""), "tokio_postgres": ("database", "postgresql", ""), "postgres": ("database", "postgresql", ""),
    "diesel": ("database", "sql", ""), "sea_orm": ("database", "sql", ""), "rusqlite": ("database", "sqlite", ""),
    "redis": ("database", "redis", ""), "mongodb": ("database", "mongodb", ""), "tiberius": ("database", "sqlserver", ""),
    "aws_sdk_s3": ("storage", "s3", ""), "aws_sdk_dynamodb": ("database", "dynamodb", ""),
    "azure_storage_blobs": ("storage", "azure-blob", ""), "azure_security_keyvault": ("storage", "azure-keyvault", ""),
    "azure_data_cosmos": ("database", "cosmos", ""), "lapin": ("queue", "amqp", ""), "rdkafka": ("queue", "kafka", ""),
    "async_openai": ("external", "openai", "api.openai.com"),
}
JAVA_IMPORTS = {
    "org.postgresql": ("database", "postgresql", ""), "com.microsoft.sqlserver": ("database", "sqlserver", ""),
    "com.mysql": ("database", "mysql", ""), "oracle.jdbc": ("database", "oracle", ""),
    "com.databricks": ("database", "databricks", ""), "net.snowflake": ("database", "snowflake", ""),
    "com.mongodb": ("database", "mongodb", ""), "redis.clients.jedis": ("database", "redis", ""),
    "software.amazon.awssdk.services.s3": ("storage", "s3", ""), "com.amazonaws.services.s3": ("storage", "s3", ""),
    "com.azure.storage.blob": ("storage", "azure-blob", ""), "com.azure.cosmos": ("database", "cosmos", ""),
    "com.azure.security.keyvault": ("storage", "azure-keyvault", ""),
    "com.azure.messaging.servicebus": ("queue", "servicebus", ""), "org.apache.kafka": ("queue", "kafka", ""),
    "com.azure.ai.openai": ("external", "azure-openai", ""), "com.openai": ("external", "openai", "api.openai.com"),
}
_GO_IMPORT_RE = re.compile(r'^\s*(?:import\s+)?(?:[\w.]+\s+)?"([\w./\-]+)"\s*$')
_RUST_USE_RE = re.compile(r"^\s*(?:pub\s+)?use\s+(\w+)(?:::|;)")
_JAVA_IMPORT_RE = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)")
CS_PATTERNS = [
    (re.compile(r"\bnew\s+SqlConnection\b|\bUseSqlServer\s*\("), ("database", "sqlserver", "")),
    (re.compile(r"\bNpgsql(Connection|DataSource)\b|\bUseNpgsql\s*\("), ("database", "postgresql", "")),
    (re.compile(r"\bMySqlConnection\b|\bUseMySql\s*\("), ("database", "mysql", "")),
    (re.compile(r"\bUseSqlite\s*\(|\bSqliteConnection\b"), ("database", "sqlite", "")),
    (re.compile(r"\bConnectionMultiplexer\.Connect"), ("database", "redis", "")),
    (re.compile(r"\bnew\s+MongoClient\b"), ("database", "mongodb", "")),
    (re.compile(r"\bnew\s+CosmosClient\b"), ("database", "cosmos", "")),
    (re.compile(r"\bnew\s+Blob(Service|Container)Client\b"), ("storage", "azure-blob", "")),
    (re.compile(r"\bnew\s+ServiceBusClient\b"), ("queue", "servicebus", "")),
    (re.compile(r"\bnew\s+(OpenAIClient|ChatClient)\b|\bAddOpenAIClient\s*\("), ("external", "openai", "api.openai.com")),
    (re.compile(r"\bnew\s+AzureOpenAIClient\b|\bAddAzureOpenAIClient\s*\("), ("external", "azure-openai", "")),
    (re.compile(r"\bnew\s+AnthropicClient\b"), ("external", "anthropic", "api.anthropic.com")),
]
# Client classes that name the provider when the import does not (the
# `openai` package serves both OpenAI and Azure OpenAI).
CODE_PATTERNS = [
    (re.compile(r"\b(?:Async)?AzureOpenAI\s*\("), ("external", "azure-openai", "")),
]
PKG_FAMILIES = {**{k.split(".")[0].lower(): v for k, v in PY_IMPORTS.items()
                   if k not in ("smtplib", "sqlite3") and not k.startswith("google.")},
                **{k.lower(): v for k, v in JS_IMPORTS.items()},
                "psycopg2-binary": ("database", "postgresql", ""), "npgsql": ("database", "postgresql", ""),
                "microsoft.data.sqlclient": ("database", "sqlserver", ""),
                "system.data.sqlclient": ("database", "sqlserver", ""),
                "stackexchange.redis": ("database", "redis", ""), "mongodb.driver": ("database", "mongodb", ""),
                "azure.storage.blobs": ("storage", "azure-blob", ""),
                "azure.messaging.servicebus": ("queue", "servicebus", ""),
                "redis-py": ("database", "redis", ""), "mysqlclient": ("database", "mysql", ""),
                "google-generativeai": ("external", "google-ai", "generativelanguage.googleapis.com"),
                "google-genai": ("external", "google-ai", "generativelanguage.googleapis.com"),
                "firebase-admin": ("database", "firestore", ""), "slack-sdk": ("external", "slack", "slack.com"),
                "notion-client": ("external", "notion", "api.notion.com"),
                "langchain-openai": ("external", "openai", "api.openai.com"),
                "langchain-anthropic": ("external", "anthropic", "api.anthropic.com"),
                "langchain-google-genai": ("external", "google-ai", "generativelanguage.googleapis.com"),
                "huggingface-hub": ("external", "huggingface", "api-inference.huggingface.co"),
                "azure.ai.openai": ("external", "azure-openai", ""),
                **{k.lower(): v for k, v in GO_IMPORTS.items()}, **RUST_IMPORTS,
                "tokio-postgres": ("database", "postgresql", ""), "aws-sdk-s3": ("storage", "s3", ""),
                "async-openai": ("external", "openai", "api.openai.com"),
                "postgresql": ("database", "postgresql", ""), "mssql-jdbc": ("database", "sqlserver", ""),
                "mysql-connector-j": ("database", "mysql", ""), "databricks-jdbc": ("database", "databricks", ""),
                "snowflake-jdbc": ("database", "snowflake", ""), "azure-storage-blob": ("storage", "azure-blob", ""),
                "azure-security-keyvault-secrets": ("storage", "azure-keyvault", ""), "azure-cosmos": ("database", "cosmos", ""),
                "databricks-sql-connector": ("database", "databricks", ""), "databricks-sdk": ("external", "databricks-api", ""),
                "snowflake-connector-python": ("database", "snowflake", ""), "pyspark": ("database", "spark", ""),
                "azure-keyvault-secrets": ("storage", "azure-keyvault", ""),
                "aspire.azure.ai.openai": ("external", "azure-openai", ""),
                "microsoft.extensions.ai.openai": ("external", "openai", "api.openai.com"),
                "anthropic.sdk": ("external", "anthropic", "api.anthropic.com")}
PKG_FAMILIES.pop("redis", None)
PKG_FAMILIES["redis"] = ("database", "redis", "")

_PY_IMPORT_RE = re.compile(r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import\b|import\s+([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)*))")
_JS_IMPORT_RE = re.compile(r"""(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*\(\s*|^\s*import\s+)["']([@\w./\-]+)["']""")
_HTTP_CALL_RE = re.compile(
    r"""(?:\.(get|post|put|patch|delete|head)|\b(fetch|urlopen|axios|request|got|ky)|\bnew\s+Uri)\s*\(\s*[rbfu]?["'`](https?://[^"'`\s]+)""",
    re.I)
_URL_CONST_RE = re.compile(r"""^\s*(?:(?:export\s+)?(?:const|let|var|static\s+readonly\s+string|private\s+const\s+string|const\s+string)\s+)?([A-Za-z_]\w*)\s*=\s*[rbu]?["'`](https?://[^"'`\s]+)["'`]""")
_CALL_TOKEN_RE = re.compile(r"(?:\.(?:get|post|put|patch|delete|head|request)|\b(?:urlopen|Request|fetch|axios|GetAsync|PostAsync|PutAsync|DeleteAsync|SendAsync))\s*\(\s*([A-Za-z_]\w*)")
_ASSIGN_FROM_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*.*?\b([A-Z_][A-Z0-9_]*)\b")
_METHOD_RE = re.compile(r"""method\s*[=:]\s*["'](\w+)["']""", re.I)
_ENV_RES = [
    re.compile(r"""os\.environ\s*\[\s*["']([A-Za-z_]\w*)["']\s*\]"""),
    re.compile(r"""os\.(?:environ\.get|getenv)\s*\(\s*["']([A-Za-z_]\w*)["']"""),
    re.compile(r"""process\.env\.([A-Za-z_]\w*)"""),
    re.compile(r"""process\.env\s*\[\s*["']([A-Za-z_]\w*)["']\s*\]"""),
    re.compile(r"""Environment\.GetEnvironmentVariable\s*\(\s*"([A-Za-z_]\w*)\""""),
    re.compile(r"""GetConnectionString\s*\(\s*"([\w.\-]+)"\s*\)"""),
    re.compile(r"""Configuration\s*\[\s*"([\w:.\-]+)"\s*\]"""),
    re.compile(r"""settings\.([A-Z][A-Z0-9_]+)\b"""),
    re.compile(r"""os\.(?:Getenv|LookupEnv)\s*\(\s*"([A-Za-z_]\w*)\""""),            # Go
    re.compile(r"""env::var(?:_os)?\s*\(\s*"([A-Za-z_]\w*)\""""),                    # Rust
    re.compile(r"""System\.getenv\s*\(\s*"([A-Za-z_]\w*)\""""),                     # Java
]
_SQL_SRC = [
    ("read", r"SELECT\b[^;]{0,200}?\bFROM\b"),
    # MERGE INTO needs its USING clause: "merge into .claude/settings.json" is prose
    ("write", r"INSERT\s+INTO\b|UPDATE\s+[\w.\"`\[\]]+\s+SET\b|MERGE\s+INTO\s+[\w.\"`\[\]]+"
              r"(?:\s+WITH\s*\([^)]*\))?(?:\s+(?:AS\s+)?\w+)?\s*(?:USING\b|$)"),
    ("delete", r"DELETE\s+FROM\b|TRUNCATE\s+TABLE\b|DROP\s+(?:TABLE|DATABASE|SCHEMA)\b"),
    ("admin", r"GRANT\s+[\w ,]{1,60}?\s+ON\s|ALTER\s+(?:DATABASE|ROLE|USER)\b|CREATE\s+(?:USER|ROLE)\b"),
]
# Upper-case SQL anywhere in a string literal, or any case when the keyword
# opens the literal. Lower-case prose ("please select a file from...")
# is not SQL.
_SQL = [(cap, re.compile(r"\b(?:%s)" % src)) for cap, src in _SQL_SRC] + \
       [(cap, re.compile(r"(?<=[\"'`])\s*(?:%s)" % src, re.I)) for cap, src in _SQL_SRC]
CAP_EDGE = {"read": "reads", "write": "writes", "delete": "deletes", "admin": "administers"}
TQ = '"' * 3
# storage/queue operations: regex -> (kind filter, capability)
_OPS = [
    (re.compile(r"\.(get_object|download_file|download_fileobj|download_blob|download_to_filename|download_as_bytes|GetObject)\b"), ("storage", "read")),
    (re.compile(r"\.(put_object|upload_file|upload_fileobj|upload_blob|upload_from_filename|upload_from_string|PutObject)\b"), ("storage", "write")),
    (re.compile(r"\.(delete_object|delete_objects|delete_blob|DeleteObject)\b"), ("storage", "delete")),
    (re.compile(r"\.(send_message|send_messages|basic_publish|publish|produce|sendMessage|SendMessageAsync)\s*\("), ("queue", "write")),
]
# Key Vault and Spark/Databricks file operations
_OPS += [
    (re.compile(r"\.(get_secret|GetSecret|GetSecretAsync|getSecret)\s*\("), ("storage", "read")),
    (re.compile(r"\.(set_secret|SetSecret|SetSecretAsync|setSecret)\s*\("), ("storage", "write")),
    (re.compile(r"\.(begin_delete_secret|StartDeleteSecret|StartDeleteSecretAsync|beginDeleteSecret)\s*\("), ("storage", "delete")),
    (re.compile(r"\bdbutils\.fs\.(?:ls|head)\s*\(|\.read\b.*\.(?:load|parquet|csv|json|text|orc)\s*\("), ("storage", "read")),
    (re.compile(r"\bdbutils\.fs\.(?:put|cp|mv|mkdirs)\s*\(|\.write\b.*\.(?:save|parquet|csv|json|text|orc)\s*\("), ("storage", "write")),
    (re.compile(r"\bdbutils\.fs\.rm\s*\("), ("storage", "delete")),
]
# Spark tables: three-part names are Unity Catalog (catalog.schema.table)
# a name segment: identifier characters and f-string {variables}
_SEG = r"(?:[\w`]|\{[A-Za-z_]\w*\})+"
_UC_READ_RE = re.compile(r"""\b(?:spark\.(?:read\.)?table|DeltaTable\.forName\s*\(\s*\w+\s*,)\s*\(?\s*f?["'`](%s(?:\.%s){0,2})["'`]"""
                         % (_SEG, _SEG))
_UC_WRITE_RE = re.compile(r"""\.(?:saveAsTable|insertInto|toTable)\s*\(\s*f?["'`](%s(?:\.%s){0,2})["'`]""" % (_SEG, _SEG))
_UC_SQL_RE = re.compile(r"""(?i)\b(FROM|JOIN|USING|INTO|UPDATE|OVERWRITE|TABLE|VIEW)\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?"""
                        r"""(%s\.%s\.%s)(?![\w{])""" % (_SEG, _SEG, _SEG))


def _uc_sql_cap(verb: str, before: str) -> Optional[str]:
    """Capability of a SQL reference from its verb and the words before it
    on the line: a delete, a create-or-replace, an insert-overwrite."""
    verb, before = verb.upper(), re.sub(r"\s+", " ", before.upper())
    if verb in ("FROM", "JOIN", "USING"):
        return "delete" if re.search(r"\bDELETE\s*$", before) else "read"
    if verb in ("INTO", "UPDATE"):
        return "write"
    if verb == "OVERWRITE":
        return "delete"                 # INSERT OVERWRITE replaces the table's data
    if re.search(r"\b(DROP|TRUNCATE)\s*$", before) or re.search(r"\bOR REPLACE\s*(?:TEMP\w*\s*)?$", before) \
            or re.search(r"\bOVERWRITE\s*$", before):
        return "delete" if verb == "TABLE" or "DROP" in before[-6:] else "write"
    if re.search(r"\bALTER\s*$", before):
        return "admin"
    if re.search(r"\bCREATE\s*(?:TEMP\w*\s*)?(?:EXTERNAL\s*)?$", before):
        return "write"
    return None                         # DESCRIBE TABLE, OPTIMIZE, comments about tables
_UC_SQL2_RE = re.compile(r"""(?i)\b(FROM|JOIN|USING|INTO|UPDATE|OVERWRITE|TABLE|VIEW)\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?"""
                         r"""(%s\.%s|\{[A-Za-z_]\w*\})(?![\w{.])""" % (_SEG, _SEG))
_SPARK_FILE_RE = re.compile(r"\bspark\.|pyspark|SparkSession|\bdbutils\.|DeltaTable")
# simple string assignments, for resolving f-string table names
_STR_ASSIGN_RE = re.compile(r"""^\s*([A-Za-z_]\w*)\s*=\s*f?(["'])((?:[\w.`\-]|\{[A-Za-z_]\w*\})+)\2\s*(?:#.*)?$""")
_FVAR_RE = re.compile(r"\{([A-Za-z_]\w*)\}")
_DBUTILS_SECRET_RE = re.compile(r"""dbutils\.secrets\.get(?:Bytes)?\s*\(\s*(?:scope\s*=\s*)?["']([\w.\-]+)["']\s*,\s*(?:key\s*=\s*)?["']([\w.\-]+)["']""")
# Python/.NET/JS constructors, Go azidentity.New...(), Java ...Builder()
_AZURE_CRED_RE = re.compile(r"\b(?:New)?(DefaultAzureCredential|ManagedIdentityCredential|ClientSecretCredential|"
                            r"ClientCertificateCredential|WorkloadIdentityCredential|AzureCliCredential|"
                            r"ChainedTokenCredential|InteractiveBrowserCredential|UsernamePasswordCredential)"
                            r"(?:Builder)?\s*\(")
_CLOUD_HOST_RE = re.compile(r"""["'`](?:https?://)?((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?::\d+)?["'`/;]""")
_BOTO_RE = re.compile(r"""boto3\.(?:client|resource)\s*\(\s*["'](\w+)["']""")
_BOTO_SERVICES = {"s3": ("storage", "s3"), "sqs": ("queue", "sqs"), "sns": ("queue", "sns"),
                  "dynamodb": ("database", "dynamodb"), "rds": ("database", "rds-api"),
                  "secretsmanager": ("external", "aws-secrets-manager"), "kinesis": ("queue", "kinesis")}
_BUCKET_RE = re.compile(r"""\bBucket\s*=\s*["']([a-z0-9][a-z0-9.\-]{1,62})["']""")
_DB_URL_RE = re.compile(r"""["'`]((?:jdbc:)?(?:%s)://[^"'`\s]+)""" % "|".join(
    re.escape(s) for s in sorted(set(G.DB_SCHEMES) | set(G.QUEUE_SCHEMES) | {"s3", "gs", "abfss", "wasbs"},
                                 key=len, reverse=True)), re.I)


def _in_string(code_line: str, pos: int) -> bool:
    return pos < len(code_line) and code_line[pos] == " " or pos >= len(code_line)


def _databricks_source(text: str) -> str:
    """A Databricks source-format notebook (.py) keeps SQL cells in
    `# MAGIC %sql` comment lines; turn each into a spark.sql() call on the
    same lines so its table operations count and line numbers stay true."""
    lines = text.split("\n")
    out: List[str] = []
    in_sql = False
    for ln in lines:
        body = ln[len("# MAGIC"):].lstrip() if ln.startswith("# MAGIC") else None
        if body is not None and body.startswith("%sql"):
            if in_sql:
                out[-1] += TQ + ")"
            out.append("spark.sql(" + TQ + body[4:].replace(TQ, ""))
            in_sql = True
        elif body is not None and in_sql:
            out.append(body.replace(TQ, ""))
        else:
            if in_sql:
                out[-1] += TQ + ")"
                in_sql = False
            out.append(ln)
    if in_sql:
        out[-1] += TQ + ")"
    return "\n".join(out)


def adapt_code(ctx: Ctx, item: Item, lang: str) -> None:
    if lang == "python" and item.text.startswith("# Databricks notebook source"):
        item = Item(item.rel, _databricks_source(item.text))
    code, nocomment, _ = sanitize(item.text, {"javascript": "js", "typescript": "ts"}.get(lang, lang))
    g = ctx.g
    families: Dict[Tuple[str, str], Tuple[str, int, str]] = {}  # family -> (host, line, snippet)
    targets: Dict[str, Set[str]] = {}  # node kind -> node ids touched in this file
    adapter = {"python": "python", "csharp": "dotnet", "go": "go", "rust": "rust", "java": "jvm",
               "kotlin": "jvm"}.get(lang, "javascript")

    def touch(nid: Optional[str]) -> None:
        if nid:
            targets.setdefault(g.nodes[nid]["kind"], set()).add(nid)

    env_hint = _file_env(item.rel)
    sparky = lang == "python" and bool(_SPARK_FILE_RE.search(item.text))
    local_vars: Dict[str, str] = {}
    sql_lines: Set[int] = set()         # lines inside a spark.sql(...) literal
    if sparky:
        inside = ""
        for i, ln in enumerate(nocomment, 1):
            m = _STR_ASSIGN_RE.match(ln) if len(ln) <= MAX_LINE else None
            if m:
                local_vars.setdefault(m.group(1), m.group(3))
            if inside:
                sql_lines.add(i)
                if inside in ln:
                    inside = ""
            elif "spark.sql(" in ln:
                sql_lines.add(i)
                rest = ln.split("spark.sql(", 1)[1].lstrip().lstrip("fr")
                for q in (TQ, "'" * 3):
                    if rest.startswith(q) and q not in rest[3:]:
                        inside = q
    for idx, line in enumerate(nocomment, 1):
        if len(line) > MAX_LINE:
            continue
        # imports
        mods: List[str] = []
        if lang == "python":
            m = _PY_IMPORT_RE.match(line)
            if m:
                mods = [m.group(1)] if m.group(1) else [x.strip() for x in m.group(2).split(",")]
        elif lang in ("go", "rust", "java", "kotlin"):
            table, rx = {"go": (GO_IMPORTS, _GO_IMPORT_RE), "rust": (RUST_IMPORTS, _RUST_USE_RE)}.get(
                lang, (JAVA_IMPORTS, _JAVA_IMPORT_RE))
            m = rx.match(line)
            if m:
                mod = m.group(1)
                fam = next((v for k, v in sorted(table.items(), key=lambda kv: -len(kv[0]))
                            if mod == k or mod.startswith(k + "/") or mod.startswith(k + ".")), None)
                if fam:
                    families.setdefault((fam[0], fam[1]), (fam[2], idx, line))
        elif lang in ("javascript", "typescript"):
            mods = [m.group(1) for m in _JS_IMPORT_RE.finditer(line)]
            # AI SDK 5+: `import { gateway } from "ai"` sends model calls through the Vercel AI Gateway.
            if "ai" in mods and re.search(r"\bgateway\b", line.split(" from ", 1)[0]):
                mods.append("@ai-sdk/gateway")
        for mod in mods:
            table = PY_IMPORTS if lang == "python" else JS_IMPORTS
            fam = None
            parts = mod.split("/")
            js_root = "/".join(parts[:2]) if mod.startswith("@") else parts[0]
            cands = ((mod, ".".join(mod.split(".")[:3]), ".".join(mod.split(".")[:2]), mod.split(".")[0])
                     if lang == "python" else (mod, "/".join(parts[:2]), js_root))
            for cand in cands:
                if cand in table:
                    fam = table[cand]
                    break
            if lang != "python" and not fam and mod.startswith("@aws-sdk/"):
                fam = ("external", "aws", "")
            if fam:
                families.setdefault((fam[0], fam[1]), (fam[2], idx, line))
        # cloud data and AI hosts written as bare hostnames (server_hostname=, host=)
        for m in _CLOUD_HOST_RE.finditer(line):
            fam = G.hosted_family(m.group(1), tenant_only=True)
            if fam and _in_string(code[idx - 1] if idx - 1 < len(code) else "", m.start(1)) \
                    and "@" not in line[max(0, m.start(1) - 1):m.start(1)]:
                ev = g.add_evidence(item.rel, idx, adapter + ":cloud-host", line, "observed")
                nid = ctx.endpoint_node({"kind": fam[0], "engine": fam[1], "host": m.group(1).lower(), "port": None,
                                         "path": "", "resolved": True}, env_hint, evidence=ev)
                touch(nid)
                g.add_edge(ctx.app, nid, "connects", "unknown", "observed", "medium", evidence=ev,
                           assumptions=["cloud service host observed in code; effective grants and live reachability not verified"])
        # Spark / Databricks tables and secrets
        uc_line = False
        if sparky:
            for rx, cap0 in ((_UC_READ_RE, "read"), (_UC_WRITE_RE, "write")):
                for m in rx.finditer(line):
                    if "." not in m.group(1) and "{" not in m.group(1):
                        continue             # a bare table name: the default schema, nothing to place
                    cap = cap0
                    if cap == "write" and re.search(r"""mode\s*\(\s*["']overwrite["']|\.overwrite\b""",
                                                    " ".join(nocomment[max(0, idx - 3):idx])):
                        cap = "delete"           # overwrite replaces the table's data
                    _uc_edge(ctx, item.rel, adapter, idx, line, m.group(1), cap, env_hint, local_vars)
            uc_refs = list(_UC_SQL_RE.finditer(line))
            if idx in sql_lines:        # schema.table and {table} count inside spark.sql text
                uc_refs += [m for m in _UC_SQL2_RE.finditer(line)
                            if not any(r.start(2) <= m.start(2) < r.end(2) for r in uc_refs)]
            for m in uc_refs:
                if not _in_string(code[idx - 1] if idx - 1 < len(code) else "", m.start(2)):
                    continue             # `from a.b.c import x` is Python, not SQL
                cap = _uc_sql_cap(m.group(1), line[:m.start(1)])
                if cap:
                    uc_line = True
                    _uc_edge(ctx, item.rel, adapter, idx, line, m.group(2), cap, env_hint, local_vars)
        if lang == "python":
            for m in _DBUTILS_SECRET_RE.finditer(line):
                ev = g.add_evidence(item.rel, idx, adapter + ":databricks-secret", line, "observed",
                                    assumptions=["secret read by scope and key name; its value and what it unlocks are not visible"])
                iid = g.add_node("identity", ["databricks-secret", m.group(1), m.group(2)],
                                 "databricks secret %s/%s" % (m.group(1), m.group(2)), trust_domain="unknown",
                                 environment=G.infer_environment(m.group(1), env_hint),
                                 attributes={"credential_refs": ["secret scope %s key %s" % (m.group(1), m.group(2))],
                                             "platform": "databricks"}, evidence=ev)
                g.add_edge(ctx.app, iid, "authenticates-as", "unknown", "observed", "medium", evidence=ev,
                           assumptions=["the code reads this secret; what it grants is not visible in the repository"])
        # Azure AD credentials (managed identity, service principal, developer login)
        for m in _AZURE_CRED_RE.finditer(line):
            ev = g.add_evidence(item.rel, idx, adapter + ":azure-credential", line, "observed",
                                assumptions=["the Azure identity's role assignments are not visible in code"])
            ckind = m.group(1)
            iid = g.add_node("identity", ["azure-credential", ckind], "azure identity (%s)" % ckind, trust_domain="external",
                             attributes={"platform": "azure", "credential_type": ckind,
                                         "secretless": ckind in ("DefaultAzureCredential", "ManagedIdentityCredential",
                                                                 "WorkloadIdentityCredential")}, evidence=ev)
            g.add_edge(ctx.app, iid, "authenticates-as", "unknown", "observed", "medium", evidence=ev,
                       assumptions=["the Azure identity's role assignments are not visible in code"])
        if lang in ("python", "javascript", "typescript"):
            for rx, fam in CODE_PATTERNS:
                if rx.search(line):
                    families.setdefault((fam[0], fam[1]), (fam[2], idx, line))
        if lang == "csharp":
            for rx, fam in CS_PATTERNS:
                if rx.search(line):
                    families.setdefault((fam[0], fam[1]), (fam[2], idx, line))
        # literal data endpoints in strings
        for m in _DB_URL_RE.finditer(line):
            if not _in_string(code[idx - 1] if idx - 1 < len(code) else "", m.start(1)):
                continue
            ep = G.parse_endpoint(m.group(1))
            if not ep:
                continue
            ev = g.add_evidence(item.rel, idx, adapter + ":endpoint-literal", line, "observed")
            nid = ctx.endpoint_node(ep, env_hint, evidence=ev)
            touch(nid)
            g.add_edge(ctx.app, nid, "connects", "unknown", "observed", "medium", evidence=ev,
                       assumptions=["literal endpoint in code; effective grants and live reachability not verified"])
        # HTTP calls with a literal URL
        for m in _HTTP_CALL_RE.finditer(line):
            ep = G.parse_endpoint(m.group(3))
            if not ep:
                continue
            method = (m.group(1) or "").lower()
            cap = {"get": "read", "head": "read", "post": "write", "put": "write", "patch": "write",
                   "delete": "delete"}.get(method, "unknown")
            if m.group(2) and m.group(2).lower() == "fetch":
                window = " ".join(nocomment[idx - 1: idx + 3])
                mm = re.search(r"""method\s*:\s*["'](\w+)["']""", window, re.I)
                cap = {"GET": "read", "HEAD": "read", "DELETE": "delete"}.get(mm.group(1).upper(), "write") if mm else "read"
            ev = g.add_evidence(item.rel, idx, adapter + ":http-call", line, "observed")
            nid = ctx.endpoint_node(ep, env_hint, evidence=ev)
            touch(nid)
            g.add_edge(ctx.app, nid, "calls", cap, "observed", "medium", evidence=ev,
                       assumptions=["HTTP call observed in code; whether it executes, and what data it carries, is not verified"])
        # boto3 service clients
        for m in _BOTO_RE.finditer(line):
            svc = _BOTO_SERVICES.get(m.group(1).lower())
            if svc:
                families[svc] = ("", idx, line)
        # env usages
        for rx in _ENV_RES:
            for m in rx.finditer(line):
                ctx.uses.append((m.group(1), item.rel, idx, set(), line))
        # SQL verbs inside string literals (a line whose table references were
        # read one by one above is not counted twice)
        cl = code[idx - 1] if idx - 1 < len(code) else ""
        for cap, rx in () if uc_line else _SQL:
            m = rx.search(line)
            if m and _in_string(cl, m.start()):
                targets.setdefault("_sql", set()).add("%s|%d|%s" % (cap, idx, line))
        for rx, (kind, cap) in _OPS:
            if rx.search(line):
                targets.setdefault("_op", set()).add("%s|%s|%d|%s" % (kind, cap, idx, line))
    # URL constants passed to an HTTP client (directly or via one assignment).
    consts: Dict[str, Tuple[str, int, str]] = {}
    for idx, line in enumerate(nocomment, 1):
        if len(line) <= MAX_LINE:
            m = _URL_CONST_RE.match(line)
            if m:
                consts[m.group(1)] = (m.group(2), idx, line)
    if consts:
        aliases: Dict[str, str] = {}
        for idx, line in enumerate(nocomment, 1):
            if len(line) > MAX_LINE:
                continue
            m = _ASSIGN_FROM_RE.match(line)
            if m and m.group(2) in consts and m.group(1) not in consts:
                aliases[m.group(1)] = m.group(2)
            joined = line + " " + nocomment[idx].strip() if line.rstrip().endswith("(") and idx < len(nocomment) else line
            for cm in _CALL_TOKEN_RE.finditer(joined):
                name = cm.group(1)
                const = name if name in consts else aliases.get(name)
                if not const:
                    continue
                url, cidx, cline = consts[const]
                ep = G.parse_endpoint(url)
                if not ep:
                    continue
                window = " ".join(nocomment[max(0, idx - 2): idx + 3])
                mm = _METHOD_RE.search(window)
                verb = (mm.group(1).upper() if mm else
                        {"post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE"}.get(
                            cm.group(0).split("(")[0].strip(". ").lower(), "GET"))
                cap = {"GET": "read", "HEAD": "read", "DELETE": "delete"}.get(verb, "write")
                ev = g.add_evidence(item.rel, idx, adapter + ":http-call", line, "observed",
                                    assumptions=["URL from constant %s defined at line %d" % (const, cidx)])
                nid = ctx.endpoint_node(ep, env_hint, evidence=ev)
                touch(nid)
                g.add_edge(ctx.app, nid, "calls", cap, "observed", "medium", evidence=ev,
                           assumptions=["HTTP call observed in code; whether it executes, and what data it carries, is not verified"])
    # Buckets named literally become concrete storage nodes.
    if ("storage", "s3") in families:
        for idx, line in enumerate(nocomment, 1):
            for m in _BUCKET_RE.finditer(line):
                ev = g.add_evidence(item.rel, idx, adapter + ":s3-bucket", line, "observed")
                nid = g.add_node("storage", ["s3", m.group(1), "", env_hint], "s3 bucket %s" % m.group(1),
                                 trust_domain="external", environment=G.infer_environment(m.group(1), env_hint),
                                 attributes={"engine": "s3"}, evidence=ev)
                touch(nid)
                g.add_edge(ctx.app, nid, "connects", "unknown", "observed", "medium", evidence=ev,
                           assumptions=["bucket name observed in code; IAM permissions not verified"])
    # An Azure OpenAI client means the `openai` import serves Azure, not api.openai.com.
    if ("external", "azure-openai") in families and ("external", "openai") in families \
            and not re.search(r"api\.openai\.com", "\n".join(nocomment)):
        families.pop(("external", "openai"))
    # Record env usages with the families in this file.
    fams = set(families)
    ctx.uses = [(n, p, l, fams if p == item.rel else f, s) for (n, p, l, f, s) in ctx.uses]
    # Import-only families: an unresolved target, weak evidence.
    specific_aws = any(f in families for f in _BOTO_SERVICES.values())
    for (kind, engine), (host, idx, line) in sorted(families.items()):
        ctx.families_seen.add((kind, engine))
        if (kind, engine) == ("external", "aws") and specific_aws:
            continue  # the specific service client below is the better evidence
        concrete = [nid for nid in targets.get(kind, set())
                    if g.nodes[nid]["attributes"].get("engine") == engine]
        if concrete:
            continue
        if host:
            ev = g.add_evidence(item.rel, idx, adapter + ":sdk", line, "inferred",
                                assumptions=["SDK presence is a hypothesis of use, not a confirmed data flow"])
            nid = ctx.endpoint_node({"kind": kind, "engine": engine, "host": host, "port": None,
                                     "path": "", "resolved": True}, evidence=ev)
            touch(nid)
            g.add_edge(ctx.app, nid, "calls", "unknown", "inferred", "low", evidence=ev,
                       assumptions=["SDK presence is a hypothesis of use, not a confirmed data flow"])
            continue
        if any(endpointish(n) for (n, p, _, _, _) in ctx.uses if p == item.rel):
            continue  # resolved later through environment definitions
        ev = g.add_evidence(item.rel, idx, adapter + ":import", line, "inferred",
                            assumptions=["import or client type only; target, reachability and grants unknown"])
        nid = ctx.endpoint_node({"kind": kind, "engine": engine, "resolved": False}, env_hint, "", evidence=ev)
        touch(nid)
        g.add_edge(ctx.app, nid, "connects", "unknown", "inferred", "low", evidence=ev,
                   assumptions=["import or client type only; target, reachability and grants unknown"])
    ctx._pending_ops = getattr(ctx, "_pending_ops", [])
    ctx._pending_ops.append((item.rel, adapter, targets))


def _uc_edge(ctx: Ctx, rel: str, adapter: str, idx: int, line: str, name: str, cap: str, env_hint: str,
             local_vars: Dict[str, str]) -> None:
    """A Spark table access: catalog.schema.table names a Unity Catalog catalog;
    a two-part name lives in the workspace's default catalog. f-string
    variables are resolved where a simple assignment gives their value; a
    catalog that stays unresolved gets its own node, never a guess."""
    g = ctx.g
    resolved = _resolve_template(name.replace("`", ""), local_vars, ctx)
    parts = resolved.split(".")
    assumption = "table operation observed in code; it does not prove the runtime identity holds this grant"
    if len(parts) > 3 or (len(parts) == 1 and "{" not in parts[0]):
        return
    if len(parts) == 3 and "{" not in parts[0]:
        catalog = parts[0]
    elif len(parts) == 2 and "{" not in parts[0]:
        catalog = "default"
    else:
        catalog = ""                    # {var}.x or {var}: the catalog is decided at runtime
    ev = g.add_evidence(rel, idx, adapter + ":spark-table-%s" % cap, line, "observed",
                        assumptions=[assumption] + ([] if resolved == name.replace("`", "") else
                                                    ["table name resolved from string assignments to %s" % resolved[:80]]))
    if catalog:
        nid = g.add_node("database", ["databricks-catalog", catalog], "databricks catalog %s" % catalog,
                         trust_domain="unknown", environment=G.infer_environment(catalog, env_hint),
                         attributes={"engine": "databricks", "catalog": catalog}, evidence=ev)
    else:
        var = _FVAR_RE.search(parts[0])
        hint = var.group(1) if var else "runtime"
        nid = g.add_node("database", ["databricks-catalog", "unresolved", hint],
                         "databricks catalog (unresolved target: %s)" % hint, trust_domain="unknown",
                         environment=env_hint, attributes={"engine": "databricks", "unresolved": True, "via": [hint]},
                         evidence=ev)
    # not touch()ed: per-reference capabilities supersede the file-level SQL verb fallback
    g.add_edge(ctx.app, nid, CAP_EDGE[cap], cap, "observed", "medium", evidence=ev, assumptions=[assumption])


def _attach_ops(ctx: Ctx) -> None:
    """Attach observed SQL/storage/queue operations to the targets in the
    same file. One target: `observed`; several or none: `inferred`."""
    g = ctx.g
    resolved_by_file: Dict[str, Set[str]] = {}
    for e in g.edges.values():
        if e["source"] != ctx.app:
            continue
        for ref in e["evidence_refs"]:
            ev = g.evidence.get(ref)
            if ev:
                resolved_by_file.setdefault(ev["path"], set()).add(e["target"])
    for rel, adapter, targets in getattr(ctx, "_pending_ops", []):
        file_targets = resolved_by_file.get(rel, set())
        for entry in sorted(targets.get("_sql", ())):
            cap, idx, line = entry.split("|", 2)
            dbs = sorted(n for n in file_targets if g.nodes[n]["kind"] in ("database", "unknown"))
            _op_edges(ctx, rel, adapter, int(idx), line, cap, dbs, "database", "sql")
        for entry in sorted(targets.get("_op", ())):
            kind, cap, idx, line = entry.split("|", 3)
            nodes = sorted(n for n in file_targets if g.nodes[n]["kind"] in (kind, "unknown"))
            _op_edges(ctx, rel, adapter, int(idx), line, cap, nodes, kind, kind)


def _op_edges(ctx: Ctx, rel: str, adapter: str, idx: int, line: str, cap: str,
              nodes: List[str], kind: str, engine: str) -> None:
    g = ctx.g
    assumption = "operation observed in code; it does not prove the runtime identity holds this grant"
    if len(nodes) == 1:
        state, conf = "observed", "medium"
    else:
        state, conf = "inferred", "low"
    ev = g.add_evidence(rel, idx, adapter + ":%s-%s" % (kind, cap), line, state, assumptions=[assumption])
    if not nodes:
        nodes = [ctx.endpoint_node({"kind": kind, "engine": engine, "resolved": False}, _file_env(rel),
                                   "operation without a resolved target", evidence=ev)]
    for nid in nodes:
        g.add_edge(ctx.app, nid, CAP_EDGE[cap] if kind != "queue" else "publishes", cap, state, conf,
                   evidence=ev, assumptions=[assumption] + ([] if len(nodes) == 1 else
                                                            ["several possible targets in this file; attribution ambiguous"]))


# ---------------------------------------------------------------------------
# Configuration adapters
# ---------------------------------------------------------------------------

_KV_RE = re.compile(r"""^\s*(?:export\s+)?["']?([A-Za-z_][\w.\-:]*)["']?\s*[:=]\s*(.+?)\s*,?\s*$""")


def adapt_config(ctx: Ctx, item: Item) -> None:
    env_hint = _file_env(item.rel)
    for idx, line in enumerate(item.text.split("\n"), 1):
        if len(line) > MAX_LINE or line.lstrip().startswith(("#", "//", ";")):
            continue
        m = _KV_RE.match(line)
        if not m:
            continue
        name, value = m.group(1), m.group(2).strip().strip(",").strip("\"'")
        ep = G.parse_endpoint(value)
        if not ep:
            continue
        if ep["kind"] in ("api", "external") and not endpointish(name):
            continue
        ev = ctx.g.add_evidence(item.rel, idx, "config:endpoint", line, "declared")
        nid = ctx.endpoint_node(ep, env_hint, unresolved_hint=name, evidence=ev)
        ctx.define(name, ep, ev, env_hint, item.rel)
        ctx.g.add_edge(ctx.app, nid, "connects", "unknown", "declared", "medium", evidence=ev,
                       assumptions=["configured endpoint; use at runtime, reachability and grants not verified"])


def adapt_appsettings(ctx: Ctx, item: Item) -> None:
    try:
        # .NET configuration accepts comments and trailing commas
        data = jh_agent.loads_jsonc(item.text)
    except ValueError as exc:
        ctx.parse_failures.append({"path": item.rel, "reason": "invalid JSON: %s" % str(exc)[:80]})
        return
    env_hint = _file_env(item.rel.replace("appsettings.", "appsettings/"))
    lines = item.text.split("\n")

    def line_of(needle: str) -> int:
        for i, ln in enumerate(lines, 1):
            if needle in ln:
                return i
        return 1

    def walk(obj: Any, path: List[str], depth: int = 0) -> None:
        if depth > 20:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, path + [str(k)], depth + 1)
        elif isinstance(obj, str) and path:
            name = ":".join(path)
            ep = G.parse_endpoint(obj)
            if not ep:
                return
            if ep["kind"] in ("api", "external") and not endpointish(path[-1]):
                return
            idx = line_of('"%s"' % path[-1])
            ev = ctx.g.add_evidence(item.rel, idx, "dotnet:appsettings", lines[idx - 1], "declared")
            nid = ctx.endpoint_node(ep, env_hint, unresolved_hint=name, evidence=ev)
            ctx.define(name, ep, ev, env_hint, item.rel)
            ctx.g.add_edge(ctx.app, nid, "connects", "unknown", "declared", "medium", evidence=ev,
                           assumptions=["configured connection; effective database grants not verified"])
    walk(data, [])


_IMAGE_ENGINES = [
    (re.compile(r"(^|/)(postgres|postgis|timescaledb)"), ("database", "postgresql")),
    (re.compile(r"(^|/)(mysql|mariadb)"), ("database", "mysql")),
    (re.compile(r"(^|/)mongo"), ("database", "mongodb")),
    (re.compile(r"(^|/)(redis|valkey|keydb)"), ("database", "redis")),
    (re.compile(r"(^|/)rabbitmq"), ("queue", "amqp")),
    (re.compile(r"(^|/)(kafka|cp-kafka|redpanda)"), ("queue", "kafka")),
    (re.compile(r"(^|/)minio"), ("storage", "s3")),
    (re.compile(r"mssql"), ("database", "sqlserver")),
    (re.compile(r"(^|/)(elasticsearch|opensearch)"), ("database", "search")),
]


def _image_family(image: str) -> Optional[Tuple[str, str]]:
    img = image.lower().split("@")[0]
    for rx, fam in _IMAGE_ENGINES:
        if rx.search(img):
            return fam
    return None


def _line_of(lines: List[str], needle: str, start: int = 0) -> int:
    for i in range(start, len(lines)):
        if needle in lines[i]:
            return i + 1
    return 1


def _env_items(env: Any) -> List[Tuple[str, Any]]:
    if isinstance(env, dict):
        return [(str(k), v) for k, v in env.items()]
    out = []
    if isinstance(env, list):
        for e in env:
            if isinstance(e, str) and "=" in e:
                k, v = e.split("=", 1)
                out.append((k, v))
            elif isinstance(e, dict) and "name" in e:
                out.append((str(e["name"]), e))
    return out


def adapt_compose(ctx: Ctx, item: Item, docs: List[Any]) -> None:
    g = ctx.g
    lines = item.text.split("\n")
    env_hint = _file_env(item.rel)
    for doc in docs:
        services = doc.get("services") if isinstance(doc, dict) else None
        if not isinstance(services, dict):
            continue
        ids: Dict[str, str] = {}
        for name, svc in sorted(services.items()):
            if not isinstance(svc, dict):
                continue
            idx = _line_of(lines, "%s:" % name)
            ev = g.add_evidence(item.rel, idx, "compose:service", lines[idx - 1], "declared")
            fam = _image_family(str(svc.get("image", "")))
            if fam:
                ids[name] = g.add_node(fam[0], [fam[1], name.lower(), "", env_hint], "%s %s" % (fam[1], name),
                                       trust_domain="internal", environment=env_hint,
                                       attributes={"engine": fam[1], "host": name.lower(),
                                                   "compose_service": name}, evidence=ev)
            else:
                ids[name] = g.add_node("workload", ["compose", item.rel, name], "compose service %s" % name,
                                       trust_domain="internal", environment=env_hint,
                                       attributes={"platform": "docker-compose"}, evidence=ev)
        for name, svc in sorted(services.items()):
            if not isinstance(svc, dict) or name not in ids:
                continue
            src = ids[name]
            deps = svc.get("depends_on") or []
            for dep in (sorted(deps) if isinstance(deps, (dict, list)) else []):
                if dep in ids:
                    idx = _line_of(lines, str(dep), _line_of(lines, "%s:" % name) - 1)
                    ev = g.add_evidence(item.rel, idx, "compose:depends_on", lines[idx - 1], "declared")
                    g.add_edge(src, ids[dep], "depends-on", "none", "declared", "high", evidence=ev,
                               assumptions=["start-up ordering dependency; not a data-access grant"])
            for key, value in _env_items(svc.get("environment")):
                if not isinstance(value, str):
                    continue
                ep = G.parse_endpoint(value)
                if not ep or (ep["kind"] in ("api", "external") and not endpointish(key)):
                    continue
                idx = _line_of(lines, key)
                ev = g.add_evidence(item.rel, idx, "compose:environment", lines[idx - 1], "declared")
                nid = ctx.endpoint_node(ep, env_hint, unresolved_hint=key, evidence=ev)
                ctx.define(key, ep, ev, env_hint, item.rel)
                if nid != src:
                    g.add_edge(src, nid, "connects", "unknown", "declared", "medium", evidence=ev,
                               assumptions=["configured endpoint; grants and live reachability not verified"])


_WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod", "ReplicaSet"}
_VERB_CAP = [({"*", "escalate", "bind", "impersonate"}, "admin"), ({"delete", "deletecollection"}, "delete"),
             ({"create", "update", "patch"}, "write"), ({"get", "list", "watch"}, "read")]


def _pod_spec(doc: Dict[str, Any]) -> Dict[str, Any]:
    spec = doc.get("spec") or {}
    if doc.get("kind") == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec") or {})
    if doc.get("kind") != "Pod":
        spec = ((spec.get("template") or {}).get("spec") or {}) if isinstance(spec, dict) else {}
    return spec if isinstance(spec, dict) else {}


def adapt_k8s(ctx: Ctx, item: Item, docs: List[Any]) -> None:
    g = ctx.g
    lines = item.text.split("\n")
    for doc in docs:
        if not isinstance(doc, dict) or not isinstance(doc.get("kind"), str):
            continue
        kind = doc["kind"]
        meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
        name = str(meta.get("name", "unnamed"))
        ns = str(meta.get("namespace", "default"))
        env_hint = G.infer_environment(ns, name)
        if env_hint == "unknown":
            env_hint = _file_env(item.rel)
        idx = _line_of(lines, "name: %s" % name)
        if kind in _WORKLOAD_KINDS:
            ev = g.add_evidence(item.rel, _line_of(lines, "kind: %s" % kind), "k8s:workload",
                                "kind: %s %s/%s" % (kind, ns, name), "declared")
            pod = _pod_spec(doc)
            wid = g.add_node("workload", ["k8s", ns, kind, name], "k8s %s %s/%s" % (kind, ns, name),
                             trust_domain="internal", environment=env_hint,
                             attributes={"platform": "kubernetes"}, evidence=ev)
            sa = pod.get("serviceAccountName") or pod.get("serviceAccount")
            if sa:
                sidx = _line_of(lines, "serviceAccountName: %s" % sa)
                sev = g.add_evidence(item.rel, sidx, "k8s:serviceaccount", lines[sidx - 1], "declared")
                iid = g.add_node("identity", ["k8s-sa", ns, sa], "k8s service account %s/%s" % (ns, sa),
                                 trust_domain="internal", environment=env_hint, evidence=sev)
                g.add_edge(wid, iid, "authenticates-as", "unknown", "declared", "high", evidence=sev,
                           assumptions=["the workload runs as this service account; its effective RBAC comes from bindings"])
            if pod.get("automountServiceAccountToken") is False:
                g.nodes[wid]["attributes"]["automount_token"] = "disabled"
            containers = list(pod.get("containers") or []) + list(pod.get("initContainers") or [])
            for c in containers:
                if not isinstance(c, dict):
                    continue
                for ename, val in _env_items(c.get("env")):
                    if isinstance(val, dict):
                        vf = val.get("valueFrom") or {}
                        ref = vf.get("secretKeyRef") if isinstance(vf, dict) else None
                        if isinstance(ref, dict):
                            g.nodes[wid]["attributes"].setdefault("credential_refs", [])
                            g.add_node("workload", ["k8s", ns, kind, name], "", attributes={
                                "credential_refs": ["secret %s:%s" % (ref.get("name"), ref.get("key"))]})
                            if endpointish(ename):
                                eidx = _line_of(lines, ename)
                                eev = g.add_evidence(item.rel, eidx, "k8s:secretKeyRef", lines[eidx - 1], "declared",
                                                     assumptions=["value lives in a Secret; not dereferenced"])
                                nid = ctx.endpoint_node({"kind": "unknown", "engine": "endpoint", "resolved": False},
                                                        env_hint, "secret %s" % ref.get("name"), evidence=eev)
                                g.add_edge(wid, nid, "connects", "unknown", "declared", "low", evidence=eev,
                                           assumptions=["endpoint supplied by a Secret reference; target unknown"])
                            continue
                        val = val.get("value")
                    if not isinstance(val, str):
                        continue
                    ep = G.parse_endpoint(val)
                    if not ep or (ep["kind"] in ("api", "external") and not endpointish(ename)):
                        continue
                    eidx = _line_of(lines, ename)
                    eev = g.add_evidence(item.rel, eidx, "k8s:env", lines[min(eidx, len(lines) - 1)], "declared")
                    nid = ctx.endpoint_node(ep, env_hint, unresolved_hint=ename, evidence=eev)
                    ctx.define(ename, ep, eev, env_hint, item.rel)
                    g.add_edge(wid, nid, "connects", "unknown", "declared", "medium", evidence=eev,
                               assumptions=["configured endpoint; grants and live reachability not verified"])
                for ef in c.get("envFrom") or []:
                    if isinstance(ef, dict):
                        for k in ("secretRef", "configMapRef"):
                            ref = ef.get(k)
                            if isinstance(ref, dict) and ref.get("name"):
                                g.add_node("workload", ["k8s", ns, kind, name], "", attributes={
                                    "credential_refs" if k == "secretRef" else "config_refs":
                                        ["%s %s" % ("secret" if k == "secretRef" else "configmap", ref["name"])]})
        elif kind in ("Role", "ClusterRole"):
            rules = [r for r in (doc.get("rules") or []) if isinstance(r, dict)]
            ctx.k8s_roles[(kind, ns if kind == "Role" else "", name)] = rules
            ctx.k8s_roles[(kind, ns if kind == "Role" else "", name)].append({"_path": item.rel, "_line": idx})
        elif kind in ("RoleBinding", "ClusterRoleBinding"):
            ctx.k8s_bindings.append((doc, item.rel, idx))


def _resolve_k8s_rbac(ctx: Ctx) -> None:
    g = ctx.g
    for doc, rel, idx in ctx.k8s_bindings:
        meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
        ns = str(meta.get("namespace", "default"))
        ref = doc.get("roleRef") or {}
        rkind, rname = ref.get("kind"), ref.get("name")
        rules = ctx.k8s_roles.get((rkind, ns if rkind == "Role" else "", rname))
        scope = "cluster" if doc.get("kind") == "ClusterRoleBinding" else "namespace %s" % ns
        if rules is None:
            ctx.warnings.append("k8s %s %s references role %s/%s that was not found in scanned files"
                                % (doc.get("kind"), meta.get("name"), rkind, rname))
            continue
        ev = g.add_evidence(rel, idx, "k8s:rbac-binding", "%s %s -> %s %s" % (doc.get("kind"), meta.get("name"), rkind, rname),
                            "declared", assumptions=["declared RBAC; the cluster may differ from the repository"])
        env_hint = G.infer_environment(ns)
        for subj in doc.get("subjects") or []:
            if not isinstance(subj, dict) or subj.get("kind") != "ServiceAccount":
                continue
            sns = str(subj.get("namespace", ns))
            iid = g.add_node("identity", ["k8s-sa", sns, subj.get("name")], "k8s service account %s/%s" % (sns, subj.get("name")),
                             trust_domain="internal", environment=G.infer_environment(sns), evidence=ev)
            for rule in rules:
                if "_path" in rule:
                    continue
                verbs = {str(v) for v in (rule.get("verbs") or [])}
                resources = {str(r) for r in (rule.get("resources") or [])}
                cap = next((c for vs, c in _VERB_CAP if verbs & vs), None)
                if not cap:
                    continue
                if resources & {"secrets", "*"}:
                    tid = g.add_node("api", ["kubernetes-secrets", scope], "kubernetes secrets (%s)" % scope,
                                     trust_domain="internal", environment=env_hint, sensitivity="restricted",
                                     attributes={"engine": "kubernetes"}, evidence=ev)
                    g.nodes[tid]["classification_source"] = "resource-type: credentials"
                    g.add_edge(iid, tid, CAP_EDGE[cap], cap, "declared", "high", evidence=ev,
                               assumptions=["declared RBAC rule; effective cluster state not verified"])
                if resources - {"secrets"}:
                    tid = g.add_node("api", ["kubernetes", scope], "kubernetes API (%s)" % scope,
                                     trust_domain="internal", environment=env_hint,
                                     attributes={"engine": "kubernetes"}, evidence=ev)
                    g.add_edge(iid, tid, CAP_EDGE[cap], cap, "declared", "high", evidence=ev,
                               assumptions=["declared RBAC rule; effective cluster state not verified"])


_SECRET_REF_RE = re.compile(r"\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
_CLOUD_ACTIONS = {"azure/login": "azure", "aws-actions/configure-aws-credentials": "aws",
                  "google-github-actions/auth": "gcp"}


def adapt_actions(ctx: Ctx, item: Item, docs: List[Any]) -> None:
    g = ctx.g
    lines = item.text.split("\n")
    doc = docs[0] if docs and isinstance(docs[0], dict) else {}
    jobs = doc.get("jobs") if isinstance(doc.get("jobs"), dict) else {}
    envs = set()
    for job in jobs.values():
        if isinstance(job, dict):
            env = job.get("environment")
            if isinstance(env, dict):
                env = env.get("name")
            if isinstance(env, str):
                envs.add(env)
    environment = G.infer_environment(*envs) if envs else "unknown"
    ev = g.add_evidence(item.rel, 1, "actions:workflow", "workflow %s" % item.rel, "declared")
    wid = g.add_node("workload", ["gha", item.rel], "CI workflow %s" % os.path.basename(item.rel),
                     trust_domain="internal", environment=environment,
                     attributes={"platform": "github-actions", **({"environments": sorted(envs)} if envs else {})},
                     evidence=ev)
    secrets = sorted(set(_SECRET_REF_RE.findall(item.text)))
    if secrets:
        g.nodes[wid]["attributes"]["credential_refs"] = ["secret %s" % s for s in secrets[:50]]
    tid = g.add_node("identity", ["github-token", item.rel], "GITHUB_TOKEN (%s)" % os.path.basename(item.rel),
                     trust_domain="internal", environment=environment, evidence=ev)
    g.add_edge(wid, tid, "authenticates-as", "unknown", "declared", "high", evidence=ev,
               assumptions=["every workflow run receives a GITHUB_TOKEN"])
    repo = g.add_node("api", ["github", "repository"], "GitHub repository (this repo)", trust_domain="external",
                      attributes={"engine": "github"})
    perm_blocks = [(doc.get("permissions"), "permissions:")]
    perm_blocks += [(j.get("permissions"), "permissions:") for j in jobs.values() if isinstance(j, dict)]
    any_perm = False
    for perms, needle in perm_blocks:
        if perms is None:
            continue
        any_perm = True
        pidx = _line_of(lines, needle)
        pev = g.add_evidence(item.rel, pidx, "actions:permissions", lines[pidx - 1], "declared")
        if isinstance(perms, str):
            cap = {"write-all": "admin", "read-all": "read"}.get(perms)
            if cap:
                g.add_edge(tid, repo, CAP_EDGE[cap], cap, "declared", "high", evidence=pev,
                           assumptions=["workflow-declared token permissions"])
            continue
        if isinstance(perms, dict):
            for scope, level in sorted(perms.items()):
                if scope == "id-token" and level == "write":
                    fid = g.add_node("identity", ["oidc-federation", item.rel], "OIDC federation (%s)" % os.path.basename(item.rel),
                                     trust_domain="external", environment=environment, evidence=pev)
                    g.add_edge(tid, fid, "authenticates-as", "unknown", "declared", "medium", evidence=pev,
                               assumptions=["id-token: write lets the job request a cloud OIDC token; the cloud-side trust is not visible here"])
                elif level in ("write", "read"):
                    cap = "write" if level == "write" else "read"
                    g.add_edge(tid, repo, CAP_EDGE[cap], cap, "declared", "high", evidence=pev,
                               assumptions=["token scope %s: %s" % (scope, level)])
    if not any_perm:
        g.add_edge(tid, repo, "connects", "unknown", "declared", "medium", evidence=ev,
                   assumptions=["no permissions block: token scope falls back to repository/org defaults, which are not visible here"])
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps") or []:
            if not isinstance(step, dict) or not isinstance(step.get("uses"), str):
                continue
            action = step["uses"].split("@")[0].lower()
            provider = _CLOUD_ACTIONS.get(action)
            if provider:
                sidx = _line_of(lines, step["uses"])
                sev = g.add_evidence(item.rel, sidx, "actions:cloud-login", lines[sidx - 1], "declared")
                cid = g.add_node("identity", ["cloud-deploy", provider, item.rel], "%s deploy identity (%s)" % (provider, os.path.basename(item.rel)),
                                 trust_domain="external", environment=environment, evidence=sev)
                g.add_edge(wid, cid, "authenticates-as", "unknown", "declared", "high", evidence=sev,
                           assumptions=["cloud login step; the identity's cloud permissions are not visible in the repository"])
                xid = g.add_node("external", ["cloud", provider], "%s cloud control plane" % provider,
                                 trust_domain="external", attributes={"engine": provider})
                g.add_edge(cid, xid, "connects", "unknown", "inferred", "medium", evidence=sev,
                           assumptions=["effective cloud role assignments unknown"])


_TF_RES_RE = re.compile(r'^\s*resource\s+"([\w-]+)"\s+"([\w-]+)"\s*\{')
_TF_KINDS = [
    (re.compile(r"(db_instance|rds_cluster|sql_server|sql_database|mssql|postgresql|mysql|cosmosdb|dynamodb|sql_database_instance|bigquery)"), "database"),
    (re.compile(r"(s3_bucket$|storage_account$|storage_bucket$|storage_container$)"), "storage"),
    (re.compile(r"(sqs_queue|sns_topic|servicebus|pubsub_topic|eventhub|kinesis)"), "queue"),
]
_TF_ADMIN_ROLES = re.compile(r'(?i)role_definition_name\s*=\s*"(Owner|Contributor|User Access Administrator)"|role\s*=\s*"roles/(owner|editor)"|"Action"\s*:\s*"\*"|actions\s*=\s*\[\s*"\*"\s*\]')


def adapt_terraform(ctx: Ctx, item: Item) -> None:
    _collect_tf_azure(ctx, item)
    g = ctx.g
    lines = item.text.split("\n")
    env_hint = _file_env(item.rel)
    current: Optional[Tuple[str, str, int]] = None
    depth = 0
    for idx, line in enumerate(lines, 1):
        if len(line) > MAX_LINE:
            continue
        m = _TF_RES_RE.match(line)
        if m and depth == 0:
            current = (m.group(1), m.group(2), idx)
            rtype = m.group(1)
            # types read in full by _collect_tf_azure / _resolve_tf_azure add nothing here
            for rx, kind in () if _az_deep(rtype) else _TF_KINDS:
                if rx.search(rtype):
                    ev = g.add_evidence(item.rel, idx, "terraform:resource", line, "declared",
                                        assumptions=["best-effort HCL reading; variables, modules and count/for_each are not evaluated"])
                    g.add_node(kind, ["terraform", rtype, m.group(2), env_hint], "%s.%s" % (rtype, m.group(2)),
                               trust_domain="unknown", environment=G.infer_environment(m.group(2), env_hint),
                               attributes={"engine": rtype.split("_")[0], "iac": "terraform"}, evidence=ev)
                    break
        if current and not _az_deep(current[0]) and _TF_ADMIN_ROLES.search(line):
            rtype, rname, _ = current
            ev = g.add_evidence(item.rel, idx, "terraform:privileged-grant", line, "declared",
                                assumptions=["best-effort HCL reading; the grant's principal and scope are not resolved"])
            provider = {"azurerm": "azure", "azuread": "azure", "google": "gcp"}.get(rtype.split("_")[0], rtype.split("_")[0])
            iid = g.add_node("identity", ["terraform-principal", rtype, rname], "principal of %s.%s" % (rtype, rname),
                             trust_domain="external", environment=env_hint, evidence=ev)
            xid = g.add_node("external", ["cloud", provider], "%s cloud control plane" % provider,
                             trust_domain="external", attributes={"engine": provider})
            g.add_edge(iid, xid, "administers", "admin", "declared", "medium", evidence=ev,
                       assumptions=["administrative role declared in IaC; applied state not verified"])
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            depth = 0
            current = None


# azurerm resource type -> (node kind, engine); compute types get a workload node
_AZ_DATA = {
    "mssql_server": ("database", "sqlserver"), "sql_server": ("database", "sqlserver"),
    "mssql_database": ("database", "sqlserver"), "sql_database": ("database", "sqlserver"),
    "mssql_managed_instance": ("database", "sqlserver"),
    "postgresql_server": ("database", "postgresql"), "postgresql_flexible_server": ("database", "postgresql"),
    "postgresql_flexible_server_database": ("database", "postgresql"), "postgresql_database": ("database", "postgresql"),
    "mysql_server": ("database", "mysql"), "mysql_flexible_server": ("database", "mysql"),
    "cosmosdb_account": ("database", "cosmos"), "redis_cache": ("database", "redis"),
    "storage_account": ("storage", "azure-blob"), "storage_container": ("storage", "azure-blob"),
    "storage_queue": ("queue", "azure-queue"), "storage_table": ("database", "azure-table"),
    "key_vault": ("storage", "azure-keyvault"), "servicebus_namespace": ("queue", "servicebus"),
    "servicebus_queue": ("queue", "servicebus"), "servicebus_topic": ("queue", "servicebus"),
    "eventhub_namespace": ("queue", "eventhub"), "eventhub": ("queue", "eventhub"),
    "databricks_workspace": ("database", "databricks"), "synapse_workspace": ("database", "synapse"),
    "kusto_cluster": ("database", "kusto"), "search_service": ("database", "azure-search"),
    "cognitive_account": ("external", "azure-ai"),
    "cosmosdb_sql_database": ("database", "cosmos"), "cosmosdb_sql_container": ("database", "cosmos"),
    "cosmosdb_mongo_database": ("database", "cosmos"), "mariadb_server": ("database", "mysql"),
    "mariadb_database": ("database", "mysql"), "mssql_managed_database": ("database", "sqlserver"),
    "mssql_elasticpool": ("database", "sqlserver"), "mysql_flexible_database": ("database", "mysql"),
    "mysql_database": ("database", "mysql"), "storage_share": ("storage", "azure-files"),
    "storage_data_lake_gen2_filesystem": ("storage", "azure-blob"), "redis_enterprise_cluster": ("database", "redis"),
    "eventgrid_topic": ("queue", "eventgrid"), "kusto_database": ("database", "kusto"),
    "synapse_sql_pool": ("database", "synapse"),
}
_AZ_COMPUTE = {"linux_web_app", "windows_web_app", "app_service", "function_app", "linux_function_app",
               "windows_function_app", "container_app", "container_group", "kubernetes_cluster",
               "linux_virtual_machine", "windows_virtual_machine", "virtual_machine", "logic_app_standard",
               "logic_app_workflow", "api_management", "data_factory", "spring_cloud_app", "static_web_app"}
_AZ_GRANTS = ("user_assigned_identity", "role_assignment", "role_definition", "key_vault_access_policy")


def _az_deep(rtype: str) -> bool:
    """True for the azurerm types that _resolve_tf_azure reads in full."""
    if not rtype.startswith("azurerm_"):
        return False
    short = rtype.split("_", 1)[1]
    return short in _AZ_DATA or short in _AZ_COMPUTE or short in _AZ_GRANTS


def role_definition_capability(actions: str) -> str:
    """Capability of a custom role from its actions and data_actions text."""
    a = actions.lower()
    if re.search(r'"\*"|"microsoft\.authorization/\*', a):
        return "admin"
    if re.search(r'/delete"', a):
        return "delete"
    if re.search(r'/(?:write|\*)"|/action"', a):
        return "write"
    if re.search(r'/read"', a):
        return "read"
    return "unknown"


_AZ_ROLE_GUIDS = {"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner", "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
                  "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
                  "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator"}
_TF_ATTR_RE = re.compile(r'^\s*([A-Za-z_][\w-]*)\s*=\s*(.+?)\s*$')
_TF_BLOCK_RE = re.compile(r'^\s*([A-Za-z_][\w-]*)\s*\{\s*$')
_TF_AZ_BLOCK_RE = re.compile(r'^\s*(resource|data)\s+"((?:azurerm|azuread)_\w+)"\s+"([\w-]+)"\s*\{')
_TF_REF_RE = re.compile(r"\b(data\.)?(azurerm_\w+|azuread_\w+)\.(\w+)((?:\[\d+\])?(?:\.\w+(?:\[\d+\])?)*)")


def azure_role_capability(role: str) -> str:
    """Capability an Azure built-in role grants over its scope's data and
    configuration (by role name; custom roles stay unknown)."""
    r = role.strip().lower()
    if r in ("owner", "contributor", "user access administrator", "role based access control administrator") \
            or r.endswith((" data owner", " administrator")) or r in ("storage account contributor",
                                                                     "sql server contributor", "sql db contributor"):
        return "admin"
    if r.endswith((" data contributor", " writer", " sender", " data sender")) or r in (
            "key vault secrets officer", "key vault crypto officer", "acrpush"):
        return "write"
    if r == "reader" or r.endswith((" reader", " receiver", " data receiver")) or r in (
            "key vault secrets user", "key vault crypto user", "acrpull"):
        return "read"
    return "unknown"


def _collect_tf_azure(ctx: Ctx, item: Item) -> None:
    """Record every azurerm/azuread resource block with its top-level
    attributes and nested blocks; resolved across files after all files."""
    lines = item.text.split("\n")
    blocks = ctx.tf_azure
    i = 0
    while i < len(lines):
        m = _TF_AZ_BLOCK_RE.match(lines[i]) if len(lines[i]) <= MAX_LINE else None
        if not m:
            i += 1
            continue
        start, depth = i, 0
        attrs: Dict[str, str] = {}
        nested: List[Tuple[str, Dict[str, str]]] = []
        cur: Optional[Tuple[str, Dict[str, str]]] = None
        while i < len(lines):
            line = lines[i]
            target = attrs if depth == 1 else (cur[1] if depth == 2 and cur is not None else None)
            bm = _TF_BLOCK_RE.match(line) if depth == 1 else None
            am = _TF_ATTR_RE.match(line) if target is not None and not bm else None
            if bm:
                cur = (bm.group(1), {})
                nested.append(cur)
            elif am and target is not None:
                value = _tf_value(am.group(2))
                # a list written across lines: read on to its closing bracket
                while value.startswith("[") and value.count("[") > value.count("]") and i + 1 < len(lines) \
                        and i - start < 2000:
                    i += 1
                    value += " " + _tf_value(lines[i])
                target[am.group(1)] = value
            depth += line.count("{") - line.count("}")
            if depth == 1 and cur is not None and line.strip() == "}":
                cur = None
            i += 1
            if depth <= 0:
                break
        blocks.append({"rel": item.rel, "line": start + 1, "type": m.group(2), "name": m.group(3),
                       "data": m.group(1) == "data", "attrs": attrs, "nested": nested, "text": lines[start]})


def _tf_value(raw: str) -> str:
    """An HCL attribute value without a trailing # or // comment."""
    v = raw.strip()
    if v.startswith('"'):
        m = re.match(r'"(?:[^"\\]|\\.)*"', v)
        return m.group(0) if m else v
    return re.split(r"\s(?:#|//)", " " + v, maxsplit=1)[0].strip()


def _tf_str(value: str) -> str:
    v = value.strip()
    return v[1:-1] if len(v) >= 2 and v[0] == v[-1] == '"' else ""


def _resolve_tf_azure(ctx: Ctx) -> None:
    g = ctx.g
    blocks = ctx.tf_azure
    if not blocks:
        return
    nodes: Dict[Tuple[str, str], str] = {}       # ("[data.]type", name) -> node id
    identities: Dict[Tuple[str, str], str] = {}  # ("[data.]type", name) -> managed identity node id
    uai_links: List[Tuple[str, Tuple[str, str], str]] = []   # (workload, identity key, evidence)
    kubelets: Dict[Tuple[str, str], str] = {}    # AKS kubelet identities, apart from the cluster's own
    role_defs: Dict[Tuple[str, str], Tuple[str, str]] = {}   # custom role -> (name, capability)

    def key_of(b: Dict[str, Any]) -> Tuple[str, str]:
        return (("data." if b["data"] else "") + b["type"], b["name"])

    def ref_key(m: Any) -> Tuple[str, str]:
        return ((m.group(1) or "") + m.group(2), m.group(3))

    def ev_for(b: Dict[str, Any], adapter: str, assumption: str) -> str:
        return g.add_evidence(b["rel"], b["line"], adapter, b["text"], "declared",
                              assumptions=[assumption, "best-effort HCL reading; variables, modules and count/for_each "
                                                       "are not evaluated"])

    for b in blocks:
        short = b["type"].split("_", 1)[1]
        env = G.infer_environment(b["name"], _tf_str(b["attrs"].get("name", "")), _file_env(b["rel"]))
        label = _tf_str(b["attrs"].get("name", "")) or b["name"]
        if short == "role_definition":
            perms = " ".join(a.get(k, "") for n, a in b["nested"] if n == "permissions"
                             for k in ("actions", "data_actions"))
            role_defs[key_of(b)] = (_tf_str(b["attrs"].get("name", "")) or b["name"], role_definition_capability(perms))
            continue
        if b["data"] and short not in _AZ_DATA and short != "user_assigned_identity":
            continue                    # data sources other than existing assets add no node
        if short in _AZ_DATA:
            kind, engine = _AZ_DATA[short]
            if short == "cognitive_account" and _tf_str(b["attrs"].get("kind", "")).lower() == "openai":
                engine = "azure-openai"
            ev = ev_for(b, "terraform:azure-resource", "existing resource referenced by IaC" if b["data"]
                        else "resource declared in IaC; applied state not verified")
            extra: Dict[str, Any] = {"engine": engine, "iac": "terraform", "azure_type": b["type"]}
            if b["data"]:
                extra["existing"] = True
            nid = g.add_node(kind, ["terraform", b["type"], label], "%s %s" % (engine, label),
                             trust_domain="unknown", environment=env, attributes=extra, evidence=ev)
            if nid is None:
                continue
            if engine in SECRET_STORES:
                # a secret store holds credentials, like a Kubernetes Secret
                g.nodes[nid]["sensitivity"] = "restricted"
                g.nodes[nid]["classification_source"] = "resource-type: credentials"
            nodes[key_of(b)] = wid = nid
        elif short == "user_assigned_identity":
            ev = ev_for(b, "terraform:azure-identity", "resource declared in IaC; applied state not verified")
            iid = g.add_node("identity", ["azure-uai", b["name"]], "managed identity %s" % label,
                             trust_domain="external", environment=env,
                             attributes={"platform": "azure", "credential_type": "user-assigned managed identity",
                                         "secretless": True}, evidence=ev)
            if iid:
                identities[key_of(b)] = iid
            continue
        elif short in _AZ_COMPUTE or any(n in ("identity", "kubelet_identity") for n, _ in b["nested"]):
            # compute, or any other resource that runs as an identity (a Databricks access connector)
            ev = ev_for(b, "terraform:azure-compute", "resource declared in IaC; applied state not verified")
            wid = g.add_node("workload", ["terraform", b["type"], b["name"]], "%s %s" % (short.replace("_", " "), label),
                             trust_domain="unknown", environment=env,
                             attributes={"platform": "azure", "azure_type": b["type"], "iac": "terraform"}, evidence=ev)
            if wid is None:
                continue
            nodes[key_of(b)] = wid
        else:
            continue
        for bname, battrs in b["nested"]:
            if bname not in ("identity", "kubelet_identity"):
                continue
            itype = _tf_str(battrs.get("type", "")) or ("kubelet" if bname == "kubelet_identity" else "")
            if "SystemAssigned" in itype or bname == "kubelet_identity":
                iid = g.add_node("identity", ["azure-mi", b["type"], b["name"], bname],
                                 "%s of %s" % ("kubelet identity" if bname == "kubelet_identity" else
                                               "managed identity", label),
                                 trust_domain="external", environment=env,
                                 attributes={"platform": "azure", "credential_type": "system-assigned managed identity",
                                             "secretless": True}, evidence=ev)
                if iid:
                    (kubelets if bname == "kubelet_identity" else identities)[key_of(b)] = iid
                    g.add_edge(wid, iid, "authenticates-as", "unknown", "declared", "high", evidence=ev,
                               assumptions=["the resource runs as its managed identity"])
            for ref in _TF_REF_RE.finditer(battrs.get("identity_ids", "")):
                if ref.group(2) == "azurerm_user_assigned_identity":
                    uai_links.append((wid, ref_key(ref), ev))
    for wid, uai, ev in uai_links:
        iid = identities.get(uai)
        if iid:
            g.add_edge(wid, iid, "authenticates-as", "unknown", "declared", "high", evidence=ev,
                       assumptions=["the resource runs as this user-assigned managed identity"])

    def principal(expr: str, b: Dict[str, Any], ev: str) -> str:
        m = _TF_REF_RE.search(expr)
        if m and ".kubelet_identity" in (m.group(4) or "") and ref_key(m) in kubelets:
            return kubelets[ref_key(m)]
        if m and ref_key(m) in identities and ".kubelet_identity" not in (m.group(4) or ""):
            return identities[ref_key(m)]
        im = re.search(r"\b(data\.)?([a-z]\w*)\.([\w-]+)\.(kubelet_identity|identity)\b", expr)
        if im:
            # <resource>.identity[0].principal_id: that resource's own managed identity
            # (an AKS cluster's kubelet identity is a second, separate one)
            key = ((im.group(1) or "") + im.group(2), im.group(3))
            kubelet = im.group(4) == "kubelet_identity"
            iid = g.add_node("identity", ["azure-mi-ref", key[0], key[1], im.group(4)],
                             "%s of %s.%s" % ("kubelet identity" if kubelet else "managed identity", im.group(2),
                                              im.group(3)), trust_domain="external",
                             attributes={"platform": "azure", "credential_type": "system-assigned managed identity",
                                         "secretless": True}, evidence=ev)
            if iid and key in nodes:
                g.add_edge(nodes[key], iid, "authenticates-as", "unknown", "declared", "high", evidence=ev,
                           assumptions=["the resource runs as its managed identity"])
            if iid:
                (kubelets if kubelet else identities)[key] = iid
                return iid
        label = re.sub(r"\s+", " ", expr.strip())[:60] or "unknown principal"
        if "azurerm_client_config" in expr:
            label = "the identity running terraform"
        return g.add_node("identity", ["azure-principal", label], "azure principal %s" % label, trust_domain="external",
                          attributes={"platform": "azure"}, evidence=ev)

    def scope_node(expr: str, b: Dict[str, Any], ev: str) -> str:
        m = _TF_REF_RE.search(expr)
        if m and ref_key(m) in nodes:
            return nodes[ref_key(m)]
        broad = True                    # authority over everything in it
        path = expr.strip().strip('"').rstrip("/")
        if m and m.group(2) == "azurerm_resource_group" or re.search(r"(?i)/resourceGroups/[^/]+$", path):
            label = "azure resource group %s" % (m.group(3) if m and m.group(2) == "azurerm_resource_group"
                                                 else path.rsplit("/", 1)[-1])
        elif re.search(r"(?i)/managementGroups/[^/]+$", path) or re.search(r"\bazurerm_management_group\.\w+\.id$", path):
            label = "azure management group"
        elif re.search(r"(?i)^/subscriptions/[^/]+$", path) or re.search(r"\bazurerm_subscription\.\w+\.id$", path):
            label = "azure subscription"
        else:
            label = "azure scope %s" % re.sub(r"\s+", " ", expr.strip())[:50]
            broad = False               # a reference not resolved here (a variable or module output)
        return g.add_node("external", ["azure-scope", label], label, trust_domain="external",
                          criticality="critical" if label in ("azure subscription", "azure management group") else "unknown",
                          attributes={"engine": "azure", "scope": "broad" if broad else "unresolved"}, evidence=ev)

    for b in blocks:
        short = b["type"].split("_", 1)[1]
        if short == "role_assignment":
            role = _tf_str(b["attrs"].get("role_definition_name", ""))
            cap = azure_role_capability(role) if role else "unknown"
            if not role:
                gm = re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
                               b["attrs"].get("role_definition_id", ""))
                role = _AZ_ROLE_GUIDS.get(gm.group(1), "") if gm else ""
                cap = azure_role_capability(role) if role else "unknown"
            for attr in ("role_definition_id", "role_definition_name"):
                rm = _TF_REF_RE.search(b["attrs"].get(attr, ""))
                if not role and rm and ref_key(rm) in role_defs:
                    role, cap = role_defs[ref_key(rm)]   # a custom role: capability from its actions
            ev = ev_for(b, "terraform:azure-role-assignment",
                        "role assignment declared in IaC (%s); applied state, conditions and inherited assignments not "
                        "verified" % (role or "role not resolved"))
            src = principal(b["attrs"].get("principal_id", ""), b, ev)
            dst = scope_node(b["attrs"].get("scope", ""), b, ev)
            g.add_edge(src, dst, {"admin": "administers", "write": "writes", "read": "reads"}.get(cap, "connects"),
                       cap, "declared", "medium", evidence=ev,
                       assumptions=["role %s on this scope" % (role or "unresolved")])
        elif short in ("key_vault_access_policy", "key_vault"):
            policies = [b["attrs"]] if short == "key_vault_access_policy" else [a for n, a in b["nested"] if n == "access_policy"]
            for pol in policies:
                perms = " ".join(pol.get(k, "") for k in ("secret_permissions", "key_permissions", "certificate_permissions")).lower()
                if not perms.strip():
                    continue
                # reading secrets and changing them are separate authorities: one edge each
                caps = [c for c, rx in (("read", r'"(get|list|all)"'),
                                        ("delete" if re.search(r'"(purge|delete|all)"', perms) else "write",
                                         r'"(set|import|create|update|restore|recover|purge|delete|all)"'))
                        if re.search(rx, perms)] or ["unknown"]
                ev = ev_for(b, "terraform:key-vault-access-policy",
                            "Key Vault access policy declared in IaC; applied state not verified")
                src = principal(pol.get("object_id", ""), b, ev)
                kv = (nodes.get(key_of(b)) if short == "key_vault"
                      else scope_node(pol.get("key_vault_id", ""), b, ev))
                for cap in caps if kv else ():
                    g.add_edge(src, kv, CAP_EDGE.get(cap, "connects"), cap, "declared", "medium", evidence=ev,
                               assumptions=["Key Vault access policy permissions: %s" % re.sub(r"\s+", " ", perms)[:80]])


def adapt_manifest(ctx: Ctx, item: Item) -> None:
    base = os.path.basename(item.rel).lower()
    names: List[Tuple[str, int, str]] = []
    lines = item.text.split("\n")
    if base == "package.json":
        try:
            data = json.loads(item.text)
        except ValueError:
            ctx.parse_failures.append({"path": item.rel, "reason": "invalid JSON"})
            return
        for sect in ("dependencies", "optionalDependencies"):
            for k in sorted((data.get(sect) or {}) if isinstance(data, dict) else {}):
                idx = _line_of(lines, '"%s"' % k)
                names.append((k.lower(), idx, lines[idx - 1]))
    elif base.endswith(".csproj"):
        for idx, line in enumerate(lines, 1):
            for m in re.finditer(r'PackageReference\s+Include="([^"]+)"', line):
                names.append((m.group(1).lower(), idx, line))
    elif base == "go.mod":
        for idx, line in enumerate(lines, 1):
            m = re.match(r"^\s*(?:require\s+)?([\w.\-]+(?:/[\w.\-]+)+)\s+v\d", line)
            if m:
                mod = m.group(1)
                # match the longest known module path this module sits under
                key = next((k for k in sorted(GO_IMPORTS, key=len, reverse=True)
                            if mod == k or mod.startswith(k + "/")), mod)
                names.append((key.lower(), idx, line))
    elif base == "pom.xml":
        for idx, line in enumerate(lines, 1):
            for m in re.finditer(r"<artifactId>\s*([\w.\-]+)\s*</artifactId>", line):
                names.append((m.group(1).lower(), idx, line))
    elif base.startswith("build.gradle"):
        for idx, line in enumerate(lines, 1):
            m = re.search(r"""(?:implementation|api|compile|runtimeOnly)\s*\(?\s*["']([\w.\-]+):([\w.\-]+)""", line)
            if m:
                names.append((m.group(2).lower(), idx, line))
    else:
        for idx, line in enumerate(lines, 1):
            m = re.match(r"""^\s*["']?([A-Za-z0-9][A-Za-z0-9._\-]*)""", line)
            if m and not line.lstrip().startswith(("#", "[")):
                names.append((m.group(1).lower(), idx, line))
    for name, idx, line in names:
        fam = PKG_FAMILIES.get(name) or PKG_FAMILIES.get(name.replace("_", "-"))
        if fam:
            ctx.manifest_deps.append(((fam[0], fam[1]), item.rel, idx, line))


def _resolve_manifests(ctx: Ctx) -> None:
    g = ctx.g
    present = {(n["kind"], n["attributes"].get("engine")) for n in g.nodes.values()}
    for (kind, engine), rel, idx, line in sorted(ctx.manifest_deps):
        if (kind, engine) in present or (kind, engine) in ctx.families_seen:
            continue
        ev = g.add_evidence(rel, idx, "manifest:dependency", line, "inferred",
                            assumptions=["dependency declared in a manifest; usage not observed in code"])
        nid = ctx.endpoint_node({"kind": kind, "engine": engine, "resolved": False}, "unknown",
                                "manifest dependency", evidence=ev)
        g.add_edge(ctx.app, nid, "connects", "unknown", "inferred", "low", evidence=ev,
                   assumptions=["dependency declared in a manifest; usage not observed in code"])


_HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options")


def adapt_openapi(ctx: Ctx, item: Item, docs: List[Any]) -> None:
    """Record servers and operations from an OpenAPI/Swagger document.
    Resolved after all code is read: a spec never creates an edge."""
    doc = docs[0] if docs and isinstance(docs[0], dict) else {}
    servers: List[Dict[str, Any]] = []
    for srv in doc.get("servers") or []:
        if isinstance(srv, dict) and isinstance(srv.get("url"), str):
            ep = G.parse_endpoint(srv["url"])
            if ep and ep.get("resolved") and ep.get("host"):
                servers.append(ep)
    if doc.get("swagger") and isinstance(doc.get("host"), str):
        scheme = (doc.get("schemes") or ["https"])[0] if isinstance(doc.get("schemes"), list) else "https"
        ep = G.parse_endpoint("%s://%s" % (scheme, doc["host"]))
        if ep and ep.get("resolved"):
            servers.append(ep)
    ops: List[str] = []
    paths = doc.get("paths") if isinstance(doc.get("paths"), dict) else {}
    for path, spec in sorted(paths.items()):
        if isinstance(spec, dict):
            for method in _HTTP_METHODS:
                if method in spec:
                    ops.append("%s %s" % (method.upper(), safe_text(str(path))[:80]))
    ctx.openapi.append((item.rel, servers, ops[:100]))


def _resolve_openapi(ctx: Ctx) -> None:
    g = ctx.g
    called_hosts: Dict[str, List[str]] = {}
    for e in g.edges.values():
        if e["source"] == ctx.app:
            host = g.nodes[e["target"]]["attributes"].get("host")
            if host:
                called_hosts.setdefault(host, []).append(e["target"])
    for rel, servers, ops in ctx.openapi:
        hosts = sorted({ep["host"] for ep in servers})
        upstream = sorted({nid for h in hosts for nid in called_hosts.get(h, [])})
        assumption = "an API description lists operations; it does not prove which ones the application invokes"
        if upstream:
            ev = g.add_evidence(rel, 1, "openapi:upstream", "OpenAPI servers: %s" % ", ".join(hosts), "declared",
                                assumptions=[assumption])
            for nid in upstream:
                node = g.nodes[nid]
                node["attributes"]["openapi_operations"] = sorted(set(node["attributes"].get("openapi_operations", [])) | set(ops))[:100]
                node["attributes"]["openapi_spec"] = sorted(set(node["attributes"].get("openapi_spec", [])) | {rel})
                if ev and ev not in node["evidence_refs"]:
                    node["evidence_refs"].append(ev)
        else:
            ev = g.add_evidence(rel, 1, "openapi:exposes", "OpenAPI document (%d operations)" % len(ops), "declared",
                                assumptions=["treated as the API this repository exposes, because no code calls its servers"])
            app = g.nodes[ctx.app]
            app["attributes"]["exposes"] = sorted(set(app["attributes"].get("exposes", [])) | set(ops))[:100]
            app["attributes"]["exposes_spec"] = sorted(set(app["attributes"].get("exposes_spec", [])) | {rel})
            if ev and ev not in app["evidence_refs"]:
                app["evidence_refs"].append(ev)


def apply_bindings(g: G.Graph, app_id: str, bindings: Sequence[Any], warnings: List[str]) -> int:
    """Declared code-to-workload bindings: the repository's code runs as the
    named workload, so it inherits that workload's identities, and the
    workload's blast radius includes everything the code can reach."""
    bound = 0
    for spec in bindings or []:
        pattern = spec.get("workload") if isinstance(spec, dict) else None
        hits = [n for n in g.nodes.values() if n["kind"] == "workload" and pattern and _matches(n, pattern)]
        if not hits:
            warnings.append("binding matched no workload: %s" % safe_text(str(pattern))[:60])
            continue
        ev = g.add_evidence("passport.bindings", 0, "declaration:binding", "binding %s" % pattern, "declared",
                            assumptions=["repository declaration: the code runs as this workload"])
        for w in sorted(hits, key=lambda n: n["id"]):
            bound += 1
            g.add_edge(w["id"], app_id, "authenticates-as", "unknown", "declared", "high", evidence=ev,
                       assumptions=["declared binding: the workload executes the repository code"])
            for e in list(g.edges.values()):
                if e["source"] == w["id"] and e["kind"] == "authenticates-as" and g.nodes[e["target"]]["kind"] == "identity":
                    g.add_edge(app_id, e["target"], "authenticates-as", "unknown", "declared", "high", evidence=ev,
                               assumptions=["declared binding: the code runs with the workload's identity"])
    return bound


def _resolve_env(ctx: Ctx) -> None:
    """Join code-side environment reads to configuration definitions."""
    g = ctx.g
    for name, rel, line, fams, snippet in sorted(ctx.uses, key=lambda u: (u[1], u[2], u[0])):
        defs = ctx.defs.get(name) or ctx.defs.get(name.split(":")[-1])
        if defs:
            for ep, def_ev, env_hint, def_path in defs:
                ev = g.add_evidence(rel, line, "env:resolved", snippet, "inferred",
                                    assumptions=["endpoint resolved by environment-variable name %s from %s" % (name, def_path)])
                nid = ctx.endpoint_node(ep, env_hint, unresolved_hint=name, evidence=def_ev)
                g.add_edge(ctx.app, nid, "connects", "unknown", "inferred", "medium", evidence=ev,
                           assumptions=["the deployed value of %s may differ from the repository definition" % name])
            continue
        if not endpointish(name):
            continue
        kinds = sorted(fams)
        fam = kinds[0] if len(kinds) == 1 else ("unknown", "endpoint")
        ev = g.add_evidence(rel, line, "env:unresolved", snippet, "inferred",
                            assumptions=["endpoint supplied at runtime via %s; no definition found in the repository" % name])
        nid = ctx.endpoint_node({"kind": fam[0], "engine": fam[1], "resolved": False}, _file_env(rel),
                                "env %s" % name, evidence=ev)
        g.add_edge(ctx.app, nid, "connects", "unknown", "inferred", "low", evidence=ev,
                   assumptions=["dynamic endpoint; the target is unknown, not absent"])


# ---------------------------------------------------------------------------
# Classification overlays: repository declarations and operator inventory
# ---------------------------------------------------------------------------

def _matches(node: Dict[str, Any], pattern: str) -> bool:
    p = str(pattern).lower().strip()
    if not p:
        return False
    if node["id"] == pattern:
        return True
    label = node["display_label"].lower()
    engine = str(node["attributes"].get("engine", "")).lower()
    return p in label or p == engine or p == node["kind"]


def apply_assets(g: G.Graph, assets: Sequence[Dict[str, Any]], source: str, warnings: List[str],
                 allow_lower: bool) -> None:
    for spec in assets:
        if not isinstance(spec, dict):
            continue
        pattern = spec.get("match", "")
        hits = [n for n in g.nodes.values() if _matches(n, pattern)]
        if not hits:
            warnings.append("%s asset declaration matched nothing: %s" % (source, safe_text(str(pattern))[:60]))
        for node in hits:
            for fld, allowed in (("sensitivity", G.SENSITIVITIES), ("criticality", G.CRITICALITIES),
                                 ("environment", G.ENVIRONMENTS), ("trust_domain", G.TRUST_DOMAINS)):
                val = spec.get(fld)
                if val is None:
                    continue
                if val not in allowed:
                    warnings.append("%s asset declaration: invalid %s %r" % (source, fld, safe_text(str(val))[:30]))
                    continue
                if node["classification_source"] == "operator-inventory" and not allow_lower:
                    continue  # repository declarations never override operator inventory
                node[fld] = val
            node["classification_source"] = source


def apply_inventory(g: G.Graph, inv: Dict[str, Any], trusted: bool, warnings: List[str], label: str) -> None:
    verification = "provider-verified" if trusted else "declared"
    source_trust = "operator-inventory" if trusted else "repository-inventory"
    apply_assets(g, inv.get("assets") or [], "operator-inventory" if trusted else "repository-declaration",
                 warnings, allow_lower=trusted)
    for grant in inv.get("grants") or []:
        if not isinstance(grant, dict):
            continue
        cap = grant.get("capability", "unknown")
        if cap not in G.CAPABILITIES:
            warnings.append("inventory grant: invalid capability %r" % safe_text(str(cap))[:20])
            continue
        claimed = grant.get("verification", "declared")
        ver = verification if claimed == "provider-verified" else ("declared" if claimed not in G.VERIFICATIONS
                                                                  or claimed == "refuted" else claimed)
        if claimed == "provider-verified" and not trusted:
            warnings.append("inventory claims provider-verified but is repository-controlled or untrusted; treated as declared")
        srcs = [n for n in g.nodes.values() if _matches(n, grant.get("principal", ""))]
        tgts = [n for n in g.nodes.values() if _matches(n, grant.get("target", ""))]
        if not tgts and grant.get("target_kind") in G.NODE_KINDS:
            tid = g.add_node(grant["target_kind"], ["inventory", grant.get("target", "")], str(grant.get("target", "")),
                             trust_domain=grant.get("target_trust_domain", "unknown")
                             if grant.get("target_trust_domain") in G.TRUST_DOMAINS else "unknown")
            tgts = [g.nodes[tid]] if tid else []
        if not srcs or not tgts:
            warnings.append("inventory grant matched no principal/target: %s -> %s"
                            % (safe_text(str(grant.get("principal")))[:40], safe_text(str(grant.get("target")))[:40]))
            continue
        kind = grant.get("kind") if grant.get("kind") in G.EDGE_KINDS else CAP_EDGE.get(cap, "connects")
        ev = g.add_evidence(label, 0, "inventory:grant", "%s %s -> %s" % (kind, grant.get("principal"), grant.get("target")),
                            ver, assumptions=["imported from inventory '%s'%s" % (label, "" if trusted else
                                                                                   " (not trusted: declared only)")])
        for s in srcs:
            for t in tgts:
                eid = g.add_edge(s["id"], t["id"], kind, cap, ver, "high", evidence=ev, source_trust=source_trust,
                                 assumptions=["inventory claim; jankhunt42 did not verify it cryptographically"])
                ds = grant.get("data_sensitivity")
                if eid and ds in G.SENSITIVITIES:
                    g.edges[eid]["data_sensitivity"] = ds
                att = grant.get("attenuation")
                if eid and att is not None:
                    if not trusted:
                        warnings.append("attenuation ignored: only a trusted operator inventory may weight edges")
                    elif isinstance(att, (int, float)) and not isinstance(att, bool) and 0.0 <= float(att) <= 1.0:
                        g.edges[eid]["attenuation"] = float(att)
                    else:
                        warnings.append("inventory grant: attenuation must be a number in [0, 1]")
    if trusted:
        for ref in inv.get("refute") or []:
            if not isinstance(ref, dict):
                continue
            for e in g.edges.values():
                if _matches(g.nodes[e["source"]], ref.get("principal", "")) and \
                        _matches(g.nodes[e["target"]], ref.get("target", "")) and \
                        (not ref.get("capability") or ref["capability"] == e["capability"]):
                    e["verification"] = "refuted"
                    e["source_trust"] = source_trust
                    e["assumptions"] = sorted(set(e["assumptions"]) | {"refuted by operator inventory"})


# ---------------------------------------------------------------------------
# AI agent tooling (MCP server definitions)
# ---------------------------------------------------------------------------

def adapt_mcp(ctx: Ctx, item: Item) -> None:
    """What an AI agent session in this repository is wired to: one agent
    principal per config file, an edge to every MCP server it would start,
    and the endpoints and credentials each server is handed. The servers'
    own tools are not visible here, so every capability is unknown."""
    g = ctx.g
    servers = [s for s in jh_agent.mcp_servers(item.rel, item.text) if not s.disabled]
    if not servers:
        return
    lines = item.text.split("\n")
    client = jh_agent.client_for(item.rel)
    ev = g.add_evidence(item.rel, 1, "mcp:config", "MCP config for %s" % client, "declared")
    agent = g.add_node("workload", ["ai-agent", item.rel], "AI agent (%s, %s)" % (client, os.path.basename(item.rel)),
                       trust_domain="local", attributes={"platform": "ai-agent", "client": client,
                                                         "config": item.rel}, evidence=ev)
    for s in servers:
        snippet = lines[s.line - 1] if 0 < s.line <= len(lines) else s.name
        sev = g.add_evidence(item.rel, s.line, "mcp:server", snippet, "declared",
                             assumptions=["an MCP server definition; whether the agent starts it is not verified"])
        if s.transport == "stdio":
            src = jh_agent.launch_source(s.command, s.args)
            attrs: Dict[str, Any] = {"platform": "mcp", "transport": "stdio", "mcp_server": s.name,
                                     "command": os.path.basename(s.command.replace("\\", "/"))[:40]}
            if src:
                attrs.update({"launcher": src["launcher"], "package": src["package"][:120],
                              "pinned": src["pinned"]})
            sid = g.add_node("workload", ["mcp-server", item.rel, s.name], "MCP server %s (local)" % s.name,
                             trust_domain="local", attributes=attrs, evidence=sev)
            g.add_edge(agent, sid, "calls", "unknown", "declared", "high", evidence=sev, assumptions=[
                "a local MCP server runs with the developer's privileges; its tools decide what it can read, "
                "write, or execute"] + ([] if not src or src["pinned"] else [
                    "unpinned: every start runs the newest release of %s" % src["package"][:80]]))
        elif s.url:
            ep = G.parse_endpoint(s.url)
            if not ep:
                continue
            host = ep.get("host", "")
            sid = g.add_node("external" if G.trust_domain_for_host(host) == "external" else "api",
                             ["mcp-remote", item.rel, s.name], "MCP server %s (remote%s)" % (s.name, ", " + host if host else ""),
                             trust_domain=G.trust_domain_for_host(host) if host else "unknown",
                             attributes={"platform": "mcp", "transport": s.transport, "mcp_server": s.name,
                                         **({"host": host} if host else {})}, evidence=sev)
            g.add_edge(agent, sid, "calls", "unknown", "declared", "high", evidence=sev, assumptions=[
                "a remote MCP server; the tools it exposes and what they reach are decided by its operator"])
        else:
            continue
        # Endpoints the server is pointed at (connection strings in args or env).
        values = [("arg", a) for a in s.args] + [("env:" + k, v) for k, v in sorted(s.env.items())]
        for where, value in values:
            ep = G.parse_endpoint(value)
            if not ep or (ep["kind"] in ("api", "external") and not (where.startswith("env:")
                                                                      and endpointish(where[4:]))):
                continue
            nid = ctx.endpoint_node(ep, evidence=sev, unresolved_hint=where[4:] if where.startswith("env:") else "")
            if nid and nid != sid:
                g.add_edge(sid, nid, "connects", "unknown", "declared", "medium", evidence=sev, assumptions=[
                    "endpoint handed to MCP server %s; the grants of its credentials are not verified" % s.name])
        # Credentials, by name only: values are never read into the graph.
        for name in jh_agent.credential_names(s):
            iid = g.add_node("identity", ["mcp-credential", item.rel, s.name, name],
                             "credential %s (MCP %s)" % (name, s.name), trust_domain="external",
                             attributes={"credential_refs": ["env %s" % name]}, evidence=sev)
            g.add_edge(sid, iid, "authenticates-as", "unknown", "declared", "high", evidence=sev, assumptions=[
                "the server acts with this credential; its scopes are not visible in the repository"])


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

# Go-template actions as Helm writes them ({{ .Values.x }}, {{- include ... }},
# {{ if }}/{{ range }}/{{ end }}); not Argo's {{inputs.x}} or Actions' ${{ }}.
_HELM_SYNTAX_RE = re.compile(r"(?<!\$)\{\{-?\s*(?:\.|include\b|if\b|else\b|range\b|end\b|define\b|template\b|with\b|toYaml\b|tpl\b)")


def _classify_file(rel: str, text: str) -> Tuple[str, Optional[List[Any]]]:
    low = rel.lower()
    base = os.path.basename(low)
    if is_test_path(rel):
        return "test", None
    if low.endswith((".md", ".rst", ".txt")) and not base.startswith("requirements"):
        return "doc", None
    if is_mcp_config(rel):
        return "mcp", None
    if base.startswith("requirements") and base.endswith(".txt") or base in (
            "pyproject.toml", "pipfile", "package.json", "go.mod", "cargo.toml", "pom.xml", "build.gradle",
            "build.gradle.kts") or base.endswith(".csproj"):
        return "manifest", None
    if low.endswith(".ipynb"):
        return "notebook", None
    if base.startswith("appsettings") and base.endswith(".json"):
        return "appsettings", None
    if low.endswith(".tf"):
        return "terraform", None
    if low.endswith((".yml", ".yaml")):
        if re.search(r"(^|/)(templates|charts)/", low) and _HELM_SYNTAX_RE.search(text):
            return "template", None              # Helm/Go templates are YAML only once rendered
        if "/.github/workflows/" in "/" + low:
            kind = "actions"
        elif re.match(r"(docker-)?compose([.\-][\w.\-]+)?\.ya?ml$", base):
            kind = "compose"
        else:
            kind = "yaml"
        try:
            docs = jh_yaml.load_all(text)
        except jh_yaml.YamlError as exc:
            if "{{" in text.replace("${{", "") and re.search(r"(^|/)(templates|charts)/", low):
                return "template", None
            return "yaml-error:" + str(exc)[:80], None
        if kind == "yaml" and any(isinstance(d, dict) and "kind" in d and "apiVersion" in d for d in docs):
            kind = "k8s"
        if kind == "yaml" and docs and isinstance(docs[0], dict) and ("openapi" in docs[0] or "swagger" in docs[0]):
            kind = "openapi"
        return kind, docs
    if low.endswith(".json") and re.search(r'"(openapi|swagger)"\s*:', text[:4096]):
        try:
            doc = json.loads(text)
        except ValueError as exc:
            return "yaml-error:invalid OpenAPI JSON: %s" % str(exc)[:60], None
        if isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc):
            return "openapi", [doc]
    if base.startswith(".env") or base.endswith((".env", ".properties", ".ini", ".cfg", ".conf", ".toml")) \
            or (low.endswith(".json") and ("config" in low or "settings" in low)):
        return "config", None
    lang = detect_lang(rel)
    lang = {"js": "javascript", "ts": "typescript"}.get(lang, lang)
    if lang in ("python", "javascript", "typescript", "csharp", "go", "rust", "java", "kotlin"):
        return "code:" + lang, None
    if is_mcp_config(rel, text):
        return "mcp", None
    return "unsupported", None


def _notebook_code(text: str) -> str:
    """A Jupyter or Databricks notebook's code cells as one Python text;
    %sql cells become spark.sql() calls so their table operations count.
    Evidence line numbers then count these joined code lines."""
    data = json.loads(text)
    out: List[str] = []
    for cell in data.get("cells", []) if isinstance(data, dict) else []:
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        src = cell.get("source", "")
        src = "".join(src) if isinstance(src, list) else str(src)
        if src.lstrip().startswith("%sql"):
            body = src.lstrip()[4:].replace(TQ, "")
            out.append("spark.sql(" + TQ + body + TQ + ")")
        else:
            out.append("\n".join(l for l in src.split("\n") if not l.lstrip().startswith(("%", "!"))))
    return "\n".join(out)


ADAPTERS = ("python", "javascript", "dotnet", "go", "rust", "jvm", "config", "appsettings", "kubernetes", "compose",
            "github-actions", "terraform", "manifest", "openapi", "mcp")


def _collect_str_vars(ctx: Ctx, items: Sequence[Item]) -> None:
    """Simple `NAME = "value"` assignments across Python files and notebooks
    (Databricks configuration is often set in one notebook and %run from
    others). Only a name with one distinct value repository-wide is used."""
    for item in items:
        low = item.rel.lower()
        if not (low.endswith(".py") or low.endswith(".ipynb")) or is_test_path(item.rel):
            continue
        try:
            text = _notebook_code(item.text) if low.endswith(".ipynb") else item.text
        except ValueError:
            continue
        for line in text.split("\n"):
            m = _STR_ASSIGN_RE.match(line) if len(line) <= MAX_LINE else None
            if m:
                ctx.str_vars.setdefault(m.group(1), set()).add(m.group(3))


def _resolve_template(name: str, local: Dict[str, str], ctx: Ctx, depth: int = 0) -> str:
    """Substitute f-string {variables} from this file's assignments, then from
    a repository-wide assignment with a single value. Unresolved variables
    stay as {name}."""
    if depth > 4 or "{" not in name:
        return name

    def one(m: "re.Match[str]") -> str:
        var = m.group(1)
        if var in local:
            return _resolve_template(local[var], local, ctx, depth + 1)
        vals = ctx.str_vars.get(var) or set()
        return _resolve_template(next(iter(vals)), local, ctx, depth + 1) if len(vals) == 1 else m.group(0)
    return _FVAR_RE.sub(one, name)


def build_graph(items: Sequence[Item], app_name: str, snapshot: str) -> Tuple[G.Graph, Ctx, Dict[str, Any]]:
    g = G.Graph(snapshot=snapshot)
    ctx = Ctx(g, app_name)
    counts: Dict[str, int] = {}
    unsupported = 0
    tests = 0
    _collect_str_vars(ctx, items)
    for item in sorted(items, key=lambda i: i.rel):
        kind, docs = _classify_file(item.rel, item.text)
        if kind.startswith("yaml-error:"):
            ctx.parse_failures.append({"path": item.rel, "reason": kind.split(":", 1)[1]})
            continue
        if kind == "test":
            tests += 1
            continue
        if kind == "template":
            ctx.templates.append(item.rel)
            unsupported += 1
            continue
        if kind in ("doc", "unsupported", "yaml"):
            unsupported += 1
            continue
        adapter = {"code:python": "python", "code:javascript": "javascript", "code:typescript": "javascript",
                   "code:csharp": "dotnet", "code:go": "go", "code:rust": "rust", "code:java": "jvm", "code:kotlin": "jvm",
                   "k8s": "kubernetes", "actions": "github-actions", "notebook": "python"}.get(kind, kind)
        try:
            if kind.startswith("code:"):
                adapt_code(ctx, item, kind.split(":", 1)[1])
            elif kind == "notebook":
                adapt_code(ctx, Item(item.rel, _notebook_code(item.text)), "python")
            elif kind == "config":
                adapt_config(ctx, item)
            elif kind == "appsettings":
                adapt_appsettings(ctx, item)
            elif kind == "k8s":
                adapt_k8s(ctx, item, docs or [])
            elif kind == "compose":
                adapt_compose(ctx, item, docs or [])
            elif kind == "actions":
                adapt_actions(ctx, item, docs or [])
            elif kind == "terraform":
                adapt_terraform(ctx, item)
            elif kind == "manifest":
                adapt_manifest(ctx, item)
            elif kind == "openapi":
                adapt_openapi(ctx, item, docs or [])
            elif kind == "mcp":
                adapt_mcp(ctx, item)
        except (RecursionError, ValueError, KeyError, TypeError, AttributeError, IndexError) as exc:
            # A malformed file degrades coverage; it never aborts the map.
            ctx.parse_failures.append({"path": item.rel, "reason": "%s: %s" % (type(exc).__name__, safe_text(str(exc))[:60])})
            continue
        counts[adapter] = counts.get(adapter, 0) + 1
        ctx.inspected.append(item.rel)
        if kind != "mcp" and is_mcp_config(item.rel, item.text):
            # A config or manifest that also defines MCP servers: its own
            # adapter already covered it, so an MCP parse problem here is not
            # a coverage gap.
            try:
                adapt_mcp(ctx, item)
                counts["mcp"] = counts.get("mcp", 0) + 1
            except (RecursionError, ValueError, KeyError, TypeError, AttributeError, IndexError) as exc:
                ctx.warnings.append("MCP server definitions in %s could not be read (%s)"
                                    % (safe_text(item.rel), type(exc).__name__))
    _resolve_env(ctx)
    _attach_ops(ctx)
    _resolve_k8s_rbac(ctx)
    _resolve_manifests(ctx)
    _resolve_openapi(ctx)
    _resolve_tf_azure(ctx)
    stats = {"by_adapter": dict(sorted(counts.items())), "unsupported_files": unsupported,
             "test_files_excluded": tests}
    return g, ctx, stats


def _unknowns(g: G.Graph, ctx: Ctx) -> List[Dict[str, Any]]:
    nodes = list(g.nodes.values())
    edges = list(g.edges.values())
    out = []
    static = [e for e in edges if e["verification"] not in ("provider-verified", "refuted")]
    if static:
        out.append({"id": "effective-privileges", "count": len(static),
                    "detail": "effective grants are not verified for %d edge(s); static evidence cannot prove privileges" % len(static)})
    unres = [n for n in nodes if n["attributes"].get("unresolved")]
    if unres:
        out.append({"id": "unresolved-targets", "count": len(unres),
                    "detail": "%d endpoint(s) are resolved only at runtime (environment, secrets, or SDK defaults)" % len(unres)})
    unk = [e for e in edges if e["capability"] == "unknown" and e["kind"] in ("connects", "calls")]
    if unk:
        out.append({"id": "unknown-capability", "count": len(unk),
                    "detail": "%d connection(s) have unknown capability; treated as possibly read, write, or destructive" % len(unk)})
    assets = [n for n in nodes if n["kind"] in ("database", "storage", "queue", "api", "external", "unknown")]
    uncls = [n for n in assets if n["sensitivity"] == "unknown"]
    if uncls:
        out.append({"id": "data-classification", "count": len(uncls),
                    "detail": "%d asset(s) have no declared data sensitivity" % len(uncls)})
    hinted = [n for n in uncls if n["attributes"].get("sensitivity_hint")]
    if hinted:
        out.append({"id": "sensitive-by-name", "count": len(hinted),
                    "detail": "%d unclassified asset(s) have names suggesting personal, health or financial data (%s); "
                              "declare their sensitivity in passport.assets" % (
                                  len(hinted), ", ".join(sorted({h for n in hinted for h in n["attributes"]["sensitivity_hint"]})[:6]))})
    env = [n for n in assets if n["environment"] == "unknown"]
    if env:
        out.append({"id": "environment", "count": len(env),
                    "detail": "%d asset(s) have unknown environment (production vs non-production)" % len(env)})
    pivots = {e["source"] for e in edges if e["capability"] in ("read", "admin") and e["verification"] != "refuted"
              and g.nodes[e["target"]]["attributes"].get("engine") in SECRET_STORES}
    if pivots:
        out.append({"id": "secret-store-pivot", "count": len(pivots),
                    "detail": "%d principal(s) or identit(ies) can read a secret store; the secrets it holds may "
                              "unlock systems that are not in this graph" % len(pivots)})
    servers = [n for n in nodes if n["attributes"].get("platform") == "mcp"]
    if servers:
        out.append({"id": "agent-tool-capability", "count": len(servers),
                    "detail": "%d MCP server(s): what their tools can read, write, or run is decided by each server "
                              "at runtime and is not visible in the repository" % len(servers)})
    has_code = any(e["source"] == ctx.app for e in edges)
    workloads = [n for n in nodes if n["kind"] == "workload"
                 and n["attributes"].get("platform") not in ("github-actions", "ai-agent", "mcp")]
    if has_code and workloads:
        out.append({"id": "code-to-workload-binding", "count": len(workloads),
                    "detail": "which workload runs the repository code is not inferred; declare it with passport.bindings if needed"})
    if ctx.templates:
        out.append({"id": "unrendered-templates", "count": len(ctx.templates),
                    "detail": "%d Helm or Go template file(s) were not rendered, so the resources they define are not "
                              "mapped; render them (for example `helm template`) and map the output" % len(ctx.templates)})
    out.append({"id": "runtime-reachability", "count": None,
                "detail": "static analysis only: network reachability, firewalls, and live data movement were not tested"})
    return out


def load_json_file(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object")
    return data


def inside(path: str, root: str) -> bool:
    try:
        rp, rr = os.path.realpath(path), os.path.realpath(root)
        return os.path.commonpath([rp, rr]) == rr
    except ValueError:
        return False


def generated_at() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch and epoch.isdigit():
        return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_report(col: Collected, root: str, app_name: str, snapshot: str, source_revision: Optional[str],
                 declarations: Optional[Dict[str, Any]] = None, inventory: Optional[Dict[str, Any]] = None,
                 inventory_trusted: bool = False, inventory_label: str = "", max_depth: int = G.DEFAULT_DEPTH,
                 extra_warnings: Sequence[str] = ()) -> Dict[str, Any]:
    g, ctx, stats = build_graph(col.items, app_name, snapshot)
    warnings = list(extra_warnings) + ctx.warnings
    if declarations:
        apply_assets(g, declarations.get("assets") or [], "repository-declaration", warnings, allow_lower=False)
    bound = apply_bindings(g, ctx.app, (declarations or {}).get("bindings") or [], warnings) if declarations else 0
    if inventory:
        apply_inventory(g, inventory, inventory_trusted, warnings, inventory_label or "inventory")
    for node in g.nodes.values():
        if node["kind"] in ("database", "storage", "queue"):
            a = node["attributes"]
            hints = G.sensitivity_hints(node["display_label"], a.get("catalog", ""), *(a.get("databases") or []))
            if hints:
                a["sensitivity_hint"] = hints
    g.finalize()
    graph = {"nodes": g.node_list(), "edges": g.edge_list()}
    coverage = {
        "files_considered": col.considered,
        "files_read": len(col.items),
        "files_inspected": len(ctx.inspected),
        "by_adapter": stats["by_adapter"],
        "adapters_available": list(ADAPTERS),
        "unsupported_files": stats["unsupported_files"],
        "test_files_excluded": stats["test_files_excluded"],
        "skipped": dict(sorted(col.skipped.items())),
        "parse_failures": sorted(ctx.parse_failures, key=lambda p: p["path"]),
        "max_files_reached": col.max_files_reached,
        "inspected_paths": sorted(ctx.inspected)[:5000],
        "skipped_paths": sorted(col.skipped_paths)[:5000],
    }
    partial_reasons = []
    if col.max_files_reached:
        partial_reasons.append("file cap reached")
    if ctx.parse_failures:
        partial_reasons.append("%d file(s) could not be parsed" % len(ctx.parse_failures))
    if g.truncated:
        partial_reasons.extend(g.truncated)
    if not ctx.inspected:
        partial_reasons.append("no supported files inspected")
    coverage["status"] = "none" if not ctx.inspected else ("partial" if partial_reasons else "complete-for-supported-types")
    coverage["partial_reasons"] = partial_reasons
    assessment = G.assess(graph, len(ctx.inspected), max_depth)
    report: Dict[str, Any] = {
        "schema_version": G.MAP_SCHEMA,
        "tool": TOOL,
        "tool_version": VERSION,
        "source_revision": source_revision,
        "scan_id": "",
        "generated_at": "",
        "scope": {"root": ".", "name": safe_text(app_name), "snapshot": snapshot, "redaction": "none",
                  "max_depth": max_depth},
        "coverage": coverage,
        "warnings": sorted(set(warnings)),
        "unknowns": [u for u in _unknowns(g, ctx) if not (bound and u["id"] == "code-to-workload-binding")],
        "evidence": g.evidence_list(),
        "graph": graph,
        "assessment": assessment,
        "egress": jh_egress.compare(jh_egress.boundaries(col.items), {"graph": graph, "assessment": assessment}),
        "truncation": {"truncated": bool(g.truncated or assessment["truncated_reachability"]),
                       "reasons": list(g.truncated) + (["reachability depth limit %d reached" % max_depth]
                                                       if assessment["truncated_reachability"] else [])},
    }
    return finalize_report(report)


def finalize_report(report: Dict[str, Any]) -> Dict[str, Any]:
    body = {k: v for k, v in report.items() if k not in ("scan_id", "generated_at")}
    report["scan_id"] = G.sha(G.canonical_json(body), 32)
    report["generated_at"] = generated_at()
    return report


def _declarations_from_items(items: Sequence[Item], warnings: List[str]) -> Optional[Dict[str, Any]]:
    """In --base mode the `passport` declarations come from the same git
    revision as the code, never from the (possibly dirty) working tree."""
    by_rel = {i.rel: i for i in items}
    if ".jankhunt42.json" in by_rel:
        try:
            data = json.loads(by_rel[".jankhunt42.json"].text)
            sect = data.get("passport") if isinstance(data, dict) else None
            return sect if isinstance(sect, dict) else None
        except ValueError:
            warnings.append(".jankhunt42.json at this revision is not valid JSON; declarations ignored")
            return None
    if ".jankhunt42.toml" in by_rel:
        try:
            import tomllib  # type: ignore[import-not-found]
        except ImportError:
            warnings.append(".jankhunt42.toml needs Python 3.11+ (tomllib); declarations at this revision ignored")
            return None
        try:
            sect = tomllib.loads(by_rel[".jankhunt42.toml"].text).get("passport")
            return sect if isinstance(sect, dict) else None
        except (ValueError, AttributeError):
            warnings.append(".jankhunt42.toml at this revision could not be parsed; declarations ignored")
    return None


def run_map(root: str, paths: Sequence[str], excludes: Sequence[str], max_files: int, max_bytes: int,
            declarations: Optional[Dict[str, Any]], inventory_path: Optional[str], max_depth: int,
            rev: Optional[str] = None, with_items: bool = False) -> Any:
    """Build a map report for the working tree (rev=None) or a git revision.
    With with_items=True, returns (report, collected) so `passport` can reuse
    the same file read for ownership and operations evidence."""
    warnings: List[str] = []
    inventory = None
    trusted = False
    label = ""
    if inventory_path:
        inventory = load_json_file(inventory_path)
        trusted = not inside(inventory_path, root)
        label = os.path.basename(inventory_path)
        if not trusted:
            warnings.append("inventory %s is inside the scanned repository: its claims are treated as declared, never provider-verified" % label)
    top = git_toplevel(root)
    if rev:
        if not top:
            raise GitError("--base needs a git repository")
        prefix = os.path.relpath(os.path.realpath(root), os.path.realpath(top)).replace(os.sep, "/")
        prefix = "" if prefix == "." else prefix + "/"
        col = collect_git(top, rev, excludes, max_files, max_bytes, prefix)
        if prefix:
            for it in col.items:
                it.rel = it.rel[len(prefix):] if it.rel.startswith(prefix) else it.rel
        declarations = _declarations_from_items(col.items, warnings)
        snapshot = "git:%s" % (git_revision(top, rev) or rev)
        source_revision = git_revision(top, rev)
        base_dir = root
    else:
        base_dir, col = collect_worktree(root, paths, excludes, max_files, max_bytes)
        source_revision = git_revision(base_dir) if top else None
        dirty = git_dirty(base_dir) if top else None
        snapshot = "working-tree" + (" (dirty)" if dirty else "")
    app_name = os.path.basename(os.path.realpath(base_dir)) or "application"
    report = build_report(col, base_dir, app_name, snapshot, source_revision, declarations, inventory,
                          trusted, label, max_depth, warnings)
    return (report, col) if with_items else report


# ---------------------------------------------------------------------------
# Views: Markdown (redirected) and TTY (interactive)
# ---------------------------------------------------------------------------

def _node_label(report: Dict[str, Any], nid: str) -> str:
    for n in report["graph"]["nodes"]:
        if n["id"] == nid:
            return n["display_label"]
    return nid


def _labels(report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {n["id"]: n for n in report["graph"]["nodes"]}


def summary(report: Dict[str, Any]) -> Dict[str, Any]:
    nodes = report["graph"]["nodes"]
    edges = report["graph"]["edges"]
    by_kind: Dict[str, int] = {}
    for n in nodes:
        by_kind[n["kind"]] = by_kind.get(n["kind"], 0) + 1
    ass = report["assessment"]
    known = 0
    potential = 0
    crossings: Set[str] = set()
    for br in ass["blast_radius"].values():
        for imp in G.IMPACTS:
            for info in br["impacts"][imp].values():
                potential += 1
                if info["tier"] == 3:
                    known += 1
        crossings.update(br["trust_boundary_crossings"])
    return {"by_kind": dict(sorted(by_kind.items())), "nodes": len(nodes), "edges": len(edges),
            "known_reach": known, "potential_reach": potential, "crossings": sorted(crossings)}


def top_paths(report: Dict[str, Any], limit: int = 5) -> List[Dict[str, Any]]:
    out = []
    for p, br in sorted(report["assessment"]["blast_radius"].items()):
        for d in br.get("drivers", []):
            info = br["impacts"].get(d["impact"], {}).get(d["node"], {})
            extra = {"strength": info["strength"]} if "strength" in info else {}
            out.append({"principal": p, **d, **extra})
    out.sort(key=lambda d: (-G.EXPOSURE_RANK[d["level"]], -G.TIER_BY_NAME[d["tier"]], d["principal"], d["node"]))
    seen = set()
    uniq = []
    for d in out:
        k = (d["principal"], d["node"], d["impact"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(d)
    return uniq[:limit]


def credential_rows(report: Dict[str, Any], limit: int = 5) -> List[Dict[str, Any]]:
    """Identities worth a reader's attention: those that unlock mutating
    authority, are shared, or pivot through a secret store or broad scope."""
    nodes = {n["id"]: n for n in report["graph"]["nodes"]}
    rows = []
    cbr = report["assessment"].get("credential_blast_radius") or {}
    for r in cbr.get("identities", []):
        flags = [f for f in r["flags"] if f != "holder-not-visible"]
        if not (r["mutating"] or flags):
            continue
        names = [nodes[t]["display_label"] for t in r["unlocks"] if t in nodes]
        rows.append({"label": r["label"], "flags": r["flags"],
                     "holders": [nodes[h]["display_label"] for h in r["holders"] if h in nodes],
                     "unlocks": len(r["unlocks"]), "mutating": len(r["mutating"]),
                     "targets": names[:4] + (["+%d more" % (len(names) - 4)] if len(names) > 4 else [])})
        if len(rows) >= limit:
            break
    return rows


def path_text(report: Dict[str, Any], principal: str, path: Sequence[str]) -> str:
    labels = _labels(report)
    edges = {e["id"]: e for e in report["graph"]["edges"]}
    parts = [labels.get(principal, {}).get("display_label", principal)]
    for eid in path:
        e = edges.get(eid)
        if not e:
            continue
        parts.append("-[%s/%s, %s]-> %s" % (e["kind"], e["capability"], e["verification"],
                                            labels.get(e["target"], {}).get("display_label", e["target"])))
    return " ".join(parts)


def markdown(report: Dict[str, Any]) -> str:
    s = summary(report)
    ass = report["assessment"]
    cov = report["coverage"]
    lines = ["# Blast radius map", "",
             "- Exposure: **%s** (qualitative; %s)" % (ass["exposure"]["class"], ass["exposure"]["basis"]),
             "- Evidence coverage: %s; %d of %d files inspected by %d adapter(s)" % (
                 cov["status"], cov["files_inspected"], cov["files_considered"], len(cov["by_adapter"])),
             "- Graph: %d nodes, %d edges; evidence tiers: %s" % (
                 s["nodes"], s["edges"], ", ".join("%d %s" % (v, k) for k, v in ass["evidence_tiers"].items())),
             "- Reach: %d known (verified) vs %d potential impact pairs; %d unknown-capability connection(s)" % (
                 s["known_reach"], s["potential_reach"], ass["unknown_capability_edges"]),
             "- Trust-boundary crossings: %s" % (", ".join(s["crossings"]) or "0 observed"),
             "- Breadth indicator: %.3f over %d trust domain(s) (informational)" % (
                 ass["breadth"]["indicator"], ass["breadth"]["distinct_trust_domains"]),
             ""]
    lines += ["## Connected systems", ""]
    if s["by_kind"]:
        lines += ["| kind | count |", "|---|---:|"] + ["| %s | %d |" % kv for kv in s["by_kind"].items()]
    else:
        lines.append("0 observed (this is not proof that none exist).")
    lines += ["", "## Highest-impact admissible paths", ""]
    tp = top_paths(report)
    if not tp:
        lines.append("0 observed.")
    for d in tp:
        lines.append("- **%s** %s (%s, %s%s): %s" % (d["level"], d["impact"], d["tier"], d["rule"],
                                                    ", heuristic strength %.3f" % d["strength"] if "strength" in d else "",
                                                    d["why"]))
        lines.append("  - `%s`" % path_text(report, d["principal"], d["path"]).replace("`", "'"))
    creds = credential_rows(report)
    if creds:
        lines += ["", "## Credential blast radius", "",
                  "What each identity unlocks if it is misused or leaks (informational; it does not change the exposure)."]
        for r in creds:
            lines.append("- **%s**%s: unlocks %d (%d mutating): %s; held by %s" % (
                r["label"], " [%s]" % ", ".join(r["flags"]) if r["flags"] else "", r["unlocks"], r["mutating"],
                ", ".join(r["targets"]) or "nothing mapped", ", ".join(r["holders"]) or "no visible holder"))
    eg = report.get("egress") or {}
    if eg.get("state") == "declared" and isinstance(eg.get("boundaries"), list):
        lines += ["", "## Egress boundary", "", "Declared allowlists compared with the hosts the map reaches (%s)."
                  % eg["note"], ""]
        for b in eg["boundaries"]:
            lines.append("- %s `%s:%s`: %d allowed, %d denied%s" % (b["tool"], b["path"], b["line"], len(b["allow"]),
                                                                  len(b["deny"]), "; %s" % b["note"] if b["note"] else ""))
        for o in eg["outside"]:
            lines.append("- **outside**: %s (%s; reached by %s): %s" % (o["host"], o["tier"], ", ".join(o["reached_by"]), o["why"]))
        if eg["wildcards"]:
            lines.append("- wildcards: %s" % ", ".join(eg["wildcards"]))
        if eg["unused"]:
            lines.append("- allowed but unused by the mapped code: %s" % ", ".join(eg["unused"]))
    lines += ["", "## Unknowns", ""]
    for u in report["unknowns"]:
        lines.append("- %s: %s" % (u["id"], u["detail"]))
    if report["warnings"]:
        lines += ["", "## Warnings", ""] + ["- %s" % w for w in report["warnings"]]
    if report["truncation"]["truncated"]:
        lines += ["", "**Truncated:** %s. Results are partial, not clean." % "; ".join(report["truncation"]["reasons"])]
    if report.get("delta"):
        lines += ["", delta_markdown(report["delta"], report)]
    if report.get("whatif"):
        lines += ["", whatif_markdown(report["whatif"], report)]
    lines += ["", "_Static evidence only: inferred connectivity is not verified access. "
                  "Export: `jankhunt42 map . --json` or `--html > map.html`._"]
    return "\n".join(safe_text(l) if "\n" not in l else l for l in lines)


def delta_markdown(delta: Dict[str, Any], report: Dict[str, Any]) -> str:
    title = "Snapshot drift" if delta.get("kind") == "snapshot-drift" else "Graph delta"
    out = ["## %s (%s -> %s)" % (title, delta["base"], delta["head"]), ""]
    if delta.get("kind") == "snapshot-drift":
        out += ["_%s_" % delta["note"], ""]
    out.append("- Nodes: +%d / -%d; edges: +%d / -%d" % (len(delta["nodes"]["added"]), len(delta["nodes"]["removed"]),
                                                      len(delta["edges"]["added"]), len(delta["edges"]["removed"])))
    out.append("- Exposure: %s -> %s" % (delta["exposure"]["base"], delta["exposure"]["head"]))
    out.append("- Permission escalations: %d; authority became unknown: %d; newly reachable sensitive assets: %d" % (
        len(delta["permission_escalations"]), len(delta.get("authority_became_unknown", [])),
        len(delta["newly_reachable_sensitive"])))
    out.append("- Trust boundaries added: %s; removed: %s" % (", ".join(delta["trust_boundaries"]["added"]) or "none",
                                                           ", ".join(delta["trust_boundaries"]["removed"]) or "none"))
    for esc in delta["permission_escalations"][:10]:
        out.append("  - escalation: %s -> %s: %s => %s" % (_node_label(report, esc["source"]), _node_label(report, esc["target"]),
                                                          "/".join(esc["before"]), "/".join(esc["after"])))
    for unk in delta.get("authority_became_unknown", [])[:10]:
        out.append("  - authority became unknown (possibly read, write or destroy): %s -> %s: %s => %s" % (
            _node_label(report, unk["source"]), _node_label(report, unk["target"]), "/".join(unk["before"]),
            "/".join(unk["after"])))
    for n in delta["newly_reachable"][:10]:
        out.append("  - newly reachable (%s, %s): %s" % (n["impact"], n["tier"], _node_label(report, n["node"])))
    if delta["coverage"]["regressed"]:
        out.append("- Coverage regressed: %d -> %d files inspected" % (delta["coverage"]["base_files_inspected"],
                                                                      delta["coverage"]["head_files_inspected"]))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# CSV export (generic diagram-tool import; JSON stays canonical)
# ---------------------------------------------------------------------------

def _csv_cell(value: Any) -> str:
    """Neutralize spreadsheet formula injection: a cell that starts with
    = + - @ (or tab/CR) is prefixed with an apostrophe."""
    text = safe_text("" if value is None else str(value))
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        text = "'" + text
    return text


def render_csv(report: Dict[str, Any]) -> Tuple[str, str]:
    import csv
    import io
    ev = {x["id"]: x for x in report.get("evidence", [])}
    tier = {"provider-verified": "verified", "observed": "supported", "declared": "supported",
            "inferred": "inferred", "unknown": "unknown", "refuted": "refuted"}
    nbuf, ebuf = io.StringIO(), io.StringIO()
    nw = csv.writer(nbuf, lineterminator="\n")
    nw.writerow(["id", "kind", "label", "trust_domain", "environment", "sensitivity", "criticality",
                 "classification_source", "evidence_count"])
    for n in sorted(report["graph"]["nodes"], key=lambda x: x["id"]):
        nw.writerow([_csv_cell(v) for v in (n["id"], n["kind"], n["display_label"], n["trust_domain"], n["environment"],
                                            n["sensitivity"], n["criticality"], n.get("classification_source", ""),
                                            len(n["evidence_refs"]))])
    ew = csv.writer(ebuf, lineterminator="\n")
    ew.writerow(["id", "source", "target", "kind", "capability", "verification", "evidence_tier", "confidence",
                 "trust_boundary", "evidence"])
    for e in sorted(report["graph"]["edges"], key=lambda x: x["id"]):
        tb = e.get("trust_boundary") or {}
        refs = ";".join("%s:%s" % (ev[r]["path"], ev[r]["line"]) for r in e["evidence_refs"] if r in ev)
        ew.writerow([_csv_cell(v) for v in (e["id"], e["source"], e["target"], e["kind"], e["capability"],
                                            e["verification"], tier.get(e["verification"], "unknown"), e["confidence"],
                                            " ".join(x for x in (tb.get("domain"), tb.get("environment")) if x), refs)])
    return nbuf.getvalue(), ebuf.getvalue()


# ---------------------------------------------------------------------------
# What-if scenarios and snapshot drift (pure functions over map reports)
# ---------------------------------------------------------------------------

WHATIF_SCHEMA = "jankhunt.whatif.v1"
WHATIF_OPS = ("remove-node", "remove-edge", "add-edge", "set-capability", "revoke", "block-egress",
              "compromise-identity")


def run_whatif(report: Dict[str, Any], scenario: Dict[str, Any], max_depth: int) -> Dict[str, Any]:
    """Apply hypothetical mutations to a copy of the graph and report what
    changes. Nothing on disk, in git, or on any network is touched; added
    edges are labeled hypothetical and declared, never observed or verified."""
    import copy
    if not isinstance(scenario, dict) or not isinstance(scenario.get("mutations"), list):
        raise ValueError("what-if scenario needs a 'mutations' list")
    nodes = {n["id"]: copy.deepcopy(n) for n in report["graph"]["nodes"]}
    edges = {e["id"]: copy.deepcopy(e) for e in report["graph"]["edges"]}

    def find(pattern: Any) -> List[str]:
        return sorted(n["id"] for n in nodes.values() if pattern is not None and _matches(n, str(pattern)))

    def edge_hits(m: Dict[str, Any]) -> List[str]:
        src, tgt = set(find(m.get("source"))) if m.get("source") else None, set(find(m.get("target"))) if m.get("target") else None
        out = []
        for e in edges.values():
            if src is not None and e["source"] not in src:
                continue
            if tgt is not None and e["target"] not in tgt:
                continue
            if m.get("kind") and e["kind"] != m["kind"]:
                continue
            if m.get("capability") and e["capability"] != m["capability"]:
                continue
            out.append(e["id"])
        return sorted(out)

    applied: List[Dict[str, Any]] = []
    compromised: List[Dict[str, Any]] = []
    for i, m in enumerate(scenario["mutations"]):
        if not isinstance(m, dict) or m.get("op") not in WHATIF_OPS:
            raise ValueError("mutation %d: op must be one of %s" % (i, ", ".join(WHATIF_OPS)))
        op = m["op"]
        matched = 0
        if op == "remove-node":
            for nid in find(m.get("match")):
                matched += 1
                nodes.pop(nid, None)
                for eid in [e for e, ed in edges.items() if nid in (ed["source"], ed["target"])]:
                    edges.pop(eid)
        elif op == "remove-edge":
            for eid in edge_hits(m):
                matched += 1
                edges.pop(eid)
        elif op == "revoke":
            for eid in edge_hits(m):
                if edges[eid]["capability"] in ("write", "delete", "admin"):
                    matched += 1
                    edges.pop(eid)
        elif op == "set-capability":
            to = m.get("to")
            if to not in G.CAPABILITIES:
                raise ValueError("mutation %d: 'to' must be a capability" % i)
            for eid in edge_hits(m):
                matched += 1
                e = edges[eid]
                e["capability"] = to
                if e["kind"] in CAP_EDGE.values():
                    e["kind"] = CAP_EDGE.get(to, "connects")
                e["assumptions"] = sorted(set(e["assumptions"]) | {"what-if: capability changed to %s" % to})
        elif op == "block-egress":
            src = set(find(m.get("principal"))) if m.get("principal") else None
            for eid in sorted(edges):
                e = edges[eid]
                if nodes.get(e["target"], {}).get("trust_domain") == "external" and (src is None or e["source"] in src):
                    matched += 1
                    edges.pop(eid)
        elif op == "add-edge":
            kind, cap = m.get("kind", "connects"), m.get("capability", "unknown")
            if kind not in G.EDGE_KINDS or cap not in G.CAPABILITIES:
                raise ValueError("mutation %d: invalid kind or capability" % i)
            for s_id in find(m.get("source")):
                for t_id in find(m.get("target")):
                    eid = "e:whatif:" + G.sha(G.canonical_json([s_id, t_id, kind, cap]))
                    matched += 1
                    edges[eid] = {"id": eid, "source": s_id, "target": t_id, "kind": kind, "capability": cap,
                                  "identity_ref": None, "verification": "declared", "confidence": "low",
                                  "source_trust": "what-if", "evidence_refs": [],
                                  "assumptions": ["hypothetical edge added by a what-if scenario"]}
        elif op == "compromise-identity":
            for nid in [x for x in find(m.get("identity")) if nodes[x]["kind"] == "identity"]:
                matched += 1
                compromised.append({"identity": nid, "label": nodes[nid]["display_label"]})
        applied.append({"index": i, "op": op, "matched": matched})
    G.annotate_boundaries(nodes, edges.values())
    graph = {"nodes": [nodes[k] for k in sorted(nodes)], "edges": [edges[k] for k in sorted(edges)]}
    files = report["coverage"]["files_inspected"]
    scenario_report = dict(report, graph=graph, assessment=G.assess(graph, files, max_depth))
    scenario_report["scope"] = dict(report["scope"], snapshot="what-if")
    edges_by_id = {e["id"]: e for e in graph["edges"]}
    for c in compromised:
        br = G.blast_radius(nodes, graph["edges"], c["identity"], max_depth)
        cls, drivers = G.classify_principal(nodes, br, edges_by_id)
        c.update({"exposure": cls, "drivers": drivers[:10],
                  "reach": {imp: sorted(br["impacts"][imp]) for imp in G.IMPACTS},
                  "note": "expands only grants the identity itself holds in the graph"})
    return {
        "schema_version": WHATIF_SCHEMA,
        "scenario": safe_text(str(scenario.get("name", "scenario")))[:80],
        "mutations": applied,
        "unmatched": [a for a in applied if a["matched"] == 0],
        "delta": G.diff(report, scenario_report),
        "compromised": compromised,
        "note": "hypothetical: computed on a copy of the graph; nothing was changed or executed",
    }


def whatif_markdown(w: Dict[str, Any], report: Dict[str, Any]) -> str:
    out = ["## What-if: %s" % w["scenario"], "", "_%s_" % w["note"], ""]
    for a in w["mutations"]:
        out.append("- mutation %d `%s`: %d match(es)" % (a["index"], a["op"], a["matched"]))
    d = w["delta"]
    out.append("- Exposure: %s -> %s" % (d["exposure"]["base"], d["exposure"]["head"]))
    lost = len([1 for _ in d["edges"]["removed"]])
    out.append("- Edges: +%d / -%d; newly reachable: %d" % (len(d["edges"]["added"]), lost, len(d["newly_reachable"])))
    for c in w["compromised"]:
        out.append("- Compromised identity %s: exposure %s; integrity reach %d node(s)" % (
            c["label"], c["exposure"], len(c["reach"]["integrity"])))
    return "\n".join(safe_text(x) for x in out)


def drift(stored: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    if stored.get("schema_version") != G.MAP_SCHEMA:
        raise ValueError("--drift needs a stored %s report" % G.MAP_SCHEMA)
    d = G.diff(stored, current)
    d["kind"] = "snapshot-drift"
    d["base"] = "stored:%s" % str(stored.get("scan_id", ""))[:12]
    d["note"] = ("comparison of a stored map with the current repository; static repository change, "
                 "not observed runtime drift")
    return d
