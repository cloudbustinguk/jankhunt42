#!/usr/bin/env python3
"""Rule catalog and scanning engine for jankhunt42."""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from jh_core import (
    Finding,
    Rule,
    SourceFile,
    SEV_RANK,
    is_test_path,
    make_finding,
    path_matches,
    redact_secrets,
    sev_at_least,
)
from jh_checks import CHECKS


def R(rid: str, title: str, sev: str, cat: str, msg: str, fix: str, **kw) -> Rule:
    return Rule(id=rid, title=title, severity=sev, category=cat, message=msg, fix=fix, **kw)


PY = ("python",)
JS = ("js", "ts", "vue", "svelte")
JVM = ("java", "kotlin", "scala", "groovy")
CLIKE = ("c", "cpp", "java", "csharp", "go", "rust", "swift", "kotlin", "scala", "dart", "php", "groovy", "solidity")
SCRIPT = ("python", "ruby", "shell", "perl", "lua", "powershell")
DOCKER = ("dockerfile",)
K8S = ("kubernetes",)
COMPOSE = ("compose",)
GH = ("github_actions",)
GL = ("gitlab_ci",)
CI = ("ci",)
TEST = ("test",)


# JH104: a query call built by concatenation; not `"query("` inside a string
# (GraphQL builders) or a name like appendRawQuery(. _dynamic_sql() asks this
# pattern for SQL or a database nearby, so a regex's exec() does not count.
_SQL_CALL_PATTERN = (r"(?i)(?<![\"'\w])(?:execute|executemany|query|exec|raw)\s*\(\s*"
                     r"(?:f['\"]|\$\{|(?:[^)\n\"'+,]|\"[^\"\n]*\"|'[^'\n]*')*\+)")      # in the first argument

RULES: List[Rule] = [
    # ------------------------------------------------------------------ security
    R("JH101", "Hardcoded secret", "critical", "security",
      "A credential-like literal is embedded in source. Anyone with repository access has the secret.",
      "Rotate the credential now, purge it from history, and load it from a secret manager or environment at runtime.",
      confidence="high", tags=("secret",), target="raw",
      patterns=(
          r"AKIA[0-9A-Z]{16}",
          r"ASIA[0-9A-Z]{16}",
          r"gh[pousr]_[A-Za-z0-9]{36,}",
          r"github_pat_[A-Za-z0-9_]{22,}",
          r"xox[baprs]-[A-Za-z0-9-]{10,}",
          r"AIza[0-9A-Za-z_\-]{35}",
          r"(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_\-]{20,}",          # not "Risk-Management-..."
          r"[sr]k_live_[0-9a-zA-Z]{20,}",
          r"\bnpm_[A-Za-z0-9]{36}\b",
          r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}",
          r"\bglpat-[A-Za-z0-9_\-]{20,}",
          r"\bhf_[A-Za-z0-9]{34,}\b",
          r"\bgsk_[A-Za-z0-9]{50,}\b",
          r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
          r"\bdop_v1_[a-f0-9]{64}\b",
          r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b",
          r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}",
          r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
          r"(?i)\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|token|passwd|password|access[_-]?key)\b\s*[:=]\s*(['\"])(?:(?!\1)[^\n]){8,}\1",
          # a quoted key ("db_password": "...") or a prefixed name (DB_PASSWORD = "..."): the value must look
          # like a credential (no spaces, a letter and a digit), so UI text ("password": "Mot de passe") is not
          r"(?i)(?:\b[a-z0-9]+[_-](?:api[_-]?key|apikey|secret(?:[_-]?key)?|token|passwd|password|access[_-]?key)\b[\"']?|"
          r"[\"'](?:api[_-]?key|apikey|secret(?:[_-]?key)?|token|passwd|password|access[_-]?key)[\"'])\s*[:=]\s*"
          r"([\"'])(?=[^\s\"']*\d)(?=[^\s\"']*[A-Za-z])"
          r"(?![^\s\"']*(?:test|e2e|mock|stub|fake|dummy|demo|never|secret|passw|example|sample|changeme|redact))"
          r"[^\s\"']{8,}\1",
      ),
      ignore=r"(?i)(example|placeholder|changeme|change_me|your[_-]|xxx+|dummy|fake|sample|redacted|synthetic|<[^>]+>|\$\{|%\(|process\.env|os\.environ|getenv|env\[|secret_key_base|notasecret)"),
    R("JH102", "Dynamic code execution", "major", "security",
      "eval/exec-style APIs turn data into code and are a classic remote-code-execution sink.",
      "Replace with a parser, dispatch table, or serialization format; never evaluate untrusted input.",
      confidence="medium", langs=JS + PY + ("php", "ruby", "lua"),
      check="dynamic_exec",
      patterns=(r"(?:(?<![\w.$])|(?<=\bwindow\.)|(?<=\bglobalThis\.)|(?<=\bglobal\.)|(?<=\bself\.))eval\s*\(",
                r"(?<![\w.])exec\s*\(", r"\bnew\s+Function\s*\(", r"\bset(?:Timeout|Interval)\s*\(\s*['\"]")),
    R("JH103", "Shell command construction", "major", "security",
      "A shell is invoked with a string, so metacharacters in any interpolated value become commands.",
      "Use an argument array with shell disabled, then validate/allowlist values.",
      confidence="medium", langs=SCRIPT + CLIKE,
      patterns=(
          r"\bshell\s*=\s*True\b",
          r"\bos\.(?:system|popen)\s*\(",
          r"\bchild_process\.(?:exec|execSync)\s*\(",
          r"\bexecSync\s*\(",
          r"Runtime\.getRuntime\(\)\.exec\s*\(",
          r"\bIO\.popen\s*\(",
          r"\bProcessBuilder\s*\(",
          r"\bcommands\.getoutput\s*\(",
      )),
    R("JH104", "Dynamic SQL", "major", "security",
      "SQL built by concatenation or interpolation lets attacker-controlled values change the query structure.",
      "Use parameterized queries / prepared statements; never interpolate values into SQL.",
      confidence="medium", target="nocomment", langs=PY + JS + JVM + CLIKE + ("ruby", "php", "go", "csharp"),
      ignore=r'^\s*r["\']|re\.compile\(|\bRegex\(',
      patterns=(
          # `%` as the Python formatting *operator* after a closing quote, not a
          # `%s` placeholder inside a parameterized query (2.1.0 FP fix).
          # concatenation means a quote next to `+` (`" + x`, `x + "`), not
          # arithmetic inside the SQL text (`value + 1`)
          # (inside the SQL literal itself, not in a later argument:
          # exec("UPDATE t SET url = ?", base + "/x") is parameterized)
          # (the literal's own quote ends it; `'` inside a "..." literal is SQL text)
          r"(?i)([\"'`])(?:(?!\1)[^\n]){0,200}?\b(?:select\b(?:(?!\1)[^\n]){0,200}\bfrom|insert\s+into|"
          r"update\s+\w+\s+set|delete\s+from)\b(?:(?!\1)[^\n]){0,400}?"
          r"(?:#\{|\$\{|\1\s*(?:\+|\.format\s*\(|%\s*[\w(\[{]))",
          # ${...} or #{...} after SQL text, also on a later line of a
          # template literal or heredoc whose opening quote is lines above
          r"(?i)\b(?:select\b[^\n]{0,200}\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b[^\n]*(?:\$\{|#\{)",
          # an f-string that interpolates into SQL-shaped text
          r"(?i)\bf([\"'])(?=[^\"']*\{)[^\"']*\b(?:select\b[^\"']{0,200}\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b",
          _SQL_CALL_PATTERN,
      )),
    R("JH105", "TLS verification disabled", "major", "security",
      "Certificate validation is turned off, so any network attacker can impersonate the peer.",
      "Enable verification and fix the trust chain (CA bundle, hostname, proxy) instead.",
      confidence="high", target="code", langs=PY + JS + JVM + CLIKE + ("ruby", "php", "go"),
      check="tls_verify_disabled",
      patterns=(
          r"\bverify\s*=\s*False\b",
          r"\brejectUnauthorized\s*:\s*false\b",
          r"\bNODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['\"]?0",
          r"\binsecure\s*[:=]\s*true\b",
          r"\bssl\._create_unverified_context\b",
          r"\bInsecureSkipVerify\s*:\s*true\b",
          r"\bcurl\b[^\n]*(?:\s-k\b|\s--insecure\b)",
      )),
    R("JH106", "Unsafe deserialization", "critical", "security",
      "Native deserializers can execute code or construct arbitrary objects when fed hostile data.",
      "Use a data-only format (JSON) with schema validation; never unpickle/unmarshal untrusted bytes.",
      confidence="high", langs=PY + JS + JVM + ("csharp", "ruby", "php"), check="unsafe_deserialization"),
    R("JH107", "Weak cryptography", "major", "security",
      "MD5/SHA-1/DES/RC4/ECB are broken or unsuitable for security-sensitive use.",
      "Use SHA-256+ for digests, bcrypt/argon2/scrypt for passwords, AES-GCM for encryption.",
      confidence="high", langs=PY + JS + JVM + CLIKE + ("ruby", "php", "go"),
      patterns=(
          r"hashlib\.(?:md5|sha1)\s*\(",
          r"MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-?1)",
          r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]",
          r"\b(?:DES|RC4|ECB)\b[^\n]*(?:Cipher|encrypt|decrypt|mode)",
          r"crypto\.createCipher\s*\(",
      )),
    R("JH108", "Debug mode enabled", "major", "security",
      "Debug mode often exposes stack traces, interactive consoles, and code execution.",
      "Force debug off outside local development and gate it behind an explicit environment check.",
      confidence="high", langs=PY + JS,
      patterns=(r"\bDEBUG\s*=\s*True\b", r"\bdebug\s*=\s*True\b", r"\bapp\.run\([^)]*debug\s*=\s*True")),
    R("JH109", "Permissive CORS", "major", "security",
      "A wildcard origin (especially with credentials) lets arbitrary sites call this API as the user.",
      "Allowlist exact origins and do not combine wildcard origins with credentials.",
      confidence="medium", target="nocomment", langs=PY + JS + JVM + CLIKE + ("ruby", "php", "go"),
      patterns=(
          r"(?i)Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*",
          r"(?i)Access-Control-Allow-Origin['\"]\s*,\s*['\"]\*['\"]",        # setHeader("...", "*")
          r"(?i)origin\s*:\s*['\"]\*['\"]",
          r"(?i)allow_origins\s*=\s*\[\s*['\"]\*['\"]",
          r"(?i)CORS_ORIGIN_ALLOW_ALL\s*=\s*True",
      )),
    R("JH110", "World-writable permissions", "major", "security",
      "chmod 777 makes files or executables writable by every local user.",
      "Grant the minimum required mode (for example 750/640) and use a dedicated group.",
      confidence="high", langs=SCRIPT + CLIKE + ("yaml",),
      patterns=(r"\bchmod\s+(?:0?777|a\+rwx)\b", r"\bos\.chmod\s*\([^,]+,\s*0o?777\b")),
    R("JH111", "Remote script piped to shell", "critical", "security",
      "curl/wget piped to a shell executes whatever the remote server returns, with no integrity check.",
      "Download, verify a checksum/signature, inspect, then execute; pin the version and URL.",
      confidence="high", target="nocomment", langs=SCRIPT + ("yaml", "docker"),
      patterns=(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b",)),
    R("JH112", "Insecure RNG for secrets", "minor", "security",
      "random/Math.random are predictable and must not generate tokens, salts, keys, or nonces.",
      "Use the platform CSPRNG: secrets/os.urandom, crypto.randomBytes, crypto.getRandomValues.",
      confidence="low", langs=PY + JS,
      patterns=(
          # a bare `key` is usually a React or history key, not a secret
          r"(?i)(?:\brandom\.(?:random|randint|randrange|choice|choices|getrandbits|sample)\s*\(|\bMath\.random\s*\()"
          r"[^\n]{0,80}(?:token|secret|passw|nonce|salt|otp|api_?key|private_?key|secret_?key|session_?id)",
          r"(?i)(?:token|secret|passw|nonce|salt|otp|api_?key|private_?key|secret_?key|session_?id)[^\n]{0,80}"
          r"(?:\brandom\.(?:random|randint|randrange|choice|choices|getrandbits|sample)\s*\(|\bMath\.random\s*\()",
      )),
    R("JH115", "JWT verification disabled", "critical", "security",
      "Disabling signature verification or accepting 'none' makes forged tokens indistinguishable from real ones.",
      "Always verify the signature and allowlist the expected algorithms.",
      confidence="high", target="nocomment", langs=PY + JS + JVM + CLIKE + ("ruby", "php", "go"),
      patterns=(
          r"verify_signatures?['\"]?\s*(?::\s*bool\s*)?[:=]\s*False\b",
          r"jwt\.decode\([^)\n]{0,200}verify\s*=\s*False",
          r"algorithms\s*=\s*\[\s*['\"]none['\"]",
      )),
    R("JH116", "Binds all network interfaces", "info", "security",
      "Listening on 0.0.0.0 exposes the service to every reachable network, not just localhost.",
      "Bind to 127.0.0.1 for local services; put public services behind an explicit proxy/firewall.",
      confidence="medium", target="nocomment", langs=PY + JS + JVM + CLIKE + ("ruby", "php", "go", "yaml", "toml", "ini"),
      patterns=(
          r"(?i)(?:^|[^A-Za-z0-9])(?:host|bind|listen|address|addr)\b\s*[=:]\s*['\"]?0\.0\.0\.0",
          r"(?i)\b(?:host|bind|listen|address|addr)\s*\(\s*['\"]0\.0\.0\.0",
          r"(?i)\b(?:listen|bind)\s*\(\s*[^,\n]{0,40},\s*['\"]0\.0\.0\.0",
          r"(?i)['\"]0\.0\.0\.0['\"]\s*,\s*(?:port|host)\b",
      )),
    R("JH118", "Review XML parser for XXE", "minor", "security",
      "XML parsers can resolve external entities or expand hostile payloads unless hardened.",
      "Disable DTDs/external entities (defusedxml, resolve_entities=False) and cap input size.",
      confidence="low", langs=PY + JVM + ("php", "csharp", "ruby"),
      patterns=(r"\b(?:xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax|lxml\.etree)[^\n]{0,40}\.(?:parse|fromstring|XML)\s*\(",)),
    R("JH119", "Unsafe tar extraction", "major", "security",
      "extractall on an untrusted tar can write outside the target directory (zip-slip/path traversal).",
      "Validate every member path, reject absolute/.. entries, and extract into a fresh sandbox directory.",
      confidence="medium", langs=PY, check="unsafe_extract"),
    R("JH120", "Unsafe archive extraction", "major", "security",
      "extractall/unpack_archive on an untrusted archive can write outside the target directory.",
      "Validate member paths before extraction or use a safe-extract helper; cap archive size and entry count.",
      confidence="medium", langs=PY, check="unsafe_extract"),
    R("JH121", "Insecure temporary file", "major", "security",
      "tempfile.mktemp has a race window: another process can create the path first.",
      "Use tempfile.mkstemp/NamedTemporaryFile with exclusive creation.",
      confidence="high", langs=PY,
      patterns=(r"\btempfile\.mktemp\s*\(",)),
    R("JH122", "Privileged container execution", "major", "security",
      "Privileged containers have host-level capabilities and weaken isolation.",
      "Drop capabilities, use a non-root user, and grant only the specific capability required.",
      confidence="high", target="nocomment", langs=SCRIPT + DOCKER + ("yaml",),
      patterns=(r"\bdocker\s+run\b[^\n]*--privileged\b", r"--cap-add(?:=|\s+)SYS_ADMIN\b", r"--pid(?:=|\s+)host\b")),
    R("JH124", "document.write sink", "major", "security",
      "document.write with dynamic content is an HTML injection sink.",
      "Build DOM nodes with textContent or sanitize with a maintained HTML sanitizer.",
      confidence="medium", langs=JS,
      patterns=(r"\bdocument\.write(?:ln)?\s*\(",)),
    R("JH125", "dangerouslySetInnerHTML", "major", "security",
      "React bypasses escaping here; unsanitized input becomes XSS.",
      "Render text normally or sanitize with DOMPurify before setting HTML.",
      confidence="high", langs=JS,
      patterns=(r"\bdangerouslySetInnerHTML\b",)),
    R("JH126", "innerHTML assignment", "major", "security",
      "Writing dynamic HTML into innerHTML/outerHTML can execute injected markup.",
      "Use textContent or a vetted sanitizer; treat all HTML as untrusted.",
      confidence="medium", langs=JS,
      patterns=(r"\.(?:inner|outer)HTML\s*=",)),
    R("JH127", "Vue v-html sink", "major", "security",
      "v-html injects raw HTML and bypasses Vue's escaping.",
      "Use interpolation or sanitize the value with DOMPurify.",
      confidence="high", langs=("vue", "html"),
      patterns=(r"\bv-html\s*=",)),
    R("JH128", "Angular security bypass", "major", "security",
      "bypassSecurityTrust* explicitly disables Angular's sanitization.",
      "Avoid the bypass; sanitize with a maintained sanitizer and justify any exception.",
      confidence="high", langs=JS,
      patterns=(r"\bbypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style)\s*\(", r"\btrustAsHtml\s*\(")),
    R("JH130", "Wildcard ALLOWED_HOSTS", "major", "security",
      "ALLOWED_HOSTS=['*'] disables Django host-header validation.",
      "List the exact hostnames the service serves.",
      confidence="high", langs=PY,
      patterns=(r"ALLOWED_HOSTS\s*=\s*\[[^\]]*['\"]\*['\"]",)),
    R("JH131", "Hidden Unicode characters", "major", "security",
      "Invisible or bidirectional characters make text read differently from how it is parsed or what a model receives.",
      "Delete the characters (or escape them explicitly), and require review of any change that adds them.",
      confidence="high", check="hidden_unicode"),
    R("JH132", "Secret shipped to the browser", "critical", "security",
      "A variable with a public prefix (NEXT_PUBLIC_, VITE_, REACT_APP_, ...) is inlined into the browser bundle, so every visitor gets the secret it holds.",
      "Move the secret to server-side code (an API route or server function), keep only non-secret values under public prefixes, and rotate the key.",
      confidence="high", tags=("secret",), check="public_env_secret"),
    R("JH133", "LLM API key used from the browser", "major", "security",
      "dangerouslyAllowBrowser ships the model API key to every visitor, who can spend on the account and use whatever the key can reach.",
      "Call the model from a server route that holds the key and authenticates the caller; let users bring their own key only by design.",
      confidence="high", target="code", langs=JS + ("html",),
      patterns=(r"\bdangerouslyAllowBrowser\s*:\s*true\b",)),
    R("JH134", "Data store open to the public", "critical", "security",
      "Security rules, row-level security, storage ACLs, or database firewalls let anyone on the internet read or change the data.",
      "Require authentication and per-user conditions in rules and policies, enable row-level security on every exposed table, keep buckets private, and keep databases off the public internet.",
      confidence="high", check="public_data_store"),

    # --------------------------------------------------------------- reliability
    R("JH201", "Empty error handler", "major", "reliability",
      "The handler swallows the error and continues, hiding failures and corrupting state.",
      "Handle, log with context, re-raise, or return a deliberate error.",
      confidence="high", check="empty_handler", langs=PY + JS + JVM + CLIKE),
    R("JH202", "Broad catch", "minor", "reliability",
      "Catching Exception/Throwable also catches programming errors and shutdown signals.",
      "Catch the specific exception types you can actually handle.",
      confidence="medium", langs=PY + JVM + ("csharp",),
      patterns=(r"\bexcept\s+(?:Exception|BaseException)\b", r"\bcatch\s*\(\s*(?:Exception|Throwable|System\.Exception)\b")),
    R("JH217", "Bare except", "major", "reliability",
      "A bare except catches everything, including KeyboardInterrupt and SystemExit.",
      "Catch specific exceptions; if cleanup is the goal, use try/finally.",
      confidence="high", langs=PY, patterns=(r"^\s*except\s*:",)),
    R("JH203", "TODO/FIXME marker", "info", "maintainability",
      "An unresolved marker records known debt or a known defect.",
      "Link it to an issue or resolve it; do not let it become permanent.",
      confidence="high", target="comments",
      patterns=(r"\b(?:TODO|FIXME|HACK|BUG)\b|\bXXX\b(?=\s*[:(\-])|(?:^|[#/*;\-]|<!--)\s*(?i:(?:todo|fixme|hack)\s*[:(])",)),
    R("JH204", "Debug leftover", "minor", "reliability",
      "Debug output or a debugger hook is still in the code path.",
      "Remove it or route it through the project logger at an appropriate level.",
      confidence="medium", langs=PY + JS + ("php", "ruby"), check="debug_leftover"),
    R("JH205", "Commented-out code", "info", "maintainability",
      "Commented code rots, confuses readers, and hides intent; version control already remembers it.",
      "Delete it or restore it with a test; keep comments for why, not what used to be.",
      confidence="low", target="comments",
      patterns=(r"(?i)^\s*(?:if|for|while|switch|return|def|class|function|const|let|var|import|from|public|private|protected|try|catch|#include)\b",
                # a trailing ; { } counts only with something code-shaped: an assignment, a call, an arrow, or braces alone
                r"^(?=.*(?:[^=!<>]=[^=]|\w\(|=>)).*[;{}]\s*$|^\s*(?://+|#+|--|/?\*+)?\s*[{}]+\s*;?\s*$")),
    R("JH206", "Mutable default argument", "major", "reliability",
      "A list/dict default is created once and shared across calls, so state leaks between invocations.",
      "Use None as the default and create a fresh container inside the function.",
      confidence="high", langs=PY,
      patterns=(r"\bdef\s+\w+\s*\([^)\n]*=\s*(?:\[\]|\{\})",)),
    R("JH207", "Comparison to None", "minor", "reliability",
      "Equality with None calls __eq__ and can behave unexpectedly for proxies and overloaded objects.",
      "Use 'is None' / 'is not None'.",
      confidence="high", langs=PY,
      patterns=(r"(?:[=!]=\s*None\b|\bNone\s*[=!]=)",)),
    R("JH208", "return inside finally", "major", "reliability",
      "A return/break/continue in finally discards exceptions and pending return values.",
      "Do cleanup only in finally; return after the try/finally block.",
      confidence="high", check="return_in_finally", langs=PY),
    R("JH210", "Blocking call in async function", "major", "reliability",
      "A synchronous network/process call inside async def blocks the event loop for every task.",
      "Use the async client or run the blocking call in a worker thread/executor.",
      confidence="medium", check="blocking_in_async", langs=PY),
    R("JH212", "HTTP call without timeout", "minor", "reliability",
      "A missing timeout can hang a worker or request forever when the peer stalls.",
      "Set connect and read timeouts explicitly; add bounded retries with backoff.",
      confidence="medium", check="missing_timeout", langs=PY),
    R("JH213", "Subprocess without timeout", "minor", "reliability",
      "A hung child process can pin the parent indefinitely.",
      "Pass a timeout and handle TimeoutExpired; kill the process group on cleanup.",
      confidence="medium", check="subprocess_timeout", langs=PY),
    # ------------------------------------------------------------ maintainability
    R("JH301", "Long function", "minor", "maintainability",
      "A long function is hard to test, reason about, and review.",
      "Extract cohesive steps into named helpers and keep one level of abstraction per function.",
      confidence="medium", check="long_function", langs=PY + CLIKE + JS),
    R("JH302", "Deep nesting", "minor", "maintainability",
      "Deep nesting multiplies branches and makes control flow hard to verify.",
      "Use guard clauses, early returns, or extract helper functions.",
      confidence="medium", check="deep_nesting", langs=PY + CLIKE + JS),
    R("JH303", "Very long line", "info", "maintainability",
      "Long lines are hard to review and often hide generated or minified content.",
      "Wrap the expression or move data into a resource file.",
      confidence="high", target="raw",
      patterns=(r"^.{201,}$",)),
    R("JH304", "Large source file", "info", "maintainability",
      "A very large file usually mixes responsibilities and slows navigation/review.",
      "Split by cohesion; keep modules focused on one reason to change.",
      confidence="medium", check="large_file"),
    R("JH305", "Duplicated block", "info", "maintainability",
      "A block of six or more lines appears more than once in the file.",
      "Extract the repeated logic or data; keep one source of truth.",
      confidence="low", check="duplicate_blocks"),
    R("JH306", "Suppression comment", "info", "maintainability",
      "A lint/type/security suppression hides a diagnostic; it may be stale or too broad.",
      "Fix the underlying issue or narrow the suppression with a reason and an owner.",
      confidence="high", target="comments",
      patterns=(r"(?i)(?:#\s*noqa|#\s*type:\s*ignore|eslint-disable|@ts-ignore|@ts-expect-error|nolint|pylint:\s*disable|rubocop:disable|#\s*nosec|#\[allow\()",)),
    R("JH307", "Wildcard import", "info", "maintainability",
      "Wildcard imports hide dependencies and can silently shadow names.",
      "Import the specific names or the module.",
      confidence="high", langs=PY, patterns=(r"^\s*from\s+[\w.]+\s+import\s+\*",)),
    R("JH308", "Dead branch", "info", "reliability",
      "A branch guarded by a constant false value can never execute.",
      "Remove it or replace the constant with a real feature flag/configuration value.",
      confidence="high", langs=PY + JS + JVM + CLIKE,
      patterns=(r"^\s*if\s*\(\s*(?:False|false|0)\s*\)", r"^\s*if\s+(?:False|false|0)\s*:")),
    R("JH315", "assert in production code", "minor", "reliability",
      "Python removes assert statements under -O, so they cannot enforce runtime invariants.",
      "Raise an explicit exception for checks that must always run; keep asserts in tests.",
      confidence="high", langs=PY, tags=("test-exclude",),
      patterns=(r"^\s*assert\s+",)),

    # -------------------------------------------------------------------- config
    R("JH401", "Secret-bearing file", "critical", "security",
      "A file that commonly stores credentials is present in the scan (and may be tracked by git).",
      "Store secrets outside the repo, add the file to .gitignore, and rotate anything committed.",
      confidence="high", tags=("secret",), check="secret_file"),
    R("JH402", "Dockerfile ADD from URL", "major", "security",
      "ADD with a URL downloads and extracts remote content without integrity verification.",
      "Use COPY for local files; download with checksum/signature verification when remote content is required.",
      confidence="high", target="nocomment", kinds=DOCKER,
      patterns=(r"^\s*ADD\s+https?://",)),
    R("JH403", "Dockerfile runs as root", "minor", "security",
      "The final image has no USER directive, so the process runs as root by default.",
      "Create/use an unprivileged user and set USER in the final stage.",
      confidence="high", check="dockerfile_user", kinds=DOCKER),
    R("JH404", "Unpinned Docker base image", "info", "supply-chain",
      "A floating base tag makes builds non-reproducible and can silently pull a broken or compromised image.",
      "Pin the base image by digest (FROM image@sha256:...) and update deliberately.",
      confidence="high", check="dockerfile_base", kinds=DOCKER),
    R("JH405", "Privileged Compose service", "major", "security",
      "privileged: true gives the container host-level access.",
      "Remove privileged, drop capabilities, and mount only the required devices.",
      confidence="high", target="nocomment", kinds=COMPOSE,
      patterns=(r"(?i)^\s*privileged\s*:\s*true\b",)),
    R("JH406", "Privileged Kubernetes workload", "critical", "security",
      "A privileged pod can escape most container isolation.",
      "Set privileged: false, drop ALL capabilities, and use a non-root security context.",
      confidence="high", target="nocomment", kinds=K8S,
      patterns=(r"(?i)^\s*privileged\s*:\s*true\b",)),
    R("JH407", "Kubernetes host namespace", "major", "security",
      "hostNetwork/hostPID/hostIPC share the node's namespaces and weaken isolation.",
      "Use the pod network/namespace; if host access is required, document and narrowly scope it.",
      confidence="high", target="nocomment", kinds=K8S,
      patterns=(r"(?i)^\s*(?:hostNetwork|hostPID|hostIPC)\s*:\s*true\b",)),
    R("JH408", "Privilege escalation allowed", "major", "security",
      "allowPrivilegeEscalation: true lets the process gain more privileges than its parent.",
      "Set allowPrivilegeEscalation: false and runAsNonRoot: true.",
      confidence="high", target="nocomment", kinds=K8S,
      patterns=(r"(?i)^\s*allowPrivilegeEscalation\s*:\s*true\b",)),
    R("JH409", "Kubernetes container runs as root", "major", "security",
      "runAsUser: 0 explicitly runs the container as root.",
      "Use an unprivileged UID and set runAsNonRoot: true.",
      confidence="high", target="nocomment", kinds=K8S,
      patterns=(r"(?i)^\s*runAsUser\s*:\s*0\b",)),
    R("JH410", "seccomp unconfined", "major", "security",
      "seccompProfile: Unconfined disables syscall filtering.",
      "Use RuntimeDefault or a restrictive custom seccomp profile.",
      confidence="high", target="nocomment", kinds=K8S,
      patterns=(r"(?i)^\s*seccompProfile\s*:\s*Unconfined\b",)),
    R("JH411", "hostPath volume", "major", "security",
      "hostPath mounts node files into the pod and is a common container-escape primitive.",
      "Use a managed volume/PVC; if hostPath is unavoidable, read-only and a narrow path.",
      confidence="high", target="nocomment", kinds=K8S,
      patterns=(r"(?i)^\s*hostPath\s*:",)),
    R("JH412", "Kubernetes image on latest", "info", "supply-chain",
      "The latest tag is mutable, so the running image can change without a manifest change.",
      "Pin an immutable tag or digest and update explicitly.",
      confidence="high", target="nocomment", kinds=K8S,
      patterns=(r"(?i)^\s*-?\s*image\s*:\s*['\"]?[^\s'\"]+:latest\b",)),
    R("JH413", "Deprecated Kubernetes apiVersion", "major", "reliability",
      "This API version was removed from modern Kubernetes; the manifest will fail on upgrade.",
      "Migrate to the current stable API version and test against the target cluster.",
      confidence="high", target="nocomment", kinds=K8S,
      patterns=(r"(?i)^\s*apiVersion\s*:\s*(?:extensions/v1beta1|apps/v1beta1|apps/v1beta2|policy/v1beta1|batch/v1beta1|networking\.k8s\.io/v1beta1|rbac\.authorization\.k8s\.io/v1beta1)\s*$",)),
    R("JH414", "Dangerous capability added", "major", "security",
      "SYS_ADMIN/NET_ADMIN/SYS_PTRACE/ALL capabilities substantially weaken isolation.",
      "Drop ALL and add only the minimal capability the workload proves it needs.",
      confidence="medium", target="nocomment", kinds=K8S, check="dangerous_capability"),
    R("JH415", "Kubernetes secret literal", "critical", "security",
      "A Kubernetes Secret manifest embeds a value in plaintext, which is committed to git.",
      "Use an external secret manager/SealedSecret/SOPS; never commit plaintext Secret data.",
      confidence="high", check="k8s_secret_literal", kinds=K8S),
    R("JH416", "CI failure allowed", "info", "ci",
      "continue-on-error/allow_failure lets a failing job report success.",
      "Remove it or narrow it to an explicitly non-blocking job with an owner.",
      confidence="high", target="nocomment", kinds=CI,
      patterns=(r"(?i)^\s*(?:continue-on-error|allow_failure)\s*:\s*true\b",)),
    R("JH417", "CI action not pinned to SHA", "major", "supply-chain",
      "A tag or branch can be moved; a compromised action then runs with your CI credentials.",
      "Pin third-party actions to a full commit SHA and update deliberately.",
      confidence="high", check="gh_action_pinning", kinds=GH),
    R("JH418", "pull_request_target checks out PR code", "critical", "security",
      "pull_request_target runs with repository secrets, and checking out the PR head lets untrusted code execute there.",
      "Do not checkout the PR head in pull_request_target; use pull_request, or split into an isolated workflow without secrets.",
      confidence="high", check="gh_pull_request_target", kinds=GH),
    R("JH419", "GitHub expression in shell", "critical", "security",
      "Untrusted github.event/head_ref values interpolated into run: allow script injection.",
      "Pass values through env: and quote them, or validate against a strict allowlist.",
      confidence="high", check="gh_expr_injection", kinds=GH),
    R("JH420", "GitHub token write-all", "major", "security",
      "permissions: write-all gives every job broad repository access.",
      "Grant per-job read/write permissions only for the scopes actually needed.",
      confidence="high", target="nocomment", kinds=GH,
      patterns=(r"(?i)^\s*permissions\s*:\s*write-all\b",)),
    R("JH421", "GitLab remote include", "major", "supply-chain",
      "A remote include executes CI configuration from a URL outside the repository.",
      "Pin the include to a specific project/ref/commit or vendor the file.",
      confidence="high", target="nocomment", kinds=GL,
      patterns=(r"(?i)^\s*-\s*remote\s*:\s*https?://",)),
    R("JH422", "GitLab image on latest", "info", "supply-chain",
      "The latest tag is mutable and can change the build without a commit.",
      "Pin an immutable image tag or digest.",
      confidence="high", target="nocomment", kinds=GL,
      patterns=(r"(?i)^\s*image\s*:\s*['\"]?[^\s'\"]+:latest\b",)),
    R("JH423", "Lockfile missing", "info", "supply-chain",
      "A JavaScript manifest without a lockfile can resolve different dependency trees on every install.",
      "Commit the lockfile and use npm ci / pnpm install --frozen-lockfile / yarn --immutable.",
      confidence="high", check="lockfile_missing", kinds=("package_json",)),
    R("JH424", "Unpinned npm dependency", "minor", "supply-chain",
      "A '*' or 'latest' version range makes installs non-reproducible and can pull breaking or hostile releases.",
      "Pin an exact version or a bounded range and update intentionally.",
      confidence="high", target="nocomment", kinds=("package_json",),
      patterns=(r'^\s*"[^"]+"\s*:\s*"(?:\*|latest)"',)),
    R("JH425", "Compose host network", "info", "security",
      "network_mode: host removes network isolation for the container.",
      "Use a user-defined network and expose only the required ports.",
      confidence="high", target="nocomment", kinds=COMPOSE,
      patterns=(r"(?i)^\s*network_mode\s*:\s*host\b",)),
    R("JH426", "npm install in CI", "info", "ci",
      "npm install can rewrite the lockfile and is not reproducible; npm ci is.",
      "Use npm ci (or pnpm install --frozen-lockfile / yarn --immutable).",
      confidence="medium", target="nocomment", kinds=CI,
      patterns=(r"\bnpm\s+install\b",)),
    R("JH427", "All secrets serialized", "critical", "security",
      "toJSON(secrets) hands every repository and organization secret to one step; a compromised step exfiltrates them all.",
      "Pass only the individual secrets the step needs (secrets.NAME), through env:.",
      confidence="high", target="nocomment", kinds=GH,
      patterns=(r"(?i)\$\{\{\s*toJSON\s*\(\s*secrets\s*\)\s*\}\}",)),
    R("JH428", "Reusable workflow inherits all secrets", "minor", "security",
      "secrets: inherit passes every secret to the called workflow, including ones it never uses.",
      "Pass the specific secrets the reusable workflow declares; never inherit into another repository's workflow.",
      confidence="high", check="gh_secrets_inherit", kinds=GH),
    R("JH429", "pip extra index (dependency confusion)", "minor", "supply-chain",
      "pip treats an extra index as equal to the main one and installs the highest version from any index, so a public package reusing a private name can win.",
      "Serve public and private packages through one controlled index (--index-url), or use per-package indexes (uv explicit indexes); install with --require-hashes.",
      confidence="medium", check="pip_extra_index"),
    R("JH430", "Dependabot runs external code", "major", "supply-chain",
      "insecure-external-code-execution: allow lets dependency manifests run code during Dependabot updates, with access to its registry credentials.",
      "Remove the setting; vendor or pre-build whatever the manifest needs instead.",
      confidence="high", target="nocomment", kinds=("dependabot",),
      patterns=(r"(?i)^\s*insecure-external-code-execution\s*:\s*['\"]?allow\b",)),
    R("JH432", "Any pushed branch runs a privileged workflow", "major", "security",
      "A workflow runs on a push to any branch with secrets or a write-scoped token, so code on an unreviewed branch (an AI agent's, or a contributor's) runs with that power before anyone approves it.",
      "Run branch builds on pull_request with permissions: contents: read and no secrets; keep secrets and write tokens for the default branch or a protected environment.",
      confidence="medium", check="gh_branch_push_privileged", kinds=GH),
    R("JH431", "Dependency updates without cooldown", "info", "supply-chain",
      "Updates are proposed the moment a release appears; most malicious releases are caught and pulled within days.",
      "Add cooldown: (for example default-days: 7) to each update entry so new releases age before they are proposed.",
      confidence="medium", check="dependabot_cooldown", kinds=("dependabot",)),

    # --------------------------------------------------------------------- tests
    R("JH501", "Skipped test", "info", "tests",
      "A skipped test provides no protection and can hide a regression for a long time.",
      "Fix and re-enable it, or delete it with a linked issue explaining the gap.",
      confidence="high", target="nocomment", kinds=TEST + ("test",),
      patterns=(r"@pytest\.mark\.skip\b", r"@unittest\.skip", r"\.skip\s*\(", r"\bxit\s*\(", r"\bxdescribe\s*\(", r"\bt\.Skip\s*\(", r"@Disabled\b")),
    R("JH502", "Test without assertions", "minor", "tests",
      "This test executes code but never checks a result, so it cannot fail meaningfully.",
      "Assert the observable behavior, or remove the test if it only checks 'no exception'.",
      confidence="medium", check="assertion_free_test", kinds=TEST + ("test",)),
    R("JH503", "Sleep in test", "info", "tests",
      "Fixed sleeps make tests slow and flaky under load.",
      "Await the condition, use fake timers, or poll with a bounded deadline.",
      confidence="high", target="code", kinds=TEST + ("test",),
      patterns=(r"\btime\.sleep\s*\(", r"\bThread\.sleep\s*\(")),
    R("JH504", "Tautological assertion", "minor", "tests",
      "The assertion is always true, so the test cannot detect a regression.",
      "Assert a specific value or behavior that would change if the code broke.",
      confidence="high", target="nocomment", kinds=TEST + ("test",),
      patterns=(r"\bassert\s+True\b",
                r"\bexpect\s*\(\s*true\s*\)\s*(?:;|\)|$|\.(?:toBe|toEqual|toStrictEqual)\s*\(\s*true\s*\)|"
                r"\.(?:toBeTruthy|toBeTrue|toBeDefined)\s*\(\s*\)|\.not\.(?:toBeFalsy|toBeNull|toBeUndefined)\s*\(\s*\)|"
                r"\.not\.toBe\s*\(\s*false\s*\)|\.to\.(?:be\.)?(?:true|ok)\b|\.to\.(?:equal|eql)\s*\(\s*true\s*\))",
                r"\bassertEqual\s*\(\s*True\s*,\s*True")),
    R("JH505", "Focused test", "major", "tests",
      "A focused test (.only/fit/fdescribe) silently skips the rest of the suite in many runners.",
      "Remove the focus marker before merging.",
      confidence="high", target="code", kinds=TEST + ("test",),
      patterns=(r"(?<![\w$.])(?:describe|it|test|context|suite|specify|fixture|scenario|feature|QUnit|tap|t|bench)"
                r"(?:\.(?:describe|serial|parallel|concurrent|sequential|skipIf\([^)]*\)|runIf\([^)]*\)))*\.only\s*\(",
                r"@pytest\.mark\.focus\b", r"(?<![\w.$])fit\s*\(\s*[\"'`,]", r"(?<![\w.$])fdescribe\s*\(\s*[\"'`,]")),

    # ---------------------------------------------------------------------- docs
    R("JH601", "Broken relative link", "minor", "docs",
      "A relative Markdown link points at a file or directory that does not exist.",
      "Fix the path or remove the link; run a link checker in CI.",
      confidence="high", check="broken_links", kinds=("markdown",)),

    # --------------------------------------------------------------------- agents
    # What an AI coding agent does when it opens, reads, or runs in this
    # repository. Patterns are written so they do not match their own source.
    R("JH701", "Suspicious agent instruction", "major", "agent",
      "An agent instruction file hides content or asks the agent to act without the user's knowledge; agents read and follow it.",
      "Remove the instruction, review the file like code, and keep agent instructions visible and specific.",
      confidence="medium", check="agent_instruction", kinds=("agent_context",)),
    R("JH702", "AI agent runs without approvals", "major", "agent",
      "An AI coding agent is started with human approval disabled: any prompt injection in what it reads becomes command execution with this environment's credentials.",
      "Keep approvals on; if automation needs autonomy, run the agent in a sandbox with no secrets, an egress allowlist, and a least-privilege token.",
      confidence="high", target="nocomment", langs=SCRIPT + JS + ("yaml", "docker", "make", "json", "toml"),
      patterns=(
          r"--dangerously[-]skip[-]permissions\b",
          r"--permission[-]mode[= ]+['\"]?bypassPermissions\b",
          r"--dangerously[-]bypass[-]approvals[-]and[-]sandbox\b",
          # The tool must be the command word (not a package name such as
          # gemini-sdk), and the flag must belong to the same command.
          r"(?:^|[\s;&|(\"'`/${])codex(?:\.exe|\.cmd)?\}?(?:@[\w.\-]+)?\s(?:[^\n;&|]*\s)?--yolo\b",
          r"(?:^|[\s;&|(\"'`/${])gemini(?:-cli)?(?:\.exe|\.cmd)?\}?(?:@[\w.\-]+)?\s(?:[^\n;&|]*\s)?(?:--yolo\b|-y\b|--approval[-]mode[= ]+['\"]?yolo\b)",
          r"--trust[-]all[-]tools\b",
          r"(?:^|[\s;&|(\"'`/${])copilot(?:\.exe|\.cmd)?\}?(?:@[\w.\-]+)?\s(?:[^\n;&|]*\s)?--allow[-]all[-]tools\b",
          r"(?:^|[\s;&|(\"'`/${])aider(?:\.exe|\.cmd)?\}?(?:@[\w.\-]+)?\s(?:[^\n;&|]*\s)?--yes[-]always\b",
          r"(?:^|[\s;&|(\"'`/${])cursor[-]agent(?:\.exe|\.cmd)?\}?(?:@[\w.\-]+)?\s(?:[^\n;&|]*\s)?(?:--force|-f)\b",
      ),
      ignore=r"\bre\.compile\(|\bnew\s+RegExp\(|\bRegex\("),
    R("JH703", "Agent approvals disabled in workspace config", "critical", "agent",
      "A committed workspace setting lets an AI agent act without asking, for everyone who opens the repository; prompt injection then needs no click.",
      "Remove the setting from the repository; approvals are a per-user choice, not a project default.",
      confidence="high", check="agent_config_approvals", kinds=("agent_config",)),
    R("JH704", "Workspace config runs commands or reroutes the agent", "major", "agent",
      "Opening the repository in an editor or agent runs commands, or sends the agent's API traffic and keys to another host.",
      "Remove auto-run tasks, hooks, and base-URL overrides from committed config, or document and review each one.",
      confidence="medium", check="agent_config_autorun", kinds=("agent_config",)),
    R("JH705", "MCP server from an unpinned package", "major", "agent",
      "Every agent start downloads and runs the newest release of the server, so a compromised or rug-pulled update executes with the agent's access.",
      "Pin an exact version (name@1.2.3, name==1.2.3) or an image digest, and review updates deliberately.",
      confidence="high", check="mcp_unpinned", kinds=("mcp_config",)),
    R("JH706", "Credential literal in MCP config", "critical", "agent",
      "A token, key, or password is written into an MCP server definition, so everyone with repository access has it.",
      "Rotate it, and reference it from the environment or an input prompt (${env:NAME}, ${input:name}) instead.",
      confidence="high", tags=("secret",), check="mcp_credentials", kinds=("mcp_config",)),
    R("JH707", "Remote MCP server over plaintext HTTP", "major", "agent",
      "Tool calls, results, and any bearer token cross the network unencrypted.",
      "Use https:// for every remote MCP server.",
      confidence="high", check="mcp_plaintext", kinds=("mcp_config",)),
    R("JH708", "Untrusted input in AI agent prompt", "critical", "agent",
      "Text that anyone can write (issue, PR, or comment fields) reaches an AI agent step; instructions hidden in it can steer the agent and its token.",
      "Do not feed untrusted event text to an agent that holds write permissions or secrets; triage with a read-only token, restrict who can trigger it, and treat agent output as untrusted.",
      confidence="medium", check="gh_agent_prompt", kinds=GH),
    R("JH709", "Agent sandbox network or file access too broad", "major", "agent",
      "A committed sandbox setting lets the agent's commands reach any host, a private network, the Docker socket, or credential paths, so a prompt injection can exfiltrate data or escape the sandbox.",
      "Allow named hosts only, keep wildcards off shared cloud domains, keep the Docker socket and home directory out of the sandbox, and scope rules to the binaries that need them.",
      confidence="high", check="agent_sandbox_scope", kinds=("agent_config", "sandbox_policy")),
    R("JH710", "Agent sandbox not enforcing", "major", "agent",
      "The sandbox policy only logs what it should block, skips TLS inspection, lets credentials pass uninspected, or runs without filesystem rules when Landlock is unavailable.",
      "Set enforcement: enforce, landlock compatibility: hard_requirement, keep TLS inspection on, and leave allow_uninspected_credentials off.",
      confidence="high", check="agent_sandbox_enforcement", kinds=("sandbox_policy",)),
    R("JH711", "Dev container weakens isolation", "major", "agent",
      "The dev container runs privileged, shares the host network or process namespace, or mounts the Docker socket; an agent or task inside it can take over the host.",
      "Drop --privileged, host networking and extra capabilities; use docker-in-docker or a rootless builder instead of the host Docker socket.",
      confidence="high", check="devcontainer_isolation", kinds=("agent_config",)),

    # ----------------------------------------------------------------- CVE (dynamic)
    R("JH901", "Known vulnerable dependency", "critical", "security",
      "A dependency version matches a published security advisory.",
      "Upgrade to a fixed version; if none exists, mitigate or replace the dependency.",
      confidence="high", tags=("cve", "supply-chain")),
]


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

@dataclass
class ScanOptions:
    min_severity: str = "info"
    categories: Optional[Set[str]] = None
    rule_ids: Optional[Set[str]] = None
    max_per_file_rule: int = 5
    max_per_rule: int = 200
    include_cve: bool = False
    # False for governance scans: repository pragmas cannot hide what the
    # citizen profile must see.
    honor_suppressions: bool = True


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    files: int = 0
    loc: int = 0
    skipped: int = 0
    # Per-rule telemetry independent of --min-severity/--category/--rule
    # filters, so it reflects what the rule actually matched, not what the
    # CLI chose to display. fired = every match before any filtering;
    # suppressed = subset dropped specifically by an inline
    # `# jankhunt42: ignore` pragma. Consumed by --calibrate (jh_calibrate.py).
    fired_by_rule: Dict[str, int] = field(default_factory=dict)
    suppressed_by_rule: Dict[str, int] = field(default_factory=dict)


_COMPILED: Dict[str, List[re.Pattern]] = {}
_IGNORES: Dict[str, re.Pattern] = {}

# Secret-shaped matches that are not credential material: references to
# where the value lives, generated runs, and descriptive fixture names
# (`"test-token"`, `"managed-bedrock-api-key"`). Found by running the scanner
# on public repositories, where these were nearly all of JH101's hits.
_SECRET_QUOTED_RE = re.compile(r"[:=]\s*([\"'])((?:(?!\1)[^\n])+)\1")
_SECRET_REF_RE = re.compile(r"\benv\(|\{\{|\$\(|\$\{|%\(|^\$\w+(?:$|[/\\.:])|^<[^>]+>$")
_SECRET_PREFIX_RE = re.compile(r"^(?:sk-ant-(?:api|admin)\d+-|sk-(?:proj-|lf-)?|[sr]k_live_|gh[pousr]_|github_pat_|xox[baprs]-|glpat-|hf_|gsk_|npm_)")
# a UI label like "Bearer Token Env Var" (Title Case); lowercase word runs may be passphrases
_SECRET_TEXT_RE = re.compile(r"^[A-Z][a-z]*(?: [A-Z][a-z]*)+$")
_SECRET_RUN_RE = re.compile(r"abcdefgh|01234567|12345678|(.)\1{7,}", re.IGNORECASE)
# words, optionally numbered ("endpoint-secret-0001"); a mixed segment such as
# "9f8a7c6b5d4e" is token material
_SECRET_WORDS_RE = re.compile(r"^[a-z]+(?:[-_.](?:[a-z]+|\d{1,4}))+$", re.IGNORECASE)
_SECRET_CAMEL_RE = re.compile(r"^(?:[a-z]+[-_])*(?:[A-Z][a-z]+){3,}$")
# words that mark a value as test data, unlike "secret" or "key", which
# people also put in real passwords ("Prod-Admin-Secret-91")
_SECRET_FIXTURE_RE = re.compile(
    r"(?:^|[-_.])(?:test|testing|tests|mock|fake|dummy|fixture|stub|sample|example|placeholder|synthetic|"
    r"redacted|changeme|replace|insert|your|here|todo|fixme)(?=[-_.]|$)", re.IGNORECASE)
_SECRET_DESCRIPTIVE_RE = re.compile(
    r"(?:^|[-_.])(?:test|testing|mock|fake|dummy|fixture|stub|static|sample|example|placeholder|local|dev|"
    r"synthetic|managed|token|secret|key|password|passwd|pass|credential|creds?|api|apikey|auth|issuer|client)(?=[-_.]|$)",
    re.IGNORECASE)


def _human_chosen(value: str) -> bool:
    """Capitalised words with a number ("Summer_Pass_2024", "Acme_Client_Key7")
    read as a password someone chose, not as a fixture name."""
    return bool(re.search(r"\d", value) and re.search(r"(?:^|[-_.])[A-Z][a-z]+", value)
                and not _SECRET_FIXTURE_RE.search(value))


def _url_without_secret(value: str) -> bool:
    """A URL with no password, no token-like query value, and no long mixed
    path segment (webhook secrets live in paths)."""
    if not re.match(r"https?://(?![^/\s]*:[^/\s]*@)", value):
        return False
    mixed = r"(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Za-z])[A-Za-z0-9_\-]"
    return not (re.search(r"[?&#][\w.\-]*=%s{10,}" % mixed, value) or re.search(r"/%s{20,}" % mixed, value))


# usernames that services fix for token authentication (the token is the password)
_TOKEN_USERNAMES = {"x-oauth-basic", "x-access-token", "oauth2", "oauth2accesstoken", "token", "__token__"}
_STOPWORDS = {"the", "a", "an", "is", "are", "not", "on", "in", "to", "of", "for", "and", "or", "with", "this",
              "that", "your", "you", "it", "be", "can", "from", "use", "create", "at", "by", "must", "should",
              "will", "has", "have", "no", "if", "only", "all", "some", "least", "characters", "required",
              "please", "enter", "invalid", "does", "do", "was", "were"}
# the most common default passwords: a weak-credential lead, not secret material
COMMON_PASSWORDS = {"password", "password1", "password123", "passw0rd", "admin", "admin123", "administrator",
                    "123456", "12345678", "123456789", "qwerty", "letmein", "welcome", "secret", "test",
                    "test123", "testing", "demo", "demo123", "root", "toor", "changeme", "default", "guest",
                    "user", "user123", "pass", "pass123", "1234", "abc123", "postgres", "mysql", "sa",
                    "hunter2", "hunter22"}


def secret_placeholder(match_text: str) -> bool:
    """True when a secret-pattern match is a reference, a generated run, or a
    descriptive fixture value rather than credential material."""
    quoted = _SECRET_QUOTED_RE.search(match_text)
    value = quoted.group(2) if quoted else match_text
    if _SECRET_REF_RE.search(value) or _SECRET_RUN_RE.search(value):
        return True
    if value.strip().lower() in _TOKEN_USERNAMES:
        return True
    # the name of a secret or setting, not its value ("DATA_BUCKET", "DN2CPP_FAULT_PROBE")
    if re.fullmatch(r"[A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+", value) and sum(1 for s in value.split("_") if re.search(r"[A-Z]{2}", s)) >= 2:
        return True
    # a sentence: five or more words, two of them common function words
    words = value.lower().replace(";", " ").replace(",", " ").replace(".", " ").split()
    if len(words) >= 5 and sum(1 for w in words if w in _STOPWORDS) >= 2:
        return True
    # a regular expression, a CSS custom property, or an elided example ("sk-live-...")
    if re.search(r"\\[dwsSbB]|\[[^\]]*-[^\]]*\]|\{\d+(?:,\d*)?\}|\(\?[:!=]", value) or \
            re.fullmatch(r"--[a-z0-9][a-z0-9-]*", value) or value.rstrip().endswith(("...", "\u2026")):
        return True
    if quoted:
        key = re.match(r"[\w-]*", match_text).group(0).lower()
        # a URL without a password, the key's own name as its value
        # (password: "password"), the xkcd example passphrase, a concatenation
        if _url_without_secret(value) or \
                re.sub(r"[\W_]", "", value.lower()) == re.sub(r"[\W_]", "", key) or \
                re.fullmatch(r"(?i)correct[ _-]?horse[ _-]?battery(?:[ _-]?staple)?", value) or re.match(r"\s+\+\s", value):
            return True
        # the match ran across string boundaries into code: split('secret=')[1],
        # '"' + crypto.randomBytes(32).toString('hex') + '"'
        if re.match(r"[)\]]", value) and re.search(r"[.(]\w", value) or re.search(r"""["'`]\s*\+\s*\w|\w[\w)\]]*\s*\+\s*["'`]""", value):
            return True
        # log("secret:", token ? "yes" : "no"): the "value" is the code between two string arguments
        if re.match(r"\s*,\s*[\w$.]+", value) or re.search(r"\s\?\s*$", value):
            return True
        # a CSS selector (Playwright and portal scrapers: password: "#login-password")
        if ("pass" not in key and re.fullmatch(r"[#.][A-Za-z_][\w\-]*", value.strip())) or \
                re.fullmatch(r"[#.][a-z]+(?:(?:-|__?)[a-z]+)+", value.strip()) or \
                re.search(r":has(?:-text)?\(|\[name[*^$|~]?=", value):
            return True
        # a capitalised label of words ("Client ID", "Escolha uma conta"), unless the key may be a password
        if "pass" not in key and re.fullmatch(r"[^\W\d_a-z][^\W\d_]*(?:[ \t]+[^\W\d_]+){1,6}(?:\s*\([^)]*\))?", value.strip()):
            return True
        # a lowercase name ("identifier", "attribute.name") is not a credential,
        # unless the key says it may be a password
        if re.fullmatch(r"[a-z]+(?:[._-][a-z]+)*", value) and "pass" not in key:
            return True
    if _SECRET_TEXT_RE.match(value):
        return bool(_SECRET_DESCRIPTIVE_RE.search(value.replace(" ", "-")))
    if _human_chosen(value):
        return False
    # descriptive words, also after a provider prefix ("sk-proj-SYNTHETIC_CREDENTIAL")
    tail = _SECRET_PREFIX_RE.sub("", value)
    for v in (value, tail):
        # two or more words, one marking test data, plus at most short ids ("test_redaction_d84e11")
        segs = [x for x in re.split(r"[-_.]", v) if x]
        words = [x for x in segs if x.isalpha()]
        if len(words) >= 2 and any(_SECRET_FIXTURE_RE.search(w) for w in words) \
                and all(len(x) <= 8 for x in segs if not x.isalpha()):
            return True
    if tail != value and (re.fullmatch(r"[a-z]+(?:[-_](?:[a-z]+|\d{1,4}))+", tail) or _SECRET_CAMEL_RE.match(tail)):
        return True                     # "sk-dynamic-file-context", "sk-lf-RandomStringFromLangfuseWebInterface"
    return any(bool(_SECRET_WORDS_RE.match(v) and _SECRET_DESCRIPTIVE_RE.search(v)) for v in (value, tail))


_PEM_BODY_RE = re.compile(r"[A-Za-z0-9+/=]{40,}")
_I18N_PATH_RE = re.compile(r"(?i)(^|/)(i18n|l10n|locales?|lang|langs|translations?)/|(^|/)i18n\.[jt]sx?$|\.po$")


def pem_has_body(sf: SourceFile, idx: int, end: int) -> bool:
    """A PEM header is a key only when key material follows it, on the same
    line (after a literal \\n) or on the next line; `...` or NOTAREALKEY is not."""
    rest = sf.raw[idx - 1][end:] if 0 < idx <= len(sf.raw) else ""
    if _PEM_BODY_RE.search(rest):
        return True
    # the next lines, past armor headers (Proc-Type:, DEK-Info:, Version:,
    # Comment:) and blank lines, as encrypted PEM and PGP keys have them
    for k in range(idx, min(idx + 8, len(sf.raw))):
        line = sf.raw[k].strip().strip("'\"`")
        if not line or re.match(r"^[A-Za-z][\w-]*:\s", line):
            continue
        return bool(_PEM_BODY_RE.match(line))
    return False


def _compile_rules() -> None:
    if _COMPILED:
        return
    for rule in RULES:
        pats: List[re.Pattern] = []
        for p in rule.patterns:
            try:
                pats.append(re.compile(p))
            except re.error as exc:
                print(f"jankhunt42: bad pattern in {rule.id}: {exc}", file=sys.stderr)
        _COMPILED[rule.id] = pats
        if rule.ignore:
            try:
                _IGNORES[rule.id] = re.compile(rule.ignore)
            except re.error:
                _IGNORES[rule.id] = re.compile(r"(?!)")


def _collect_suppressions(sources: Sequence[SourceFile]) -> Dict[str, Tuple[Set[str], Dict[int, Set[str]]]]:
    suppression: Dict[str, Tuple[Set[str], Dict[int, Set[str]]]] = {}
    for sf in sources:
        file_ids: Set[str] = set()
        line_ids: Dict[int, Set[str]] = {}
        # `jankhunt42:` is canonical; the pre-0.4 `jankhunt:` prefix is still
        # honored so existing suppressions in users' code keep working.
        for raw in sf.raw[:12]:
            m = re.search(r"jankhunt(?:42)?:\s*ignore-file\s+([A-Za-z0-9, ]+)", raw)
            if m:
                file_ids.update(re.findall(r"JH\d{3}|ALL", m.group(1).upper()))
        for i, raw in enumerate(sf.raw, 1):
            m = re.search(r"jankhunt(?:42)?:\s*ignore\s+([A-Za-z0-9, ]+)", raw)
            if m:
                line_ids[i] = set(re.findall(r"JH\d{3}|ALL", m.group(1).upper()))
        suppression[sf.rel] = (file_ids, line_ids)
    return suppression


class _FindingAcceptor:
    def __init__(self, opts: ScanOptions,
                 suppression: Dict[str, Tuple[Set[str], Dict[int, Set[str]]]]) -> None:
        self.opts = opts
        self.suppression = suppression
        self.per_file_rule: Dict[Tuple[str, str], int] = {}
        self.per_rule: Dict[str, int] = {}
        self.seen: Set[Tuple[str, str, int]] = set()
        self.fired_by_rule: Dict[str, int] = {}
        self.suppressed_by_rule: Dict[str, int] = {}

    def suppressed(self, finding: Finding) -> bool:
        file_ids, line_ids = self.suppression.get(finding.path, (set(), {}))
        ids = set(file_ids)
        ids |= line_ids.get(finding.line, set())
        ids |= line_ids.get(finding.line - 1, set())
        return "ALL" in ids or finding.rule in ids

    def accept(self, finding: Finding) -> bool:
        opts = self.opts
        # Telemetry first, independent of the CLI's display filters below,
        # so it reflects the rule's actual precision in this repo.
        self.fired_by_rule[finding.rule] = self.fired_by_rule.get(finding.rule, 0) + 1
        if self.suppressed(finding):
            self.suppressed_by_rule[finding.rule] = self.suppressed_by_rule.get(finding.rule, 0) + 1
            if opts.honor_suppressions:
                return False
        if not sev_at_least(finding.severity, opts.min_severity):
            return False
        if opts.categories and finding.category not in opts.categories:
            return False
        if opts.rule_ids and finding.rule not in opts.rule_ids:
            return False
        key = (finding.rule, finding.path, finding.line)
        if key in self.seen:
            return False
        self.seen.add(key)
        file_rule = (finding.rule, finding.path)
        if self.per_file_rule.get(file_rule, 0) >= opts.max_per_file_rule:
            return False
        if self.per_rule.get(finding.rule, 0) >= opts.max_per_rule:
            return False
        self.per_file_rule[file_rule] = self.per_file_rule.get(file_rule, 0) + 1
        self.per_rule[finding.rule] = self.per_rule.get(finding.rule, 0) + 1
        return True


def scan_sources(sources: Sequence[SourceFile], options: Optional[ScanOptions] = None) -> ScanResult:
    opts = options or ScanOptions()
    _compile_rules()
    result = ScanResult(files=len(sources), loc=sum(s.loc for s in sources))
    acceptor = _FindingAcceptor(opts, _collect_suppressions(sources))

    for sf in sources:
        for rule in RULES:
            if not path_matches(rule, sf):
                continue
            if "test-exclude" in rule.tags and "test" in sf.kinds:
                continue
            if "minified" in sf.kinds and "secret" not in rule.tags and rule.category != "agent" and rule.id != "JH131":
                continue                # a build bundle: a leaked key, hidden Unicode or agent hazard still counts
            if opts.rule_ids and rule.id not in opts.rule_ids:
                continue
            if rule.check:
                fn = CHECKS.get(rule.check)
                if not fn:
                    continue
                try:
                    found = fn(sf, rule)
                except Exception as exc:  # jankhunt42: ignore JH202  (a broken check must not kill the scan)
                    print(f"jankhunt42: check {rule.check} failed on {sf.rel}: {exc}", file=sys.stderr)
                    continue
                for f in found:
                    _example_context(f)
                    if acceptor.accept(f):
                        result.findings.append(f)
                continue
            pats = _COMPILED.get(rule.id) or []
            if not pats:
                continue
            lines = getattr(sf, rule.target)
            ignore = _IGNORES.get(rule.id)
            for idx, line in enumerate(lines, 1):
                if not line or not line.strip():
                    continue
                # on a long (minified) line, an ignore word elsewhere on it must not hide a match
                if ignore and len(line) <= 400 and ignore.search(line):
                    continue
                placeholders: List[str] = []
                for pat in pats:
                    m = pat.search(line)
                    if not m:
                        continue
                    if ignore and len(line) > 400 and ignore.search(line[max(0, m.start() - 80):m.end() + 80]):
                        continue
                    severity = confidence = message = None
                    ev = sf.raw[idx - 1].strip() if 0 < idx <= len(sf.raw) else line.strip()
                    if rule.id == "JH111":
                        sev = _pipe_to_shell_severity(line, m.group(0))
                        if sev is None:
                            continue
                        if sev != rule.severity:
                            severity = sev
                            message = rule.message + " The script comes from an official installer over TLS: the " \
                                                     "publisher is known, but the content is still unpinned and unverified."
                        hint = _quoted_hint(sf, line, m)
                        if hint:
                            severity, confidence = "minor", "low"
                            message = (rule.message + " Here it is text inside a quoted argument of `%s`, which looks "
                                       "like an install hint; confirm that command does not run it." % hint)
                    if rule.id == "JH101" and re.match(r"\s*(?:>>>|\.\.\.)\s", line) and "(?i)" in pat.pattern[:4]:
                        severity, confidence = "minor", "low"
                        message = rule.message + " It is a doctest example."
                    if rule.id == "JH122" and "docker" not in pat.pattern and not _container_command(sf, idx):
                        continue            # a flag in a list of strings, not in a container command
                    if rule.id == "JH104" and not _dynamic_sql(sf, idx, line, m, pat.pattern):
                        continue
                    if rule.id == "JH109" and "CORS_ORIGIN_ALLOW_ALL" not in pat.pattern and \
                            not _CORS_CREDENTIALS_RE.search(sf.text):
                        severity, confidence = "minor", "medium"
                        message = ("A wildcard origin lets any site call this endpoint, but browsers send no cookies or "
                                   "credentials to a wildcard origin; it matters when the endpoint trusts network "
                                   "position (an intranet or localhost service) rather than a token.")
                    if rule.id == "JH107" and m.group(0).startswith(("hashlib", "createHash", "MessageDigest")):
                        if "usedforsecurity=False" in line:
                            continue        # Python says so explicitly
                        own = " ".join(sf.nocomment[max(0, idx - 2):idx]).lower()   # this statement and the one before
                        target = re.match(r"\s*(?:self\.)?(\w+)\s*=", sf.nocomment[idx - 1])
                        above = " ".join(l for l in sf.raw[max(0, idx - 5):idx - 1]
                                         if re.match(r"\s*(?:#|//|/?\*|\"{3}|'{3})", l)).lower()
                        below = sf.nocomment[idx].lower() if idx < len(sf.nocomment) else ""
                        purpose = (target and re.search(r"(?i)(?:^|_)(?:ids?|keys?|cache\w*|etags?|checksum|"
                                                        r"fingerprint|slug|bucket|shard|folds?|colou?r|avatar|filename)$",
                                                        target.group(1))) or \
                            re.search(r"cache|etag|dedup|fingerprint|checksum|identifier|缓存", above) or \
                            re.search(r"cache|etag|dedup", below) or \
                            re.search(r"hexdigest\(\)\s*\[|digest\(\)\s*\[", sf.nocomment[idx - 1])
                        if not re.search(r"passw|token|sign|hmac|secret|auth|salt|session|nonce|otp|api_?key", own) and purpose:
                            severity, confidence = "minor", "medium"
                            message = ("MD5/SHA-1 as an identifier, cache key or checksum is fine; it matters only for "
                                       "signatures, passwords or tokens.")
                    if rule.id == "JH108" and m.group(0).startswith("debug") and not _web_debug(sf, idx, m.start()):
                        continue            # a library's verbosity flag, not a web debug server
                    if rule.id == "JH103" and _argv_without_shell(sf, idx, m.start(), pat.pattern):
                        continue
                    if rule.id in ("JH124", "JH125", "JH126") and _constant_html(sf, idx, m.end()):
                        continue
                    if rule.id in ("JH124", "JH125", "JH126"):
                        window = " ".join([sf.nocomment[idx - 1][m.end():]] + sf.nocomment[idx:idx + 2])
                        if re.match(r"\s*=\s*\{\{\s*__html\s*:\s*Object\.entries\(\s*THEMES\s*\)", window):
                            severity, confidence = "minor", "low"
                            message = ("The shadcn/ui chart component writes CSS variables from its config into a "
                                       "style tag; it matters only if chart colours come from user input.")
                        elif re.match(r"\s*=\s*\{\{\s*__html\s*:\s*(?:i18n\.|intl\.)?t\(\s*[\"'][\w.\-:]+[\"']\s*[,)]", window):
                            severity, confidence = "minor", "low"
                            message = (rule.message + " The value is a translation string looked up by a constant "
                                       "key; it matters only if translations are user-contributed.")
                        elif _sanitized_value(sf.nocomment[idx - 1][m.end():]) or \
                                _sanitized_earlier(sf, idx, sf.nocomment[idx - 1][m.end():]):
                            severity, confidence = "minor", "low"
                            message = (rule.message + " The value passes through a sanitizer: check that it allows "
                                       "no script, event handlers or javascript: URLs.")
                    if rule.id in _TEST_DATA_MINOR and ("test" in sf.kinds or is_test_path(sf.rel)):
                        severity, confidence = "minor", "low"
                        message = rule.message + " It is in test code, where it is usually test data."
                    if "secret" in rule.tags:
                        # the first match that is neither a placeholder nor the assignment pattern
                        # re-matching one (apiKey: "AIza<words>"); a real secret later on the line counts
                        while m and (secret_placeholder(m.group(0)) or any(p in m.group(0) for p in placeholders)):
                            placeholders.append(m.group(0))
                            m = pat.search(line, m.end())
                        if not m:
                            continue
                        provider = "[:=]" not in pat.pattern and "PRIVATE KEY" not in pat.pattern
                        if provider and re.search(r"(?:AWSAccessKeyId|X-Amz-Credential)=(?:\S*?%2F)?$|"
                                                  r"(?:AWSAccessKeyId|X-Amz-Credential)=$", line[:m.start()]):
                            severity, confidence = "minor", "low"
                            message = ("An AWS access key id is embedded in a presigned URL. The id alone does not "
                                       "grant access and presigned links expire, but it identifies the account; "
                                       "prefer links without credentials.")
                        elif provider and _code_sample_secret(line, m.end()) and (
                                "test" in sf.kinds or is_test_path(sf.rel) or sf.lang == "markdown"):
                            severity, confidence = "minor", "low"
                            message = ("A provider-shaped key inside a code sample that is itself a string, in a test "
                                       "or document: usually a fixture for a scanner or parser. Confirm it was never "
                                       "a real key.")
                        elif provider and pat.pattern.startswith("AIza") and _firebase_web_config(sf, idx):
                            severity, confidence = "minor", "low"
                            message = ("A Firebase web API key: it identifies the project and is public by design. "
                                       "Restrict the key in Google Cloud and rely on security rules, not on secrecy.")
                        quoted = _SECRET_QUOTED_RE.search(m.group(0))
                        if quoted and "[:=]" in pat.pattern and quoted.group(2).strip().lower() in COMMON_PASSWORDS:
                            severity, confidence = "minor", "medium"
                            message = ("A common default password is written into the code. It is not secret, but "
                                       "anything still using it can be logged into by anyone; keep it to local test data.")
                        pem = "PRIVATE KEY" in pat.pattern
                        if pem and not pem_has_body(sf, idx, m.end()):
                            continue
                        if pem and ("test" in sf.kinds or is_test_path(sf.rel)):
                            severity = "major"
                            message = rule.message + " It is in test data: confirm it is a throwaway test key."
                        ev = redact_secrets(ev)
                        # A generic `key = "..."` assignment in test code or
                        # docs is usually a fixture or an example, and in
                        # translation files a label; provider-shaped tokens
                        # and keys keep their severity everywhere.
                        if "[:=]" in pat.pattern:
                            if _I18N_PATH_RE.search(sf.rel):
                                continue
                            if len(line) > 400 and sf.rel.lower().endswith((".jsonl", ".ndjson", ".csv", ".tsv")):
                                severity, confidence = "minor", "low"
                                message = (rule.message + " It is inside a long data row (a dataset or export), which "
                                           "usually holds sample text: confirm it is not a real credential.")
                            if "test" in sf.kinds or is_test_path(sf.rel) or sf.lang == "markdown" or \
                                    sf.rel.lower().endswith(".txt"):
                                severity, confidence = "minor", "low"
                                message = rule.message + " It is in test code or documentation: confirm it is an " \
                                                         "example, not a real credential."
                    f = make_finding(rule, sf, idx, evidence=ev, column=m.start() + 1, severity=severity,
                                     confidence=confidence, message=message)
                    _example_context(f)
                    if acceptor.accept(f):
                        result.findings.append(f)
                    break

    result.findings.sort(key=lambda f: f.sort_key())
    result.fired_by_rule = acceptor.fired_by_rule
    result.suppressed_by_rule = acceptor.suppressed_by_rule
    return result


# Pattern rules whose matches in test code are usually test data.
_TEST_DATA_MINOR = {"JH104", "JH111", "JH115", "JH122", "JH702"}
# Installers published by the tool's own vendor, over TLS (JH111 major, not critical).
_OFFICIAL_INSTALLERS = ("sh.rustup.rs", "astral.sh", "get.docker.com", "deb.nodesource.com", "rpm.nodesource.com",
                        "ollama.com", "ollama.ai", "claude.ai", "bun.sh", "deno.land", "get.pnpm.io",
                        "install.python-poetry.org", "sdk.cloud.google.com", "cli.github.com", "starship.rs",
                        "tailscale.com", "fly.io", "get.helm.sh", "opencode.ai", "cursor.com", "install.determinate.systems",
                        "nixos.org", "foundry.paradigm.xyz", "get.sdkman.io", "volta.sh", "pyenv.run", "get.rvm.io",
                        "raw.githubusercontent.com/nvm-sh/nvm/", "raw.githubusercontent.com/Homebrew/install/")


# a deliberately vulnerable example: examples/vulnerable-app/, fixtures/insecure_rules/
_VULN_EXAMPLE_RE = re.compile(r"(?i)(?:^|/)(?:examples?|samples?|demos?|fixtures?|testdata|test-data|labs?|challenges?)/"
                              r"(?:[^/]+/)*?[^/]*(?:vulnerable|insecure|vuln|exploit|unsafe|damn)[^/]*/|"
                              r"(?:^|/)(?:eval|vuln|test|bench(?:mark)?)[_-]?corpus/")


# a committed credential is real wherever it sits, examples included
_SECRET_RULE_IDS = {"JH101", "JH401", "JH415", "JH706"}


def _example_context(f: Finding) -> None:
    """Security leads in a deliberately vulnerable example are minor: the
    weakness is the point of the example."""
    if f.category in ("security", "agent", "supply-chain") and f.severity in ("blocker", "critical", "major") \
            and f.rule not in _SECRET_RULE_IDS and _VULN_EXAMPLE_RE.search(f.path):
        f.severity, f.confidence = "minor", "low"
        f.message = f.message + " It is in a deliberately vulnerable example."


def _pipe_to_shell_severity(line: str, match: str) -> Optional[str]:
    """None when the curl|sh text is printed, not run; major for an official
    vendor installer over https; otherwise the rule's critical."""
    if re.match(r"""^\s*(?:-\s+)?(?:echo|printf|print|puts|console\.log|log|info|warn|say)\b""", line) or \
            re.search(r"""(?:echo|printf)\s+["'][^"']*$""", line[:line.find(match)] if match in line else ""):
        return None
    between = re.sub(r"^\W*(?:curl|wget)\b|\|.*$", "", match)
    if not re.search(r"[-$/:]|http", between):
        return None                     # no URL, variable, flag or path: a description of the pattern
    url = re.search(r"https?://[^\s\"'|)]+", match)
    if url and url.group(0).startswith("https://"):
        target = url.group(0)[len("https://"):]
        if any(target == h or target.startswith(h + "/") or target.startswith(h) and h.endswith("/")
               for h in _OFFICIAL_INSTALLERS):
            return "major"
    return "critical"


_WEB_FRAMEWORK_RE = re.compile(r"^\s*(?:from|import)\s+(?:flask\w*|quart|django|fastapi|starlette|sanic|litestar|"
                               r"aiohttp|tornado|bottle|werkzeug|uvicorn|dash)\b", re.M)


# a wildcard CORS origin is dangerous with credentials (some frameworks then reflect the origin)
_CORS_CREDENTIALS_RE = re.compile(r"(?i)Access-Control-Allow-Credentials['\"]?\s*[:=,]\s*['\"]?true|"
                                  r"\bcredentials\s*:\s*true\b|\b(?:supports|allow)_credentials\s*=\s*True\b|"
                                  r"\bCORS_ALLOW_CREDENTIALS\s*=\s*True\b|\bAllowCredentials\s*\(\s*\)|"
                                  r"allowCredentials\s*[:=(]\s*['\"]?true\b|\bAllowAnyOrigin\(\)\.AllowCredentials")
# a key inside a code sample that is itself a string: 'API_KEY = "sk-..."', '{"key":"sk-..."}'
_CODE_SAMPLE_SECRET_RE = re.compile(r"""(?<![\w\\])(["'])(?:(?!\1)[^\n])*?\b[A-Za-z_][\w.]*(?:(?!\1)["'])?\s*[:=]\s*"""
                                    r"""(?:(?!\1)["'])?(?:Bearer\s+)?[\w\-]+$""")


def _code_sample_secret(line: str, end: int) -> bool:
    """The key at line[:end] sits inside a string that is itself code: the
    opening quote starts a string (not a word's apostrophe or a closing
    quote) and the same quote closes it after the key."""
    m = _CODE_SAMPLE_SECRET_RE.search(line[:end])
    return bool(m and m.group(1) in line[end:])
# a database call: what a concatenated query() or execute() must be near to count as SQL
_SQL_CONTEXT_RE = re.compile(r"(?i)\b(?:select|insert|update|delete|where|from|join|values|explain|alter|create|drop|"
                             r"grant|truncate|merge|upsert|cursor|cur|conn\w*|db|database|client|pool|knex|sequelize|"
                             r"session|tx|trx|stmt|statement|jdbc\w*|engine|dbh|pg|mysql|sqlite3?|sql\w*|\w*query|"
                             r"\w*clause)\b")
_SQL_TAG_RE = re.compile(r"(?:\b(?:sql|SQL|Prisma\.sql|db\.sql|tx\.sql)|\$(?:queryRaw|executeRaw))\s*$")


# a value passed through an HTML sanitizer or escaper before it reaches the sink
_SANITIZER_RE = re.compile(r"\b(?:DOMPurify\.sanitize|sanitize\w*|purify\w*|escapeHtml|escape_html|htmlEscape|"
                           r"he\.encode|xss|filterXSS|sanitizeHtml)\s*\(")


def _sanitized_value(rest: str) -> bool:
    """The whole value is one sanitizer call: `= DOMPurify.sanitize(x);`,
    `__html: sanitize(x) }}`, `document.write(escapeHtml(x))`; not
    `sanitize(a) + userHtml`, and not a sanitizer elsewhere nearby."""
    m = re.match(r"\s*(?:=\s*\{\{\s*__html\s*:\s*|=\s*|\(\s*)", rest)
    if not m:
        return False
    call = _SANITIZER_RE.match(rest, m.end())
    if not call:
        return False
    depth, k = 1, call.end()
    while k < len(rest) and depth:
        depth += (rest[k] == "(") - (rest[k] == ")")
        k += 1
    return depth == 0 and re.match(r"\s*(?:\}\s*\}|\)|;|$)", rest[k:]) is not None


def _sanitized_earlier(sf: SourceFile, idx: int, rest: str) -> bool:
    """The value is one variable whose assignment, up to 15 lines above, goes
    through a sanitizer: `const html = DOMPurify.sanitize(x)` or
    `useMemo(() => DOMPurify.sanitize(x), [x])`."""
    m = re.match(r"\s*(?:=\s*\{\{\s*__html\s*:\s*|=\s*|\(\s*)([A-Za-z_$][\w$]*)\s*(?:\}\s*\}|\)|;|$)", rest)
    if not m:
        return False
    name = re.escape(m.group(1))
    window = "\n".join(sf.nocomment[max(0, idx - 16):idx - 1])
    a = list(re.finditer(r"\b(?:const|let|var)?\s*%s\s*=(?!=)" % name, window))
    if not a:
        return False
    rhs = window[a[-1].end():]
    return bool(re.match(r"\s*(?:await\s+)?(?:(?:React\.)?useMemo\s*\(\s*\(\s*\)\s*=>\s*)?", rhs) and
                _SANITIZER_RE.match(rhs, re.match(r"\s*(?:await\s+)?(?:(?:React\.)?useMemo\s*\(\s*\(\s*\)\s*=>\s*)?", rhs).end()))


def _container_command(sf: SourceFile, idx: int) -> bool:
    """The line is part of a container command (docker/podman/nerdctl run or
    create, docker compose run, also continued with backslashes) or of
    container options (GitHub Actions `options:`, dev container runArgs)."""
    k, text = idx - 1, sf.nocomment[idx - 1]
    while k > 0 and k > idx - 8 and sf.nocomment[k - 1].rstrip().endswith("\\"):
        k -= 1
        text = sf.nocomment[k] + " " + text
    return bool(re.search(r"\b(?:docker|podman|nerdctl)(?:\s+compose|-compose)?\s+(?:[\w-]+\s+)?(?:run|create)\b", text)
                or re.match(r"""\s*["']?(?:options|runArgs)["']?\s*:""", sf.nocomment[idx - 1]))


_EXECUTOR_WORDS = {"sh", "bash", "zsh", "ksh", "dash", "eval", "exec", "ssh", "su", "sudo", "doas", "env", "nohup",
                   "time", "timeout", "command", "xargs", "watch", "docker", "podman", "kubectl", "nsenter", "chroot",
                   "script", "parallel", "tmux", "screen", "flock", "nice", "ionice", "stdbuf", "busybox"}


def _quoted_hint(sf: SourceFile, line: str, m: "re.Match[str]") -> Optional[str]:
    """The command word when a shell script's curl|sh sits inside a quoted
    argument of a command that does not run it (`require_tool zz "... (curl ... | sh)"`,
    `echo "..."`); None when it may run (sh -c, ssh host, eval, docker exec)."""
    if sf.lang != "shell":
        return None
    before = line[:m.start()]
    for q in ('"', "'"):
        if before.count(q) % 2 == 1 and q in line[m.end():]:
            head = before[:before.rfind(q)]
            if re.search(r"(?:^|\s)-\w*c\s*$|\$\(|`|\|\s*$|[;&]", head):
                return None
            words = head.split()
            if not words or re.match(r"\w+=", words[0]) or words[0] in _EXECUTOR_WORDS or \
                    any(w in _EXECUTOR_WORDS for w in words[:3]):
                return None
            return words[0]
    return None


def _dynamic_sql(sf: SourceFile, idx: int, line: str, m: "re.Match[str]", pattern: str) -> bool:
    """False for what looks like dynamic SQL but is not: a query()/exec()
    built by concatenation with nothing database- or SQL-shaped on the line
    (a regex exec(), a spatial index query()), a sql`...` tagged template
    (the tag binds every interpolation as a parameter), and interpolation of
    CONSTANT_NAMES only."""
    if pattern.startswith(r"(?i)\b(?:select"):
        # SQL text in a "..." or '...' literal that closes before the ${...}: the interpolation is a later
        # argument (.run(`repo:${id}`)), a bound value, not part of the SQL
        before = line[:m.start()]
        q = re.search(r"([\"'])[^\"'\n]*$", before)
        if q and before.count(q.group(1)) % 2 == 1:
            close = line.find(q.group(1), m.start())
            interp = [k for k in (line.find("${", m.start()), line.find("#{", m.start())) if k >= 0]
            if close >= 0 and interp and close < min(interp):
                return False
    if pattern == _SQL_CALL_PATTERN:
        # the receiver, the first argument and the rest of the line, but not the method name itself
        arg = re.sub(r"(?i)^(?:execute|executemany|query|exec|raw)\s*\(", "", m.group(0))
        if not _SQL_CONTEXT_RE.search(line[:m.start()] + " " + arg + " " + line[m.end():]):
            return False
    raw = line
    if "${" in raw or "#{" in raw:
        # find the backtick that opens the template holding the match, up to 30 lines back
        text = "\n".join(sf.nocomment[max(0, idx - 31):idx - 1] + [raw[:m.end()]])
        ticks = [k for k, ch in enumerate(text) if ch == "`" and (k == 0 or text[k - 1] != "\\")]
        if len(ticks) % 2 == 1 and _SQL_TAG_RE.search(text[:ticks[-1]]):
            return False
    exprs = re.findall(r"\$\{([^}]*)\}|#\{([^}]*)\}", raw)
    names = [a or b for a, b in exprs]
    if not names and re.search(r"(?i)\bf[\"']", raw):
        names = re.findall(r"(?<!\{)\{([^{}]*)\}(?!\})", raw)
    if names and all(re.fullmatch(r"\s*(?:self\.|cls\.)?_*[A-Z][A-Z0-9_]*\s*", n) for n in names) and \
            not re.search(r"[\"'`]\s*(?:\+|%|\.format\b)|\+\s*[\"'`]", raw):
        return False
    return True


def _web_debug(sf: SourceFile, idx: int, col: int) -> bool:
    """debug=True in a file that imports a web framework, or as an argument
    of a .run(...) call still open from up to five lines before (an app
    imported from a local module)."""
    if _WEB_FRAMEWORK_RE.search(sf.text):
        return True
    before = "\n".join(sf.code[max(0, idx - 6):idx - 1] + [sf.code[idx - 1][:col]])
    calls = list(re.finditer(r"\.run(?:_server)?\s*\(", before))
    if not calls:
        return False
    depth = 1
    for ch in before[calls[-1].end():]:
        depth += (ch == "(") - (ch == ")")
        if depth == 0:
            return False
    return True
# shells, and programs that hand their arguments to one or run another program
_SHELL_PROGRAMS = {"sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "ash", "fish", "busybox", "cmd", "powershell",
                   "pwsh", "su", "sudo", "doas", "env", "nohup", "xargs", "ssh", "script"}


def _argv_without_shell(sf: SourceFile, idx: int, col: int, pattern: str) -> bool:
    """Runtime.exec(new String[]{"prog", ...}) and new ProcessBuilder("prog", ...)
    name the program as a literal: unless it is a shell or runs commands
    (su, env, ssh...), nothing parses the arguments. Read from the match on."""
    if "Runtime" not in pattern and "ProcessBuilder" not in pattern:
        return False
    call = " ".join([sf.nocomment[idx - 1][col:]] + sf.nocomment[idx:idx + 2])
    m = re.match(r"(?:Runtime\.getRuntime\(\)\.exec\s*\(\s*new\s+String\s*\[\s*\]\s*\{|ProcessBuilder\s*\(\s*"
                 r"(?:(?:List\.of|Arrays\.asList)\s*\()?)\s*\"([^\"\\]*)\"", call)
    if not m:
        return False
    program = re.split(r"[\\/]", m.group(1).strip())[-1].lower()
    return bool(program) and re.sub(r"\.exe$", "", program) not in _SHELL_PROGRAMS


def _constant_html(sf: SourceFile, idx: int, col: int) -> bool:
    """innerHTML = "" / "<p>fixed</p>", or __html: a literal with no
    interpolation (or only CONSTANT_NAME interpolation), is not a sink.
    Read with strings intact: the code view blanks template literals whole."""
    lit = r"""(?:(["'])(?:(?!\1)[^\\\n])*\1|`(?:[^`$\\]|\$\{[A-Z][A-Z0-9_]*\})*`)"""
    line = sf.nocomment[idx - 1]
    rest = line[col:]
    if not rest.strip() and idx < len(sf.nocomment):
        rest = sf.nocomment[idx]                    # `el.innerHTML =` then the literal on the next line
        line = rest
        idx += 1
    if re.match(r"\s*`[^`]*$", rest):
        # a template literal that runs over several lines: constant unless it interpolates
        body = [rest.split("`", 1)[1]]
        for n in sf.nocomment[idx:idx + 300]:
            body.append(n)
            if "`" in n:
                tail = n.split("`", 1)[1]
                text = "\n".join(body)[:-len(tail) - 1] if tail else "\n".join(body)[:-1]
                if re.search(r"\$\{(?![A-Z][A-Z0-9_]*\})", text) or not re.match(r"\s*\)?\s*;?\s*$", tail):
                    return False
                k = idx + len(body) - 1             # index of the line after the closing backtick
                nxt = next((x for x in sf.nocomment[k:k + 3] if x.strip()), "")
                return tail.strip().endswith(";") or not re.match(r"\s*(?:[-+*/%?:.,|&]|concat\b)", nxt)
        return False
    if re.match(r"\s*%s\s*\)?\s*;?\s*$" % lit, rest):
        # unless the statement goes on: `= '<div>'` then `+ message` on the next line
        nxt = next((n for n in sf.nocomment[idx:idx + 3] if n.strip()), "")
        return line.rstrip().endswith(";") or not re.match(r"\s*(?:[-+*/%?:.,|&]|concat\b)", nxt)
    # dangerouslySetInnerHTML={{ __html: "..." }}, read from this attribute on
    window = " ".join([line[col:]] + sf.nocomment[idx:idx + 3])
    m = re.match(r"\s*=\s*\{\{\s*__html\s*:\s*", window)
    return bool(m and re.match(r"%s\s*,?\s*\}" % lit, window[m.end():]))


def _firebase_web_config(sf: SourceFile, idx: int) -> bool:
    """An AIza key in a Firebase client config: a web config object
    (authDomain, projectId...), google-services.json, or GoogleService-Info.plist."""
    if sf.basename.lower() in ("google-services.json", "googleservice-info.plist"):
        return True
    window = "\n".join(sf.raw[max(0, idx - 6):idx + 6])
    return bool(re.search(r"\b(?:authDomain|projectId|storageBucket|messagingSenderId|appId)\b|firebaseapp\.com", window))


def rule_by_id(rid: str) -> Optional[Rule]:
    for rule in RULES:
        if rule.id == rid:
            return rule
    return None
