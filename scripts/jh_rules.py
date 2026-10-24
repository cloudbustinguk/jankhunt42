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
          r"(?i)\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|token|passwd|password|access[_-]?key)\b\s*[:=]\s*['\"][^'\"\n]{8,}['\"]",
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
          r"(?i)\b(?:select\b[^\"'`\n]{0,200}\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b[^\"'`\n]*"
          r"(?:#\{|\$\{|[\"'`]\s*(?:\+|\.format\s*\(|%\s*[\w(\[{]))",
          # an f-string that interpolates into SQL-shaped text
          r"(?i)\bf([\"'])(?=[^\"']*\{)[^\"']*\b(?:select\b[^\"']{0,200}\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b",
          # a query call built by concatenation; not `"query("` inside a
          # string (GraphQL builders) or a name like appendRawQuery(
          r"(?i)(?<![\"'\w])(?:execute|executemany|query|exec|raw)\s*\(\s*"
          r"(?:f['\"]|\$\{|(?:[^)\n\"'+,]|\"[^\"\n]*\"|'[^'\n]*')*\+)",       # in the first argument
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
      confidence="high", langs=PY + JS + JVM + CLIKE + ("ruby", "php", "go"),
      patterns=(
          r"verify_signature[^\n]{0,40}False",
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
      confidence="high", target="comments", patterns=(r"(?i)\b(?:TODO|FIXME|HACK|XXX|BUG)\b",)),
    R("JH204", "Debug leftover", "minor", "reliability",
      "Debug output or a debugger hook is still in the code path.",
      "Remove it or route it through the project logger at an appropriate level.",
      confidence="medium", langs=PY + JS + ("php", "ruby"), check="debug_leftover"),
    R("JH205", "Commented-out code", "info", "maintainability",
      "Commented code rots, confuses readers, and hides intent; version control already remembers it.",
      "Delete it or restore it with a test; keep comments for why, not what used to be.",
      confidence="low", target="comments",
      patterns=(r"(?i)^\s*(?:if|for|while|switch|return|def|class|function|const|let|var|import|from|public|private|protected|try|catch|#include)\b", r"[;{}]\s*$")),
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
      patterns=(r"\bassert\s+True\b", r"\bexpect\s*\(\s*true\s*\)", r"\bassertEqual\s*\(\s*True\s*,\s*True")),
    R("JH505", "Focused test", "major", "tests",
      "A focused test (.only/fit/fdescribe) silently skips the rest of the suite in many runners.",
      "Remove the focus marker before merging.",
      confidence="high", target="nocomment", kinds=TEST + ("test",),
      patterns=(r"\.only\s*\(", r"@pytest\.mark\.focus\b", r"\bfit\s*\(", r"\bfdescribe\s*\(")),

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
      )),
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
_SECRET_QUOTED_RE = re.compile(r"[:=]\s*([\"'])([^\"'\n]+)\1")
_SECRET_REF_RE = re.compile(r"\benv\(|\{\{|\$\(|\$\{|%\(|^\$\w+$|^<[^>]+>$")
_SECRET_PREFIX_RE = re.compile(r"^(?:sk-(?:proj-|lf-)?|[sr]k_live_|gh[pousr]_|github_pat_|xox[baprs]-|glpat-|hf_|gsk_|npm_)")
# a UI label like "Bearer Token Env Var" (Title Case); lowercase word runs may be passphrases
_SECRET_TEXT_RE = re.compile(r"^[A-Z][a-z]*(?: [A-Z][a-z]*)+$")
_SECRET_RUN_RE = re.compile(r"abcdefgh|01234567|12345678|(.)\1{7,}", re.IGNORECASE)
# words, optionally numbered ("endpoint-secret-0001"); a mixed segment such as
# "9f8a7c6b5d4e" is token material
_SECRET_WORDS_RE = re.compile(r"^[a-z]+(?:[-_.](?:[a-z]+|\d{1,4}))+$", re.IGNORECASE)
_SECRET_CAMEL_RE = re.compile(r"^(?:[a-z]+[-_])*(?:[A-Z][a-z]+){3,}$")
_SECRET_DESCRIPTIVE_RE = re.compile(
    r"(?:^|[-_.])(?:test|testing|mock|fake|dummy|fixture|stub|static|sample|example|placeholder|local|dev|"
    r"synthetic|managed|token|secret|key|password|passwd|pass|credential|creds?|api|apikey|auth|issuer|client)(?=[-_.]|$)",
    re.IGNORECASE)


def secret_placeholder(match_text: str) -> bool:
    """True when a secret-pattern match is a reference, a generated run, or a
    descriptive fixture value rather than credential material."""
    quoted = _SECRET_QUOTED_RE.search(match_text)
    value = quoted.group(2) if quoted else match_text
    if _SECRET_REF_RE.search(value) or _SECRET_RUN_RE.search(value):
        return True
    if quoted:
        key = re.match(r"[\w-]*", match_text).group(0).lower()
        # a URL without a password, the key's own name as its value
        # (password: "password"), the xkcd example passphrase, a concatenation
        if re.match(r"https?://(?![^/\s]*:[^/\s]*@)", value) or \
                re.sub(r"[\W_]", "", value.lower()) == re.sub(r"[\W_]", "", key) or \
                re.fullmatch(r"(?i)correct[ _-]?horse[ _-]?battery(?:[ _-]?staple)?", value) or re.match(r"\s+\+\s", value):
            return True
        # the match ran across string boundaries into code: split('secret=')[1]
        if re.match(r"[)\]]", value) and re.search(r"[.(]\w", value):
            return True
        # a lowercase name ("identifier", "attribute.name") is not a credential,
        # unless the key says it may be a password
        if re.fullmatch(r"[a-z]+(?:[._-][a-z]+)*", value) and "pass" not in key:
            return True
    if _SECRET_TEXT_RE.match(value):
        return bool(_SECRET_DESCRIPTIVE_RE.search(value.replace(" ", "-")))
    # descriptive words, also after a provider prefix ("sk-proj-SYNTHETIC_CREDENTIAL")
    tail = _SECRET_PREFIX_RE.sub("", value)
    for v in (value, tail):
        # two or more words, one descriptive, plus at most short ids ("test_redaction_d84e11")
        segs = [x for x in re.split(r"[-_.]", v) if x]
        words = [x for x in segs if x.isalpha()]
        if len(words) >= 2 and any(_SECRET_DESCRIPTIVE_RE.search(w) for w in words) \
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
                if ignore and ignore.search(line):
                    continue
                for pat in pats:
                    m = pat.search(line)
                    if not m:
                        continue
                    severity = confidence = message = None
                    ev = sf.raw[idx - 1].strip() if 0 < idx <= len(sf.raw) else line.strip()
                    if "secret" in rule.tags:
                        if secret_placeholder(m.group(0)):
                            continue
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
                            if "test" in sf.kinds or is_test_path(sf.rel) or sf.lang in ("markdown", "text"):
                                severity, confidence = "minor", "low"
                                message = rule.message + " It is in test code or documentation: confirm it is an " \
                                                         "example, not a real credential."
                    f = make_finding(rule, sf, idx, evidence=ev, column=m.start() + 1, severity=severity,
                                     confidence=confidence, message=message)
                    if acceptor.accept(f):
                        result.findings.append(f)
                    break

    result.findings.sort(key=lambda f: f.sort_key())
    result.fired_by_rule = acceptor.fired_by_rule
    result.suppressed_by_rule = acceptor.suppressed_by_rule
    return result


def rule_by_id(rid: str) -> Optional[Rule]:
    for rule in RULES:
        if rule.id == rid:
            return rule
    return None
