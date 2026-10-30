#!/usr/bin/env python3
"""Rule catalog and scanning engine for jankhunt42."""
from __future__ import annotations

import ast
from bisect import bisect_right
import re
import sys
import warnings
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from jh_core import (
    Finding,
    Rule,
    SourceFile,
    SEV_RANK,
    _regex_literal_end,
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
          # a database connection string (appsettings.json, web.config, a DSN in code) with its password inline
          r"(?i)\b(?:server|host|data\s+source)\s*=[^\"'\n]*?\b(?:password|pwd)\s*[:=]\s*['\"]?[^;\"'\s${%<]{6,}",
          # a JWT whose payload grants a privileged role (a Supabase service-role key)
          r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
          r"(?i)\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|token|passwd|password|access[_-]?key)\b\s*[:=]\s*(['\"])(?:(?!\1)[^\n]){8,}\1",
          # a quoted key ("db_password": "...") or a prefixed name (DB_PASSWORD = "..."): the value must look
          # like a credential (no spaces, a letter and a digit), so UI text ("password": "Mot de passe") is not
          r"(?i)(?:\b(?:[a-z0-9]+[_-])+(?:api[_-]?key|apikey|secret(?:[_-]?key)?|token|passwd|password|access[_-]?key)\b[\"']?|"
          r"[\"'](?:api[_-]?key|apikey|secret(?:[_-]?key)?|token|passwd|password|access[_-]?key)[\"'])\s*[:=]\s*"
          r"([\"'])(?=[^\s\"']*\d)(?=[^\s\"']*[A-Za-z])"
          r"(?![^\s\"']*(?:test|(?<![0-9a-f])e2e(?![0-9a-f])|mock|stub|fake|dummy|demo|never|secret|passw|example|"
          r"sample|changeme|redact))"
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
      confidence="medium", langs=SCRIPT + CLIKE + JS,          # JS/TS: child_process exec/execSync (missing until 2.8.1)
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
          # an f-string that interpolates into SQL-shaped text (its own quote ends it; '{name}' inside an f"..." is
          # quoted SQL text, the commonest injection shape)
          r"(?i)\bf([\"'])(?=(?:(?!\1)[^\n])*\{)(?:(?!\1)[^\n])*?\b(?:select\b(?:(?!\1)[^\n]){0,200}\bfrom|"
          r"insert\s+into|update\s+\w+\s+set|delete\s+from)\b",
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
          r"\bverify_mode\s*=\s*(?:ssl\.)?CERT_NONE\b",
          r"\bcheck_hostname\s*=\s*False\b",
          r"\bcert_reqs\s*=\s*ssl\.CERT_NONE\b",       # the code view blanks strings: "CERT_NONE" is not seen
          r"\bServerCertificate(?:Custom)?ValidationCallback\s*\+?=\s*[^;\n]*=>\s*true\b",
          r"\bDangerousAcceptAnyServerCertificateValidator\b",
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
      confidence="high", target="nocomment", langs=SCRIPT + ("yaml", "docker", "json"),
      patterns=(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b",)),
    R("JH112", "Insecure RNG for secrets", "minor", "security",
      "random/Math.random are predictable and must not generate tokens, salts, keys, or nonces.",
      "Use the platform CSPRNG: secrets/os.urandom, crypto.randomBytes, crypto.getRandomValues.",
      confidence="low", langs=PY + JS, check="insecure_rng",
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

    # --------------------------------------------------------------- ASP.NET Core
    R("JH135", "ASP.NET data endpoint without authorization", "major", "security",
      "An endpoint appears to change or return application data without visible authorization metadata.",
      "Require an authorization policy on the endpoint/controller or a global fallback; review data ownership too.",
      confidence="medium", langs=("csharp",), check="dotnet_auth", tags=("dotnet",)),
    R("JH136", "ASP.NET credentialed CORS allows any origin", "major", "security",
      "An all-origin policy is combined with credentials; this is unsafe or rejected by ASP.NET Core.",
      "Use exact trusted origins and keep credentialed policies separate from public anonymous CORS.",
      confidence="high", langs=("csharp",), check="dotnet_cors", tags=("dotnet",)),
    R("JH137", "ASP.NET developer errors outside a development guard", "major", "security",
      "Detailed development errors can expose request data and stack traces outside local development.",
      "Guard developer errors with Environment.IsDevelopment and use a production exception handler elsewhere.",
      confidence="high", langs=("csharp",), check="dotnet_errors", tags=("dotnet",)),
    R("JH138", "Kestrel accepts public cleartext HTTP", "major", "security",
      "An HTTP listener accepts nonlocal traffic and no HTTPS redirection is visible; confirm TLS termination.",
      "Use HTTPS or a verified TLS-terminating proxy, and restrict interfaces that should remain local.",
      confidence="medium", langs=("csharp", "json"), check="dotnet_http", tags=("dotnet",)),
    R("JH139", "Interpolated SQL passed to a .NET database API", "major", "security",
      "C# interpolation creates SQL text before the database API can bind its values as parameters.",
      "Use Dapper/ADO.NET parameters or EF FromSql/FromSqlInterpolated; never interpolate into FromSqlRaw.",
      confidence="high", langs=("csharp",), check="dotnet_sql", tags=("dotnet",)),
    R("JH140", "Untrusted .NET object type deserialization", "critical", "security",
      "Deserialization accepts type metadata that can instantiate unexpected objects with side effects.",
      "Use TypeNameHandling.None/data-only models; otherwise enforce a narrow reviewed serialization binder.",
      confidence="high", langs=("csharp",), check="dotnet_types", tags=("dotnet",)),
    R("JH141", "Personal request data sent to an AI client", "major", "security",
      "Personal request fields are passed to an AI client without visible redaction at the call.",
      "Remove personal fields before sending, establish consent/purpose, and review the provider's data policy.",
      confidence="medium", langs=("csharp",), check="dotnet_ai", tags=("dotnet",)),
    R("JH142", "Floating NuGet package version", "major", "supply-chain",
      "A wildcard PackageReference/PackageVersion can resolve to different dependency code on a later restore.",
      "Pin the version and commit a hash-pinned lock file; restore in locked mode.",
      confidence="high", files=("*.csproj", "*.props", "*.targets"), check="dotnet_packages", tags=("dotnet",)),
    R("JH143", "MSBuild downloads content during build", "major", "supply-chain",
      "An MSBuild Exec command downloads remote content during the build, outside a separate verified acquisition step.",
      "Acquire and verify fixed artifacts separately, then restore and build from a local feed without network access.",
      confidence="high", files=("*.csproj", "*.props", "*.targets"), check="dotnet_exec", tags=("dotnet",)),
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
      # BUG is also an English word ("the BUG reporting pipeline"): it counts where a marker would sit, at the
      # start of a comment or before : ( - or the end of the line; TODO, FIXME and HACK count anywhere
      patterns=(r"\b(?:TODO|FIXME|HACK)\b|\bBUG\b(?=\s*[:(\-]|\s*$)|(?:^|[#/*;\-]|<!--)\s*BUG\b|"
                r"\bXXX\b(?=\s*[:(\-])|(?:^|[#/*;\-]|<!--)\s*(?i:(?:todo|fixme|hack)\s*[:(])",)),
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
      confidence="high", check="package_json_dep", kinds=("package_json",)),
    R("JH425", "Compose host network", "info", "security",
      "network_mode: host removes network isolation for the container.",
      "Use a user-defined network and expose only the required ports.",
      confidence="high", target="nocomment", kinds=COMPOSE,
      patterns=(r"(?i)^\s*network_mode\s*:\s*host\b",)),
    R("JH426", "npm install in CI", "info", "ci",
      "npm install can rewrite the lockfile and is not reproducible; npm ci is.",
      "Use npm ci (or pnpm install --frozen-lockfile / yarn --immutable).",
      confidence="medium", target="nocomment", kinds=CI,
      patterns=(r"\bnpm\s+install\b(?!\s+(?:--global|-g)\b)",)),   # -g installs a tool, not the project's dependencies
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
      patterns=(r"@pytest\.mark\.skip\b", r"@unittest\.skip",
                # `.skip(` is a skipped test only on a runner (describe/test/context/...); on another receiver
                # it is a library call such as Rust's Iterator::skip(n). `it` and `t` are also common iterator
                # names, so for them the first argument must be a title string: it.skip('...', fn)
                r"\b(?:describe|test|context|suite|specify|feature|module|QUnit|tap|fixture|scenario|bench)\.skip\s*\(",
                r"(?<![\w$.])(?:it|t)\.skip\s*\(\s*[\"'`]", r"\bpytest\.skip\s*\(", r"\bthis\.skip\s*\(\s*\)",
                r"\bxit\s*\(", r"\bxdescribe\s*\(", r"\bt\.Skip\s*\(", r"@Disabled\b")),
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
                r"\bexpect\s*\(\s*true\s*\)\s*(?:;|\)|\.(?:toBe|toEqual|toStrictEqual)\s*\(\s*true\s*\)|"
                r"\.(?:toBeTruthy|toBeTrue|toBeDefined)\s*\(\s*\)|\.not\.(?:toBeFalsy|toBeNull|toBeUndefined)\s*\(\s*\)|"
                r"\.not\.toBe\s*\(\s*false\s*\)|\.to\.(?:be\.)?(?:true|ok)\b|\.to\.exist\b|"
                r"\.to\.(?:be\.)?(?:equal|eql)\s*\(\s*true\s*\)|\.to\.not\.(?:be\.)?(?:false|null|undefined)\b|"
                r"\.to\.not\.(?:be\.)?(?:equal|eql)\s*\(\s*false\s*\))",
                r"\bassertEqual\s*\(\s*True\s*,\s*True")),
    R("JH505", "Focused test", "major", "tests",
      "A focused test (.only/fit/fdescribe) silently skips the rest of the suite in many runners.",
      "Remove the focus marker before merging.",
      confidence="high", target="code", kinds=TEST + ("test",),
      patterns=(r"(?<![\w$])(?:describe|it|test|context|suite|specify|fixture|scenario|feature|module|QUnit|tap|t|bench)"
                r"(?:\.(?:describe|test|module|serial|parallel|concurrent|sequential|"
                r"(?:skipIf|runIf)\((?:[^()]|\([^()]*\))*\)))*\.only(?:\.each)?\s*\(",
                r"@pytest\.mark\.focus\b",
                # fit(title, fn) / fdescribe(title, fn): the second argument is a function; in the code view a
                # string title is masked, so fit('modelFit', 10) and expect(fit('abc', 2)) do not match
                r"(?<![\w.$])f(?:it|describe)\s*\(\s*[^,(]*\s*,\s*(?:(?:async\s+)?(?:\([^()]*\)\s*=>|\w+\s*=>|function\b)|"
                r"(?:fakeAsync|waitForAsync|async|inject|waitsForAsync)\s*\()")),

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
    # rules the operator set aside (--ignore-rule): never reported, scored or gated on
    ignore_rule_ids: Optional[Set[str]] = None
    max_per_file_rule: int = 5
    max_per_rule: int = 200
    include_cve: bool = False
    # False for governance scans: repository pragmas cannot hide what the
    # citizen profile must see.
    honor_suppressions: bool = True


SITE_BUDGET = 10.0        # seconds one site rule may spend in a run; a rule that runs over is switched off
_SITE_SPENT: Dict[str, float] = {}


def _site_rule(rule: Rule, sf: SourceFile, pats: List["re.Pattern[str]"], acceptor: Any, result: Any) -> None:
    """A site rule (jh_ruleset) on one file, inside its time budget. Its patterns come from a policy file, not this
    code, so one that runs away is stopped by the timer, switched off for the rest of the run, and named in
    result.site_overrun, so the scan still ends with a report."""
    import time
    import jh_ruleset
    spent = _SITE_SPENT.get(rule.id, 0.0)
    if spent >= SITE_BUDGET:
        return
    start = time.monotonic()
    ignore = _IGNORES.get(rule.id)
    try:
        with jh_ruleset.bounded(SITE_BUDGET - spent):
            for idx, line in enumerate(getattr(sf, rule.target), 1):
                if not line.strip() or (ignore and ignore.search(line)):
                    continue
                if any(p.search(line) for p in pats):
                    f = make_finding(rule, sf, idx)
                    if acceptor.accept(f):
                        result.findings.append(f)
    except jh_ruleset._Overrun:
        _SITE_SPENT[rule.id] = SITE_BUDGET
        result.site_overrun.add(rule.id)
        return
    _SITE_SPENT[rule.id] = spent + time.monotonic() - start


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
    # site rules switched off for running over their time budget (_site_rule)
    site_overrun: Set[str] = field(default_factory=set)


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
_UI_MESSAGE_RE = re.compile(r"(?i)\b(?:is|are)\s+(?:required|invalid|missing|empty|incorrect|too\s+(?:short|long|weak))\b|"
                            r"\bmust\s+(?:be|contain|have|match|include)\b|\bplease\s+(?:enter|provide|choose|type)\b|"
                            r"\b(?:enter|confirm)\s+(?:a|an|the|your)\b|\bdo(?:es)?\s+not\s+match\b")
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
    # text in a non-Latin script, such as a translated label for "API key": credentials are ASCII
    if any(ch.isalpha() and ord(ch) > 0x24F for ch in value):
        return True
    # a form or validation message ("Password is required", "Token must be 32 characters")
    if len(value.split()) >= 3 and _UI_MESSAGE_RE.search(value):
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


# A translation/locale file holds UI text an i18n library renders; the text is
# never executed, so an agent-launch flag written in it starts nothing (JH702).
# Match (1) any translation-format file under an i18n directory, except a
# manifest such as package.json whose scripts DO run agents, and (2) a file
# named like a locale (`es.json`, `pt-BR.json`, `zh_Hans.json`) anywhere: a two-letter
# language code, not any short name (`mcp.json`, `app.json` and `cdk.json` launch things).
# Agent and MCP configs are never locale files. CI workflow YAML stays at full severity.
_I18N_DIR_RE = re.compile(r"(?i)(^|/)(i18n|l10n|locales?|lang|langs|translations?)/")
_ISO_639_1 = set("aa ab ae af ak am an ar as av ay az ba be bg bh bi bm bn bo br bs ca ce ch co cr cs cu cv cy da de "
                 "dv dz ee el en eo es et eu fa ff fi fj fo fr fy ga gd gl gn gu gv ha he hi ho hr ht hu hy hz ia id ie ig "
                 "ii ik io is it iu ja jv ka kg ki kj kk kl km kn ko kr ks ku kv kw ky la lb lg li ln lo lt lu lv mg mh mi "
                 "mk ml mn mr ms mt my na nb nd ne ng nl nn no nr nv ny oc oj om or os pa pi pl ps pt qu rm rn ro ru rw sa "
                 "sc sd se sg si sk sl sm sn so sq sr ss st su sv sw ta te tg th ti tk tl tn to tr ts tt tw ty ug uk ur uz "
                 "ve vi vo wa wo xh yi yo za zh zu".split())
_LOCALE_NAME_RE = re.compile(r"([a-z]{2})(?:[-_](?:[A-Z]{2}|[A-Z][a-z]{3}|\d{3}))?\.(?:json|po)$")
_MANIFEST_NAME_RE = re.compile(r"(?i)(?:package|tsconfig|jsconfig|composer|bower)\.json$")


def is_locale_text(sf: SourceFile) -> bool:
    """True when the file is a translation file, where a `--dangerously-
    skip-permissions`-style flag is UI copy rather than a command."""
    if {"agent_config", "mcp_config", "agent_context", "ci"} & set(sf.kinds):
        return False
    rel = sf.rel
    base = rel.replace("\\", "/").rsplit("/", 1)[-1]
    loc = _LOCALE_NAME_RE.match(base)
    if loc and loc.group(1) in _ISO_639_1:
        return True
    if _I18N_DIR_RE.search(rel) and rel.lower().endswith(
            (".json", ".yml", ".yaml", ".po", ".properties")) \
            and not _MANIFEST_NAME_RE.search(base):
        return True
    return False


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
        if opts.ignore_rule_ids and finding.rule in opts.ignore_rule_ids:
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
    import jh_dotnet
    dotnet_context = jh_dotnet.context(sources)

    for sf in sources:
        python_docstrings = None
        for rule in RULES:
            if not path_matches(rule, sf):
                continue
            if "test-exclude" in rule.tags and "test" in sf.kinds:
                continue
            if "minified" in sf.kinds and "secret" not in rule.tags and rule.category != "agent" and rule.id != "JH131" and "dotnet" not in rule.tags:
                continue                # a build bundle: a leaked key, hidden Unicode or agent hazard still counts
            if opts.rule_ids and rule.id not in opts.rule_ids:
                continue
            if opts.ignore_rule_ids and rule.id in opts.ignore_rule_ids:
                continue
            if rule.id == 'JH101' and sf.rel.lower().endswith('.json'):     # only a .json file can be an n8n export
                import jh_n8n
                try:
                    flows = jh_n8n.parse(sf.rel, '\n'.join(sf.raw)) or []
                    pointers = [jh_n8n.pointer(n['pointer'] + ['parameters']) + p
                                for flow in flows for n in flow['nodes']
                                for p in jh_n8n.secret_sites(n['raw']['parameters'])]
                except (ValueError, RecursionError):
                    pointers = []
                if pointers:
                    f = make_finding(rule, sf, 1, evidence='n8n export contains literal secret-shaped parameters (values withheld)',
                                     extra={'json_pointers': [jh_n8n.safe_pointer(p) for p in pointers[:50]], 'sites': len(pointers)})
                    _example_context(f)
                    if acceptor.accept(f):
                        result.findings.append(f)
            if rule.check:
                fn = CHECKS.get(rule.check)
                if not fn and not rule.check.startswith("dotnet_"):
                    continue
                try:
                    found = jh_dotnet.findings(sf, rule, dotnet_context) if rule.check.startswith("dotnet_") else fn(sf, rule)
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
            if rule.id == "JH111" and sf.lang == "json":
                # in JSON only package.json scripts run: each one checked on its own, at the line that holds it
                try:
                    scripts = _npm_scripts(sf)
                except (RecursionError, ValueError, IndexError):
                    scripts = []                # never let one odd package.json stop the scan
                for line_no, script in scripts:
                    for pat in pats:
                        m = pat.search(script)
                        if not m:
                            continue
                        severity = _pipe_to_shell_severity(script, m.group(0))
                        if severity is None:
                            break
                        confidence = message = None
                        if severity != rule.severity:
                            message = rule.message + " The script comes from an official installer over TLS: the " \
                                                     "publisher is known, but the content is still unpinned and unverified."
                        if "test" in sf.kinds or is_test_path(sf.rel):
                            severity, confidence = "minor", "low"
                            message = rule.message + " It is in test code, where it is usually test data."
                        f = make_finding(rule, sf, line_no, severity=severity, confidence=confidence, message=message)
                        _example_context(f)
                        if acceptor.accept(f):
                            result.findings.append(f)
                        break
                continue
            if "site" in rule.tags:
                _site_rule(rule, sf, pats, acceptor, result)
                continue
            lines = getattr(sf, rule.target)
            ignore = _IGNORES.get(rule.id)
            for idx, line in enumerate(lines, 1):
                if not line or not line.strip():
                    continue
                if rule.id == "JH205" and _is_http_route_comment(sf, idx):
                    continue                # documented HTTP routes can contain example objects and assignments
                # on a long (minified) line, an ignore word elsewhere on it must not hide a match
                if ignore and len(line) <= 400 and ignore.search(line):
                    continue
                placeholders: List[str] = []
                agent_regexes = None
                for pat in pats:
                    m = pat.search(line)
                    if m and rule.id == "JH111" and sf.lang == "python":
                        if python_docstrings is None:
                            python_docstrings = _python_docstring_spans(sf)
                        while m and _in_python_docstring(sf, idx, m, python_docstrings):
                            m = pat.search(line, m.end())
                    if m and rule.id == "JH702" and sf.lang in JS:
                        if agent_regexes is None:
                            agent_regexes = _js_regex_spans(sf.code[idx - 1])
                        while m and _in_regex_spans(agent_regexes, m.end() - 1):
                            m = pat.search(line, m.end())
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
                        security = re.search(r"passw|token|sign|hmac|secret|auth|salt|session|nonce|otp|api_?key", own)
                        if not security and (_HASHING_TRICK_RE.search(line) and "digest" in line
                                             or _GIT_BLOB_HASH_RE.search(sf.nocomment[idx - 1])):
                            continue        # int(digest, 16) % n buckets; b"blob %d\0" is git's content address
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
                        if not security and purpose:
                            severity, confidence = "minor", "medium"
                            message = ("MD5/SHA-1 as an identifier, cache key or checksum is fine; it matters only for "
                                       "signatures, passwords or tokens.")
                    if rule.id == "JH108" and m.group(0).startswith("debug") and not _web_debug(sf, idx, m.start()):
                        continue            # a library's verbosity flag, not a web debug server
                    if rule.id == "JH103" and (
                            pat.pattern == r"\bshell\s*=\s*True\b" and _shell_true_constant(sf, idx, m.start())
                            or pat.pattern in _SHELL_STRING_CALLS and _fixed_command(sf.nocomment[idx - 1], m.end())):
                        severity, confidence = "minor", "medium"
                        message = (rule.message + " The command is a fixed literal with no interpolated or "
                                   "concatenated value, so nothing attacker-controlled reaches the shell; a "
                                   "minor hygiene note, not a shell-injection.")
                    if rule.id == "JH103" and _argv_without_shell(sf, idx, m.start(), pat.pattern):
                        continue
                    if rule.id == "JH205" and _in_doc_block(sf, idx):
                        continue                # a /** ... */ documentation block describes code; it is not code
                    shell = _processbuilder_shell(" ".join([sf.nocomment[idx - 1][m.start():]] + sf.nocomment[idx:idx + 2])) \
                        if rule.id == "JH103" and "ProcessBuilder" in pat.pattern else "major"
                    if shell is None:
                        continue                # separate arguments naming a program: no shell runs
                    if shell == "minor":
                        severity, confidence = "minor", "low"
                        message = (rule.message + " ProcessBuilder runs no shell itself; its single argument hides "
                                   "what runs, so check that it never starts a shell with -c.")
                    if rule.id == "JH109" and _inside_prose_string(sf.nocomment[idx - 1], m.start()):
                        continue                # advice text ("origin: '*' lets any website ..."), not a setting
                    if rule.id in ("JH124", "JH125", "JH126") and _inside_regex_literal(sf.nocomment[idx - 1], m.start()):
                        continue                # a detector's pattern (/innerHTML|dangerouslySetInnerHTML/i)
                    if rule.id in ("JH124", "JH125", "JH126") and _constant_html(sf, idx, m.end()):
                        continue
                    if rule.id in ("JH124", "JH125", "JH126") and _constant_name_html(sf, idx, m.end()):
                        severity, confidence = "minor", "low"
                        message = (rule.message + " The HTML comes from a CONSTANT_NAME (an icon, a theme script), "
                                   "which usually holds fixed markup; check that it is not built from user data.")
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
                    if rule.id == "JH702" and sf.lang == "json" and _descriptive_json_value(line, m.start()):
                        severity, confidence = "minor", "medium"
                        message = rule.message + " It is the text of a descriptive JSON field (a description, " \
                                                   "title or help text), which launches nothing."
                    if rule.id == "JH702" and is_locale_text(sf):
                        severity, confidence = "minor", "medium"
                        message = rule.message + " It is in a translation file: UI text that an i18n " \
                                                   "library renders, not a command, so it launches no agent."
                    if "secret" in rule.tags:
                        # the first match that is neither a placeholder nor the assignment pattern
                        # re-matching one (apiKey: "AIza<words>"); a real secret later on the line counts
                        while m and (secret_placeholder(m.group(0)) or any(p in m.group(0) for p in placeholders)):
                            placeholders.append(m.group(0))
                            m = pat.search(line, m.end())
                        if not m:
                            continue
                        if "data\\s+source" in pat.pattern:
                            host = _CONN_HOST_RE.search(m.group(0))
                            if host and _local_db_host(host.group(1)):
                                severity, confidence = "minor", "low"
                                message = ("A database password in a connection string for a database on this machine "
                                           "or in a local container (%s): usually a development default. Keep it to "
                                           "local work, and make sure it is used nowhere else." % host.group(1)[:40])
                        if pat.pattern.startswith(r"\beyJ"):
                            while m and _jwt_role(m.group(0)) not in _PRIVILEGED_JWT_ROLES:
                                m = pat.search(line, m.end())   # an anon or user token: public by design
                            if not m:
                                continue
                            message = ("A Supabase service-role key is in the code. It bypasses row-level security "
                                       "and gives full access to the database; in front-end code every visitor has it.")
                        provider = "[:=]" not in pat.pattern and "PRIVATE KEY" not in pat.pattern
                        if provider and _inside_base64_blob(line, m.start(), m.end()):
                            continue    # a provider-shaped run by chance inside embedded binary (a font, an image)
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


def _npm_scripts(sf: SourceFile) -> List[Tuple[int, str]]:
    """A package.json's top-level scripts as (line, decoded command): npm runs them, the lifecycle hooks (preinstall,
    install, postinstall, prepare) on every install. The file is walked as JSON (members of the top-level object
    only, any white space), and each string is decoded by the JSON decoder itself. Anything else, or JSON that does
    not parse, has none."""
    import json
    if "package_json" not in sf.kinds:
        return []
    text = sf.text[1:] if sf.text.startswith("\ufeff") else sf.text
    try:
        json.loads(text)
    except RecursionError:
        pass                                # deeper than this Python's decoder goes (npm reads it); the walk has no limit
    except ValueError:
        return []
    n = len(text)

    def ws(i: int) -> int:
        while i < n and text[i] in " \t\n\r":
            i += 1
        return i

    def string_end(i: int) -> int:          # i at an opening quote; the index after its closing quote
        i += 1
        while text[i] != '"':
            i += 2 if text[i] == "\\" else 1
        return i + 1

    def value_end(i: int) -> int:           # i at a value; the index after it (no recursion: any depth)
        depth = 0
        while True:
            c = text[i]
            if c == '"':
                i = string_end(i)
            elif c in "{[":
                depth, i = depth + 1, i + 1
            elif c in "}]":
                depth, i = depth - 1, i + 1
            elif c in ",: \t\n\r":
                i += 1
            else:
                while i < n and text[i] not in ",:}] \t\n\r":
                    i += 1
            if depth == 0:
                return i

    def members(i: int) -> List[Tuple[str, int, int]]:    # i at "{": (key, value start, value end)
        out, i = [], ws(i + 1)
        while text[i] != "}":
            key_end = string_end(i)
            key = json.loads(text[i:key_end])
            start = ws(ws(key_end) + 1)
            end = value_end(start)
            out.append((key, start, end))
            i = ws(end)
            if text[i] == ",":
                i = ws(i + 1)
        return out

    top = ws(0)
    if top >= n or text[top] != "{":
        return []
    top_members = {key: (start, end) for key, start, end in members(top)}       # the last of each key, as json.loads
    if "scripts" not in top_members or text[top_members["scripts"][0]] != "{":
        return []
    found = []
    for start, end in {key: (s, e) for key, s, e in members(top_members["scripts"][0])}.values():
        if text[start] == '"':
            value = json.loads(text[start:end])
            if value:
                found.append((text.count("\n", 0, start) + 1, value))
    return found


_CONN_HOST_RE = re.compile(r"(?i)\b(?:server|host|data\s+source)\s*=\s*(?:tcp:)?([^;\"'\s,]+)")
_LOCAL_DB_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0", "(local)", ".", "(localdb)",
                   "host.docker.internal"}


def _loopback_address(host: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _local_db_host(host: str) -> bool:
    """localhost, loopback, SQL Server's local names, or a single-label name (a container or compose service)."""
    h = host.lower().split("\\")[0]
    h = h.rsplit(":", 1)[0] if h.count(":") == 1 else h        # host:port, not an IPv6 address
    if h in _LOCAL_DB_HOSTS or h.startswith("(localdb)") or _loopback_address(h):
        return True
    return "." not in h and ":" not in h and not h.replace("_", "").replace("-", "").isdigit()


def _jwt_role(token: str) -> Optional[str]:
    """The `role` claim of a JWT's payload, or None when it is not a readable JWT."""
    import base64
    import json
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, TypeError, RecursionError):
        return None
    role = payload.get("role") if isinstance(payload, dict) else None
    return role if isinstance(role, str) else None


# Supabase keys are JWTs: `anon` is public by design, these bypass row-level security
_PRIVILEGED_JWT_ROLES = {"service_role", "supabase_admin"}


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
    printed = re.match(r"""^\s*(?:-\s+)?(?:echo|printf|print|puts|console\.log|log|info|warn|say)\b""", line) or \
        re.search(r"""(?:echo|printf)\s+["'][^"']*$""", line[:line.find(match)] if match in line else "")
    # echo "curl ... | sh" | sh pipes the printed text into a shell: that runs it
    if printed and not re.search(r"""["']\s*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b""", line[line.find(match) + len(match):]
                                 if match in line else ""):
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
# JH107 digests that guard nothing: the hashing trick int(<digest>, 16) % n reduces a digest to a bucket
# number, and git's object hash sha1(b"blob %d\0" ...) is content addressing. Matched exactly, so a plain
# sha1(user_data) still fires; skipped only when the statement names no security use (an MD5 OTP stays).
_HASHING_TRICK_RE = re.compile(r"int\s*\(.*?,\s*16\s*\)\s*%\s*\S")
_GIT_BLOB_HASH_RE = re.compile(r"hashlib\.(?:md5|sha1)\s*\(\s*b[\"']blob %d(?:\\0|\\x00)[\"']")


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


# commands that print or report their argument; anything else may run it (retry, trap, alias, ansible -a)
_HINT_WORDS = re.compile(r"(?i)^(?:echo|printf|print|say|msg|note|hint|tip|info|warn\w*|err(?:or)?|die|fail|abort|"
                         r"log(?:_\w+)?|need\w*|require\w*|missing\w*|suggest\w*|usage)$")


def _python_docstring_spans(sf: SourceFile) -> List[Tuple[int, int, int, int]]:
    """Literal module/class/function docstrings, without treating assigned commands as documentation."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")       # compiler warnings must not echo unredacted source
            tree = ast.parse(sf.text)
    except (SyntaxError, ValueError, RecursionError):
        return []                       # malformed or unsupported Python keeps its leads
    spans = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) or not node.body:
            continue
        first = node.body[0]
        if not isinstance(first, ast.Expr) or not isinstance(first.value, ast.Constant) \
                or not isinstance(first.value.value, str):
            continue
        value = first.value
        spans.append((value.lineno, value.col_offset, value.end_lineno, value.end_col_offset))
    return sorted(spans)


def _in_python_docstring(sf: SourceFile, idx: int, match: "re.Match[str]",
                         spans: List[Tuple[int, int, int, int]]) -> bool:
    # AST columns count UTF-8 bytes, whereas regex match positions count characters.
    line = sf.raw[idx - 1]
    start = len(line[:match.start()].encode("utf-8"))
    end = len(line[:match.end()].encode("utf-8"))
    i = bisect_right(spans, (idx, start, sys.maxsize, sys.maxsize)) - 1
    return i >= 0 and (idx, end) <= spans[i][2:]


def _quoted_hint(sf: SourceFile, line: str, m: "re.Match[str]") -> Optional[str]:
    """The command word when a shell script's curl|sh sits inside a quoted
    argument of a command that prints or reports it (`echo "..."`,
    `require_tool zz "... (curl ... | sh)"`). None when anything may run it:
    another command word, a $(...) or backtick inside the quotes, or a pipe,
    redirect or chain after them."""
    if sf.lang != "shell":
        return None
    before = line[:m.start()]
    for q in ('"', "'"):
        if before.count(q) % 2 == 1 and q in line[m.end():]:
            start = before.rfind(q)
            end = line.index(q, m.end())
            head, inner, tail = before[:start], line[start + 1:end], line[end + 1:]
            if re.search(r"\$\(|`|<\(", inner) or re.search(r"[|;&<>`]|\$\(", head + tail):
                return None
            words = head.split()
            if not words or not _HINT_WORDS.match(words[0]):
                return None
            return words[0]
    return None


_PLAIN_LIT = r"""(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')"""
_CONST_CONCAT_RE = re.compile(r"\s*(?:%s\s*\+\s*)*%s\s*[),;]" % (_PLAIN_LIT, _PLAIN_LIT))


# JSON keys whose string value describes something rather than configuring it. Only these are downgraded:
# any other key ("postCreateCommand", "args", "run", an unknown one) may be what a tool executes.
_DESCRIPTIVE_KEY_RE = re.compile(r"(?i)^(?:description|desc|summary|title|subtitle|label|help|hint|tooltip|caption|"
                                 r"note|notes|comment|about|details|tagline|excerpt|\w*[_-]?description)$")
_JSON_PAIR_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"\s*:\s*"((?:[^"\\\n]|\\.)*)"')


def _descriptive_json_value(line: str, pos: int) -> bool:
    """The match sits inside the string value of a descriptive key on this line ("description": "...")."""
    for m in _JSON_PAIR_RE.finditer(line):
        if m.start(2) <= pos < m.end(2):
            return bool(_DESCRIPTIVE_KEY_RE.match(m.group(1)))
    return False


_CONST_OPERAND = r"(?:(?:self|cls)\s*\.\s*)?_*[A-Z][A-Z0-9_]*"
_CONSTANT_EXPR_RE = re.compile(
    r"\s*(?:" + _CONST_OPERAND +
    r"|''\s*\.\s*join\s*\(\s*" + _CONST_OPERAND + r"\s*\)" +
    r"|" + _CONST_OPERAND + r"\s*\.\s*(?:replace|upper|lower|strip|lstrip|rstrip|title)\s*\(\s*(?:''\s*(?:,\s*''\s*)*)?\))\s*")


def _constant_derived(expr: str) -> bool:
    """An interpolation of a CONSTANT_NAME (as before 3.6.2: CONSTANT, self.CONSTANT, cls.CONSTANT), or of one only
    through '<literal>'.join(CONSTANT) or CONSTANT.replace(...) and similar string methods with literal arguments.
    Any call (TAKE_INPUT(), BAG.read_value()), attribute (BAG.value), variable or other shape keeps the finding."""
    return bool(_CONSTANT_EXPR_RE.fullmatch(re.sub(r"\"[^\"]*\"|'[^']*'", "''", expr)))


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
    if pattern.startswith("(?i)([") and m.group(0).rstrip().endswith("+"):
        # "DELETE FROM t " + "WHERE id = ?": only fixed literals joined up to the end of the argument
        tail = " ".join([line[m.end():]] + sf.nocomment[idx:idx + 3])
        if _CONST_CONCAT_RE.match(tail):
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
    # only placeholders interpolated (f"... IN ({placeholders})", built from ? or %s) with the values bound on the
    # call: the query's shape varies, its values do not reach it
    if names and all(_PLACEHOLDER_NAME_RE.fullmatch(n) for n in names) and \
            re.search(r"[\"']\s*,\s*[\w(\[*]|\.bind\s*\(\s*\*", " ".join([raw] + sf.nocomment[idx:idx + 3])):
        return False
    if names and all(_constant_derived(n) for n in names) and \
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


# a ProcessBuilder call that hands a shell a "-c" command string (e.g.
# "bash", "-c" or '/bin/sh', '-c'): separate arguments run no shell of their own,
# so this is the only shape of theirs that actually invokes a shell. Either quote
# style — Java/ProcessBuilder double quotes or Kotlin single quotes.
_SHELL_ARGV_RE = re.compile(
    r'"(?:[^"\\]*/)?(?:sh|bash|dash|zsh|ksh|csh|tcsh|ash|fish|busybox)"\s*,\s*"-c"'
    r'|'
    r"'(?:[^'\\]*/)?(?:sh|bash|dash|zsh|ksh|csh|tcsh|ash|fish|busybox)'\s*,\s*'-c'")


def _processbuilder_shell(tail: str) -> Optional[str]:
    """ProcessBuilder runs no shell of its own. "major" when its arguments hand a
    shell a -c command, or the program named first is a shell or a command runner
    (bash -lc, cmd /c, powershell -Command, ssh, sudo, env); None when they are
    separate arguments naming another program (ProcessBuilder(node, "--version"));
    "minor" when a single list or spread argument (ProcessBuilder(cmd),
    ProcessBuilder(*command)) hides what runs. `tail` is the call from the match,
    over up to three lines, so split arguments count."""
    m = re.match(r"ProcessBuilder\s*\((.*)", tail, re.S)
    rest, depth, end = (m.group(1) if m else ""), 0, None
    for k, ch in enumerate(rest):                       # this call's own arguments, up to its ")"
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                end = k
                break
            depth -= 1
    args = rest[:end] if end is not None else rest
    first = re.search(r"[\"']([^\"'\n]+)[\"']", args)
    program = re.sub(r"\.exe$", "", re.split(r"[\\/]", first.group(1).strip())[-1].lower()) if first else ""
    if _SHELL_ARGV_RE.search(args) or re.search(r"[\"']-c[\"']", args) or program in _SHELL_PROGRAMS:
        return "major"
    depth, buf, parts = 0, "", []
    for ch in args:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(buf)
            buf = ""
        else:
            buf += ch
    parts = [p.strip() for p in parts + [buf] if p.strip()]
    if not parts or len(parts) == 1 and not re.match(r"[\"']|(?:List\.of|Arrays\.asList|listOf|mutableListOf)\s*\(",
                                                     parts[0]):
        return "minor"
    return None


def _argv_without_shell(sf: SourceFile, idx: int, col: int, pattern: str) -> bool:
    """Runtime.exec(new String[]{"prog", ...}) and new ProcessBuilder(...) name the
    program explicitly, so no shell parses the arguments. Runtime is reported only
    when the literal program is itself a shell or command runner (sh, su, env,
    ssh...); ProcessBuilder with separate arguments runs no shell at all and is
    reported only when the arguments visibly hand a shell a "-c" command. The
    other JH103 forms (shell=True, os.system, execSync...) are left to the caller.
    Read from the match on."""
    tail = sf.nocomment[idx - 1][col:]
    if "ProcessBuilder" in pattern:
        return False                    # decided by _processbuilder_shell in scan_sources
    call = tail + " " + " ".join(sf.nocomment[idx:idx + 2])
    m = re.match(r"Runtime\.getRuntime\(\)\.exec\s*\(\s*new\s+String\s*\[\s*\]\s*\{\s*\"([^\"\\]*)\"", call)
    if not m:
        return False
    program = re.split(r"[\\/]", m.group(1).strip())[-1].lower()
    return bool(program) and re.sub(r"\.exe$", "", program) not in _SHELL_PROGRAMS


# the command is the call's first argument and a plain literal (r/b/u prefixes, never f), followed
# directly by , or ): "ls %s" % x, "ls {}".format(x), "git diff " + arg and a variable all fail to match
_SHELL_CALL_LITERAL_RE = re.compile(
    r"\b(?:subprocess\.)?(?:run|call|Popen|check_output|check_call)\s*(?P<open>\()\s*[rRbBuU]{0,2}"
    r"(?P<q>['\"])(?:(?!(?P=q))[^\\\n]|\\.)*(?P=q)\s*[,)]")


# calls that hand their first argument to a shell as one string (os.system, os.popen, exec/execSync, IO.popen)
_SHELL_STRING_CALLS = {r"\bos\.(?:system|popen)\s*\(", r"\bchild_process\.(?:exec|execSync)\s*\(",
                       r"\bexecSync\s*\(", r"\bIO\.popen\s*\(", r"\bcommands\.getoutput\s*\("}
_FIXED_COMMAND_RE = re.compile(r"""\s*[rRbBuU]{0,2}(?P<lit>(?P<q>['"])(?:(?!(?P=q))[^\\\n]|\\.)*(?P=q)|`[^`$\\\n]*`)\s*[,)]""")


def _fixed_command(text: str, start: int) -> bool:
    """The call's first argument is one fixed string literal ("git rev-parse HEAD"): nothing is interpolated
    or concatenated. An f-string, a template with ${...}, Ruby's #{...}, % or .format(), + or a variable is not."""
    m = _FIXED_COMMAND_RE.match(text, start)
    return bool(m) and "#{" not in m.group("lit")


def _shell_true_constant(sf: SourceFile, idx: int, col: int) -> bool:
    """`shell=True` on a call whose command is a fixed literal: nothing attacker-
    controlled reaches the shell, so it is minor. An f-string, % or .format()
    formatting, concatenation, or a variable command stays major. The literal must
    open the call that holds this shell=True, not an earlier call on the line."""
    code, text = sf.code[idx - 1][:col], sf.nocomment[idx - 1][:col]
    depth = 0
    for k in range(len(code) - 1, -1, -1):             # the unclosed "(" of the enclosing call
        if code[k] == ")":
            depth += 1
        elif code[k] == "(":
            if depth:
                depth -= 1
                continue
            m = _SHELL_CALL_LITERAL_RE.search(text[max(0, k - 40):])
            return bool(m) and max(0, k - 40) + m.end("open") == k + 1
    return False


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


_CONST_NAME = r"[A-Z][A-Z0-9_]{2,}(?![\w.(\[])"


def _constant_name_html(sf: SourceFile, idx: int, col: int) -> bool:
    """innerHTML = EYE_ICON_SVG, = open ? EYE : EYE_CLOSED, or __html: THEME_INIT_SCRIPT: the markup comes from
    names written as constants. A naming convention, not proof, so the caller downgrades rather than skips."""
    line = sf.nocomment[idx - 1]
    rest = line[col:]
    nxt = next((n for n in sf.nocomment[idx:idx + 3] if n.strip()), "")
    goes_on = not line.rstrip().endswith(";") and re.match(r"\s*(?:[-+*/%?:.,|&]|concat\b)", nxt)
    if re.match(r"\s*=?\s*(?:%s|[^;?\n]{1,80}\?\s*%s\s*:\s*%s)\s*\)?\s*;?\s*$" % (_CONST_NAME, _CONST_NAME, _CONST_NAME),
                rest):
        return not goes_on
    window = " ".join([rest] + sf.nocomment[idx:idx + 3])
    m = re.match(r"\s*=\s*\{\{\s*__html\s*:\s*", window)
    return bool(m and re.match(r"%s\s*,?\s*\}" % _CONST_NAME, window[m.end():]))


_PLACEHOLDER_NAME_RE = re.compile(r"\s*\w*(?:placeholders?|qmarks|marks|bind_list|in_clause)\w*\s*|"
                                  r"\s*[\"']\s*,\s*[\"']\.join\(\s*\[?\s*[\"'](?:\?|%s)[\"'].*\)\s*", re.IGNORECASE)


def _inside_base64_blob(line: str, start: int, end: int) -> bool:
    """The match is part of, and not the start of, a base64 run of 200+ characters: encoded binary data, where any
    four-letter prefix turns up by chance. A key on its own is never 200 characters long."""
    a, b = start, end
    while a > 0 and (line[a - 1].isalnum() or line[a - 1] in "+/="):
        a -= 1
    while b < len(line) and (line[b].isalnum() or line[b] in "+/="):
        b += 1
    return b - a >= 200 and start > a


def _inside_prose_string(line: str, col: int) -> bool:
    """col sits inside a quoted string of eight or more words: a sentence of advice or documentation."""
    for q in re.finditer(r"""(["'`])((?:(?!\1)[^\\\n]|\\.)*)\1""", line):
        if q.start(2) <= col < q.end(2):
            return "${" not in q.group(2) and len(q.group(2).split()) >= 8     # a template with ${...} holds code
    return False


def _inside_regex_literal(line: str, col: int) -> bool:
    """col sits inside a JavaScript regex literal on this line."""
    for k in range(col - 1, -1, -1):
        if line[k] == "/" and (k == 0 or line[k - 1] != "\\"):
            end = _regex_literal_end(line, k)
            if end and end > col:
                return True
    return False


def _js_regex_spans(code: str) -> List[Tuple[int, int]]:
    """Regex literals in a code view, where ordinary string contents are already blanked."""
    spans = []
    pos = code.find("/")
    while pos >= 0:
        end = _regex_literal_end(code, pos)
        if end:
            spans.append((pos, end))
        pos = code.find("/", end if end else pos + 1)
    return spans


def _in_regex_spans(spans: List[Tuple[int, int]], pos: int) -> bool:
    i = bisect_right(spans, (pos, sys.maxsize)) - 1
    return i >= 0 and pos < spans[i][1]


def _in_doc_block(sf: SourceFile, idx: int) -> bool:
    """Line idx (1-based) sits inside a /** ... */ documentation block (JSDoc, Javadoc, PHPDoc), which describes
    parameters and shapes in code-like text. A plain /* ... */ block may hold commented-out code, so it does not count."""
    for k in range(idx - 1, max(-1, idx - 201), -1):
        line = sf.raw[k]
        if k < idx - 1 and "*/" in line:
            return False
        opener = line.rfind("/*")
        if opener >= 0:
            return line.startswith("/**", opener) and not line.startswith("/**/", opener)
    return False


def _is_http_route_comment(sf: SourceFile, idx: int) -> bool:
    """Route examples in comments document an API; they are not disabled code."""
    if idx <= 0 or idx > len(sf.raw):
        return False
    line = re.sub(r"^\s*(?://+|#+|--|/\*+|\*)\s*", "", sf.raw[idx - 1])
    return bool(re.match(r"(?i)(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+/\S*", line)
                and re.search(r"(?:→|->|\breturns?\b|\bresponds?\b)", line, re.I))


def _firebase_web_config(sf: SourceFile, idx: int) -> bool:
    """An AIza key in a Firebase client config: a web config object
    (authDomain, projectId...), google-services.json, or GoogleService-Info.plist."""
    if sf.basename.lower() in ("google-services.json", "googleservice-info.plist"):
        return True
    window = "\n".join(sf.raw[max(0, idx - 6):idx + 6])
    return bool(re.search(r"\b(?:authDomain|projectId|storageBucket|messagingSenderId|appId)\b|firebaseapp\.com", window))


def register(rules: Sequence[Rule]) -> None:
    """Add site rules (jh_ruleset) to this run's engine, compiled like the shipped ones."""
    _compile_rules()
    for rule in rules:
        RULES.append(rule)
        _COMPILED[rule.id] = [re.compile(p) for p in rule.patterns]
        if rule.ignore:
            _IGNORES[rule.id] = re.compile(rule.ignore)


def rule_by_id(rid: str) -> Optional[Rule]:
    for rule in RULES:
        if rule.id == rid:
            return rule
    return None
