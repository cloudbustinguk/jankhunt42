"""Power Platform: read Power Automate cloud flows from solution exports, inertly.

A citizen developer exports a solution as a .zip (solution.xml, customizations.xml, Workflows/<flow>.json) or commits
the unpacked folder. expand() opens a solution zip within fixed limits and returns the members worth reading as text,
each named <zip path>!/<member>, so every rule (hardcoded secrets included) reads a flow inside a zip as it reads an
unpacked one. Nothing here runs a flow, evaluates an expression, resolves a connection or fetches anything.

Flow definitions use the Logic Apps workflow definition language: properties.definition.triggers and .actions, with
connectors named by API (/providers/Microsoft.PowerApps/apis/shared_<connector>) through properties.connectionReferences
or the action's host. The rules here report what the export shows; tenant DLP policy, the connection's real account and
whether the flow is turned on are not in an export and are never assumed.
"""
from __future__ import annotations

import io
import json
import re
import zipfile
from typing import Any, Dict, Iterator, List, Optional, Tuple

from jh_core import MAX_ARCHIVE_BYTES, Finding, Rule, SourceFile, make_finding, source_from_text

MAX_ZIP_BYTES = MAX_ARCHIVE_BYTES        # a solution zip larger than this is not opened
MAX_MEMBERS = 5000                       # entries in the central directory
MAX_MEMBER_BYTES = 4 * 1024 * 1024       # one member, uncompressed
MAX_TOTAL_BYTES = 48 * 1024 * 1024       # everything read from one zip, uncompressed
MAX_RATIO = 200                          # uncompressed / compressed, per member: beyond this it is a bomb
MAX_DEPTH = 64                           # nesting of actions inside scopes, conditions and loops

# members read as text: the flows, and the manifest that identifies the zip. A solution export keeps flows in
# Workflows/<flow>.json; the older flow package (Export > Package (.zip)) keeps each in
# Microsoft.Flow/flows/<id>/definition.json beside a root manifest.json.
_READ = re.compile(r"(?i)^(?:solution\.xml|manifest\.json|workflows/[^/]{1,200}\.json|"
                   r"microsoft\.flow/flows/[^/]{1,100}/definition\.json)$")
_PACKAGE_FLOW = re.compile(r"(?i)^microsoft\.flow/flows/[^/]{1,100}/definition\.json$")
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._/ ()+-]")


def is_archive(rel: str) -> bool:
    return rel.lower().endswith(".zip")


def expand(data: Any, rel: str, size: Optional[int] = None) -> Tuple[List[Tuple[str, str]], List[str]]:
    """The text members of a Power Platform export (bytes, or a seekable binary file of `size` bytes), as
    (virtual path, text), and what could not be read. Only the central directory and the members read are touched.
    A zip that is not a Power Platform export gives nothing and no warning."""
    out: List[Tuple[str, str]] = []
    gaps: List[str] = []
    if isinstance(data, (bytes, bytearray)):
        size, data = len(data), io.BytesIO(data)
    if size is None or size > MAX_ZIP_BYTES:
        return out, ["%s: larger than %d MB, not opened" % (rel, MAX_ZIP_BYTES >> 20)]
    try:
        zf = zipfile.ZipFile(data)
        infos = zf.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, OSError, EOFError, NotImplementedError):
        return out, []
    names = {i.filename.lower() for i in infos[:MAX_MEMBERS]}
    solution = "solution.xml" in names and "customizations.xml" in names
    package = "manifest.json" in names and any(_PACKAGE_FLOW.match(n) for n in names)
    if not solution and not package:
        return out, []                                   # an ordinary zip, not a Power Platform export
    if len(infos) > MAX_MEMBERS:
        return out, ["%s: more than %d entries, not read" % (rel, MAX_MEMBERS)]
    total = 0
    for info in infos:
        name = info.filename
        if info.is_dir() or not _READ.match(name):
            continue
        if info.flag_bits & 0x1:
            gaps.append("%s!/%s: encrypted, not read" % (rel, _SAFE_NAME.sub("_", name)))
            continue
        if info.file_size > MAX_MEMBER_BYTES or info.file_size > MAX_RATIO * max(info.compress_size, 1):
            gaps.append("%s!/%s: too large or too compressed, not read" % (rel, _SAFE_NAME.sub("_", name)))
            continue
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            gaps.append("%s: more than %d MB of flows, the rest not read" % (rel, MAX_TOTAL_BYTES >> 20))
            break
        try:
            with zf.open(info) as fh:
                raw = fh.read(MAX_MEMBER_BYTES + 1)      # the header's size may lie; never read past the limit
        except (zipfile.BadZipFile, NotImplementedError, ValueError, OSError, EOFError, RuntimeError):
            gaps.append("%s!/%s: unreadable, not read" % (rel, _SAFE_NAME.sub("_", name)))
            continue
        if len(raw) > MAX_MEMBER_BYTES:
            gaps.append("%s!/%s: too large, not read" % (rel, _SAFE_NAME.sub("_", name)))
            continue
        text = raw.decode("utf-8-sig", "replace")
        out.append(("%s!/%s" % (rel, _SAFE_NAME.sub("_", name)), text))
    return out, gaps


GAPS: List[str] = []                     # what load_archive could not read during this load, for the report's warnings


def load_archive(path: Any, root: Any) -> List[SourceFile]:
    """The readable members of a solution zip on disk as sources named <zip>!/<member>; gaps go to GAPS."""
    import os
    rel = os.path.relpath(str(path), str(root)).replace(os.sep, "/")
    try:
        with open(path, "rb") as fh:
            members, gaps = expand(fh, rel, os.fstat(fh.fileno()).st_size)
    except OSError:
        return []
    GAPS.extend(gaps)
    out = []
    for name, text in members:
        sf = source_from_text(name, str(path) + name[len(rel):], text)
        if sf is not None:
            out.append(sf)
    return out


# ------------------------------------------------------------------ flows

def flow(sf: SourceFile) -> Optional[Dict[str, Any]]:
    """The flow in a JSON file (an exported Workflows/<flow>.json or a Logic Apps-style definition), or None."""
    if sf.lang != "json" or '"definition"' not in sf.text or ('"triggers"' not in sf.text and '"actions"' not in sf.text):
        return None
    cached = getattr(sf, "_jh_flow", False)
    if cached is not False:
        return cached
    doc: Any = None
    try:
        doc = json.loads(sf.text)
    except (ValueError, RecursionError):
        doc = None
    result = None
    if isinstance(doc, dict):
        props = doc.get("properties") if isinstance(doc.get("properties"), dict) else doc
        definition = props.get("definition")
        if isinstance(definition, dict) and (isinstance(definition.get("triggers"), dict) or
                                             isinstance(definition.get("actions"), dict)) and \
                ("workflowdefinition" in str(definition.get("$schema", "")).lower() or
                 "connectionReferences" in props or "contentVersion" in definition):
            refs = props.get("connectionReferences") if isinstance(props.get("connectionReferences"), dict) else {}
            result = {"definition": definition, "refs": refs}
    try:
        sf._jh_flow = result                             # type: ignore[attr-defined]
    except AttributeError:
        pass
    return result


def nodes(definition: Dict[str, Any]) -> Iterator[Tuple[str, str, Dict[str, Any]]]:
    """(kind, name, node) for every trigger and every action, including those inside scopes, conditions, switches and
    loops."""
    for name, node in (definition.get("triggers") or {}).items():
        if isinstance(node, dict):
            yield "trigger", str(name), node
    pending = [(definition.get("actions") or {}, 0)]
    while pending:
        actions, depth = pending.pop()
        if not isinstance(actions, dict) or depth > MAX_DEPTH:
            continue
        for name, node in actions.items():
            if not isinstance(node, dict):
                continue
            yield "action", str(name), node
            pending.append((node.get("actions"), depth + 1))
            if isinstance(node.get("else"), dict):
                pending.append((node["else"].get("actions"), depth + 1))
            if isinstance(node.get("default"), dict):
                pending.append((node["default"].get("actions"), depth + 1))
            for case in (node.get("cases") or {}).values() if isinstance(node.get("cases"), dict) else ():
                if isinstance(case, dict):
                    pending.append((case.get("actions"), depth + 1))


_API = re.compile(r"\bshared_[a-z0-9]+(?:_[a-z][a-z0-9]*)*", re.I)


def connector(node: Dict[str, Any], refs: Dict[str, Any]) -> Optional[str]:
    """The connector an action uses (shared_gmail), from its host and the flow's connection references."""
    inputs = node.get("inputs") if isinstance(node.get("inputs"), dict) else {}
    host = inputs.get("host") if isinstance(inputs.get("host"), dict) else {}
    name = host.get("connectionName")
    if isinstance(name, str):
        ref = refs.get(name)
        api = ref.get("api") if isinstance(ref, dict) else None
        if isinstance(api, dict) and isinstance(api.get("name"), str):
            return api["name"].lower()
    for value in (host.get("apiId"), name, json.dumps(host)[:4000]):
        if isinstance(value, str):
            m = _API.search(value)
            if m:
                return re.sub(r"_\d+$", "", m.group(0).lower())
    return None


def operation(node: Dict[str, Any]) -> str:
    inputs = node.get("inputs") if isinstance(node.get("inputs"), dict) else {}
    host = inputs.get("host") if isinstance(inputs.get("host"), dict) else {}
    return str(host.get("operationId", ""))


def _secured(node: Dict[str, Any], what: str) -> bool:
    rc = node.get("runtimeConfiguration")
    secure = rc.get("secureData") if isinstance(rc, dict) else None
    props = secure.get("properties") if isinstance(secure, dict) else None
    return isinstance(props, list) and what in props


def _at(sf: SourceFile, rule: Rule, name: str, **kw: Any) -> Finding:
    """A finding at the line where a trigger or action is named. A flow package is one minified line, so the evidence
    is the name itself rather than the start of the file."""
    key = json.dumps(name)
    m = re.search(re.escape(key) + r"\s*:", sf.text)
    line = sf.text.count("\n", 0, m.start()) + 1 if m else 1
    return make_finding(rule, sf, line, evidence=key[:120] + ": {", **kw)


# consumer-capable connectors: each can connect a personal account, so a flow using one can move work data out of the
# organisation. Whether this connection is personal is not in the export.
CONSUMER = {
    "shared_gmail": "Gmail", "shared_outlook": "Outlook.com", "shared_onedrive": "OneDrive (personal)",
    "shared_dropbox": "Dropbox", "shared_googledrive": "Google Drive", "shared_googlesheet": "Google Sheets",
    "shared_googlecalendar": "Google Calendar", "shared_googlecontacts": "Google Contacts",
}
# AI services reached through a connector; AI Builder prompts run through Dataverse as aibuilderpredict_* operations
AI_CONNECTORS = {"shared_openaiip", "shared_azureopenai", "shared_azureopenaiservice", "shared_anthropic"}
_AI_HOST = re.compile(r"(?i)https://(?:[\w-]+\.)*(?:openai\.com|openai\.azure\.com|anthropic\.com|"
                      r"generativelanguage\.googleapis\.com|api\.mistral\.ai|api\.cohere\.(?:ai|com))(?:[/:?]|$)")
# personal fields as flows name them: request schema properties, list columns, Dataverse columns (emailaddress1,
# telephone1, mobilephone, birthdate, address1_line1)
_PERSONAL = re.compile(r"(?i)\[\s*'(?:[^'\]]*/)?(?:\w*(?:e-?mail|phone|mobile|birth(?:date|day)?|dateofbirth|dob|ssn|"
                       r"socialsecurity|nationalid|passport|fullname|surname|lastname|address(?:\d_line\d)?)\w*)'\s*\]")
_REDACTOR = re.compile(r"(?i)redact|anonymi[sz]|pseudonymi[sz]|mask")


def findings(sf: SourceFile, rule: Rule) -> List[Finding]:
    parsed = flow(sf)
    if not parsed:
        return []
    out: List[Finding] = []
    definition, refs = parsed["definition"], parsed["refs"]
    for kind, name, node in nodes(definition):
        typ = str(node.get("type", ""))
        inputs = node.get("inputs") if isinstance(node.get("inputs"), dict) else {}
        if rule.check == "powerplatform_http_trigger" and kind == "trigger" and typ.lower() == "request" and \
                str(node.get("kind", "")).lower() in ("http", ""):      # not Button, PowerApp or Skills: those sign in
            mode = inputs.get("triggerAuthenticationType")
            if isinstance(mode, str) and mode.strip().lower() == "anyone":
                out.append(_at(sf, rule, name, confidence="high", message=(
                    "The flow's HTTP trigger '%s' is set to Anyone: whoever has its URL can start the flow, with no "
                    "sign-in. The URL is the only key, and it travels in logs, scripts and chat." % name[:60])))
            elif mode is None:
                out.append(_at(sf, rule, name, severity="minor", confidence="low", message=(
                    "The flow starts from an HTTP request ('%s') and the export does not say who may call it. A flow "
                    "made before sign-in options existed, or set to Anyone, runs for whoever has the URL. Check the "
                    "trigger's 'Who can trigger the flow' setting." % name[:60])))
        if kind != "action":
            continue
        api = connector(node, refs)
        op = operation(node)
        if rule.check == "powerplatform_secret_history":
            if api == "shared_keyvault" and op.lower().startswith("getsecret") and not _secured(node, "outputs"):
                out.append(_at(sf, rule, name, message=(
                    "The Key Vault action '%s' reads a secret without Secure outputs, so the secret is shown in the "
                    "flow's run history to everyone who can open it (co-owners and admins)." % name[:60])))
            elif typ.lower() == "http" and not _secured(node, "inputs") and (
                    isinstance(inputs.get("authentication"), dict) or
                    any(str(k).lower() in ("authorization", "x-api-key", "api-key", "apikey", "ocp-apim-subscription-key")
                        for k in (inputs.get("headers") or {}) if isinstance(inputs.get("headers"), dict))):
                out.append(_at(sf, rule, name, severity="minor", confidence="medium", message=(
                    "The HTTP action '%s' sends a credential without Secure inputs, so it is shown in the flow's run "
                    "history to everyone who can open it." % name[:60])))
        if rule.check == "powerplatform_consumer" and api in CONSUMER:
            out.append(_at(sf, rule, name, message=(
                "The action '%s' uses the %s connector, which can connect a personal account. Work data the flow "
                "handles can leave the organisation through it; the export cannot show whose account it is. Check "
                "your data policy classifies it." % (name[:60], CONSUMER[api]))))
        if rule.check == "powerplatform_ai_personal":
            uri = inputs.get("uri") if isinstance(inputs.get("uri"), str) else ""
            ai = api in AI_CONNECTORS or op.lower().startswith("aibuilderpredict") or \
                (typ.lower() == "http" and bool(_AI_HOST.match(uri)))
            if not ai:
                continue
            sent = json.dumps({k: v for k, v in inputs.items() if k not in ("host", "authentication")})[:200000]
            fields = sorted({m.group(0) for m in _PERSONAL.finditer(sent)})
            if fields and not _REDACTOR.search(sent):
                out.append(_at(sf, rule, name, message=(
                    "The action '%s' sends personal data (%s) to an AI service with no visible redaction. Check the "
                    "service is approved for this data and that the minimum is sent." % (
                        name[:60], ", ".join(f.strip("[]' ") for f in fields[:4])))))
    return out
