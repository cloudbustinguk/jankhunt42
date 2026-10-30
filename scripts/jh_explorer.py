#!/usr/bin/env python3
"""Self-contained HTML for the blast radius explorer and the software passport.

One file, no external assets, fonts, CDNs, fetches, or telemetry. A
Content-Security-Policy of `default-src 'none'` makes that a browser-
enforced property, not just a promise. Repository-derived data is embedded
as JSON inside <script type="application/json"> with every `<`, `>`, `&`,
and line separator escaped, then rendered exclusively with textContent and
setAttribute, never innerHTML, so a hostile label stays inert text.
"""
from __future__ import annotations

import json
from html import escape
from typing import Any, Dict

from jh_core import TOOL, VERSION

CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
       "img-src data:; base-uri 'none'; form-action 'none'")


def embed_json(data: Any) -> str:
    text = json.dumps(data, ensure_ascii=False, sort_keys=False)
    return (text.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def _page(title: str, body: str, data: Any, script: str) -> str:
    return "\n".join([
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta http-equiv="Content-Security-Policy" content="%s">' % CSP,
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta name="color-scheme" content="dark light">',
        '<meta name="referrer" content="no-referrer">',
        '<meta name="generator" content="%s %s">' % (TOOL, escape(VERSION)),
        "<title>%s</title>" % escape(title),
        "<style>", _CSS, "</style>",
        "</head>",
        "<body>",
        body,
        '<script type="application/json" id="jh-data">%s</script>' % embed_json(data),
        "<script>", script, "</script>",
        "</body>",
        "</html>",
    ])


def render_map(report: Dict[str, Any]) -> str:
    body = """
<header class="hero">
  <div class="brand"><span class="word">jankhunt42</span><span class="sub">// blast radius explorer</span></div>
  <div class="meta" id="meta"></div>
  <nav class="tabs" aria-label="views">
    <button class="tab" data-view="graph" aria-pressed="true">graph</button>
    <button class="tab" data-view="table" aria-pressed="false">edges table</button>
    <button class="tab" data-view="coverage" aria-pressed="false">coverage &amp; unknowns</button>
    <button class="tab" data-view="delta" aria-pressed="false" id="tab-delta" hidden>graph delta</button>
  </nav>
</header>
<section class="cards" id="cards" aria-label="summary"></section>
<section class="toolbar" aria-label="filters">
  <label>search <input id="q" type="search" placeholder="label, kind, engine" autocomplete="off"></label>
  <label>principal <select id="principal"></select></label>
  <label>impact <select id="impact">
    <option value="">none</option><option value="confidentiality">confidentiality</option>
    <option value="integrity">integrity</option><option value="availability">availability</option></select></label>
  <label>min evidence <select id="tier">
    <option value="0">unknown+</option><option value="1">inferred+</option>
    <option value="2">supported+</option><option value="3">verified only</option></select></label>
  <label><input id="unknowns" type="checkbox"> highlight unknowns</label>
  <span class="kinds" id="kinds" role="group" aria-label="node kinds"></span>
</section>
<main class="layout">
  <section class="view" id="view-graph" aria-label="graph">
    <div class="graphwrap" id="graphwrap" tabindex="0" aria-label="graph canvas: drag or arrow keys to pan, +/- to zoom">
      <svg id="svg" role="img" aria-label="connectivity graph"></svg>
    </div>
    <p class="hint">Click or Tab to a node or edge, then Enter, to inspect its evidence. Link a view with #principal=…&amp;impact=…&amp;select=…. Drag or arrow keys to pan; wheel or +/- to zoom; double-click to fit; Esc clears.
    Dashed edges are inferred or unknown; a path is a possibility, not proof of access.</p>
  </section>
  <section class="view" id="view-table" hidden aria-label="edges table"><table class="grid" id="edges"></table></section>
  <section class="view" id="view-coverage" hidden aria-label="coverage and unknowns"></section>
  <section class="view" id="view-delta" hidden aria-label="graph delta"></section>
  <aside class="inspector" id="inspector" aria-live="polite"><h2>inspector</h2><p class="muted">Select a node or edge.</p></aside>
</main>
<footer class="foot">Generated offline by jankhunt42. Static evidence only: inferred connectivity is not verified access.</footer>
"""
    return _page("jankhunt42 map: %s" % report.get("scope", {}).get("name", ""), body, report, _MAP_JS)


def render_passport(passport: Dict[str, Any]) -> str:
    body = """
<header class="hero">
  <div class="brand"><span class="word">jankhunt42</span><span class="sub">// software passport</span></div>
  <div class="meta" id="meta"></div>
</header>
<section class="cards" id="cards" aria-label="summary"></section>
<main class="doc" id="doc"></main>
<footer class="foot">Generated offline by jankhunt42. A local assessment, not a certificate or an approval.</footer>
"""
    return _page("jankhunt42 passport: %s" % passport.get("subject", {}).get("name", ""), body, passport, _PASSPORT_JS)


def render_agent_fuzz(report: Dict[str, Any]) -> str:
    """Render a self-contained policy-fuzz report without raw input/evidence."""
    evaluating = report.get("evaluation") == "provided-observations"
    title = "Policy fuzz evaluation" if evaluating else "Policy fuzz campaign validation"
    summary = report.get("summary") or {}

    def cell(value: Any, cls: str = "") -> str:
        return '<td class="%s">%s</td>' % (escape(cls, quote=True), escape(str(value), quote=True))

    cards = []
    if evaluating:
        if summary.get("fail", 0):
            verdict = ("FAIL", "fail")
        elif summary.get("policy-not-loaded", 0) or summary.get("inconclusive", 0):
            verdict = ("REVIEW", "inconclusive")
        else:
            verdict = ("PASS", "pass")
        cards.append('<article class="card"><small>VERDICT</small><strong class="%s">%s</strong></article>' %
                     (verdict[1], verdict[0]))
        labels = (("pass", "PASS"), ("fail", "FAIL"), ("inconclusive", "INCONCLUSIVE"),
                  ("policy-not-loaded", "POLICY NOT LOADED"))
        for key, label in labels:
            cards.append('<article class="card"><small>%s</small><strong>%s</strong></article>' %
                         (escape(label), escape(str(summary.get(key, 0)))))
        rows = []
        order = {"fail": 0, "policy-not-loaded": 1, "inconclusive": 2, "pass": 3}
        cases = sorted(report.get("cases") or [], key=lambda case: order.get(case.get("outcome"), 4))
        for case in cases:
            outcome = str(case.get("outcome", "unknown"))
            probes = case.get("probes") or []
            counts: Dict[str, int] = {}
            for probe in probes:
                state = str(probe.get("outcome", "unknown"))
                counts[state] = counts.get(state, 0) + 1
            breakdown = ", ".join("%s %s" % (count, state) for state, count in sorted(counts.items())) or "No probe detail"
            rows.append("<tr>%s%s%s</tr>" % (cell(case.get("case_id", "case"), "mono"),
                                             cell(outcome, "state " + outcome), cell(breakdown)))
        table = ("<h2>Case outcomes</h2><div class=\"scroll\"><table><thead><tr><th>Case</th>"
                 "<th>Outcome</th><th>Probe summary</th></tr></thead><tbody>%s</tbody></table></div>" % "".join(rows))
        meta = "<p>Campaign <code>%s</code> · evaluation: <strong>caller-provided observations</strong>. No agent was run.</p>" % escape(str(report.get("campaign_id", "campaign")))
        hashes = "<dl><dt>Campaign SHA-256</dt><dd>%s</dd><dt>Observations SHA-256</dt><dd>%s</dd></dl>" % (
            escape(str(report.get("campaign_sha256", "unavailable"))),
            escape(str(report.get("observations_sha256", "unavailable"))))
    else:
        cards = [('<article class="card"><small>STATUS</small><strong class="%s">%s</strong></article>' %
                  ("pass" if report.get("valid") else "fail", "VALID" if report.get("valid") else "INVALID")),
                 '<article class="card"><small>CASES / PROBES</small><strong>%s / %s</strong></article>' %
                 (escape(str(summary.get("cases", 0))), escape(str(summary.get("probes", 0)))),
                 '<article class="card"><small>ATTACK / CONTROL</small><strong>%s / %s</strong></article>' %
                 (escape(str(summary.get("attack_cases", 0))), escape(str(summary.get("control_cases", 0))))]
        table = "<h2>Targets</h2><p>%s</p>" % escape(", ".join(summary.get("targets") or []))
        meta = "<p>Campaign <code>%s</code> · validation only: campaign text was not executed.</p>" % escape(str(summary.get("id", "campaign")))
        hashes = "<dl><dt>Campaign SHA-256</dt><dd>%s</dd></dl>" % escape(str(report.get("campaign_sha256", "unavailable")))
    body = """<header><p class="brand">jankhunt42 <span>/ policy fuzz</span></p><h1>%s</h1>%s</header>
<main><section class="cards">%s</section><section>%s</section><section><h2>Evidence and scope</h2>%s
<p class="note">Reports omit prompts, policy text, resources, raw events, and adapter notes. Hashes identify the input files but do not authenticate their source.</p></section></main>
<footer>Generated offline. Static report; caller-provided observations are not an authenticated client run.</footer>""" % (
        escape(title), meta, "".join(cards), table, hashes)
    css = """<style>
:root{color-scheme:dark light;--bg:#0a0d14;--panel:#121824;--line:#2b3546;--text:#e7edf7;--muted:#9aa8bb;--cyan:#48d9eb;--red:#ff7884;--green:#65d99a;--yellow:#ffd166;--violet:#c4a7ff}
@media(prefers-color-scheme:light){:root{--bg:#f5f7fb;--panel:#fff;--line:#d9deea;--text:#18202d;--muted:#647084}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,sans-serif}header,main,footer{max-width:1050px;margin:auto;padding:22px}header{border-bottom:1px solid var(--line)}h1{font-size:clamp(1.7rem,4vw,2.5rem);margin:.3em 0}.brand{font-weight:800;letter-spacing:.1em;color:var(--cyan)}.brand span{color:var(--muted);font-weight:400}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}.card,section{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;margin:14px 0}.card small{display:block;color:var(--muted);letter-spacing:.08em}.card strong{display:block;font-size:1.6rem;margin-top:5px}.pass{color:var(--green)}.fail{color:var(--red)}.inconclusive{color:var(--yellow)}.policy-not-loaded{color:var(--violet)}h2{font-size:1.05rem;margin-top:0}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted)}.mono,dd{font-family:ui-monospace,monospace;overflow-wrap:anywhere}.scroll{overflow-x:auto}dl{display:grid;grid-template-columns:minmax(140px,190px) 1fr;gap:8px}dt{color:var(--muted)}dd{margin:0}.note,footer{color:var(--muted)}footer{font-size:.85rem}@media print{body{background:white;color:black}section,.card{break-inside:avoid}}
</style>"""
    return "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\"><title>%s</title>%s</head><body>%s</body></html>" % (
        escape(title), css, body)


_CSS = r"""
:root{--bg:#07090e;--panel:#10141d;--panel2:#151a26;--line:#232a3a;--text:#e6e9f2;--muted:#8a93a8;
--cyan:#38e1ff;--magenta:#ff4fd8;--green:#62d98b;--yellow:#ffd166;--red:#ff6b6b;--violet:#a78bfa;--grey:#6b7280}
@media (prefers-color-scheme: light){:root{--bg:#f6f7fb;--panel:#fff;--panel2:#eef1f7;--line:#d6dbe6;--text:#141824;--muted:#5a6275;
--cyan:#0077a8;--magenta:#b0128f;--green:#1d8a4b;--yellow:#946200;--red:#c0392b;--violet:#6941c6;--grey:#6b7280}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.hero{padding:18px 20px 10px;border-bottom:1px solid var(--line);background:linear-gradient(90deg,rgba(56,225,255,.08),rgba(255,79,216,.08))}
.brand .word{font-weight:800;letter-spacing:.18em;background:linear-gradient(90deg,var(--cyan),var(--magenta));-webkit-background-clip:text;background-clip:text;color:transparent;font-size:20px}
.brand .sub{color:var(--muted);margin-left:10px}.meta{color:var(--muted);margin-top:4px;word-break:break-all}
.tabs{margin-top:10px;display:flex;gap:6px;flex-wrap:wrap}
button,select,input{font:inherit;color:var(--text);background:var(--panel2);border:1px solid var(--line);border-radius:7px;padding:4px 9px}
button:focus-visible,select:focus-visible,input:focus-visible,[tabindex]:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
.tab[aria-pressed=true]{border-color:var(--cyan);color:var(--cyan)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;padding:14px 20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:10px 12px}
.card .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}.card .v{font-size:20px;font-weight:700;margin-top:2px}
.card .n{color:var(--muted);font-size:12px}
.lvl-Critical,.out-block{color:var(--magenta)}.lvl-High{color:var(--red)}.lvl-Moderate,.out-review{color:var(--yellow)}
.lvl-Low,.out-pass{color:var(--green)}.lvl-Unknown,.out-insufficient-evidence{color:var(--grey)}
.toolbar{display:flex;flex-wrap:wrap;gap:10px 16px;align-items:center;padding:0 20px 10px;color:var(--muted)}
.kinds label{margin-right:8px;white-space:nowrap}
.layout{display:grid;grid-template-columns:minmax(0,1fr) 360px;gap:12px;padding:0 20px 20px}
@media (max-width:900px){.layout{grid-template-columns:1fr}}
.graphwrap{background:var(--panel);border:1px solid var(--line);border-radius:12px;height:68vh;overflow:hidden;cursor:grab;touch-action:none}
svg{width:100%;height:100%;display:block}
.node rect{fill:var(--panel2);stroke:var(--line);stroke-width:1.2;rx:8}.node text{fill:var(--text);font-size:12px;pointer-events:none}
.node .kind{fill:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.06em}
.node.sel rect{stroke:var(--cyan);stroke-width:2.5}.node.hit rect{stroke:var(--magenta);stroke-width:2}
.node.dim,.edge.dim{opacity:.18}.node.unk rect{stroke-dasharray:4 3;stroke:var(--yellow)}
.node.added rect{stroke:var(--green);stroke-width:2.5}
.edge path{fill:none;stroke:var(--grey);stroke-width:1.4}.edge.t3 path{stroke:var(--green)}.edge.t2 path{stroke:var(--cyan)}
.edge.t1 path,.edge.t0 path{stroke-dasharray:5 4}.edge.witness path{stroke:var(--magenta);stroke-width:3}
.edge.sel path{stroke:var(--yellow);stroke-width:3}.edge path.hitbox{stroke:transparent!important;stroke-width:12;fill:none;stroke-dasharray:none}
.edge.added path{stroke:var(--green);stroke-width:2.6}
.hint,.muted{color:var(--muted)}.inspector{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:10px 14px;max-height:78vh;overflow:auto}
.inspector h2,.doc h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:6px 0 8px}
.inspector dl,.card dl{display:grid;grid-template-columns:110px 1fr;gap:3px 8px;margin:0}.inspector dt,.card dt{color:var(--muted)}.inspector dd,.card dd{margin:0;word-break:break-word}
.ev{border-top:1px solid var(--line);padding:6px 0}.badge{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:0 7px;font-size:11.5px;margin-right:4px}
.st-provider-verified,.st-verified{color:var(--green)}.st-observed,.st-supported{color:var(--cyan)}.st-declared{color:var(--violet)}
.st-inferred{color:var(--yellow)}.st-unknown,.st-not-observed,.st-refuted{color:var(--grey)}.st-failed{color:var(--red)}
table.grid{width:100%;border-collapse:collapse;background:var(--panel);border-radius:12px;overflow:hidden}
.grid th,.grid td{border-bottom:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}.grid th{color:var(--muted);font-weight:600}.grid td.mono{white-space:nowrap}
.grid tr[tabindex]:hover{background:var(--panel2);cursor:pointer}
.doc{padding:0 20px 20px;max-width:1100px}.doc section{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:10px 14px;margin-bottom:12px}
.doc li{margin:3px 0}.foot{color:var(--muted);padding:10px 20px 24px;font-size:12px}
@media print{.toolbar,.tabs,.graphwrap,.hint{display:none}body{background:#fff;color:#000}}
"""

_COMMON_JS = r"""
'use strict';
const DATA = JSON.parse(document.getElementById('jh-data').textContent);
function el(tag, attrs, text){const n=document.createElement(tag);if(attrs)for(const k of Object.keys(attrs))n.setAttribute(k,attrs[k]);if(text!==undefined&&text!==null)n.textContent=String(text);return n;}
function add(parent, child){parent.appendChild(child);return child;}
function card(host,k,v,n,cls){const c=add(host,el('div',{class:'card'}));add(c,el('div',{class:'k'},k));add(c,el('div',{class:'v '+(cls||'')},v));if(n)add(c,el('div',{class:'n'},n));}
function badge(text,cls){return el('span',{class:'badge '+(cls||'')},text);}
"""

_MAP_JS = _COMMON_JS + r"""
const TIER={'provider-verified':3,'observed':2,'declared':2,'inferred':1,'unknown':0,'refuted':-1};
const TIERNAME={3:'verified',2:'supported',1:'inferred',0:'unknown'};
const nodes=DATA.graph.nodes, edges=DATA.graph.edges;
const byId={};nodes.forEach(n=>byId[n.id]=n);const edgeById={};edges.forEach(e=>edgeById[e.id]=e);
const evById={};(DATA.evidence||[]).forEach(e=>evById[e.id]=e);
const ass=DATA.assessment, cov=DATA.coverage;
document.getElementById('meta').textContent=[DATA.scope.name,DATA.scope.snapshot,'schema '+DATA.schema_version,'scan '+DATA.scan_id.slice(0,12),DATA.scope.redaction==='share'?'redacted (shareable)':'full local view'].join('  ·  ');
const cards=document.getElementById('cards');
card(cards,'exposure',ass.exposure.class,'qualitative; a path is a possibility','lvl-'+ass.exposure.class);
card(cards,'coverage',cov.status,cov.files_inspected+' / '+cov.files_considered+' files inspected');
card(cards,'nodes / edges',nodes.length+' / '+edges.length,Object.keys(cov.by_adapter).length+' adapters');
const triggers=(DATA.triggers||{}).counts;if(triggers&&triggers.total)card(cards,'declared triggers',triggers.inbound+' inbound / '+triggers.unattended+' unattended','deployment and activation unverified');
const t=ass.evidence_tiers;card(cards,'edge evidence',t.verified+' verified',t.supported+' supported · '+t.inferred+' inferred · '+t.unknown+' unknown');
card(cards,'unknown capability',ass.unknown_capability_edges,'treated as possibly write or destructive');
card(cards,'breadth',ass.breadth.indicator.toFixed(3),ass.breadth.distinct_trust_domains+' trust domains (informational)');
if(DATA.truncation&&DATA.truncation.truncated)card(cards,'truncated','partial',DATA.truncation.reasons.join('; '),'lvl-High');

const ORDER=['application','workload','identity','api','queue','database','storage','external','unknown'];
const cols={};nodes.forEach(n=>{(cols[n.kind]=cols[n.kind]||[]).push(n);});
const pos={};let colX=20;const W=190,H=44,GX=48,GY=16;
ORDER.forEach(k=>{if(!cols[k])return;cols[k].forEach((n,i)=>{pos[n.id]={x:colX,y:20+i*(H+GY)};});colX+=W+GX;});
const svg=document.getElementById('svg');const NS='http://www.w3.org/2000/svg';
function s(tag,attrs){const n=document.createElementNS(NS,tag);for(const k of Object.keys(attrs||{}))n.setAttribute(k,attrs[k]);return n;}
const defs=s('defs');const mk=s('marker',{id:'arrow',viewBox:'0 0 10 10',refX:'10',refY:'5',markerWidth:'7',markerHeight:'7',orient:'auto-start-reverse'});
mk.appendChild(s('path',{d:'M0,0 L10,5 L0,10 z',fill:'currentColor'}));defs.appendChild(mk);svg.appendChild(defs);
const vp=s('g',{id:'vp'});svg.appendChild(vp);
const big=nodes.length>300;
const edgeEls={},nodeEls={};
const deltaAddedN=new Set(DATA.delta?DATA.delta.nodes.added:[]),deltaAddedE=new Set(DATA.delta?DATA.delta.edges.added:[]);
function drawGraph(){
  edges.forEach(e=>{const a=pos[e.source],b=pos[e.target];if(!a||!b)return;
    const g=s('g',{class:'edge t'+Math.max(0,TIER[e.verification]),tabindex:'0',role:'button','aria-label':'edge '+e.kind+' '+byId[e.source].display_label+' to '+byId[e.target].display_label});
    if(deltaAddedE.has(e.id))g.classList.add('added');
    const x1=a.x+W,y1=a.y+H/2,x2=b.x,y2=b.y+H/2;let d;
    if(x2>x1){const mx=(x1+x2)/2;d='M'+x1+','+y1+' C'+mx+','+y1+' '+mx+','+y2+' '+x2+','+y2;}
    else{const lift=40+Math.abs(y2-y1)/4;d='M'+(a.x+W/2)+','+a.y+' C'+(a.x+W/2)+','+(a.y-lift)+' '+(b.x+W/2)+','+(b.y-lift)+' '+(b.x+W/2)+','+b.y;}
    g.appendChild(s('path',{d:d,'marker-end':'url(#arrow)'}));g.appendChild(s('path',{d:d,class:'hitbox'}));
    const tt=s('title');tt.textContent=e.kind+' / '+e.capability+' ('+e.verification+')';g.appendChild(tt);
    g.addEventListener('click',ev=>{ev.stopPropagation();selectEdge(e.id);});
    g.addEventListener('keydown',ev=>{if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();selectEdge(e.id);}});
    vp.appendChild(g);edgeEls[e.id]=g;});
  nodes.forEach(n=>{const p=pos[n.id];const g=s('g',{class:'node',transform:'translate('+p.x+','+p.y+')',tabindex:'0',role:'button','aria-label':n.kind+': '+n.display_label});
    if(n.attributes&&n.attributes.unresolved)g.dataset.unresolved='1';if(deltaAddedN.has(n.id))g.classList.add('added');
    g.appendChild(s('rect',{width:W,height:H,rx:8}));
    const k=s('text',{x:10,y:15,class:'kind'});k.textContent=n.kind+(n.sensitivity!=='unknown'?' · '+n.sensitivity:'')+(n.environment!=='unknown'?' · '+n.environment:'');g.appendChild(k);
    const l=s('text',{x:10,y:33});const lab=n.display_label;l.textContent=lab.length>30?lab.slice(0,29)+'…':lab;g.appendChild(l);
    const tt=s('title');tt.textContent=lab;g.appendChild(tt);
    g.addEventListener('click',ev=>{ev.stopPropagation();selectNode(n.id);});
    g.addEventListener('keydown',ev=>{if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();selectNode(n.id);}});
    vp.appendChild(g);nodeEls[n.id]=g;});
}
let view={x:0,y:0,k:1};function applyView(){vp.setAttribute('transform','translate('+view.x+','+view.y+') scale('+view.k+')');}
const wrap=document.getElementById('graphwrap');let drag=null;
wrap.addEventListener('pointerdown',e=>{if(e.target.closest&&e.target.closest('.node,.edge'))return;drag={x:e.clientX,y:e.clientY,vx:view.x,vy:view.y};wrap.setPointerCapture(e.pointerId);});
wrap.addEventListener('pointermove',e=>{if(!drag)return;view.x=drag.vx+e.clientX-drag.x;view.y=drag.vy+e.clientY-drag.y;applyView();});
wrap.addEventListener('pointerup',()=>{drag=null;});
wrap.addEventListener('wheel',e=>{e.preventDefault();const f=e.deltaY<0?1.1:1/1.1;view.k=Math.min(4,Math.max(0.15,view.k*f));applyView();},{passive:false});
wrap.addEventListener('keydown',e=>{const step=40;if(e.target!==wrap)return;
  if(e.key==='+'||e.key==='=')view.k=Math.min(4,view.k*1.15);else if(e.key==='-')view.k=Math.max(0.15,view.k/1.15);
  else if(e.key==='ArrowLeft')view.x+=step;else if(e.key==='ArrowRight')view.x-=step;else if(e.key==='ArrowUp')view.y+=step;else if(e.key==='ArrowDown')view.y-=step;else return;e.preventDefault();applyView();});
document.addEventListener('keydown',e=>{if(e.key==='Escape')clearSel();});
svg.addEventListener('click',()=>clearSel());

const insp=document.getElementById('inspector');
function resetInsp(title){while(insp.firstChild)insp.removeChild(insp.firstChild);add(insp,el('h2',null,title));}
function dl(rows){const d=el('dl');rows.forEach(([k,v])=>{add(d,el('dt',null,k));const dd=add(d,el('dd'));if(v instanceof Node)dd.appendChild(v);else dd.textContent=(v===null||v===undefined||v==='')?'—':String(v);});return d;}
function evidenceList(refs){const box=el('div');add(box,el('h2',null,'evidence ('+refs.length+')'));
  if(!refs.length)add(box,el('p',{class:'muted'},'no receipt (e.g. a derived node)'));
  refs.forEach(r=>{const ev=evById[r];const d=add(box,el('div',{class:'ev'}));if(!ev){add(d,el('code',null,r));return;}
    add(d,badge(ev.state,'st-'+ev.state));add(d,el('code',null,ev.path+(ev.line?':'+ev.line:'')));add(d,el('div',{class:'muted'},ev.adapter));
    if(ev.snippet)add(d,el('code',{class:'mono'},ev.snippet));
    (ev.assumptions||[]).forEach(a=>add(d,el('div',{class:'muted'},'assumes: '+a)));
    (ev.counterevidence||[]).forEach(a=>add(d,el('div',{class:'muted'},'counter: '+a)));});return box;}
function clearSel(){Object.values(nodeEls).forEach(g=>g.classList.remove('sel'));Object.values(edgeEls).forEach(g=>g.classList.remove('sel'));}
function selectNode(id){clearSel();const n=byId[id];if(nodeEls[id])nodeEls[id].classList.add('sel');resetInsp('node');
  insp.appendChild(dl([['label',n.display_label],['kind',n.kind],['id',n.id],['trust domain',n.trust_domain],['environment',n.environment],
    ['sensitivity',n.sensitivity],['criticality',n.criticality],['classified by',n.classification_source],
    ['attributes',Object.keys(n.attributes||{}).map(k=>k+'='+JSON.stringify(n.attributes[k])).join('; ')]]));
  const out=edges.filter(e=>e.source===id),inn=edges.filter(e=>e.target===id);
  add(insp,el('h2',null,'edges out '+out.length+' / in '+inn.length));const ul=add(insp,el('ul'));
  out.concat(inn).slice(0,40).forEach(e=>{const li=add(ul,el('li'));const a=add(li,el('a',{href:'#',class:'mono'},(e.source===id?'→ ':'← ')+e.kind+'/'+e.capability+' '+byId[e.source===id?e.target:e.source].display_label));
    a.addEventListener('click',ev=>{ev.preventDefault();selectEdge(e.id);});});
  insp.appendChild(evidenceList(n.evidence_refs||[]));}
function selectEdge(id){clearSel();const e=edgeById[id];if(edgeEls[id])edgeEls[id].classList.add('sel');resetInsp('edge');
  const tb=e.trust_boundary||{};
  insp.appendChild(dl([['from',byId[e.source].display_label],['to',byId[e.target].display_label],['kind',e.kind],['capability',e.capability],
    ['verification',badge(e.verification,'st-'+e.verification)],['attenuation',e.attenuation===undefined?'':String(e.attenuation)],['evidence tier',TIERNAME[Math.max(0,TIER[e.verification])]],['confidence',e.confidence],['source trust',e.source_trust],
    ['identity',e.identity_ref?byId[e.identity_ref]&&byId[e.identity_ref].display_label:''],['boundary',[tb.domain,tb.environment].filter(Boolean).join('; ')],['id',e.id]]));
  add(insp,el('h2',null,'assumptions'));const ul=add(insp,el('ul'));(e.assumptions||[]).forEach(a=>add(ul,el('li',null,a)));
  insp.appendChild(evidenceList(e.evidence_refs||[]));}

const psel=document.getElementById('principal');Object.keys(ass.blast_radius).forEach(p=>{add(psel,el('option',{value:p},byId[p].display_label+' ['+ass.blast_radius[p].exposure+']'));});
const kindsHost=document.getElementById('kinds');const kindOn={};ORDER.filter(k=>cols[k]).forEach(k=>{kindOn[k]=true;const l=add(kindsHost,el('label'));const c=add(l,el('input',{type:'checkbox'}));c.checked=true;
  c.addEventListener('change',()=>{kindOn[k]=c.checked;refresh();});l.appendChild(document.createTextNode(' '+k+' ('+cols[k].length+')'));});
['q','principal','impact','tier','unknowns'].forEach(id=>document.getElementById(id).addEventListener('input',refresh));
function refresh(){const q=document.getElementById('q').value.trim().toLowerCase();const p=psel.value,imp=document.getElementById('impact').value;
  const minT=+document.getElementById('tier').value;const unk=document.getElementById('unknowns').checked;
  let reach=null,wit=new Set();if(imp&&p&&ass.blast_radius[p]){reach=ass.blast_radius[p].impacts[imp];Object.values(reach).forEach(r=>r.path.forEach(x=>wit.add(x)));}
  nodes.forEach(n=>{const g=nodeEls[n.id];if(!g)return;const text=(n.display_label+' '+n.kind+' '+JSON.stringify(n.attributes||{})).toLowerCase();
    let show=kindOn[n.kind];g.style.display=show?'':'none';
    const dim=(q&&!text.includes(q))||(reach&&!(n.id in reach)&&n.id!==p);g.classList.toggle('dim',!!dim);g.classList.toggle('hit',!!(reach&&n.id in reach));
    g.classList.toggle('unk',unk&&(!!(n.attributes&&n.attributes.unresolved)||n.sensitivity==='unknown'&&n.kind!=='application'&&n.kind!=='workload'&&n.kind!=='identity'));});
  edges.forEach(e=>{const g=edgeEls[e.id];if(!g)return;const show=kindOn[byId[e.source].kind]&&kindOn[byId[e.target].kind]&&Math.max(0,TIER[e.verification])>=minT&&TIER[e.verification]>=0;
    g.style.display=show?'':'none';g.classList.toggle('witness',wit.has(e.id));g.classList.toggle('dim',!!(reach&&!wit.has(e.id)));
    g.classList.toggle('unk',unk&&e.capability==='unknown');});}

const tbl=document.getElementById('edges');const hr=add(add(tbl,el('thead')),el('tr'));['from','edge','to','verification','confidence','evidence'].forEach(h=>add(hr,el('th',null,h)));
const tb=add(tbl,el('tbody'));edges.forEach(e=>{const tr=add(tb,el('tr',{tabindex:'0'}));add(tr,el('td',null,byId[e.source].display_label));add(tr,el('td',{class:'mono'},e.kind+'/'+e.capability));
  add(tr,el('td',null,byId[e.target].display_label));const v=add(tr,el('td'));v.appendChild(badge(e.verification,'st-'+e.verification));add(tr,el('td',null,e.confidence));
  add(tr,el('td',{class:'mono'},(e.evidence_refs||[]).map(r=>evById[r]?evById[r].path+':'+evById[r].line:r).join(', ')));
  tr.addEventListener('click',()=>selectEdge(e.id));tr.addEventListener('keydown',ev=>{if(ev.key==='Enter')selectEdge(e.id);});});

const cv=document.getElementById('view-coverage');
function section(host,title){const s=add(host,el('div',{class:'card'}));add(s,el('h2',null,title));return s;}
let sc,ul;
if(DATA.whatif){const W=DATA.whatif;sc=section(cv,'what-if (hypothetical): '+W.scenario);add(sc,el('p',{class:'muted'},W.note));
  ul=add(sc,el('ul'));W.mutations.forEach(m=>add(ul,el('li',null,'#'+m.index+' '+m.op+': '+m.matched+' match(es)')));
  sc.appendChild(dl([['exposure',W.delta.exposure.base+' → '+W.delta.exposure.head],['edges',' +'+W.delta.edges.added.length+' / -'+W.delta.edges.removed.length],
   ['newly reachable',W.delta.newly_reachable.length]]));
  (W.compromised||[]).forEach(cp=>add(sc,el('p',null,'compromised identity '+cp.label+': exposure '+cp.exposure)));}
sc=section(cv,'coverage');sc.appendChild(dl([['status',cov.status],['considered',cov.files_considered],['inspected',cov.files_inspected],['unsupported',cov.unsupported_files],
  ['tests excluded',cov.test_files_excluded],['skipped',JSON.stringify(cov.skipped)],['adapters',Object.keys(cov.by_adapter).map(k=>k+' '+cov.by_adapter[k]).join(', ')],
  ['partial because',(cov.partial_reasons||[]).join('; ')]]));
if((cov.parse_failures||[]).length){sc=section(cv,'parse failures');const ul=add(sc,el('ul'));cov.parse_failures.forEach(p=>add(ul,el('li',null,p.path+': '+p.reason)));}
sc=section(cv,'unknowns (unknown is not safe, and not dangerous)');ul=add(sc,el('ul'));DATA.unknowns.forEach(u=>add(ul,el('li',null,u.id+': '+u.detail)));
if(DATA.warnings.length){sc=section(cv,'warnings');ul=add(sc,el('ul'));DATA.warnings.forEach(w=>add(ul,el('li',null,w)));}
sc=section(cv,'highest-impact paths');ul=add(sc,el('ul'));
Object.keys(ass.blast_radius).forEach(p=>(ass.blast_radius[p].drivers||[]).slice(0,6).forEach(d=>{const li=add(ul,el('li'));add(li,el('b',{class:'lvl-'+d.level},d.level+' '));
  li.appendChild(document.createTextNode(d.impact+' ('+d.tier+') '+byId[p].display_label+' → '+(byId[d.node]?byId[d.node].display_label:d.node)+': '+d.why));}));
const EG=DATA.egress||{};if(Array.isArray(EG.boundaries)&&EG.boundaries.length){sc=section(cv,'egress boundary (declared allowlists vs reached hosts)');
  add(sc,el('p',{class:'muted'},EG.note||''));if(EG.state==='unknown')add(sc,el('p',null,'Coverage unknown: '+(EG.unassessed||[]).length+' reached endpoint(s) unassessed.'));
  ul=add(sc,el('ul'));EG.boundaries.forEach(b=>add(ul,el('li',null,b.tool+(b.profile?' ['+b.profile+']':'')+' '+b.path+':'+b.line+': '+b.allow.length+' allowed, '+b.deny.length+' denied'+(b.note?' ('+b.note+')':''))));
  EG.outside.forEach(o=>{const li=add(ul,el('li'));li.appendChild(badge('outside','st-failed'));const host=o.port==null?o.host:(o.host.includes(':')?'['+o.host.replace(/^\[|\]$/g,'')+']':o.host)+':'+o.port;li.appendChild(document.createTextNode(' '+host+' ('+o.tier+', reached by '+o.reached_by.join(', ')+'): '+o.why+((EG.contexts||[]).length>1?' ['+(o.contexts||[]).join(', ')+']':'')));});
  if(EG.wildcards.length)add(ul,el('li',null,'wildcards: '+EG.wildcards.join(', ')));if(EG.unused.length)add(ul,el('li',null,'allowed but unused by the mapped code: '+EG.unused.join(', ')));}
const CBR=((ass.credential_blast_radius||{}).identities||[]).filter(r=>r.mutating.length||r.flags.some(f=>f!=='holder-not-visible'));
if(CBR.length){sc=section(cv,'credential blast radius (what each identity unlocks; informational)');ul=add(sc,el('ul'));
  const lbl=id=>byId[id]?byId[id].display_label:id;
  CBR.slice(0,20).forEach(r=>{const li=add(ul,el('li'));add(li,el('b',null,lbl(r.identity)+' '));
   li.appendChild(document.createTextNode((r.flags.length?'['+r.flags.join(', ')+'] ':'')+'unlocks '+Object.keys(r.unlocks).length+' ('+r.mutating.length+' mutating): '+
    Object.keys(r.unlocks).map(lbl).join(', ')+' · held by '+(r.holders.map(lbl).join(', ')||'no visible holder')));});}
if(DATA.delta){document.getElementById('tab-delta').hidden=false;const dv=document.getElementById('view-delta');const D=DATA.delta;
  sc=section(dv,'delta '+D.base+' → '+D.head);sc.appendChild(dl([['exposure',D.exposure.base+' → '+D.exposure.head],['nodes',' +'+D.nodes.added.length+' / -'+D.nodes.removed.length],
   ['edges',' +'+D.edges.added.length+' / -'+D.edges.removed.length],['escalations',D.permission_escalations.length],['authority became unknown',(D.authority_became_unknown||[]).length],['newly reachable sensitive',D.newly_reachable_sensitive.length],
   ['boundaries added',D.trust_boundaries.added.join(', ')],['boundaries removed',D.trust_boundaries.removed.join(', ')],['coverage regressed',String(D.coverage.regressed)]]));
  if((D.authority_became_unknown||[]).length){sc=section(dv,'authority became unknown (possibly read, write or destroy)');ul=add(sc,el('ul'));D.authority_became_unknown.forEach(x=>add(ul,el('li',null,(byId[x.source]?byId[x.source].display_label:x.source)+' → '+(byId[x.target]?byId[x.target].display_label:x.target)+': '+x.before.join('/')+' ⇒ '+x.after.join('/'))));}
  sc=section(dv,'permission escalations');ul=add(sc,el('ul'));D.permission_escalations.forEach(x=>add(ul,el('li',null,(byId[x.source]?byId[x.source].display_label:x.source)+' → '+(byId[x.target]?byId[x.target].display_label:x.target)+': '+x.before.join('/')+' ⇒ '+x.after.join('/'))));
  sc=section(dv,'newly reachable');ul=add(sc,el('ul'));D.newly_reachable.forEach(x=>add(ul,el('li',null,x.impact+' ('+x.tier+') '+(byId[x.node]?byId[x.node].display_label:x.node)+(x.sensitive?' [sensitive/critical]':''))));
  sc=section(dv,'removed (head side)');ul=add(sc,el('ul'));D.edges.removed.concat(D.nodes.removed).forEach(x=>add(ul,el('li',{class:'mono'},x.id+' — '+x.state)));
  add(dv,el('p',{class:'muted'},D.note));}
document.querySelectorAll('.tab').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('.tab').forEach(x=>x.setAttribute('aria-pressed',String(x===b)));
  document.querySelectorAll('.view').forEach(v=>v.hidden=v.id!=='view-'+b.dataset.view);if(b.dataset.view==='graph'&&!vp.firstChild)drawGraph(),refresh();}));
if(big){document.querySelectorAll('.tab').forEach(x=>x.setAttribute('aria-pressed',String(x.dataset.view==='table')));document.querySelectorAll('.view').forEach(v=>v.hidden=v.id!=='view-table');
  add(cards,el('div',{class:'card'},nodes.length+' nodes: table view first; open the graph tab to render it.'));}
else{drawGraph();refresh();}
function fit(){const box=vp.getBBox?vp.getBBox():null;const r=wrap.getBoundingClientRect();if(!box||!box.width||!r.width)return;
  view.k=Math.min(1.2,Math.max(0.62,Math.min((r.width-40)/box.width,(r.height-40)/box.height)));view.x=20-box.x*view.k;view.y=20-box.y*view.k;}
fit();applyView();
// Deep link: #principal=<id>&impact=<c|i|a name>&select=<node or edge id>&tab=<view>
(function(){const h=new URLSearchParams((location.hash||'').slice(1));
  const p=h.get('principal'),imp=h.get('impact'),sel=h.get('select'),tab=h.get('tab');
  if(p&&ass.blast_radius[p])psel.value=p;
  if(imp&&['confidentiality','integrity','availability'].includes(imp))document.getElementById('impact').value=imp;
  if(p||imp)refresh();
  if(sel&&byId[sel])selectNode(sel);else if(sel&&edgeById[sel])selectEdge(sel);
  if(tab){const b=document.querySelector('.tab[data-view="'+tab.replace(/[^a-z]/g,'')+'"]');if(b)b.click();}})();
wrap.addEventListener('dblclick',()=>{fit();applyView();});
"""

_PASSPORT_JS = _COMMON_JS + r"""
const P=DATA,A=P.assessment,D=A.decision,C=P.coverage;
document.getElementById('meta').textContent=[P.subject.name,'revision '+(P.subject.revision||'unknown'),'schema '+P.schema_version,'scan '+P.scan_id.slice(0,12),P.scope.redaction==='share'?'redacted (shareable)':'full local view'].join('  ·  ');
const cards=document.getElementById('cards');
card(cards,'release assessment',D.result,D.mode,'out-'+D.result);
card(cards,'technical jank score',A.jank.score+'/100','grade '+A.jank.grade+' · policy '+A.jank.policy);
card(cards,'exposure',A.exposure.class,'separate from the Jank Score','lvl-'+A.exposure.class);
card(cards,'evidence coverage',C.evidence_areas_present+'/'+C.evidence_areas_total,'areas observed, declared, or inferred');
card(cards,'lifecycle',P.lifecycle.state,'acceptance: '+P.lifecycle.acceptance.state);
const triggers=(P.triggers||{}).counts;if(triggers&&triggers.total)card(cards,'declared triggers',triggers.inbound+' inbound / '+triggers.unattended+' unattended','deployment and activation unverified');
const G=P.governance||{profile:'standard',custodians:[],brief:[],agent:{servers:[]}};
if(G.profile==='citizen')card(cards,'profile','citizen','custodian: '+(G.custodians.join(', ')||'not named'),G.custodians.length?'out-pass':'out-block');
const doc=document.getElementById('doc');
function sec(title){const s=add(doc,el('section'));add(s,el('h2',null,title));return s;}
let s;
if(G.profile==='citizen'){s=sec('in plain terms · citizen-developer profile');let pl=null;
  G.brief.forEach((b,i)=>{if(b.startsWith('- ')){if(!pl)pl=add(s,el('ul'));add(pl,el('li',null,b.slice(2)));}
    else{pl=null;const para=add(s,el('p',null,i===0?'':b));if(i===0)add(para,el('b',{class:'out-'+D.result},b));}});}
s=sec('why this decision');add(s,el('p',{class:'muted'},D.note));let ul=add(s,el('ul'));
if(!D.reasons.length)add(ul,el('li',null,'No rule triggered. This is an assessment, not an approval.'));
D.reasons.forEach(r=>{const li=add(ul,el('li'));add(li,el('b',{class:'out-'+r.outcome},r.outcome+' '));add(li,el('code',null,r.rule));li.appendChild(document.createTextNode((r.hard_floor?' (hard floor) ':' ')+r.message));});
const SB=P.sandbox_run;if(SB&&SB.state&&SB.state!=='not-supplied'){s=sec('sandbox run');if(SB.state!=='matched'){add(s,el('p',{class:'muted'},'Supplied but not used: '+(SB.reason||'made on a different tree')+'.'));}else{const cnt=SB.counts||{};add(s,el('p',null,(cnt.ALERT||0)+' ALERT · '+(cnt.DENY||0)+' blocked network attempt(s) · '+(cnt.UNDECLARED||0)+' to destinations the repository does not declare · coverage '+SB.coverage.state));const ta=add(s,el('table',{class:'grid'}));const ha=add(add(ta,el('thead')),el('tr'));['verdict','what','detail','step'].forEach(x=>add(ha,el('th',null,x)));const tba=add(ta,el('tbody'));(SB.alerts||[]).forEach(a=>{const tr=add(tba,el('tr'));add(tr,el('td')).appendChild(badge('ALERT','st-failed'));[a.kind,a.detail,a.step].forEach(v=>add(tr,el('td',{class:'mono'},v)));});const und=new Set(SB.undeclared||[]);(SB.attempts||[]).forEach(a=>{const tr=add(tba,el('tr'));const u=a.declared===false||(a.declared===undefined&&und.has(a.target));add(tr,el('td')).appendChild(badge(u?'undeclared':'declared',u?'st-failed':'st-observed'));[a.kind==='dns'?'DNS lookup':'connection',a.target,''].forEach(v=>add(tr,el('td',{class:'mono'},v)));});if((SB.attempts_total||0)>(SB.attempts||[]).length)add(s,el('p',{class:'muted'},'+'+(SB.attempts_total-SB.attempts.length)+' more attempts in the JSON.'));add(s,el('p',{class:'muted'},'Evidence tier sandbox-observed: it adds to the static findings and never refutes them; a clean run proves nothing about what it did not reach.'));}}
s=sec('all rules');const t=add(s,el('table',{class:'grid'}));const h=add(add(t,el('thead')),el('tr'));['rule','outcome','detail'].forEach(x=>add(h,el('th',null,x)));
const tb=add(t,el('tbody'));D.rules.forEach(r=>{const tr=add(tb,el('tr'));add(tr,el('td',{class:'mono'},r.rule));add(tr,el('td',{class:'out-'+r.outcome},r.outcome));add(tr,el('td',null,r.title+': '+r.message));});
add(s,el('p',{class:'muted'},'policy '+D.policy.hash.slice(0,16)+' from '+D.policy.sources.map(x=>x.kind+(x.label?' '+x.label:'')).join(', ')));
s=sec('evidence areas');const t2=add(s,el('table',{class:'grid'}));const tb2=add(t2,el('tbody'));
Object.keys(C.evidence_areas).forEach(k=>{const tr=add(tb2,el('tr'));add(tr,el('td',null,k.replace(/_/g,' ')));const td=add(tr,el('td'));td.appendChild(badge(C.evidence_areas[k],'st-'+C.evidence_areas[k]));
  const o=P.operations[k];add(tr,el('td',{class:'muted'},o?o.note:''));});
s=sec('ownership');add(s,el('p',null,(P.ownership.owners.concat(P.ownership.declared_owners).join(', '))||'unknown'));add(s,el('p',{class:'muted'},P.ownership.note));
s=sec('provenance');add(s,el('p',null,P.provenance.sboms+' SBOM(s), '+(P.provenance.attestations||[]).length+' attestation(s)'));add(s,el('p',{class:'muted'},P.provenance.note||''));
ul=add(s,el('ul'));(P.subject.artifact_digests||[]).forEach(d=>add(ul,el('li',{class:'mono'},d.digest+' — '+d.verification)));
s=sec('data sources ('+(P.data.sources||[]).length+')');const t3=add(s,el('table',{class:'grid'}));const h3=add(add(t3,el('thead')),el('tr'));['source','kind','sensitivity','criticality','environment','trust'].forEach(x=>add(h3,el('th',null,x)));
const tb3=add(t3,el('tbody'));(P.data.sources||[]).forEach(d=>{const tr=add(tb3,el('tr'));[d.label,d.kind,d.sensitivity,d.criticality,d.environment,d.trust_domain].forEach(v=>add(tr,el('td',null,v)));});
const CC=P.change_control;if(CC){s=sec('change control (default branch)');add(s,el('p',{class:'muted'},'evidence: '+CC.state+(CC.source&&CC.source.label?' ('+CC.source.label+')':'')+'. '+(CC.note||'')));
  const tc=add(s,el('table',{class:'grid'}));const tbc=add(tc,el('tbody'));Object.keys(CC.checks).forEach(k=>{const tr=add(tbc,el('tr'));add(tr,el('td',null,k.replace(/_/g,' ')));
   const td=add(tr,el('td'));td.appendChild(badge(CC.checks[k].state,'st-'+(CC.checks[k].state==='met'?'observed':CC.checks[k].state==='not-met'?'failed':'unknown')));add(tr,el('td',null,CC.checks[k].detail));});
  (CC.notes||[]).forEach(n=>add(s,el('p',{class:'muted'},n)));}
const PK=P.package_sources;if(PK&&Object.keys(PK.ecosystems||{}).length){s=sec('package sources');add(s,el('p',{class:'muted'},PK.note||''));
  const tp=add(s,el('table',{class:'grid'}));const hp=add(add(tp,el('thead')),el('tr'));['ecosystem','state','sources'].forEach(x=>add(hp,el('th',null,x)));const tbp=add(tp,el('tbody'));
  Object.keys(PK.ecosystems).forEach(k=>{const v=PK.ecosystems[k];const tr=add(tbp,el('tr'));add(tr,el('td',null,k));add(tr,el('td',null,v.state));
   add(tr,el('td',null,(v.sources||[]).map(x=>x.url+' ('+x.kind+')').join(', ')||('not configured; default '+v.default_if_unconfigured)));});
  const A=PK.assessment||{};if((A.allowed_registries||[]).length)add(s,el('p',null,'outside the allowed registries: '+(((A.disallowed||[]).map(x=>x.url)).join(', ')||'none')));}
if((G.agent.servers||[]).length){s=sec('AI agent tooling ('+G.agent.servers.length+' MCP server(s))');add(s,el('p',{class:'muted'},'what an agent session in this repository is wired to; each server decides at runtime what its tools can do'));
  const t4=add(s,el('table',{class:'grid'}));const h4=add(add(t4,el('thead')),el('tr'));['server','transport','pinned','credentials','reaches'].forEach(x=>add(h4,el('th',null,x)));
  const tb4=add(t4,el('tbody'));G.agent.servers.forEach(v=>{const tr=add(tb4,el('tr'));[v.name,v.transport,v.pinned===null||v.pinned===undefined?'n/a':(v.pinned?'yes':'no'),(v.credentials||[]).join(', ')||'none',(v.reaches||[]).join(', ')||'-'].forEach(x=>add(tr,el('td',null,x)));});}
const AI=P.ai||{};if(AI.observed){
  s=sec('AI use');add(s,el('p',{class:'muted'},AI.note||''));const ul2=add(s,el('ul'));
  (AI.model_services||[]).forEach(v=>add(ul2,el('li',null,'AI service: '+v.label+' ('+v.evidence+'; reached by '+((v.reached_by||[]).join(', ')||'nothing')+')')));
  if(AI.agent_tool_servers)add(ul2,el('li',null,'AI agent tool servers: '+AI.agent_tool_servers));
  if((AI.instruction_files||[]).length)add(ul2,el('li',null,'agent instruction files: '+AI.instruction_files.join(', ')));
  add(ul2,el('li',null,'human oversight of agents: '+(AI.human_oversight||'unknown')));
  (AI.sensitive_data_with_ai||[]).forEach(x=>add(ul2,el('li',null,'reachable together: '+x.data+' ('+x.sensitivity+') and '+x.ai_service+', from '+(x.reached_by||[]).join(', '))));}
const AL=P.alignment||{};if(AI.observed&&Object.keys(AL.triggered||{}).length){s=sec('framework orientation (NIST AI RMF, AIGP)');add(s,el('p',{class:'muted'},AL.note));
  const t5=add(s,el('table',{class:'grid'}));const h5=add(add(t5,el('thead')),el('tr'));['rule','NIST AI RMF','AIGP domain'].forEach(x=>add(h5,el('th',null,x)));
  const tb5=add(t5,el('tbody'));Object.keys(AL.triggered).forEach(r=>{const tr=add(tb5,el('tr'));add(tr,el('td',{class:'mono'},r));
    const td=add(tr,el('td'));AL.triggered[r].nist_ai_rmf.forEach(id=>{const b=badge(id);b.title=(AL.subcategories||{})[id]||'';td.appendChild(b);});
    add(tr,el('td',null,AL.triggered[r].aigp.join('; ')));});}
if(P.remediation.length){s=sec('top remediation steps');const ol=add(s,el('ol'));P.remediation.forEach(r=>add(ol,el('li',null,r)));}
s=sec('unknowns');ul=add(s,el('ul'));P.unknowns.forEach(u=>add(ul,el('li',null,u.id+': '+u.detail)));
s=sec('limitations');ul=add(s,el('ul'));P.limitations.forEach(u=>add(ul,el('li',null,u)));
if(P.warnings.length){s=sec('warnings');ul=add(s,el('ul'));P.warnings.forEach(u=>add(ul,el('li',null,u)));}
s=sec('evidence receipts ('+P.evidence.length+')');ul=add(s,el('ul'));P.evidence.forEach(e=>{const li=add(ul,el('li'));li.appendChild(badge(e.state,'st-'+e.state));add(li,el('code',null,e.path+(e.line?':'+e.line:'')));li.appendChild(document.createTextNode(' '+e.area+': '+e.detail));});
"""


# ---------------------------------------------------------------------------
# Mermaid: a lightweight documentation view; JSON stays the evidence store.
# ---------------------------------------------------------------------------

_MERMAID_KIND_STYLE = {
    "application": "fill:#1f2937,stroke:#38e1ff,color:#e6e9f2",
    "workload": "fill:#1f2937,stroke:#38e1ff,color:#e6e9f2",
    "identity": "fill:#1f2937,stroke:#a78bfa,color:#e6e9f2",
    "database": "fill:#1f2937,stroke:#ffd166,color:#e6e9f2",
    "storage": "fill:#1f2937,stroke:#ffd166,color:#e6e9f2",
    "queue": "fill:#1f2937,stroke:#ffd166,color:#e6e9f2",
    "api": "fill:#1f2937,stroke:#62d98b,color:#e6e9f2",
    "external": "fill:#1f2937,stroke:#ff6b6b,color:#e6e9f2",
    "unknown": "fill:#1f2937,stroke:#6b7280,color:#e6e9f2,stroke-dasharray:4 3",
}
_TIER = {"provider-verified": 3, "observed": 2, "declared": 2, "inferred": 1, "unknown": 0, "refuted": -1}


def mermaid_text(text: str, limit: int = 60) -> str:
    """Escape a label for a quoted Mermaid string. Entity codes keep quotes,
    brackets, pipes, and angle brackets from closing the label or opening
    markup; control characters and newlines are removed."""
    from jh_core import safe_text
    t = " ".join(safe_text(text).split())
    if len(t) > limit:
        t = t[: limit - 1] + "…"
    out = []
    for ch in t:
        if ch in '"#<>|[]{}()`;':
            out.append("#%d;" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def render_mermaid(report: Dict[str, Any], max_nodes: int = 200) -> str:
    nodes = sorted(report["graph"]["nodes"], key=lambda n: n["id"])
    shown = nodes[:max_nodes]
    alias = {n["id"]: "n%d" % i for i, n in enumerate(shown, 1)}
    lines = ["%% jankhunt42 map (jankhunt.map.v1, scan " + str(report.get("scan_id", ""))[:12] + ")",
             "%% legend: solid = observed/declared/verified evidence; dashed = inferred/unknown; "
             "a path is a possibility, not proof of access",
             "flowchart LR"]
    for n in shown:
        label = "%s: %s" % (n["kind"], n["display_label"])
        lines.append('  %s["%s"]' % (alias[n["id"]], mermaid_text(label)))
    for e in sorted(report["graph"]["edges"], key=lambda x: x["id"]):
        if e["source"] not in alias or e["target"] not in alias or e["verification"] == "refuted":
            continue
        arrow = "-->" if _TIER.get(e["verification"], 0) >= 2 else "-.->"
        lines.append('  %s %s|"%s"| %s' % (alias[e["source"]], arrow,
                                           mermaid_text("%s/%s %s" % (e["kind"], e["capability"], e["verification"]), 40),
                                           alias[e["target"]]))
    for kind, style in _MERMAID_KIND_STYLE.items():
        members = [alias[n["id"]] for n in shown if n["kind"] == kind]
        if members:
            lines.append("  classDef %s %s" % (kind, style))
            lines.append("  class %s %s" % (",".join(members), kind))
    if len(nodes) > max_nodes:
        lines.append("%% truncated: " + str(len(nodes) - max_nodes) + " node(s) omitted; use --json or --html for the full graph")
    return "\n".join(lines)
