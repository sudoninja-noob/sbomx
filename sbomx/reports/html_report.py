"""Self-contained HTML CVE report.

Single HTML file, dark terminal aesthetic. The full report JSON is embedded
into the page; a small vanilla-JS layer renders a severity pie chart
(Chart.js via CDN), a sortable/filterable component table, expandable CVE
detail rows, and JSON/CSV export buttons.
"""
from __future__ import annotations

import json
from typing import List

from .. import __version__, TOOL_NAME
from ..core.component import Component
from .json_report import build_report

_TEMPLATE = """<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sbomx CVE Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
  :root {
    --bg:#0b0f14; --panel:#121822; --panel2:#0e141d; --border:#1e2a38;
    --text:#c8d6e5; --muted:#6b7b8c; --accent:#39d353;
    --crit:#ff4d4f; --high:#ff7a45; --med:#ffc53d; --low:#4dabf7; --unk:#6b7b8c;
    --mono: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text);
         font-family:var(--mono); font-size:13px; line-height:1.5; }
  header { padding:20px 24px; border-bottom:1px solid var(--border);
           display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;}
  h1 { margin:0; font-size:18px; color:var(--accent); letter-spacing:.5px; }
  h1 span { color:var(--muted); font-weight:normal; font-size:12px; }
  .meta { color:var(--muted); font-size:11px; }
  .wrap { padding:24px; max-width:1200px; margin:0 auto; }
  .cards { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:8px;
          padding:14px 18px; min-width:110px; flex:1; }
  .card .n { font-size:26px; font-weight:bold; }
  .card .l { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.5px;}
  .card.crit .n{color:var(--crit)} .card.high .n{color:var(--high)}
  .card.med .n{color:var(--med)} .card.low .n{color:var(--low)}
  .layout { display:flex; gap:20px; flex-wrap:wrap; margin-bottom:20px;}
  .chartbox { background:var(--panel); border:1px solid var(--border); border-radius:8px;
              padding:18px; width:320px; max-width:100%; }
  .controls { display:flex; gap:10px; margin:16px 0; flex-wrap:wrap; align-items:center;}
  input, select, button { font-family:var(--mono); font-size:12px; background:var(--panel2);
          color:var(--text); border:1px solid var(--border); border-radius:6px; padding:7px 10px; }
  button { cursor:pointer; } button:hover { border-color:var(--accent); color:var(--accent);}
  input#q { flex:1; min-width:180px; }
  table { width:100%; border-collapse:collapse; background:var(--panel); border-radius:8px; overflow:hidden;}
  th, td { text-align:left; padding:9px 12px; border-bottom:1px solid var(--border); }
  th { background:var(--panel2); cursor:pointer; user-select:none; font-size:11px;
       text-transform:uppercase; letter-spacing:.5px; color:var(--muted);}
  th:hover { color:var(--accent); }
  tr.comp { cursor:pointer; } tr.comp:hover td { background:#16202c; }
  .badge { display:inline-block; padding:1px 8px; border-radius:10px; font-size:11px; font-weight:bold;}
  .b-CRITICAL{background:var(--crit);color:#000} .b-HIGH{background:var(--high);color:#000}
  .b-MEDIUM{background:var(--med);color:#000} .b-LOW{background:var(--low);color:#000}
  .b-UNKNOWN,.b-NONE{background:var(--unk);color:#000}
  .detail { background:var(--panel2); }
  .detail td { padding:0; }
  .cve { padding:10px 16px; border-bottom:1px solid var(--border); }
  .cve:last-child{border-bottom:none}
  .cve a { color:var(--low); text-decoration:none; } .cve a:hover{text-decoration:underline;}
  .cve .desc { color:var(--muted); margin-top:4px; }
  .vex { color:var(--accent); font-size:11px; margin-left:6px;}
  .none { color:var(--muted); font-style:italic;}
  footer { color:var(--muted); font-size:11px; padding:16px 24px; border-top:1px solid var(--border);}
</style>
</head>
<body>
<header>
  <h1>sbomx <span>// CVE vulnerability report</span></h1>
  <div class="meta" id="meta"></div>
</header>
<div class="wrap">
  <div class="cards" id="cards"></div>
  <div class="layout">
    <div class="chartbox"><canvas id="pie"></canvas></div>
  </div>
  <div class="controls">
    <input id="q" placeholder="filter components / CVEs...">
    <select id="sev">
      <option value="">all severities</option>
      <option value="CRITICAL">critical</option>
      <option value="HIGH">high</option>
      <option value="MEDIUM">medium</option>
      <option value="LOW">low</option>
      <option value="vuln">vulnerable only</option>
    </select>
    <button onclick="exportJSON()">export JSON</button>
    <button onclick="exportCSV()">export CSV</button>
  </div>
  <table id="tbl">
    <thead><tr>
      <th data-k="name">component</th>
      <th data-k="version">version</th>
      <th data-k="type">type</th>
      <th data-k="maxsev">top severity</th>
      <th data-k="count">CVEs</th>
    </tr></thead>
    <tbody id="tbody"></tbody>
  </table>
</div>
<footer>Generated by __TOOL__ v__VERSION__ — self-contained report</footer>

<script>
const REPORT = __REPORT_JSON__;
const ORDER = {CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1,NONE:0,UNKNOWN:0};
let sortKey="maxsev", sortDir=-1;

function activeCves(c){ return (c.cves||[]).filter(v => v.vex_status !== "not_affected"); }
function enrich(c){
  const cves = activeCves(c);
  let max="NONE";
  cves.forEach(v=>{ if((ORDER[v.severity]||0)>(ORDER[max]||0)) max=v.severity||"UNKNOWN"; });
  c._max = cves.length? max : "NONE"; c._count = cves.length; return c;
}
REPORT.components.forEach(enrich);

function renderMeta(){
  document.getElementById("meta").innerHTML =
    `source: ${REPORT.sbom_source} &nbsp;|&nbsp; generated: ${REPORT.generated_at}`;
  const s=REPORT.summary;
  document.getElementById("cards").innerHTML = [
    ["components",s.total_components,""],["total CVEs",s.total_cves,""],
    ["critical",s.critical,"crit"],["high",s.high,"high"],
    ["medium",s.medium,"med"],["low",s.low,"low"]
  ].map(([l,n,c])=>`<div class="card ${c}"><div class="n">${n}</div><div class="l">${l}</div></div>`).join("");
}

function renderChart(){
  const s=REPORT.summary;
  new Chart(document.getElementById("pie"),{
    type:"doughnut",
    data:{labels:["Critical","High","Medium","Low","Unknown"],
      datasets:[{data:[s.critical,s.high,s.medium,s.low,s.unknown||0],
      backgroundColor:["#ff4d4f","#ff7a45","#ffc53d","#4dabf7","#6b7b8c"],borderWidth:0}]},
    options:{plugins:{legend:{labels:{color:"#c8d6e5",font:{family:"monospace"}}}}}
  });
}

function filtered(){
  const q=(document.getElementById("q").value||"").toLowerCase();
  const sev=document.getElementById("sev").value;
  let rows=REPORT.components.filter(c=>{
    if(sev==="vuln" && c._count===0) return false;
    if(sev && sev!=="vuln"){
      if(!activeCves(c).some(v=>v.severity===sev)) return false;
    }
    if(!q) return true;
    const hay=(c.name+" "+c.version+" "+(c.purl||"")+" "+
      activeCves(c).map(v=>v.id+" "+(v.description||"")).join(" ")).toLowerCase();
    return hay.includes(q);
  });
  rows.sort((a,b)=>{
    let av,bv;
    if(sortKey==="maxsev"){av=ORDER[a._max]||0;bv=ORDER[b._max]||0;}
    else if(sortKey==="count"){av=a._count;bv=b._count;}
    else {av=(a[sortKey]||"").toString().toLowerCase();bv=(b[sortKey]||"").toString().toLowerCase();}
    return av<bv?-sortDir:av>bv?sortDir:0;
  });
  return rows;
}

function renderTable(){
  const tb=document.getElementById("tbody"); tb.innerHTML="";
  filtered().forEach((c,i)=>{
    const tr=document.createElement("tr"); tr.className="comp";
    tr.innerHTML=`<td>${esc(c.name)}</td><td>${esc(c.version)}</td><td>${esc(c.type)}</td>
      <td><span class="badge b-${c._max}">${c._max}</span></td><td>${c._count}</td>`;
    const det=document.createElement("tr"); det.className="detail"; det.style.display="none";
    const cves=activeCves(c);
    det.innerHTML=`<td colspan="5">${cves.length? cves.map(v=>`
      <div class="cve"><span class="badge b-${v.severity||'UNKNOWN'}">${v.severity||'UNKNOWN'}</span>
      <a href="${v.nvd_url||'#'}" target="_blank" rel="noopener">${esc(v.id)}</a>
      ${v.cvss_score!=null?` — CVSS ${v.cvss_score}`:''}
      ${v.vex_status?`<span class="vex">[VEX: ${esc(v.vex_status)}]</span>`:''}
      <div class="desc">${esc(v.description||'')}</div></div>`).join("")
      : '<div class="cve none">no known vulnerabilities</div>'}</td>`;
    tr.onclick=()=>{det.style.display = det.style.display==="none"?"":"none";};
    tb.appendChild(tr); tb.appendChild(det);
  });
}

function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}

document.querySelectorAll("th").forEach(th=>th.onclick=()=>{
  const k=th.dataset.k; if(sortKey===k) sortDir*=-1; else {sortKey=k; sortDir=1;} renderTable();
});
document.getElementById("q").oninput=renderTable;
document.getElementById("sev").onchange=renderTable;

function download(name,text,type){
  const b=new Blob([text],{type}); const a=document.createElement("a");
  a.href=URL.createObjectURL(b); a.download=name; a.click();
}
function exportJSON(){ download("cve-report.json",JSON.stringify(REPORT,null,2),"application/json"); }
function exportCSV(){
  const rows=[["component","version","cve","severity","cvss","vex"]];
  REPORT.components.forEach(c=>activeCves(c).forEach(v=>
    rows.push([c.name,c.version,v.id,v.severity,v.cvss_score??"",v.vex_status||""])));
  download("cve-report.csv",rows.map(r=>r.map(x=>`"${String(x).replace(/"/g,'""')}"`).join(",")).join("\\n"),"text/csv");
}

renderMeta(); renderChart(); renderTable();
</script>
</body>
</html>
"""


def build_html(components: List[Component], sbom_source: str = "unknown") -> str:
    report = build_report(components, sbom_source)
    return (
        _TEMPLATE.replace("__REPORT_JSON__", json.dumps(report))
        .replace("__TOOL__", TOOL_NAME)
        .replace("__VERSION__", __version__)
    )


def write_html_report(
    components: List[Component], output: str, sbom_source: str = "unknown"
) -> str:
    html = build_html(components, sbom_source)
    with open(output, "w", encoding="utf-8") as fh:
        fh.write(html)
    return output
