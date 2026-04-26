package dashboard

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
)

// Server serves the audit log as a real-time web dashboard.
type Server struct {
	auditPath string
}

func New(auditPath string) *Server {
	return &Server{auditPath: auditPath}
}

// Start listens on addr and blocks. addr is "host:port".
func (s *Server) Start(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.serveIndex)
	mux.HandleFunc("/api/events", s.serveEvents)
	fmt.Printf("\n  mcpredict dashboard → http://%s\n\n", addr)
	return http.ListenAndServe(addr, mux)
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, dashboardHTML)
}

func (s *Server) serveEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	limitStr := r.URL.Query().Get("limit")
	limit := 500
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 5000 {
		limit = l
	}

	events, err := s.readEvents(limit)
	if err != nil && !os.IsNotExist(err) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Sort: newest first
	sort.Slice(events, func(i, j int) bool {
		return events[i]["ts"].(string) > events[j]["ts"].(string)
	})

	json.NewEncoder(w).Encode(events)
}

func (s *Server) readEvents(limit int) ([]map[string]any, error) {
	f, err := os.Open(s.auditPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []map[string]any{}, nil
		}
		return nil, err
	}
	defer f.Close()

	var events []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)

	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry["ts"] == nil {
			entry["ts"] = ""
		}
		events = append(events, entry)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	if len(events) > limit {
		events = events[len(events)-limit:]
	}
	return events, nil
}

// dashboardHTML is the embedded single-page dashboard.
// It polls /api/events every 2 seconds and renders the audit table.
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>mcpredict — dashboard</title>
<style>
:root{
  --bg:#0d1117;--card:#161b22;--hover:#1c2128;--border:#30363d;
  --text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;
  --red:#f85149;--red-bg:#2d1517;--red-border:#6e2e2e;
  --yellow:#e3b341;--yellow-bg:#272115;--yellow-border:#6e5225;
  --green:#3fb950;--green-bg:#0d2818;--green-border:#1f5c2e;
  --purple:#d2a8ff;--purple-bg:#1e1535;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,monospace;font-size:14px}
/* ── Header ── */
header{
  background:var(--card);border-bottom:1px solid var(--border);
  padding:14px 24px;display:flex;align-items:center;justify-content:space-between;
  position:sticky;top:0;z-index:10;
}
.logo{font-size:1rem;font-weight:700;letter-spacing:-0.5px}
.logo span{color:var(--accent)}
.live-badge{
  display:flex;align-items:center;gap:6px;font-size:.75rem;color:var(--muted);
}
.live-dot{
  width:8px;height:8px;border-radius:50%;background:var(--green);
  box-shadow:0 0 6px var(--green);animation:blink 2s infinite;
}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
/* ── Stats ── */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;padding:20px 24px 0}
.stat{
  background:var(--card);border:1px solid var(--border);border-radius:8px;
  padding:14px 18px;position:relative;overflow:hidden;
}
.stat::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px}
.stat.s-total::before{background:var(--accent)}
.stat.s-block::before{background:var(--red)}
.stat.s-warn::before{background:var(--yellow)}
.stat.s-allow::before{background:var(--green)}
.stat .lbl{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;font-weight:600}
.stat .val{
  font-size:1.9rem;font-weight:800;margin-top:3px;
  font-variant-numeric:tabular-nums;transition:color .3s;
}
.stat.s-block .val{color:var(--red)}
.stat.s-warn  .val{color:var(--yellow)}
.stat.s-allow .val{color:var(--green)}
.stat.s-total .val{color:var(--accent)}
.stat .sub{font-size:.72rem;color:var(--muted);margin-top:2px}
/* ── Controls ── */
.controls{
  padding:16px 24px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;
}
.btn{
  background:var(--card);border:1px solid var(--border);color:var(--muted);
  padding:5px 14px;border-radius:6px;cursor:pointer;font-size:.8rem;font-weight:500;
  transition:all .15s;line-height:1.6;
}
.btn:hover{background:var(--hover);color:var(--text)}
.btn.active{color:var(--text);border-color:var(--accent)}
.btn.f-block.active{color:var(--red);border-color:var(--red);background:var(--red-bg)}
.btn.f-warn.active{color:var(--yellow);border-color:var(--yellow);background:var(--yellow-bg)}
.btn.f-allow.active{color:var(--green);border-color:var(--green);background:var(--green-bg)}
.search{
  margin-left:auto;background:var(--card);border:1px solid var(--border);
  color:var(--text);padding:5px 14px;border-radius:6px;font-size:.82rem;width:280px;
}
.search::placeholder{color:var(--muted)}
.search:focus{outline:none;border-color:var(--accent)}
/* ── Table ── */
.tbl-wrap{padding:0 24px 32px;overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{
  text-align:left;padding:9px 12px;color:var(--muted);font-size:.7rem;
  font-weight:600;text-transform:uppercase;letter-spacing:.6px;
  border-bottom:1px solid var(--border);white-space:nowrap;
}
tr{border-bottom:1px solid var(--border);transition:background .1s}
tr:hover{background:var(--hover)}
tr.new{animation:slidein .35s ease-out}
@keyframes slidein{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
td{padding:9px 12px;vertical-align:top}
.ts{color:var(--muted);font-family:monospace;font-size:.78rem;white-space:nowrap}
.evt-type{color:var(--muted);font-size:.78rem;white-space:nowrap}
.sid{color:var(--muted);font-family:monospace;font-size:.75rem;white-space:nowrap}
.tool-tag{
  display:inline-block;background:var(--hover);border:1px solid var(--border);
  padding:2px 9px;border-radius:4px;font-family:monospace;font-size:.78rem;white-space:nowrap;
}
.badge{
  display:inline-block;padding:2px 10px;border-radius:10px;
  font-size:.7rem;font-weight:700;letter-spacing:.5px;text-transform:uppercase;white-space:nowrap;
}
.b-block{background:var(--red-bg);color:var(--red);border:1px solid var(--red-border)}
.b-warn{background:var(--yellow-bg);color:var(--yellow);border:1px solid var(--yellow-border)}
.b-allow{background:var(--green-bg);color:var(--green);border:1px solid var(--green-border)}
.reasons{display:flex;flex-wrap:wrap;gap:3px;max-width:480px}
.rtag{
  background:var(--hover);border:1px solid var(--border);
  padding:1px 7px;border-radius:4px;font-family:monospace;font-size:.72rem;color:var(--muted);
}
.rtag.policy{border-color:#3c4f6b;color:#79b8ff}
.rtag.dlp{border-color:#6e2e2e;color:#f97583}
.rtag.intent{border-color:#3d3314;color:#e3b341}
.rtag.bypass{border-color:#3e1e5e;color:var(--purple)}
.rtag.injection{border-color:#2e3e1e;color:#73c95e}
/* ── Empty / loading ── */
.empty{text-align:center;padding:60px 24px;color:var(--muted)}
.empty .ico{font-size:2.4rem;margin-bottom:12px}
.empty code{background:var(--card);padding:2px 8px;border-radius:4px;font-size:.82rem}
/* ── Scrollbar ── */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
</style>
</head>
<body>
<header>
  <div class="logo">mc<span>predict</span> <span style="color:var(--border);font-weight:300">|</span> <span style="color:var(--muted);font-size:.85rem;font-weight:400">security dashboard</span></div>
  <div class="live-badge">
    <div class="live-dot" id="dot"></div>
    <span id="ts">connecting…</span>
  </div>
</header>

<div class="stats">
  <div class="stat s-total"><div class="lbl">Total Events</div><div class="val" id="sTotal">0</div><div class="sub">all tool calls</div></div>
  <div class="stat s-block"><div class="lbl">Blocked</div><div class="val" id="sBlock">0</div><div class="sub">denied by guardrail</div></div>
  <div class="stat s-warn"><div class="lbl">Warned</div><div class="val" id="sWarn">0</div><div class="sub">suspicious, allowed</div></div>
  <div class="stat s-allow"><div class="lbl">Allowed</div><div class="val" id="sAllow">0</div><div class="sub">clean pass-through</div></div>
</div>

<div class="controls">
  <button class="btn active" id="btnAll"   onclick="filt('all',this)">All</button>
  <button class="btn f-block" id="btnBlock" onclick="filt('block',this)">Block</button>
  <button class="btn f-warn"  id="btnWarn"  onclick="filt('warn',this)">Warn</button>
  <button class="btn f-allow" id="btnAllow" onclick="filt('allow',this)">Allow</button>
  <input class="search" id="q" type="search" placeholder="Search tool, session, reason…" oninput="render()">
</div>

<div class="tbl-wrap">
  <table>
    <thead>
      <tr>
        <th>Time</th><th>Event</th><th>Session</th><th>Tool</th>
        <th>Verdict</th><th>Detections</th>
      </tr>
    </thead>
    <tbody id="tbody"></tbody>
  </table>
  <div id="empty" class="empty" style="display:none">
    <div class="ico">🛡</div>
    <div>No audit events yet.</div>
    <div style="margin-top:8px;font-size:.82rem">Run a scenario: <code>make scenario1</code> or install the hook and use Claude Code.</div>
  </div>
</div>

<script>
var events=[], prevLen=0, curFilt='all';

function filt(v,btn){
  curFilt=v;
  document.querySelectorAll('.btn').forEach(function(b){b.classList.remove('active')});
  btn.classList.add('active');
  render();
}

function cls(verdict){
  return verdict==='block'?'b-block':verdict==='warn'?'b-warn':'b-allow';
}

function tagClass(prefix){
  var m={'policy':'policy','dlp':'dlp','intent':'intent','bypass':'bypass','injection':'injection'};
  return m[prefix]||'';
}

function buildTags(reason, rules){
  if(!reason&&(!rules||!rules.length)) return '<span style="color:var(--border)">—</span>';
  var html='<div class="reasons">';
  var seen={};
  // Show rules_matched first (most specific)
  if(rules&&rules.length){
    rules.forEach(function(r){
      if(seen[r]) return; seen[r]=1;
      var pre=r.split(':')[0];
      html+='<span class="rtag '+tagClass(pre)+'" title="'+r+'">'+r+'</span>';
    });
  }
  // Parse reason string for additional context
  if(reason){
    reason.split('; ').forEach(function(part){
      var pre=part.split('[')[0].split(':')[0].replace(/^(policy|DLP|intent|bypass|injection).*$/,'$1').toLowerCase();
      var short=part.length>55?part.substring(0,55)+'…':part;
      // Only add if not already covered by rules_matched
      var key=pre+':'+part.substring(0,20);
      if(!seen[key]){
        seen[key]=1;
        html+='<span class="rtag '+tagClass(pre)+'" title="'+part+'">'+short+'</span>';
      }
    });
  }
  html+='</div>';
  return html;
}

function render(){
  var q=(document.getElementById('q').value||'').toLowerCase();
  var filtered=events.filter(function(e){
    if(curFilt!=='all'&&e.verdict!==curFilt) return false;
    if(q){
      var hay=[e.tool||'',e.verdict||'',e.reason||'',e.session_id||'',
               (e.rules_matched||[]).join(' '),e.event||''].join(' ').toLowerCase();
      if(hay.indexOf(q)<0) return false;
    }
    return true;
  });
  var tbody=document.getElementById('tbody');
  var empty=document.getElementById('empty');
  if(!filtered.length){tbody.innerHTML='';empty.style.display='block';return;}
  empty.style.display='none';
  var newCount=events.length-prevLen;
  tbody.innerHTML=filtered.slice(0,300).map(function(e,i){
    var isNew=(i<newCount&&prevLen>0);
    var ts=e.ts?new Date(e.ts).toLocaleTimeString('en-US',{hour12:false}):'—';
    var sid=(e.session_id||'—').substring(0,10);
    return '<tr class="'+(isNew?'new':'')+'">'+
      '<td class="ts">'+ts+'</td>'+
      '<td class="evt-type">'+(e.event||'—')+'</td>'+
      '<td class="sid">'+sid+'</td>'+
      '<td><span class="tool-tag">'+(e.tool||'—')+'</span></td>'+
      '<td><span class="badge '+cls(e.verdict)+'">'+(e.verdict||'—')+'</span></td>'+
      '<td>'+buildTags(e.reason,e.rules_matched)+'</td>'+
      '</tr>';
  }).join('');
}

function updateStats(){
  var b=events.filter(function(e){return e.verdict==='block'}).length;
  var w=events.filter(function(e){return e.verdict==='warn'}).length;
  var a=events.filter(function(e){return e.verdict==='allow'}).length;
  document.getElementById('sTotal').textContent=events.length;
  document.getElementById('sBlock').textContent=b;
  document.getElementById('sWarn').textContent=w;
  document.getElementById('sAllow').textContent=a;
}

async function poll(){
  try{
    var r=await fetch('/api/events');
    if(!r.ok) throw new Error('http '+r.status);
    var data=await r.json();
    if(data.length!==events.length){
      prevLen=events.length;
      events=data;
      updateStats();
      render();
    }
    document.getElementById('ts').textContent='updated '+new Date().toLocaleTimeString('en-US',{hour12:false});
    document.getElementById('dot').style.background='var(--green)';
    document.getElementById('dot').style.boxShadow='0 0 6px var(--green)';
  }catch(e){
    document.getElementById('dot').style.background='var(--red)';
    document.getElementById('dot').style.boxShadow='0 0 6px var(--red)';
    document.getElementById('ts').textContent='error — retrying';
  }
}

poll();
setInterval(poll,2000);
</script>
</body>
</html>`
