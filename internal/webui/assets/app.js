const $ = (id) => document.getElementById(id);
const state = { session: "", action: "", sensitive: false };

function text(value) { return value === null || value === undefined || value === "" ? "—" : String(value); }
function subject(event) { return event.file_path || event.command || [event.mcp_server, event.mcp_tool].filter(Boolean).join("/") || event.tool_name || event.session_id; }
function shortTime(value) { const date = new Date(value); return Number.isNaN(date.valueOf()) ? text(value) : date.toLocaleTimeString([], {hour:"2-digit", minute:"2-digit", second:"2-digit"}); }

async function json(url) {
  const response = await fetch(url, {headers:{Accept:"application/json"}});
  if (!response.ok) throw new Error(`Local API returned ${response.status}`);
  return response.json();
}

function renderSessions(sessions) {
  const list = $("session-list"); list.replaceChildren();
  if (!sessions.length) { const empty=document.createElement("div"); empty.className="empty"; empty.textContent="No sessions captured yet."; list.append(empty); return; }
  sessions.forEach((session) => {
    const button=document.createElement("button"); button.type="button"; button.className=`session${state.session===session.id?" active":""}`;
    const title=document.createElement("strong"); title.textContent=session.label || session.id;
    const meta=document.createElement("span"); meta.textContent=`${session.event_count} events · ${shortTime(session.started_at)}`;
    const health=document.createElement("span"); health.className=session.completeness==="partial"?"partial":""; health.textContent=session.completeness==="partial"?"Partial evidence":"Complete evidence";
    button.append(title,meta,health); button.addEventListener("click",()=>{state.session=session.id; $("clear-session").hidden=false; renderSessions(sessions); loadEvents();}); list.append(button);
  });
}

function renderEvents(events) {
  const body=$("event-list"); body.replaceChildren(); $("record-count").textContent=`${events.length} record${events.length===1?"":"s"}`; $("empty-state").hidden=events.length>0;
  events.forEach((event)=>{
    const row=document.createElement("tr");
    const time=document.createElement("td"); time.textContent=shortTime(event.timestamp); time.title=event.timestamp;
    const action=document.createElement("td"); const tag=document.createElement("code"); tag.className="tag"; tag.textContent=event.action_type; action.append(tag);
    const evidence=document.createElement("td"); evidence.className="subject"; evidence.textContent=subject(event); if(event.is_sensitive){const badge=document.createElement("span");badge.className="sensitive";badge.textContent="SENSITIVE";evidence.append(badge);}
    const outcome=document.createElement("td"); outcome.className=`status-${event.outcome||event.result_status||"unknown"}`; outcome.textContent=event.outcome||event.result_status||"unknown";
    const complete=document.createElement("td"); complete.textContent=event.completeness?.state||"legacy"; if(event.completeness?.state==="partial") complete.className="partial";
    row.append(time,action,evidence,outcome,complete); body.append(row);
  });
}

async function loadEvents() {
  const query=new URLSearchParams({limit:"500"}); if(state.session)query.set("session",state.session);if(state.action)query.set("action",state.action);if(state.sensitive)query.set("sensitive","true");
  try { renderEvents(await json(`/api/events?${query}`)); } catch(error) { $("empty-state").hidden=false; $("empty-state").textContent=error.message; }
}

async function load() {
  try {
    const data=await json("/api/overview"); const summary=data.summary;
    $("sessions-count").textContent=summary.today.sessions; $("actions-count").textContent=summary.today.actions; $("files-count").textContent=summary.today.files_changed; $("failures-count").textContent=summary.capture_failures;
    $("failures-count").className=summary.capture_failures?"status-error":"status-success"; $("version").textContent=`Secuarden ${data.version}`; $("updated").textContent=`Updated ${new Date(data.generated_at).toLocaleTimeString()}`; renderSessions(summary.recent_sessions);
  } catch(error) { $("updated").textContent=error.message; }
  await loadEvents();
}

$("action-filter").addEventListener("change",(event)=>{state.action=event.target.value;loadEvents();});
$("sensitive-filter").addEventListener("change",(event)=>{state.sensitive=event.target.checked;loadEvents();});
$("clear-session").addEventListener("click",()=>{state.session="";$("clear-session").hidden=true;load();});
$("refresh").addEventListener("click",load);
load();
