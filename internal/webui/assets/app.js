const $ = (id) => document.getElementById(id);
const state = {session:"", action:"", sensitive:false, agent:"", file:"", command:"", failures:false, changes:false, non_pre:false, since:"", until:"", label:""};
let recentSessions = [];
let eventLoadID = 0;
let todayBounds = {since:"", until:""};

function text(value) { return value === null || value === undefined || value === "" ? "—" : String(value); }
function subject(event) { return event.file_path || event.command || [event.mcp_server, event.mcp_tool].filter(Boolean).join("/") || event.tool_name || event.session_id; }
function shortTime(value) { const date = new Date(value); return Number.isNaN(date.valueOf()) ? text(value) : date.toLocaleTimeString([], {hour:"2-digit", minute:"2-digit", second:"2-digit"}); }
function setText(id, value) { $(id).textContent = text(value); }

async function json(url) {
  const response = await fetch(url, {headers:{Accept:"application/json"}});
  if (!response.ok) throw new Error(`Local API returned ${response.status}`);
  return response.json();
}

function applyDrill(label, filters) {
  Object.assign(state, {session:"",action:"",sensitive:false,agent:"",file:"",command:"",failures:false,changes:false,non_pre:false,since:todayBounds.since,until:todayBounds.until,label}, filters);
  $("action-filter").value=state.action;
  $("sensitive-filter").checked=state.sensitive;
  renderSessions(recentSessions);
  loadEvents();
  $("evidence-stream").scrollIntoView({behavior:"smooth",block:"start"});
}

function makeLink(label, count, click, className="") {
  const button=document.createElement("button"); button.type="button"; button.className=`data-link ${className}`;
  const title=document.createElement("span"); title.textContent=label;
  const value=document.createElement("strong"); value.textContent=count;
  button.append(title,value); button.addEventListener("click",click);
  return button;
}

function renderList(id, items, click, empty="No records today") {
  const list=$(id); list.replaceChildren();
  if (!items.length) { const message=document.createElement("span"); message.className="list-empty"; message.textContent=empty; list.append(message); return; }
  items.forEach(item=>list.append(makeLink(item.label,item.count,()=>click(item))));
}

function renderDashboard(summary) {
  const d=summary.dashboard;
  setText("sessions-count",summary.today.sessions); setText("session-total",summary.today.sessions);
  setText("actions-count",summary.today.actions); setText("files-count",summary.today.files_changed);
  setText("failures-count",summary.capture_failures); $("failures-count").className=summary.capture_failures?"status-error":"status-success";
  setText("changed-count",summary.today.files_changed);
  setText("command-count",summary.today.commands); setText("command-passed",d.command_passed); setText("command-failed",d.command_failed); setText("command-unknown",d.command_unknown);
  setText("error-count",d.errors); setText("blocked-count",d.blocked); setText("rejected-count",d.rejected);
  setText("partial-count",d.partial); setText("sensitive-count",d.sensitive);

  const activity=$("activity-bars"); activity.replaceChildren();
  const top=d.activity.slice(0,5); const max=Math.max(1,...top.map(item=>item.count));
  if (!top.length) activity.textContent="No records today";
  top.forEach(item=>{
    const button=document.createElement("button"); button.type="button"; button.className="bar-row";
    const label=document.createElement("span"); label.textContent=item.label.replaceAll("_"," ");
    const track=document.createElement("span"); track.className="bar-track";
    const fill=document.createElement("span"); fill.className="bar-fill"; fill.style.width=`${Math.max(2,item.count/max*100)}%`; track.append(fill);
    const count=document.createElement("strong"); count.textContent=item.count;
    button.append(label,track,count);
    button.addEventListener("click",()=>applyDrill(`${item.label.replaceAll("_"," ")} · today`,{action:item.label}));
    activity.append(button);
  });
  $("activity-note").textContent="Counts include each captured hook record.";
  renderList("agent-list",d.agents,item=>applyDrill(`${item.label} · today`,{agent:item.label}),"No agents today");
  renderList("changed-list",d.changed_files,item=>applyDrill(`${item.label} · today`,{file:item.label,changes:true}));
  renderList("command-list",d.top_commands,item=>applyDrill(`${item.label} · today`,{action:"command_exec",command:item.label,non_pre:true}));

  const timeline=$("timeline-bars"); timeline.replaceChildren();
  const peak=Math.max(1,...d.timeline.map(item=>item.count));
  d.timeline.forEach(item=>{
    const button=document.createElement("button"); button.type="button"; button.className="hour";
    button.style.setProperty("--height",`${Math.max(item.count?5:2,item.count/peak*100)}%`);
    button.title=`${item.since} · ${item.count} events`; button.setAttribute("aria-label",button.title);
    button.addEventListener("click",()=>{
      applyDrill(`${item.label}:00 · today`,{since:item.since,until:item.until});
    });
    timeline.append(button);
  });
  const peek=$("session-peek"); peek.replaceChildren();
  const sessions=summary.recent_sessions.slice(0,3);
  if (!sessions.length) peek.textContent="No recent sessions";
  sessions.forEach(session=>peek.append(makeLink(session.label||session.id,session.event_count,()=>selectSession(session.id))));
}

function selectSession(id) {
  Object.assign(state,{session:id,action:"",sensitive:false,agent:"",file:"",command:"",failures:false,changes:false,non_pre:false,since:"",until:"",label:"Session"});
  $("action-filter").value=""; $("sensitive-filter").checked=false;
  renderSessions(recentSessions); loadEvents();
  $("evidence-stream").scrollIntoView({behavior:"smooth",block:"start"});
}

function renderSessions(sessions) {
  const list=$("session-list"); list.replaceChildren();
  if (!sessions.length) { const empty=document.createElement("div"); empty.className="empty"; empty.textContent="No sessions captured yet."; list.append(empty); return; }
  sessions.forEach((session) => {
    const button=document.createElement("button"); button.type="button"; button.className=`session${state.session===session.id?" active":""}`;
    const title=document.createElement("strong"); title.textContent=session.label || session.id;
    const meta=document.createElement("span"); meta.textContent=`${session.agent} · ${session.event_count} events · ${shortTime(session.started_at)}`;
    const health=document.createElement("span"); health.className=session.completeness==="partial"?"partial":""; health.textContent=session.completeness==="partial"?"Partial evidence":"Complete evidence";
    button.append(title,meta,health); button.addEventListener("click",()=>selectSession(session.id)); list.append(button);
  });
}

function renderEvents(events) {
  const body=$("event-list"); body.replaceChildren();
  $("record-count").textContent=`${events.length}${events.length===500?" latest":""} record${events.length===1?"":"s"}`;
  $("empty-state").hidden=events.length>0;
  if (!events.length) $("empty-state").textContent="No evidence matches these filters.";
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
  const requestID = ++eventLoadID;
  const query=new URLSearchParams({limit:"500"});
  for (const key of ["session","action","agent","file","command","since","until"]) if(state[key]) query.set(key,state[key]);
  if(state.sensitive) query.set("sensitive","true");
  if(state.failures) query.set("failures","true");
  if(state.changes) query.set("changes","true");
  if(state.non_pre) query.set("non_pre","true");
  $("active-filter").hidden=!state.label; $("active-filter").textContent=state.label;
  $("clear-session").hidden=!state.label;
  try { const events=await json(`/api/events?${query}`); if(requestID===eventLoadID) renderEvents(events); }
  catch(error) { if(requestID!==eventLoadID) return; $("event-list").replaceChildren(); $("record-count").textContent="0 records"; $("empty-state").hidden=false; $("empty-state").textContent=error.message; }
}

async function load() {
  try {
    const data=await json("/api/overview"); const summary=data.summary;
    const now=new Date(data.generated_at); todayBounds={since:data.period_start,until:data.period_end};
    recentSessions=summary.recent_sessions;
    $("version").textContent=`Secuarden ${data.version}`;
    $("updated").textContent=`Updated ${now.toLocaleTimeString()}`;
    renderDashboard(summary); renderSessions(recentSessions);
  } catch(error) { $("updated").textContent=error.message; }
  await loadEvents();
}

$("action-filter").addEventListener("change",event=>{Object.assign(state,{action:event.target.value,agent:"",file:"",command:"",failures:false,changes:false,non_pre:false,since:"",until:""});state.label=state.action?`Action: ${state.action}`:state.session?"Session":"";loadEvents();});
$("sensitive-filter").addEventListener("change",event=>{Object.assign(state,{sensitive:event.target.checked,agent:"",file:"",command:"",failures:false,changes:false,non_pre:false,since:"",until:""});state.label=state.sensitive?"Sensitive records":state.action?`Action: ${state.action}`:state.session?"Session":"";loadEvents();});
$("clear-session").addEventListener("click",()=>{Object.assign(state,{session:"",action:"",sensitive:false,agent:"",file:"",command:"",failures:false,changes:false,non_pre:false,since:"",until:"",label:""});$("action-filter").value="";$("sensitive-filter").checked=false;renderSessions(recentSessions);loadEvents();});
$("refresh").addEventListener("click",load);
document.querySelectorAll("[data-drill]").forEach(button=>button.addEventListener("click",()=>{
  switch(button.dataset.drill) {
    case "all": applyDrill("All events · today",{}); break;
    case "changes": applyDrill("Code changes · today",{changes:true}); break;
    case "commands": applyDrill("Commands · today",{action:"command_exec",non_pre:true}); break;
    case "errors": applyDrill("Errors and blocks · today",{failures:true}); break;
    case "sessions": $("session-list").scrollIntoView({behavior:"smooth",block:"start"}); break;
  }
}));
load();
