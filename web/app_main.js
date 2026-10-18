<script>
"use strict";
/* app_main.js — ASMB4 iKVM SPA against bmcweb's /api/* JSON.
 * KVM over ws://host/ws -> adviserd (IVTP). Flash via /fw/* -> stock flasher. */
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

/* ---------- session ---------- */
function sessionDead(){
  document.cookie="IKVMSESS=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/";
  document.cookie="SessionCookie=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/";
  $("#app").style.display="none";$("#login").style.display="flex";
  $("#lerr").textContent="session expired — sign in again";
}
async function api(path,body){
  const r=await fetch(path,body?{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body}:{});
  if(r.status===401){sessionDead();throw new Error("session expired");}
  if(!r.ok)throw new Error("HTTP "+r.status);
  return r.json();
}
/* ---- legacy goahead proxy (authenticated) ----
 * ga(path)         GET  /api/ga?p=<encoded /rpc/...>   -> raw text/binary
 * gapost(path,obj) POST /api/ga  body: path\nurlencoded -> raw text */
async function ga(path){
  const r=await fetch("/api/ga?p="+encodeURIComponent(path));
  if(r.status===401){sessionDead();throw new Error("session expired");}
  if(!r.ok)throw new Error("HTTP "+r.status);
  return r;
}
async function gaText(path){return (await ga(path)).text();}
async function gapost(path,params){
  const body=Object.entries(params||{}).map(([k,v])=>k+"="+encodeURIComponent(v)).join("&");
  const r=await fetch("/api/ga",{method:"POST",body:path+"\n"+body});
  if(r.status===401){sessionDead();throw new Error("session expired");}
  if(!r.ok)throw new Error("HTTP "+r.status);
  return r.text();
}
/* WEBVAR reply: 'NAME' : 'val' inside WEBVAR_JSONVAR_X = { ... } */
function wvParse(txt){
  const i=txt.indexOf("{"),j=txt.lastIndexOf("}");
  if(i<0||j<=i)throw new Error("no WEBVAR payload");
  const o=new Function("return("+txt.slice(i,j+1)+")")();
  const st=o.HAPI_STATUS??o.HAPISTATUS;
  const tables={};
  for(const k in o)if(/^WEBVAR_STRUCTNAME_/.test(k)&&Array.isArray(o[k]))
    tables[k.replace("WEBVAR_STRUCTNAME_","")]=o[k].filter(r=>r&&typeof r==="object"&&Object.keys(r).length);
  return{st,tables,raw:o};
}
function wvHtml(txt){
  let p;try{p=wvParse(txt);}catch(e){return`<pre class="mono" style="white-space:pre-wrap">${esc(txt.slice(0,4000))}</pre>`;}
  let h="";
  if(p.st!=null&&p.st!==0)h+=`<p class="err">HAPI_STATUS: ${esc(p.st)}</p>`;
  let any=false;
  for(const[name,rows]of Object.entries(p.tables)){
    if(!rows.length)continue;any=true;
    const cols=[...new Set(rows.flatMap(r=>Object.keys(r)))];
    h+=`<h2 style="margin:14px 0 6px;font-size:11px;color:var(--dim);text-transform:uppercase">${esc(name)}</h2>
      <table><tr>${cols.map(c=>`<th>${esc(c)}</th>`).join("")}</tr>`+
      rows.map(r=>`<tr>${cols.map(c=>`<td>${esc(r[c]??"")}</td>`).join("")}</tr>`).join("")+"</table>";
  }
  if(!any&&!h)h="<p class='dim'>empty result</p>";
  return h;
}
async function loadRpcInto(el,path){
  el.innerHTML="<p class='dim'>loading…</p>";
  try{el.innerHTML=wvHtml(await gaText(path));}catch(e){report(el,e);}
}
const stEl=id=>{const e=$(id);return m=>{e.textContent=m;setTimeout(()=>{if(e.textContent===m)e.textContent="";},6000);};};

/* ---------- auth ---------- */
$("#lform").addEventListener("submit",async e=>{
  e.preventDefault();$("#lerr").textContent="";
  try{
    await api("/api/login",`u=${encodeURIComponent($("#u").value)}&p=${encodeURIComponent($("#p").value)}`);
    enterApp();
  }catch(x){$("#lerr").textContent=x.message==="session expired"?"invalid username or password":x.message;}
});
function enterApp(){
  $("#login").style.display="none";$("#app").style.display="flex";
  $("#hd-user").textContent=$("#u").value||"admin";
  loadDash();
}
$("#logout").onclick=async()=>{client?.disconnect();try{await api("/api/logout")}catch(e){}location.reload();};
if(document.cookie.includes("IKVMSESS"))enterApp();

/* ---------- nav ---------- */
const LOADERS={};
$$("nav a[data-v]").forEach(a=>a.onclick=()=>{
  $$("nav a").forEach(x=>x.classList.remove("on"));a.classList.add("on");
  $$(".view").forEach(v=>v.classList.remove("on"));$("#v-"+a.dataset.v).classList.add("on");
  LOADERS[a.dataset.v]?.();
});
const report=(el,e)=>{el.innerHTML=`<p class="err">${esc(e.message)}</p>`;};

/* ---------- sensors ---------- */
const STYPE={1:"Temp",2:"Voltage",3:"Current",4:"Fan",5:"PhysSec",7:"CPU",8:"Memory",9:"DrvBay",12:"OEM"};
function sensRow(r){
  const val=r.raw<0?"n/a":(r.mv/1000).toFixed(r.mv%1000?2:0)+" "+(r.u||"");
  const cls=r.evt?(r.evt&0x40?"err":"warn"):"ok";
  const lbl=r.evt?(r.evt&0x40?"ALERT":"WARN"):"OK";
  return`<tr><td>${esc(r.name||"sensor "+r.n)}</td><td>${STYPE[r.type]||r.type}</td>
   <td>${val}</td><td>${r.raw<0?"":r.raw}</td><td><span class="badge ${cls}">${lbl}</span></td></tr>`;
}
async function loadSensors(el,limit){
  el.innerHTML="<p class='dim'>loading…</p>";
  try{
    const rows=await api("/api/sensors");
    const list=limit?rows.slice(0,limit):rows;
    el.innerHTML=`<table><tr><th>Sensor</th><th>Type</th><th>Reading</th><th>Raw</th><th>State</th></tr>`+
      list.map(sensRow).join("")+"</table>";
  }catch(e){report(el,e);}
}
$("#sens-refresh").onclick=()=>loadSensors($("#top-sensors"),8);
$("#sens-refresh2").onclick=()=>loadSensors($("#sensor-table"));

/* ---------- dashboard ---------- */
async function loadDash(){
  try{
    const hs=await api("/api/host");
    const on=hs.power==="on";
    $("#c-pwr").textContent=on?"ON":"OFF";
    $("#c-pwr").className="v "+(on?"ok":"off");
    const hb=$("#hd-pwr");hb.textContent="HOST "+(on?"ON":"OFF");
    hb.className="badge "+(on?"ok":"err");
  }catch(e){$("#c-pwr").textContent="?";}
  try{
    const s=await api("/api/sys");
    $("#c-fw").textContent=s.fw||"—";
    $("#nav-sub").textContent=`AST2050 · FW ${s.fw||"?"}`;
    $("#c-board").textContent="KCMA-D8 / ASMB4";
    $("#hd-board").textContent="ASMB4-iKVM";
    if(s.fru_size)$("#c-build").textContent=`FRU ${s.fru_size}B`;
  }catch(e){}
  loadSensors($("#top-sensors"),8);
}
async function power(cmd){
  const names={0:"power off (force)",1:"power on",2:"power cycle",3:"reset",5:"graceful shutdown"};
  if(!confirm(`Really ${names[cmd]} the host?`))return;
  try{
    const r=await api("/api/power","cmd="+cmd);
    alert(r.ok?`${names[cmd]} sent`:"command failed");
    setTimeout(loadDash,3000);
  }catch(e){alert("power cmd failed: "+e.message);}
}
$$("[data-pwr]").forEach(b=>b.onclick=()=>power(b.dataset.pwr));
$$("[data-idl]").forEach(b=>b.onclick=async()=>{
  try{await api("/api/identify","sec="+b.dataset.idl);
    $("#idl-st").textContent=b.dataset.idl==="0"?"identify off":"identify on";}
  catch(e){$("#idl-st").textContent=e.message;}
});

/* ---------- SEL ---------- */
async function loadSEL(){
  const el=$("#sel-table");el.innerHTML="<p class='dim'>loading…</p>";
  try{
    const d=await api("/api/sel");
    if(!d.events.length){el.innerHTML="<p class='dim'>Event log empty.</p>";return;}
    el.innerHTML=`<table><tr><th>#</th><th>Timestamp</th><th>SelType</th><th>Sensor#</th><th>Data</th></tr>`+
      d.events.map(e=>`<tr><td>${e.id}</td><td>${e.ts?new Date(e.ts*1000).toLocaleString():"—"}</td>
        <td>0x${e.type.toString(16)}</td><td>${e.snr}</td><td>0x${e.d.toString(16)}</td></tr>`).join("")+"</table>";
  }catch(e){report(el,e);}
}
$("#sel-refresh").onclick=loadSEL;
$("#sel-clear").onclick=async()=>{
  if(!confirm("Clear the system event log?"))return;
  try{await api("/api/sel/clear","x=1");loadSEL();}catch(e){alert(e.message);}
};

/* ---------- users ---------- */
const PRIV={15:"N/A",4:"Administrator",3:"Operator",2:"User",1:"Callback",0:"No access"};
async function loadUsers(){
  const el=$("#users-table");el.innerHTML="<p class='dim'>loading…</p>";
  try{
    const rows=await api("/api/users");
    el.innerHTML=`<table><tr><th>Slot</th><th>User</th><th>Privilege</th><th>Enabled</th></tr>`+
      rows.map(r=>`<tr><td>${r.id}</td><td>${esc(r.name||"—")}</td>
        <td>${PRIV[r.priv]??r.priv}</td><td>${r.en?"yes":"no"}</td></tr>`).join("")+"</table>";
  }catch(e){report(el,e);}
}

/* ---------- network ---------- */
async function loadNet(){
  const el=$("#net-table");el.innerHTML="<p class='dim'>loading…</p>";
  try{
    const d=await api("/api/net");
    const ipsrc={0:"unspecified",1:"static",2:"DHCP",15:"BIOS/ROM"}[d.ipsrc]??d.ipsrc;
    el.innerHTML=`<table>
      <tr><td style="width:260px;color:var(--dim)">IP address</td><td>${esc(d.ip||"")}</td></tr>
      <tr><td style="color:var(--dim)">IP source</td><td>${ipsrc}</td></tr>
      <tr><td style="color:var(--dim)">Subnet mask</td><td>${esc(d.mask||"")}</td></tr>
      <tr><td style="color:var(--dim)">MAC</td><td>${esc(d.mac||"")}</td></tr>
      <tr><td style="color:var(--dim)">Gateway</td><td>${esc(d.gw||"")}</td></tr></table>`;
  }catch(e){report(el,e);}
}

/* ---------- system ---------- */
async function loadSys(){
  const el=$("#sys-table");el.innerHTML="<p class='dim'>loading…</p>";
  try{
    const s=await api("/api/sys");
    el.innerHTML=`<table>
      <tr><td style="width:260px;color:var(--dim)">Firmware Revision</td><td>${esc(s.fw||"")}</td></tr>
      <tr><td style="color:var(--dim)">IPMI Version</td><td>${esc(s.ipmi||"")}</td></tr>
      <tr><td style="color:var(--dim)">Manufacturer ID</td><td>0x${(s.mfg||0).toString(16)}</td></tr>
      <tr><td style="color:var(--dim)">Product ID</td><td>0x${(s.prod||0).toString(16)}</td></tr>
      <tr><td style="color:var(--dim)">Device ID</td><td>${s.devid}</td></tr>
      <tr><td style="color:var(--dim)">FRU area</td><td>${s.fru_size??"—"} bytes</td></tr></table>
      <h2 style="margin:18px 0 8px;font-size:12px;color:var(--dim);text-transform:uppercase">FRU raw</h2>
      <pre class="mono" style="white-space:pre-wrap;word-break:break-all">${esc((s.fru||"").slice(0,400))}</pre>`;
  }catch(e){report(el,e);}
}

/* ---------- firmware (stock flasher path, 1:1) ---------- */
const flog=t=>$("#fwlog").textContent+=t+"\n";
async function fwcall(p){const r=await api(p);return r;}
let fwfile=null;
$("#fwfile")?.addEventListener("change",e=>{fwfile=e.target.files[0];
  $("#fwstat").textContent=fwfile?`${fwfile.name} (${fwfile.size} B)`:"no file";});
$("#fwgo")?.addEventListener("click",async()=>{
  if(!fwfile){alert("pick an .ima first");return;}
  if(!confirm(`Flash ${fwfile.name} (${fwfile.size} bytes)?\nThe BMC reboots after flashing.`))return;
  $("#fwlog").textContent="";$("#fwgo").disabled=true;
  try{
    flog("[1/5] setTimeEEPROM");await fwcall("/fw/time");
    flog("[2/5] prepflash (stops services)");await fwcall("/fw/prep");
    flog("[3/5] upload "+fwfile.size+" bytes …");
    const bound="----IKVMBOUNDARY"+Date.now();
    const head=`--${bound}\r\nContent-Disposition: form-data; name="/mnt/rom.ima?${fwfile.size}"; filename="rom.ima"\r\nContent-Type: application/octet-stream\r\n\r\n`;
    const tail=`\r\n--${bound}--\r\n`;
    const body=new Blob([head,fwfile,tail]);
    const r=await fetch("/fw/upload",{method:"POST",headers:{"Content-Type":`multipart/form-data; boundary=${bound}`},body});
    const rt=await r.text();
    if(!r.ok)throw new Error("upload HTTP "+r.status);
    flog("    upload done");
    flog("[4/5] verifyimage (CRC on card)");
    const v=await fwcall("/fw/verify");
    const vt=typeof v==="object"?JSON.stringify(v):String(v);
    flog("    "+vt.slice(0,300));
    if(/IMGCOMPSTATUS' : '0'|HAPI_STATUS:0/.test(vt)===false&&typeof v==="string"&&!v.includes("0")){}
    flog("[5/5] startflash PRESERVECFG=1 — writing flash, then reboot");
    await fwcall("/fw/start");
    flog("DONE — card reboots in ~10 s. Wait ~2 min, then reload.");
  }catch(e){flog("ERR "+e.message);}
  $("#fwgo").disabled=false;
});

/* ---------- KVM console ---------- */
const kstat=t=>$("#kvmstat").textContent=t;
const cv=$("#screen"),ctx=cv.getContext("2d");
let client=null,lastBtn=0;
async function kvmStart(){
  try{
    kstat("fetching session token");
    const d=await api("/api/kvmtoken");
    if(!d.token)throw new Error("no session token");
    client=new IvKvmClient({
      wsUrl:`ws://${location.host}/ws`,
      onStatus:kstat,
      onBlank:()=>{ctx.fillStyle="#000";ctx.fillRect(0,0,cv.width,cv.height);kstat("blank screen — host off or no video");},
      onLed:b=>$("#leds").innerHTML=
        `NUM ${b&1?"<b>◆</b>":"◇"} CAPS ${b&2?"<b>◆</b>":"◇"} SCRL ${b&4?"<b>◆</b>":"◇"}`,
      onFrame:fr=>{
        if(cv.width!==fr.width||cv.height!==fr.height){cv.width=fr.width;cv.height=fr.height;}
        const img=ctx.createImageData(fr.width,fr.height);
        for(let i=0,j=0;i<fr.bgr.length;i+=3,j+=4){
          img.data[j]=fr.bgr[i+2];img.data[j+1]=fr.bgr[i+1];img.data[j+2]=fr.bgr[i];img.data[j+3]=255;}
        ctx.putImageData(img,0,0);
        kstat(`live · ${fr.width}x${fr.height} · frame ${fr.frameNumber}`);
      },
    });
    client.connect(d.token,"0");
    $("#kvm-stop").disabled=false;
  }catch(e){if(e.message!=="session expired")kstat("ERR "+e.message);}
}
$("#kvm-go").onclick=kvmStart;
$("#kvm-stop").onclick=()=>{client?.disconnect();client=null;$("#kvm-stop").disabled=true;kstat("stopped");};
$("#kvm-refresh").onclick=()=>client?.sendCtrl(IVTP.REFRESH);
$("#kvm-shot").onclick=()=>{
  const a=document.createElement("a");
  a.href=cv.toDataURL("image/png");a.download=`ikvm-${Date.now()}.png`;a.click();
};
/* global key capture: while connected & console view on, every key goes to
 * the host (except fields). Ctrl+Alt+End maps to Ctrl+Alt+Del (iDRAC trick;
 * real CAD never reaches the page). */
const INFIELD=e=>/^(INPUT|TEXTAREA|SELECT)$/.test(e.target?.tagName);
const KVMON=()=>$("#v-kvm")?.classList.contains("on");
document.addEventListener("keydown",e=>{
  if(!client||!KVMON()||INFIELD(e)||e.repeat)return;
  if(e.ctrlKey&&e.altKey&&e.code==="End"){
    e.preventDefault();
    ["ControlLeft","AltLeft","Delete"].forEach(c=>client.keyDown(c));
    setTimeout(()=>["ControlLeft","AltLeft","Delete"].forEach(c=>client.keyUp(c)),120);
    return;
  }
  e.preventDefault();client.keyDown(e.code);
},true);
document.addEventListener("keyup",e=>{
  if(!client||!KVMON()||INFIELD(e))return;
  e.preventDefault();client.keyUp(e.code);
},true);
cv.addEventListener("keydown",e=>{e.preventDefault();});
cv.addEventListener("keyup",e=>{e.preventDefault();});
window.addEventListener("blur",()=>{oskRelease();client&&["ControlLeft","ShiftLeft","AltLeft","MetaLeft","ControlRight","ShiftRight","AltRight","MetaRight"].forEach(c=>client.keyUp(c));});
const mxy=e=>{const b=cv.getBoundingClientRect();return[e.clientX-b.left,e.clientY-b.top];};
cv.addEventListener("mousemove",e=>{const[x,y]=mxy(e);client?.mouse(e.buttons&7,x,y,cv.width,cv.height);});
cv.addEventListener("mousedown",e=>{cv.focus();const[x,y]=mxy(e);lastBtn|=(1<<e.button);client?.mouse(lastBtn&7,x,y,cv.width,cv.height);});
cv.addEventListener("mouseup",e=>{const[x,y]=mxy(e);lastBtn&=~(1<<e.button);client?.mouse(lastBtn&7,x,y,cv.width,cv.height);});
cv.addEventListener("contextmenu",e=>e.preventDefault());
cv.addEventListener("wheel",e=>e.preventDefault(),{passive:false});
const MACROS={cad:["ControlLeft","AltLeft","Delete"],del:["Delete"],f2:["F2"],f11:["F11"],f12:["F12"]};
$$("[data-mac]").forEach(b=>b.onclick=()=>{
  if(!client)return;
  const seq=MACROS[b.dataset.mac];if(!seq)return;
  seq.forEach(c=>client.keyDown(c));
  setTimeout(()=>seq.forEach(c=>client.keyUp(c)),120);
});
/* ---------- on-screen keyboard overlay ---------- */
const OSK_MODS=new Set(["ControlLeft","ControlRight","ShiftLeft","ShiftRight","AltLeft","AltRight","MetaLeft","MetaRight"]);
const LATCHED=new Set();
const OSK_ROWS=[
 [["Escape","Esc"],["F1"],["F2"],["F3"],["F4"],["F5"],["F6"],["F7"],["F8"],["F9"],["F10"],["F11"],["F12"],["PrintScreen","PrtSc"],["ScrollLock","ScrLk"],["Pause","Pause"]],
 [["Backquote","`"],["Digit1","1"],["Digit2","2"],["Digit3","3"],["Digit4","4"],["Digit5","5"],["Digit6","6"],["Digit7","7"],["Digit8","8"],["Digit9","9"],["Digit0","0"],["Minus","-"],["Equal","="],["Backspace","⌫","wide"]],
 [["Tab","Tab","wide"],["KeyQ","Q"],["KeyW","W"],["KeyE","E"],["KeyR","R"],["KeyT","T"],["KeyY","Y"],["KeyU","U"],["KeyI","I"],["KeyO","O"],["KeyP","P"],["BracketLeft","["],["BracketRight","]"],["Backslash","\\"]],
 [["CapsLock","Caps","xwide"],["KeyA","A"],["KeyS","S"],["KeyD","D"],["KeyF","F"],["KeyG","G"],["KeyH","H"],["KeyJ","J"],["KeyK","K"],["KeyL","L"],["Semicolon",";"],["Quote","'"],["Enter","Enter","xwide"]],
 [["ShiftLeft","Shift","xwide"],["KeyZ","Z"],["KeyX","X"],["KeyC","C"],["KeyV","V"],["KeyB","B"],["KeyN","N"],["KeyM","M"],["Comma",","],["Period","."],["Slash","/"],["ShiftRight","Shift","xwide"]],
 [["ControlLeft","Ctrl","wide"],["MetaLeft","◆","wide"],["AltLeft","Alt","wide"],["Space","Space","space"],["AltRight","AltGr","wide"],["MetaRight","◆","wide"],["ContextMenu","☰","wide"],["ControlRight","Ctrl","wide"]],
 [["Insert","Ins"],["Home","Home"],["PageUp","PgUp"],["Delete","Del"],["End","End"],["PageDown","PgDn"],["NumLock","Num"],["ArrowLeft","←"],["ArrowUp","↑"],["ArrowDown","↓"],["ArrowRight","→"]],
];
function oskRelease(){
  for(const c of LATCHED)client?.keyUp(c);
  LATCHED.clear();
  $$("#osk .k.mod.on").forEach(k=>k.classList.remove("on"));
}
{
  const rows=$("#oskrows");
  for(const row of OSK_ROWS){
    const r=document.createElement("div");r.className="row";
    for(const[code,label,cls]of row){
      const k=document.createElement("div");
      k.className="k"+(cls?" "+cls:"")+(OSK_MODS.has(code)?" mod":"");
      k.textContent=label||code;
      k.onmousedown=e=>{e.preventDefault();
        if(!client){kstat("connect first");return;}
        if(OSK_MODS.has(code)){
          if(LATCHED.has(code)){LATCHED.delete(code);k.classList.remove("on");client.keyUp(code);}
          else{LATCHED.add(code);k.classList.add("on");client.keyDown(code);}
        }else{client.keyDown(code);setTimeout(()=>client.keyUp(code),80);}
      };
      r.appendChild(k);
    }
    rows.appendChild(r);
  }
}
$("#oskbtn").onclick=()=>{const o=$("#osk");o.classList.toggle("on");if(!o.classList.contains("on"))oskRelease();};
$("#oskx").onclick=()=>{$("#osk").classList.remove("on");oskRelease();};
$("#kvm-stop").addEventListener("click",()=>oskRelease());

/* ================= iDRAC-style views over /api/ga ================= */
LOADERS.sensors=()=>loadSensors($("#sensor-table"));
LOADERS.sel=loadSEL;

/* ---------- FRU / inventory ---------- */
async function loadFru(){
  await Promise.all([
    loadRpcInto($("#fru-table"),"/rpc/getallfruinfo.asp"),
    loadRpcInto($("#fru-bmc"),"/rpc/getallfruinfo_bmc.asp"),
  ]);
}
$("#fru-refresh").onclick=loadFru;
LOADERS.fru=loadFru;

/* ---------- users ---------- */
LOADERS.users=loadUsers;
$("#users-refresh").onclick=loadUsers;
$("#uf-save").onclick=async()=>{
  const st=stEl("#uf-st");
  const idx=+$("#uf-idx").value,name=$("#uf-name").value,pw=$("#uf-pass").value,priv=$("#uf-priv").value;
  if(!idx||!name){st("slot + username required");return;}
  const fields={WEBVAR_USERINDEX:idx,WEBVAR_USERNAME:name,WEBVAR_PASSWD:pw,WEBVAR_NETWORKPRIV:priv,WEBVAR_SERIALPRIV:priv};
  try{
    let r;
    if(pw)r=await gapost("/rpc/adduser.asp",fields);
    else{r=await gapost("/rpc/moduser.asp",{...fields,WEBVAR_ISPWDCHANGE:0});}
    if(wvParse(r).st!==0){ // add failed -> try modify
      r=await gapost("/rpc/moduser.asp",{...fields,WEBVAR_ISPWDCHANGE:pw?1:0});
    }
    st(wvParse(r).st===0?"saved":"err "+wvParse(r).st);loadUsers();
  }catch(e){st(e.message);}
};
$("#uf-del").onclick=async()=>{
  const st=stEl("#uf-st"),idx=+$("#uf-idx").value;
  if(!idx)return st("slot required");
  if(!confirm(`Delete user slot ${idx}?`))return;
  try{const r=await gapost("/rpc/deluser.asp",{WEBVAR_USERINDEX:idx});st(wvParse(r).st===0?"deleted":"err "+wvParse(r).st);loadUsers();}
  catch(e){st(e.message);}
};

/* ---------- network ---------- */
function loadNet2(){loadNet();
  loadRpcInto($("#ncsi-table"),"/rpc/getnwconfig_NCSI.asp");}
LOADERS.net=loadNet2;
$("#net-refresh").onclick=loadNet2;
$("#ncsi-refresh").onclick=()=>loadRpcInto($("#ncsi-table"),"/rpc/getnwconfig_NCSI.asp");
$("#nf-save").onclick=async()=>{
  const st=stEl("#nf-st");
  const src=$("#nf-src").value,ip=$("#nf-ip").value,mask=$("#nf-mask").value,gw=$("#nf-gw").value;
  if(!confirm(`Apply LAN config?\nIP: ${ip||"(unchanged)"}  src=${src==="2"?"DHCP":"static"}`))return;
  try{
    const p={IPAddrSource:src};
    if(ip)p.IP=ip;if(mask)p.Mask=mask;if(gw)p.Gateway=gw;
    const r=await gapost("/rpc/setnwconfig.asp",p);
    st("done — card may rebind");setTimeout(loadNet2,2500);
  }catch(e){st(e.message);}
};

/* ---------- time / ntp ---------- */
async function loadTime(){
  await Promise.all([
    loadRpcInto($("#time-table"),"/rpc/getdatetime.asp"),
    loadRpcInto($("#ntp-table"),"/rpc/getntp.asp"),
  ]);
}
LOADERS.time=loadTime;
$("#time-refresh").onclick=loadTime;
$("#ntp-refresh").onclick=()=>loadRpcInto($("#ntp-table"),"/rpc/getntp.asp");
$("#ntp-save").onclick=async()=>{
  const st=stEl("#ntp-st"),srv=$("#ntp-srv").value;if(!srv)return st("server required");
  try{
    let r=await gapost("/rpc/setntp.asp",{V_SERVER_NAME:srv});
    if(wvParse(r).st!==0)r=await gapost("/rpc/setNTPserver.asp",{CHECK:1,NTPSERVERP:srv,NTPSERVERS:""});
    st("saved");
  }catch(e){st(e.message);}
};
$("#tz-save").onclick=async()=>{
  const st=stEl("#tz-st"),tz=$("#tz-val").value;if(!tz)return;
  try{await gapost("/rpc/setTimeZone.asp",{TIMEZONE:tz});st("saved");}catch(e){st(e.message);}
};
$("#tf-now").onclick=()=>{
  const d=new Date();
  $("#tf-year").value=d.getFullYear();$("#tf-month").value=String(d.getMonth()+1).padStart(2,"0");
  $("#tf-day").value=String(d.getDate()).padStart(2,"0");
  $("#tf-hour").value=String(d.getHours()).padStart(2,"0");
  $("#tf-min").value=String(d.getMinutes()).padStart(2,"0");
  $("#tf-sec").value=String(d.getSeconds()).padStart(2,"0");
};
$("#tf-save").onclick=async()=>{
  const st=stEl("#tf-st");
  try{
    const r=await gapost("/rpc/setdatetime.asp",{
      V_HOUR:+$("#tf-hour").value,V_MIN:+$("#tf-min").value,V_SECS:+$("#tf-sec").value,
      V_DATE:+$("#tf-day").value,V_MONTH:+$("#tf-month").value,V_YEAR:+$("#tf-year").value});
    st("clock set");loadTime();
  }catch(e){st(e.message);}
};

/* ---------- alerts ---------- */
async function loadAlerts(){
  await Promise.all([
    loadRpcInto($("#al-table"),"/rpc/getlanalertdests.asp"),
    loadRpcInto($("#smtp-table"),"/rpc/getsmtpcfg.asp"),
    loadRpcInto($("#alv-table"),"/rpc/getalertlevels.asp"),
  ]);
}
LOADERS.alerts=loadAlerts;
$("#al-refresh").onclick=()=>loadRpcInto($("#al-table"),"/rpc/getlanalertdests.asp");
$("#smtp-refresh").onclick=()=>loadRpcInto($("#smtp-table"),"/rpc/getsmtpcfg.asp");
$("#alv-refresh").onclick=()=>loadRpcInto($("#alv-table"),"/rpc/getalertlevels.asp");
$("#af-save").onclick=async()=>{
  const st=stEl("#af-st");
  try{
    const r=await gapost("/rpc/setalertentry.asp",{
      WEBVAR_INDEX:+$("#af-idx").value||0,WEBVAR_ALERTTYPE:+$("#af-type").value,
      WEBVAR_EVENTSEV:+$("#af-sev").value,WEBVAR_EVENTSEVERITY:+$("#af-sev").value,
      WEBVAR_DESTIP:$("#af-ip").value,WEBVAR_EMAILADDR:$("#af-mail").value,
      WEBVAR_SUBJECT:$("#af-subj").value,WEBVAR_MESSAGE:"",WEBVAR_ALERTPOLICYNUM:0,WEBVAR_ENTRYINDEX:+$("#af-idx").value||0});
    st("saved");loadRpcInto($("#al-table"),"/rpc/getlanalertdests.asp");
  }catch(e){st(e.message);}
};
$("#af-test").onclick=async()=>{
  const st=stEl("#af-st");
  try{await gapost("/rpc/testalert.asp",{WEBVAR_DSTSEL:+$("#af-idx").value||0});st("test sent");}
  catch(e){st(e.message);}
};
$("#smtp-save").onclick=async()=>{
  const st=stEl("#smtp-st"),ip=$("#smtp-ip").value;if(!ip)return;
  try{await gapost("/rpc/setsmtpcfg.asp",{SERVER_IP:ip});st("saved");loadRpcInto($("#smtp-table"),"/rpc/getsmtpcfg.asp");}
  catch(e){st(e.message);}
};

/* ---------- PEF ---------- */
function loadPef(){loadRpcInto($("#pef-table"),"/rpc/GetPEFTable.asp");}
LOADERS.pef=loadPef;
$("#pef-refresh").onclick=loadPef;
$("#pf-save").onclick=async()=>{
  const st=stEl("#pf-st");
  try{
    await gapost("/rpc/SetEvtFilterAction.asp",{
      WEBVAR_ENTRYINDEX:+$("#pf-idx").value||0,WEBVAR_FILTERCONFIG:+$("#pf-en").value,
      WEBVAR_EVTFILTERACTION:+$("#pf-action").value||0,WEBVAR_ALERTPOLICYNUM:+$("#pf-pol").value||0,
      WEBVAR_EVENTSEVERITY:+$("#pf-sev").value||0,WEBVAR_SENSORTYPE:+$("#pf-stype").value||0,
      WEBVAR_SENSORNUM:+$("#pf-snum").value||0,WEBVAR_EVENTTRIGGER:+$("#pf-trig").value||0,
      WEBVAR_EVENTDATA1OFFSETMASK:0,WEBVAR_EVENTDATA1ANDMASK:0,WEBVAR_EVENTDATA1CMP1:0,WEBVAR_EVENTDATA1CMP2:0,
      WEBVAR_EVENTDATA2ANDMASK:0,WEBVAR_EVENTDATA2CMP1:0,WEBVAR_EVENTDATA2CMP2:0,
      WEBVAR_EVENTDATA3ANDMASK:0,WEBVAR_EVENTDATA3CMP1:0,WEBVAR_EVENTDATA3CMP2:0});
    st("applied");loadPef();
  }catch(e){st(e.message);}
};

/* ---------- SNMP ---------- */
async function loadSnmp(){
  await Promise.all([
    loadRpcInto($("#snmp-table"),"/rpc/getsnmpsettings.asp"),
    loadRpcInto($("#snmpc-table"),"/rpc/getsnmpcomm.asp"),
    loadRpcInto($("#snmpu-table"),"/rpc/getsnmpusrlist.asp"),
    loadRpcInto($("#snmp-table"),"/rpc/getsnmpnwconfig.asp").catch(()=>{}),
  ]);
}
LOADERS.snmp=loadSnmp;
$("#snmp-refresh").onclick=loadSnmp;
$("#snmpc-refresh").onclick=()=>loadRpcInto($("#snmpc-table"),"/rpc/getsnmpcomm.asp");
$("#snmpu-refresh").onclick=()=>loadRpcInto($("#snmpu-table"),"/rpc/getsnmpusrlist.asp");

/* ---------- directory ---------- */
async function loadDir(){
  await Promise.all([
    loadRpcInto($("#ad-table"),"/rpc/getactivedircfg.asp"),
    loadRpcInto($("#rg-table"),"/rpc/getallrolegroupcfg.asp"),
    loadRpcInto($("#ldap-table"),"/rpc/getldapconfig.asp"),
  ]);
}
LOADERS.dir=loadDir;
$("#ad-refresh").onclick=()=>loadRpcInto($("#ad-table"),"/rpc/getactivedircfg.asp");
$("#rg-refresh").onclick=()=>loadRpcInto($("#rg-table"),"/rpc/getallrolegroupcfg.asp");
$("#ldap-refresh").onclick=()=>loadRpcInto($("#ldap-table"),"/rpc/getldapconfig.asp");
$("#adcert-refresh").onclick=()=>loadRpcInto($("#adcert-table"),"/rpc/getadcert.asp");
async function rgOp(verb){
  const st=stEl("#rg-st");
  try{
    await gapost(`/rpc/${verb}rolegroup.asp`,{ROLEGROUP_ID:+$("#rg-id").value||0,ROLEGROUP_NAME:$("#rg-name").value,ROLEGROUP_DOMAIN:$("#rg-dom").value,ROLEGROUP_PRIV:+$("#rg-priv").value});
    st(verb+" ok");loadRpcInto($("#rg-table"),"/rpc/getallrolegroupcfg.asp");
  }catch(e){st(e.message);}
}
$("#rg-add").onclick=()=>rgOp("add");
$("#rg-mod").onclick=()=>rgOp("mod");
$("#rg-del").onclick=async()=>{if(confirm("Delete role group "+$("#rg-id").value+"?"))rgOp("del");};
$("#ldap-save").onclick=async()=>{
  const st=stEl("#ldap-st");
  try{
    await gapost("/rpc/setldapconfig.asp",{ENABLE:+$("#ldap-en").value,PORTNUM:+$("#ldap-port").value||389,
      IP:$("#ldap-ip").value,PASSWORD:$("#ldap-pw").value,BINDDN:$("#ldap-dn").value,SEARCHBASE:$("#ldap-sb").value});
    st("saved");loadRpcInto($("#ldap-table"),"/rpc/getldapconfig.asp");
  }catch(e){st(e.message);}
};
$("#adcert-save").onclick=async()=>{
  const st=stEl("#adcert-st");
  try{await gapost("/rpc/setadcert.asp",{WEBVAR_AD_CERT:$("#adcert-pem").value});st("sent");}
  catch(e){st(e.message);}
};

/* ---------- serial / SOL ---------- */
async function loadSerial(){
  await Promise.all([
    loadRpcInto($("#sol-table"),"/rpc/getserialcfg_sol.asp"),
    loadRpcInto($("#ser-table"),"/rpc/getserial.asp"),
    loadRpcInto($("#serm-table"),"/rpc/getserialcfg_messaging.asp"),
  ]);
}
LOADERS.serial=loadSerial;
$("#sol-refresh").onclick=()=>loadRpcInto($("#sol-table"),"/rpc/getserialcfg_sol.asp");
$("#ser-refresh").onclick=()=>loadRpcInto($("#ser-table"),"/rpc/getserial.asp");
$("#serm-refresh").onclick=()=>loadRpcInto($("#serm-table"),"/rpc/getserialcfg_messaging.asp");
$("#sol-save").onclick=async()=>{
  const st=stEl("#sol-st");
  try{
    await gapost("/rpc/setserialcfg_sol.asp",{BAUDRATE1:+$("#sol-baud").value,SOL_ENABLED:+$("#sol-en").value});
    st("saved");loadRpcInto($("#sol-table"),"/rpc/getserialcfg_sol.asp");
  }catch(e){st(e.message);}
};

/* ---------- sessions & mouse ---------- */
async function loadSess(){
  await Promise.all([
    loadRpcInto($("#sto-table"),"/rpc/getsessiontime.asp"),
    loadRpcInto($("#mm-table"),"/rpc/getmousemode.asp"),
  ]);
}
LOADERS.sess=loadSess;
$("#sto-refresh").onclick=()=>loadRpcInto($("#sto-table"),"/rpc/getsessiontime.asp");
$("#mm-refresh").onclick=()=>loadRpcInto($("#mm-table"),"/rpc/getmousemode.asp");
$("#sto-save").onclick=async()=>{
  const st=stEl("#sto-st"),s=+$("#sto-secs").value;if(!s)return;
  try{await gapost("/rpc/setsessiontime.asp",{WEBVAR_SESSIONTIME:s,TIMEOUT:s});st("saved");}
  catch(e){st(e.message);}
};
$("#mm-save").onclick=async()=>{
  const st=stEl("#mm-st");
  try{
    await gapost("/rpc/setmousemode.asp",{SET_MOUSE_MODE:+$("#mm-mode").value,IS_HYPERV:+$("#mm-hv").value});
    st("saved");loadRpcInto($("#mm-table"),"/rpc/getmousemode.asp");
  }catch(e){st(e.message);}
};
$("#ipmis-go").onclick=()=>loadRpcInto($("#ipmis-table"),"/rpc/ipmisess.asp");

/* ---------- system extras ---------- */
$("#ext-go").onclick=()=>loadRpcInto($("#ext-table"),"/rpc/getextbmccfg.asp");
LOADERS.sys=loadSys;

/* ---------- maintenance ---------- */
const MSTC=stEl("#maint-st");
async function mcall(rpc,msg){
  if(!confirm(msg))return;
  try{const r=await gaText("/rpc/"+rpc);MSTC(rpc+": "+(wvParse(r).st??"sent"));}
  catch(e){MSTC(e.message);}
}
$("#m-reboot").onclick=()=>mcall("rebootcard.asp","Reboot the BMC card? This session will drop.");
$("#m-webre").onclick=()=>mcall("restartwebserver.asp","Restart the legacy webserver?");
$("#m-postflash").onclick=()=>mcall("postflashreset.asp","Post-flash reset (reboots card)?");
$("#m-spfiles").onclick=()=>mcall("usenewspfiles.asp","Switch to new SP files?");
$("#m-factory").onclick=()=>mcall("setfactorydefaults.asp","RESET ALL BMC SETTINGS TO FACTORY DEFAULTS? IPs, users, everything.");
$("#cert-go").onclick=()=>loadRpcInto($("#cert-table"),"/rpc/validatesslcert.asp");
$("#cap-go").onclick=async()=>{
  const st=$("#cap-st");st.textContent="capturing…";
  try{
    const r=await ga("/rpc/Capture.asp");
    const b=await r.blob();
    if(!b.size)throw new Error("empty capture (host off?)");
    const url=URL.createObjectURL(b);
    $("#cap-box").innerHTML=`<img src="${url}" style="max-width:100%;border:1px solid var(--border);border-radius:6px">
      <p class="note"><a href="${url}" download="capture-${Date.now()}.jpg" style="color:var(--accent)">download</a> · ${b.size} B</p>`;
    st.textContent="";
  }catch(e){st.textContent=e.message;}
};

/* ---------- raw RPC console ---------- */
const RPCS=["WEBSES/create.asp","Capture.asp","GetPEFTable.asp","PWRbutton.asp","RCOCX.asp","SetEvtFilterAction.asp","ShowTime.asp",
"addrolegroup.asp","addsnmpcomm.asp","addsnmpuser.asp","adduser.asp","buttonctl.asp","buttonstatus.asp","chassisidentify.asp",
"clearsel.asp","delrolegroup.asp","delsnmpcomm.asp","delsnmpuser.asp","deluser.asp","editsnmpuser.asp","flashstatus.asp",
"getNTPserver.asp","getactivedircfg.asp","getadcert.asp","getalertlevels.asp","getallfruinfo.asp","getallfruinfo_bmc.asp",
"getallrolegroupcfg.asp","getallselentries.asp","getallselentries_bmc.asp","getallsensors.asp","getallsensors_bmc.asp",
"getalluserinfo.asp","getbldtime.asp","getchannelpriv.asp","getdatetime.asp","getdeviceid.asp","getextbmccfg.asp",
"getlanalertdests.asp","getldapconfig.asp","getmousemode.asp","getntp.asp","getnwconfig.asp","getnwconfig_NCSI.asp",
"getnwconfig_interface.asp","getpmcpfilestat.asp","getrole.asp","getrolegroupcfg.asp","getserial.asp",
"getserialcfg_messaging.asp","getserialcfg_sol.asp","getsessiontime.asp","getsessiontoken.asp","getsmtpcfg.asp",
"getsnmpcomm.asp","getsnmpnwconfig.asp","getsnmpsettings.asp","getsnmpusrlist.asp","getuserdetail.asp","hostctl.asp",
"hostctl_bmc.asp","hoststatus.asp","hoststatus_bmc.asp","ipmisess.asp","modrolegroup.asp","modsnmpcomm.asp","moduser.asp",
"postflashreset.asp","prepflash.asp","rebootcard.asp","restartwebserver.asp","setNTPserver.asp","setTimeEEPROM.asp",
"setTimeZone.asp","setactivedircfg.asp","setadcert.asp","setalertentry.asp","setdatetime.asp","setextbmccfg.asp",
"setfactorydefaults.asp","setldapconfig.asp","setmousemode.asp","setntp.asp","setnwconfig.asp","setnwconfig_NCSI.asp",
"setnwconfig_interface.asp","setrolegroupcfg.asp","setserial.asp","setserialcfg_messaging.asp","setserialcfg_sol.asp",
"setsessiontime.asp","setsmtpcfg.asp","setsnmpnwconfig.asp","setsnmpsettings.asp","startflash.asp","testalert.asp",
"testalertv3.asp","usenewspfiles.asp","validatesslcert.asp","verifyimage.asp","verifytmpsdrdat.asp","verifytmpspbin.asp"];
const rpcpick=$("#rpc-pick");
rpcpick.innerHTML='<option value="">— pick an RPC —</option>'+RPCS.map(r=>`<option>/rpc/${r}</option>`).join("");
rpcpick.onchange=()=>{if(rpcpick.value)$("#rpc-path").value=rpcpick.value;};
$("#rpc-go").onclick=async()=>{
  const out=$("#rpc-out"),p=$("#rpc-path").value.trim();
  if(!p){out.textContent="no path";return;}
  out.textContent="…";
  try{
    let t;
    if($("#rpc-m").value==="POST"){
      const q=Object.fromEntries(new URLSearchParams($("#rpc-body").value));
      t=await gapost(p.split("?")[0],q);
    }else t=await gaText(p.startsWith("/")?p:"/rpc/"+p);
    let pretty;try{pretty=JSON.stringify(wvParse(t),null,1);}catch(e){pretty=t;}
    out.textContent=(pretty+"\n\n--- raw ---\n"+t).slice(0,20000);
  }catch(e){out.textContent="ERR "+e.message;}
};
</script>
