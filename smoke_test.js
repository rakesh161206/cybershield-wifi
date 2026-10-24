// Headless smoke test for the CyberShield dashboard render functions.
// Minimal DOM shim + the real frontend script + the real running API.
const fs = require('fs');
const path = require('path');
const http = require('http');

const BASE = process.env.CS_BASE || 'http://127.0.0.1:8123';

class El {
  constructor(tag='div', id=''){
    this.tagName=tag.toUpperCase(); this.id=id; this.children=[];
    this.dataset={}; this.style={}; this._html=''; this._text=''; this.listeners={};
    this.value=''; this.classList={_s:new Set(),
      add(c){this._s.add(c)},remove(c){this._s.delete(c)},
      toggle(c,f){f?this._s.add(c):this._s.delete(c)},contains(c){return this._s.has(c)}};
  }
  set innerHTML(v){this._html=String(v)} get innerHTML(){return this._html}
  set textContent(v){this._text=String(v)} get textContent(){return this._text}
  set className(v){this.classList._s=new Set(String(v).split(/\s+/).filter(Boolean))}
  get className(){return [...this.classList._s].join(' ')}
  addEventListener(ev,fn){(this.listeners[ev]||=[]).push(fn)}
  removeEventListener(){}
  appendChild(c){this.children.push(c);return c}
  remove(){}
  querySelectorAll(){return []}
  getBoundingClientRect(){return {left:0,top:0,width:400,height:400}}
  getContext(){return new Proxy({},{get:()=>()=>({addColorStop(){}})})}
  set onclick(f){this._onclick=f} get onclick(){return this._onclick}
  closest(){return null}
}
const registry=new Map();
const IDS=['liveDot','apiDot','clock','liveVerdict','diagKpi','netKpi','ipKpi','ipRiskKpi',
'lanCount','lanCount2','devTabBadge','netTabBadge','ipTabBadge','pktKpi','liveCards','liveChecks',
'liveReasons','liveRecs','speedOut','btnSpeed','btnDisconnect','btnScan','btnProbe','btnCapStart',
'btnCapStop','btnVerify','btnLookup','btnWatch','btnFeeds','btnAckAll',
'radar','radarMeta','radarList',
'radarDetail','policyBanner','rogueBanner','diagPanel','ipAlertBanner','ipSources','ipLookupResult',
'ipObsMeta','ipSummary','ipRows','ipDetail','ipAlertList','ipAlertCount','ipObsNote','ipSearch','ipFilter',
'ipInput','netSearch','netFilter','devSearch','tlFilter','verifyWindow','healthSpark','healthMeta',
'aiDot','aiVerdict','aiBar','aiDetail','aiRows','pktDot','pktCards','pktMeta','capStatus','capFiles',
'verdictHero','heroIcon','heroTitle','heroSub','heroScore','heroBar','heroWhy',
'capIface','capDur','capPkts','capFilter','lanRows','lanMeta','timelineList','verifyResult',
'tab-overview','tab-networks','tab-devices','tab-ipintel','tab-dnsintel','tab-intel','tab-timeline',
'dnsStatus','dnsSetup','dnsSetupHint','dnsConnectForm','dnsApiKey','dnsProfileId','btnDnsConnect',
'dnsConnectMsg','dnsSetupMsg','dnsStats','dnsStatusDetail','dnsMeta','dnsSearch','dnsDevice',
'dnsSeverity','dnsRange','dnsRows','dnsEmpty','dnsSecurity','dnsParticipants','dnsDomains',
'dnsNote','dnsLimits','dnsTabBadge','btnDnsRefresh','btnDnsDisconnect','btnDnsPurge'];
IDS.forEach(id=>{const e=new El('div',id);registry.set(id,e)});

function httpGet(p){
  return new Promise((ok,no)=>{
    http.get(BASE+p, r=>{let b='';r.on('data',c=>b+=c);r.on('end',()=>ok(b));}).on('error',no);
  });
}

global.document={
  getElementById:id=>registry.get(id)||null,
  querySelectorAll:sel=>{
    if(sel==='[data-tab]')return ['overview','networks','devices','ipintel','dnsintel','intel','timeline'].map(t=>{
      const e=new El('button');e.dataset.tab=t;return e;});
    return [];
  },
  createElement:t=>new El(t), addEventListener:()=>{}, body:new El('body'), hidden:false,
};
global.window=global;
global.setInterval=()=>0;
global.setTimeout=(f)=>{return 0};
global.clearTimeout=()=>{};
global.requestAnimationFrame=()=>0;
global.confirm=()=>true;
global.alert=()=>{};
global.Blob=class{constructor(){}};
global.URL={createObjectURL:()=>''};
global.fetch=async(p,o)=>{
  try{
    const res=await httpGet(p);
    return {ok:true, status:200, json:async()=>JSON.parse(res)};
  }catch(e){ return {ok:false, status:0, json:async()=>({error:String(e)})}; }
};

const html=fs.readFileSync(path.join(__dirname,'frontend','index.html'),'utf8');
const js=html.match(/<script>\n([\s\S]*)\n<\/script>/)[1];
// expose internals for the test
eval(js + `
;global.__T = { esc, arr, obj, num, refreshLive, refreshHealth, loadRadar, renderIPTable,
  renderIPDetail, renderIPSources, renderIPAlerts, renderRadarSel, renderRogue, renderDiag,
  refreshAI, refreshPacket, refreshTimeline, refreshIPIntel, refreshIPAlerts, refreshLan, refreshDns,
  sparkline, sevChip, purposeChip, vendorOf, AI_LABELS, renderHero, verdictState,
  set radarNets(v){ radarNets=v }, get radarNets(){ return radarNets },
  set ipObserved(v){ ipObserved=v }, get ipObserved(){ return ipObserved },
  set ipSelected(v){ ipSelected=v }, get ipSelected(){ return ipSelected },
  set radarSel(v){ radarSel=v }, get radarSel(){ return radarSel } };
`);

const T=global.__T;
const results=[];
async function check(name,fn){
  try{ await fn(); results.push(['PASS',name,'']); }
  catch(e){ results.push(['FAIL',name,(e&&(e.stack||e.message||String(e))||'').split('\n').slice(0,4).join('\n      ')]); }
}
function assert(cond,msg){ if(!cond) throw new Error(msg); }
function noUndef(html,label){
  if(html.indexOf('undefined')>=0) throw new Error(label+' contains the literal "undefined"');
  if(html.indexOf('NaN')>=0) throw new Error(label+' contains NaN');
  if(html.indexOf('[object Object]')>=0) throw new Error(label+' contains [object Object]');
}

(async()=>{
  await check('refreshLive renders connection + checks', async()=>{
    await T.refreshLive();
    const cards=document.getElementById('liveCards').innerHTML;
    assert(cards.length>50,'live cards empty');
    noUndef(cards,'liveCards');
    const chk=document.getElementById('liveChecks').innerHTML;
    assert(chk.length>10,'live checks empty');
    assert(document.getElementById('liveVerdict').textContent.length>1,'verdict empty');
  });

  await check('refreshHealth renders sparklines', async()=>{
    await T.refreshHealth();
    const h=document.getElementById('healthSpark').innerHTML;
    noUndef(h,'healthSpark');
  });

  await check('loadRadar renders table + banners', async()=>{
    await T.loadRadar();
    const h=document.getElementById('radarList').innerHTML;
    assert(h.length>50,'radar list empty');
    noUndef(h,'radarList');
    assert(document.getElementById('radarDetail').innerHTML.length>50,'radar detail empty');
    T.renderRogue([]); T.renderDiag(null);
  });

  await check('refreshAI renders feature table', async()=>{
    await T.refreshAI();
    const h=document.getElementById('aiRows').innerHTML;
    assert(h.length>50,'ai rows empty');
    noUndef(h,'aiRows');
    assert(document.getElementById('aiDetail').textContent.length>1,'ai detail empty');
  });

  await check('refreshPacket renders flow cards', async()=>{
    await T.refreshPacket();
    const h=document.getElementById('pktCards').innerHTML;
    assert(h.length>50,'packet cards empty');
    noUndef(h,'pktCards');
  });

  await check('verdict hero renders a plain-language state', async()=>{
    await T.refreshLive();
    const t=document.getElementById('heroTitle').textContent;
    if(!['SAFE','CAREFUL','DANGER','UNKNOWN'].includes(t)) throw new Error('bad verdict state: '+t);
    if(document.getElementById('heroScore').textContent.indexOf('/100')<0) throw new Error('bad score');
  });

  await check('refreshIPIntel renders peers + detail', async()=>{
    await T.refreshIPIntel();
    const rows=document.getElementById('ipRows').innerHTML;
    assert(rows.length>50,'ip rows empty');
    noUndef(rows,'ipRows');
    assert(document.getElementById('ipSummary').innerHTML.length>10,'ip summary empty');
    assert(document.getElementById('ipSources').innerHTML.length>10,'ip sources empty');
    const ip=(T.ipObserved[0]||{}).ip;
    if(ip){ T.ipSelected=ip; T.renderIPDetail();
      const d=document.getElementById('ipDetail').innerHTML;
      assert(d.length>100,'ip detail empty'); noUndef(d,'ipDetail'); }
  });

  await check('IP table filter + sort do not throw', ()=>{
    const before=document.getElementById('ipRows').innerHTML.length;
    T.renderIPTable();
    assert(document.getElementById('ipRows').innerHTML.length>0,'rows vanished');
  });

  await check('refreshIPAlerts renders alert list', async()=>{
    await T.refreshIPAlerts();
    const h=document.getElementById('ipAlertList').innerHTML;
    assert(h.length>10,'alert list empty');
    noUndef(h,'ipAlertList');
  });

  await check('refreshDns renders DNS activity without crashing', async()=>{
    await T.refreshDns();
    const stats=document.getElementById('dnsStats').innerHTML;
    const rows=document.getElementById('dnsRows').innerHTML;
    assert(stats.length>10,'dns stats empty');
    assert(rows.length>10,'dns rows empty');
    assert(document.getElementById('dnsNote').textContent.length>20,'dns note empty');
    assert(document.getElementById('dnsLimits').innerHTML.length>10,'dns limits empty');
    assert(document.getElementById('dnsConnectForm').classList.contains('hidden') === false,
      'local setup form should be visible');
    assert(document.getElementById('dnsSetupMsg').classList.contains('hidden'),
      'unconfigured profile should not show a sync-error message');
    noUndef(stats,'dnsStats'); noUndef(rows,'dnsRows');
    noUndef(document.getElementById('dnsSetup').innerHTML,'dnsSetup');
  });

  await check('refreshTimeline renders chronology', async()=>{
    await T.refreshTimeline();
    const h=document.getElementById('timelineList').innerHTML;
    assert(h.length>10,'timeline empty');
    noUndef(h,'timelineList');
  });

  await check('refreshLan renders device table', async()=>{
    await T.refreshLan('fast',0);
    const h=document.getElementById('lanRows').innerHTML;
    assert(h.length>10,'lan rows empty');
    noUndef(h,'lanRows');
  });

  await check('demo mode is fully removed', ()=>{
    assert(!/data-tab="demo"|refreshDemo|Simulate Wi-Fi attack|\/api\/simulate|\/api\/decoy/.test(html),
      'demo markup or API calls remain');
  });

  await check('null payloads do not break renders', ()=>{
    T.renderRogue(null); T.renderDiag(null); T.renderDiag({verdict:'healthy'});
    T.renderIPSources(null); T.renderIPAlerts(null);
    T.renderIPDetail();
    T.sevChip(undefined); T.purposeChip(undefined);
    T.arr(null); T.obj(undefined);
  });

  let fails=0;
  results.forEach(([s,n,e])=>{ if(s==='FAIL')fails++; console.log(`${s}  ${n}${e?'\n      '+e:''}`); });
  console.log(`\n${results.length-fails}/${results.length} checks passed`);
  process.exit(fails?1:0);
})();
