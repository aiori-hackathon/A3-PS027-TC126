(function(){
var CHECKS=[
{k:"Apex AAAA",w:15,p:.7,d:"Domain resolves to an IPv6 address",f:"Add an AAAA record for the root domain."},
{k:"www AAAA",w:10,p:.72,d:"www host resolves over IPv6",f:"Add an AAAA record for www or point it to a dual-stack CNAME."},
{k:"Nameservers",w:15,p:.62,d:"Authoritative servers answer over IPv6",f:"Enable IPv6 on at least two authoritative nameservers."},
{k:"Mail (MX)",w:5,p:.55,d:"Mail exchangers have AAAA records",f:"Give each MX host an AAAA record and listener."},
{k:"HTTPS on IPv6",w:20,p:.68,d:"Port 443 accepts connections over IPv6",f:"Bind the web server and firewall rules to the IPv6 address."},
{k:"TLS on IPv6",w:10,p:.8,d:"Certificate and response match the IPv4 path",f:"Serve the same certificate chain and content on both families."},
{k:"Dependencies",w:15,p:.6,d:"Third-party hosts reachable over IPv6",f:"Replace or proxy IPv4-only third-party hosts."},
{k:"IPv6-only test",w:10,p:.58,d:"Page loads through DNS64 and NAT64",f:"Remove hard-coded IPv4 literals from pages and scripts."}];
var POOL=[["fonts.googleapis.com",1],["cdn.jsdelivr.net",1],["cdnjs.cloudflare.com",1],["www.googletagmanager.com",1],["static.cloudflareinsights.com",1],["api.payments.example",.7],["js.heatmap-tool.example",.45],["ads.legacy-network.example",.1],["widgets.old-social.example",.15],["img.cdn-v4only.example",0]];
var HEX=["2001","0db8","a1c4","5e07","00ff","9b3d","7c20","1f88"];
function hash(s){var x=1779033703^s.length;for(var i=0;i<s.length;i++){x=Math.imul(x^s.charCodeAt(i),3432918353);x=x<<13|x>>>19}return x>>>0}
function rng(a){return function(){a|=0;a=a+1831565813|0;var t=Math.imul(a^a>>>15,1|a);t=t+Math.imul(t^t>>>7,61|t)^t;return((t^t>>>14)>>>0)/4294967296}}
function $(i){return document.getElementById(i)}
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]})}
function host(v){return v.trim().toLowerCase().replace(/^[a-z]+:\/\//,"").replace(/[\/?#].*$/,"").replace(/^www\./,"")}
function label(s){return s==="pass"?"Pass":s==="warn"?"Review":"Fail"}
function audit(){
var d=host($("dom").value);
if(!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(d)){$("dom").focus();$("dom").style.borderColor="var(--fail)";$("target").textContent="Enter a valid domain such as example.org";$("result").style.display="block";$("addr").innerHTML="";$("checks").innerHTML="";$("deps").innerHTML="";$("fixes").innerHTML="";$("score").textContent="";$("verdict").textContent="";return}
$("dom").style.borderColor="";
var r=rng(hash(d)),n=6+Math.floor(r()*4),pool=POOL.slice(),deps=[],i;
for(i=0;i<n&&pool.length;i++){var e=pool.splice(Math.floor(r()*pool.length),1)[0];deps.push({h:e[0],ok:r()<e[1]})}
var bad=deps.filter(function(x){return!x.ok}).length;
var res=CHECKS.map(function(c,j){
var s,v=r(),p=c.p;
if(c.k==="Dependencies"){s=bad===0?"pass":bad<=2?"warn":"fail"}
else{s=v<p?"pass":v<p+.14?"warn":"fail"}
return{c:c,s:s}});
var web=res[4].s,sc=0;
res.forEach(function(x){sc+=x.c.w*(x.s==="pass"?1:x.s==="warn"?.5:0)});
sc=Math.round(sc);
$("target").innerHTML="<b>"+esc(d)+"</b><br>Report ID SC-"+hash(d).toString(16).toUpperCase().slice(0,6)+"<br>Generated "+new Date().toLocaleString()+" (simulated data)";
$("addr").innerHTML=res.map(function(x,j){return '<div class="hx '+x.s+'" title="'+esc(x.c.k)+': '+label(x.s)+'"><b>'+HEX[j]+'</b><span>'+esc(x.c.k)+'</span></div>'}).join("");
$("score").textContent=sc+"/100";
var col=sc>=85?"var(--pass)":sc>=60?"var(--warn)":"var(--fail)";$("score").style.color=col;$("ring").style.setProperty("--c",col);$("ring").style.setProperty("--p",sc);
$("verdict").textContent=sc>=85?"IPv6 ready":sc>=60?"Partly ready":"Not ready for IPv6 users";
$("checks").innerHTML=res.map(function(x){return '<div class="row"><div><b>'+esc(x.c.k)+'</b><small>Weight '+x.c.w+'</small></div><div><span class="pill '+x.s+'">'+label(x.s)+'</span></div><div>'+esc(x.c.d)+(x.s==="pass"?"":'<small>'+esc(x.c.f)+'</small>')+'</div></div>'}).join("");
$("deps").innerHTML='<tr><th>Host</th><th>IPv6</th><th>Impact</th></tr>'+deps.map(function(x){return '<tr><td class="mono">'+esc(x.h)+'</td><td><span class="pill '+(x.ok?"pass":"fail")+'">'+(x.ok?"Reachable":"IPv4 only")+'</span></td><td>'+(x.ok?"None":"IPv6-only visitors may see slow or broken loads")+'</td></tr>'}).join("");
var fx=res.filter(function(x){return x.s!=="pass"}).sort(function(a,b){return b.c.w*(b.s==="fail"?1:.5)-a.c.w*(a.s==="fail"?1:.5)});
$("fixes").innerHTML=fx.length?fx.slice(0,4).map(function(x){return '<div class="row"><div><b>'+esc(x.c.k)+'</b></div><div><span class="pill '+x.s+'">'+label(x.s)+'</span></div><div>'+esc(x.c.f)+'</div></div>'}).join(""):'<div class="row"><div><b>No action needed</b></div><div></div><div>All eight checks passed.</div></div>';
$("result").style.display="block";
$("result").scrollIntoView({behavior:"smooth",block:"nearest"});
}
$("go").addEventListener("click",audit);
$("pr").addEventListener("click",function(){window.print()});
$("dom").addEventListener("keydown",function(e){if(e.key==="Enter")audit()});
document.querySelectorAll("[data-d]").forEach(function(b){b.addEventListener("click",function(){$("dom").value=b.getAttribute("data-d");audit()})});
audit();
})();
