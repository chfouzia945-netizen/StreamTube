const vid=new URLSearchParams(location.search).get("id");
function token(){return localStorage.token||""}
async function load(){if(!vid)return;let r=await fetch("/api/videos/"+vid);let v=await r.json();if(!r.ok)return title.textContent="Video not found";title.textContent=v.title;meta.textContent=`${(v.views||0).toLocaleString()} views • ${v.creatorName} • ${v.category}`;desc.textContent=v.description||"";if(v.status === "processing"){ player.innerHTML='<div class="card" style="padding:40px;text-align:center">Processing video for streaming…</div>'; setTimeout(load,3000); return; }
if(v.hlsUrl){
  player.innerHTML=`<video id="streamVideo" controls playsinline poster="${v.thumbnail||""}"></video>`;
  const el=document.getElementById("streamVideo");
  if(window.Hls && Hls.isSupported()){ const hls=new Hls(); hls.loadSource(v.hlsUrl); hls.attachMedia(el); }
  else if(el.canPlayType("application/vnd.apple.mpegurl")){ el.src=v.hlsUrl; }
  else if(v.videoUrl){ el.src=v.videoUrl; }
} else if(v.videoUrl){ player.innerHTML=`<video controls playsinline src="${v.videoUrl}" poster="${v.thumbnail||""}"></video>`; }
else { player.innerHTML=`<div class="thumb" style="height:500px">▶</div>`; }fetch("/api/videos/"+vid+"/view",{method:"POST"});loadComments();like.onclick=async()=>{let r=await fetch("/api/videos/"+vid+"/like",{method:"POST",headers:{Authorization:"Bearer "+token()}});let x=await r.json();if(r.status===401)return location="login.html";like.textContent="👍 Liked ("+x.likes+")"};sub.onclick=async()=>{let r=await fetch("/api/videos/"+vid+"/subscribe",{method:"POST",headers:{Authorization:"Bearer "+token()}});let x=await r.json();if(r.status===401)return location="login.html";sub.textContent=x.error||"Subscribed ✓"}}
async function loadComments(){let a=await (await fetch("/api/videos/"+vid+"/comments")).json();commentList.innerHTML=a.map(c=>`<div class="comment"><b>${c.username}</b><p>${c.body}</p></div>`).join("")||'<p class="muted">No comments yet.</p>'}
async function comment(){
  if(!token()) return location="login.html";

  const input=document.getElementById("comment");
  const body=input.value.trim();

  if(!body) return;

  const r=await fetch("/api/videos/"+vid+"/comments",{
    method:"POST",
    headers:{
      "Content-Type":"application/json",
      Authorization:"Bearer "+token()
    },
    body:JSON.stringify({body})
  });

  const x=await r.json();

  if(!r.ok){
    alert(x.error||"Comment failed");
    return;
  }

  input.value="";
  loadComments();
}
function shareVideo(){navigator.clipboard?.writeText(location.href);alert("Video link copied")}
async function reportVideo(){let reason=prompt("Report reason:");if(reason)await fetch("/api/report",{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+token()},body:JSON.stringify({videoId:vid,reason})});alert("Report received")}
load();
