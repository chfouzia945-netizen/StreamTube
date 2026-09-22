const express = require("express");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const crypto = require("crypto");
const { spawn } = require("child_process");
const { loadDB, saveDB, initDB } = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA = path.join(ROOT, "data", "db.json");
const UPLOADS = path.join(ROOT, "uploads");
const MEDIA = path.join(ROOT, "media");
const SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";
if (process.env.NODE_ENV === "production" && SECRET === "change-this-secret-in-production") {
  throw new Error("JWT_SECRET must be set in production");
}

if (!fs.existsSync(path.dirname(DATA))) fs.mkdirSync(path.dirname(DATA), {recursive:true});
if (!fs.existsSync(UPLOADS)) fs.mkdirSync(UPLOADS, {recursive:true});
if (!fs.existsSync(MEDIA)) fs.mkdirSync(MEDIA, {recursive:true});

const initial = {
  users: [{
    id:"u_admin", username:"admin", email:"admin@streamtube.local",
    password:bcrypt.hashSync("Admin123!",10), role:"admin", createdAt:new Date().toISOString()
  }],
  videos: [
    {id:"v1",title:"Beautiful Places of Pakistan",description:"Explore beautiful places across Pakistan.",category:"Travel",creatorId:"u_demo",creatorName:"Pakistan Travel",views:125000,likes:3200,createdAt:new Date(Date.now()-172800000).toISOString(),duration:"12:45",thumbnail:"",status:"published"},
    {id:"v2",title:"Best Gaming Highlights",description:"Gaming highlights and entertainment.",category:"Gaming",creatorId:"u_demo",creatorName:"Gaming Zone",views:98000,likes:2500,createdAt:new Date(Date.now()-86400000).toISOString(),duration:"18:20",thumbnail:"",status:"published"},
    {id:"v3",title:"Learn Something New Today",description:"Simple educational videos.",category:"Education",creatorId:"u_demo",creatorName:"Learn Academy",views:61000,likes:1800,createdAt:new Date(Date.now()-18000000).toISOString(),duration:"09:18",thumbnail:"",status:"published"}
  ],
  subscriptions:[], comments:[], reports:[], earnings:[], withdrawals:[], ads:[]
};
if (!fs.existsSync(DATA)) fs.writeFileSync(DATA, JSON.stringify(initial,null,2));

async function db(){ return loadDB(); }
async function save(d){ return saveDB(d); }
function id(p){ return p+"_"+Date.now()+"_"+Math.random().toString(36).slice(2,8); }
function auth(req,res,next){
  const h=req.headers.authorization||"";
  if(!h.startsWith("Bearer ")) return res.status(401).json({error:"Login required"});
  try { req.user=jwt.verify(h.slice(7),SECRET); next(); } catch(e){res.status(401).json({error:"Invalid session"});}
}
function optionalAuth(req,res,next){
  const h=req.headers.authorization||"";
  if(h.startsWith("Bearer ")){ try{req.user=jwt.verify(h.slice(7),SECRET)}catch(e){} }
  next();
}
function admin(req,res,next){ if(req.user?.role!=="admin") return res.status(403).json({error:"Admin only"}); next(); }

const storage=multer.diskStorage({
  destination:(req,file,cb)=>cb(null,UPLOADS),
  filename:(req,file,cb)=>cb(null, Date.now()+"_"+file.originalname.replace(/[^a-zA-Z0-9._-]/g,"_"))
});
const ALLOWED_VIDEO = new Set(["video/mp4","video/webm","video/quicktime","video/x-matroska"]);
const ALLOWED_IMAGE = new Set(["image/jpeg","image/png","image/webp"]);
const upload=multer({storage,limits:{fileSize:1024*1024*1024},fileFilter:(req,file,cb)=>{
  const ok = file.fieldname === "video" ? ALLOWED_VIDEO.has(file.mimetype) : file.fieldname === "thumbnail" ? ALLOWED_IMAGE.has(file.mimetype) : false;
  cb(ok ? null : new Error("Unsupported file type"), ok);
}});

app.use(helmet({contentSecurityPolicy:false}));
app.use(rateLimit({windowMs:15*60*1000,max:300,standardHeaders:true,legacyHeaders:false}));
app.use(express.json({limit:"2mb"}));
app.disable("x-powered-by");
app.use((req,res,next)=>{
  res.setHeader("X-Content-Type-Options","nosniff");
  res.setHeader("X-Frame-Options","SAMEORIGIN");
  res.setHeader("Referrer-Policy","strict-origin-when-cross-origin");
  next();
});
app.use(express.urlencoded({extended:true}));
app.use("/uploads",express.static(UPLOADS));
app.use("/media",express.static(MEDIA, {
  setHeaders:(res,filePath)=>{
    if (filePath.endsWith(".m3u8")) res.setHeader("Content-Type","application/vnd.apple.mpegurl");
    if (filePath.endsWith(".ts")) res.setHeader("Content-Type","video/mp2t");
    res.setHeader("Cache-Control","public, max-age=31536000, immutable");
  }
}));
app.use(express.static(ROOT));

app.post("/api/register", async (req,res)=>{
  const {username,email,password}=req.body;
  const cleanUsername=String(username||"").trim();
  const cleanEmail=String(email||"").trim().toLowerCase();
  if(!cleanUsername||!cleanEmail||!password||password.length<8) return res.status(400).json({error:"Username, email and 6+ character password required"});
  const d=await db();
  if(d.users.some(u=>u.email.toLowerCase()===cleanEmail||u.username.toLowerCase()===cleanUsername.toLowerCase())) return res.status(409).json({error:"Username or email already exists"});
  const u={id:id("u"),username:cleanUsername,email:cleanEmail,password:bcrypt.hashSync(password,10),role:"creator",createdAt:new Date().toISOString()};
  d.users.push(u); save(d);
  const token=jwt.sign({id:u.id,username:u.username,role:u.role},SECRET,{expiresIn:"7d"});
  res.json({token,user:{id:u.id,username:u.username,email:u.email,role:u.role}});
});

app.post("/api/login",async (req,res)=>{
  const d=await db(), {email,password}=req.body;
  const u=d.users.find(x=>x.email.toLowerCase()===String(email||"").toLowerCase());
  if(!u||!bcrypt.compareSync(password||"",u.password)) return res.status(401).json({error:"Wrong email or password"});
  const token=jwt.sign({id:u.id,username:u.username,role:u.role},SECRET,{expiresIn:"7d"});
  res.json({token,user:{id:u.id,username:u.username,email:u.email,role:u.role}});
});

app.get("/api/me",auth,async (req,res)=>{
  const d=await db(),u=d.users.find(x=>x.id===req.user.id);
  if(!u)return res.status(404).json({error:"User not found"});
  res.json({id:u.id,username:u.username,email:u.email,role:u.role});
});

app.get("/api/videos",async (req,res)=>{
  const d=await db(); let v=d.videos.filter(x=>x.status==="published");
  const q=String(req.query.q||"").toLowerCase(), cat=String(req.query.category||"");
  if(q)v=v.filter(x=>(x.title+" "+x.description+" "+x.creatorName+" "+x.category).toLowerCase().includes(q));
  if(cat)v=v.filter(x=>x.category===cat);
  v.sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt));
  res.json(v);
});

app.get("/api/videos/:id",async (req,res)=>{
  const d=await db(),v=d.videos.find(x=>x.id===req.params.id);
  if(!v)return res.status(404).json({error:"Video not found"});
  res.json(v);
});

app.post("/api/videos/:id/view",async (req,res)=>{
  const d=await db(),v=d.videos.find(x=>x.id===req.params.id);
  if(!v)return res.status(404).json({error:"Video not found"});
  v.views=(v.views||0)+1; save(d); res.json({views:v.views});
});

app.post("/api/videos/:id/like",auth,async (req,res)=>{
  const d=await db(),v=d.videos.find(x=>x.id===req.params.id);
  if(!v)return res.status(404).json({error:"Video not found"});
  v.likes=(v.likes||0)+1; save(d); res.json({likes:v.likes});
});

app.post("/api/videos/:id/comments",auth,async (req,res)=>{
  const d=await db(), body=String(req.body.body||"").trim();
  if(!body)return res.status(400).json({error:"Comment required"});
  const c={id:id("c"),videoId:req.params.id,userId:req.user.id,username:req.user.username,body,createdAt:new Date().toISOString()};
  d.comments.push(c); save(d); res.json(c);
});
app.get("/api/videos/:id/comments",async (req,res)=>{
  const d=await db(); res.json(d.comments.filter(c=>c.videoId===req.params.id).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)));
});

app.post("/api/videos/:id/subscribe",auth,async (req,res)=>{
  const d=await db(); const v=d.videos.find(x=>x.id===req.params.id);
  if(!v)return res.status(404).json({error:"Video not found"});
  if(v.creatorId===req.user.id)return res.status(400).json({error:"You cannot subscribe to yourself"});
  if(!d.subscriptions.some(s=>s.userId===req.user.id&&s.creatorId===v.creatorId)){
    d.subscriptions.push({id:id("s"),userId:req.user.id,creatorId:v.creatorId,createdAt:new Date().toISOString()}); save(d);
  }
  res.json({subscribed:true});
});


function transcodeToHls(inputPath, videoId, onDone){
  const outDir=path.join(MEDIA, videoId);
  fs.mkdirSync(outDir,{recursive:true});
  const args=["-y","-i",inputPath,
    "-vf","scale=w=1280:h=-2:force_original_aspect_ratio=decrease",
    "-c:v","libx264","-preset","veryfast","-crf","23","-c:a","aac","-b:a","128k",
    "-f","hls","-hls_time","6","-hls_playlist_type","vod","-hls_segment_filename",path.join(outDir,"segment_%03d.ts"),
    path.join(outDir,"index.m3u8")];
  const ff=spawn(process.env.FFMPEG_PATH || "ffmpeg",args,{stdio:["ignore","ignore","pipe"]});
  let err=""; ff.stderr.on("data",d=>{err+=d.toString().slice(-2000)});
  ff.on("close",code=>onDone(code===0 ? null : new Error(err||"FFmpeg failed"), outDir));
  ff.on("error",e=>onDone(e,outDir));
}

app.post("/api/upload",auth,upload.fields([{name:"video",maxCount:1},{name:"thumbnail",maxCount:1}]),async (req,res)=>{
  if(!req.files?.video?.[0]) return res.status(400).json({error:"Video file required"});
  const d=await db(), f=req.files.video[0], t=req.files.thumbnail?.[0];
  const videoId=id("v");
  const v={id:videoId,title:req.body.title||f.originalname,description:req.body.description||"",category:req.body.category||"Entertainment",
    creatorId:req.user.id,creatorName:req.user.username,views:0,likes:0,createdAt:new Date().toISOString(),
    duration:"",thumbnail:t?"/uploads/"+t.filename:"",videoUrl:"/uploads/"+f.filename,hlsUrl:"",status:"processing"};
  d.videos.push(v); save(d);
  transcodeToHls(path.join(UPLOADS,f.filename),videoId,async (err)=>{
    const latest=await db(), item=latest.videos.find(x=>x.id===videoId);
    if(!item)return;
    if(!err){ item.hlsUrl="/media/"+videoId+"/index.m3u8"; item.status="published"; }
    else { item.status="published"; item.processingError="HLS transcode failed; original video remains available"; }
    save(latest);
  });
  res.status(202).json(v);
});

app.get("/api/studio",auth,async (req,res)=>{
  const d=await db(), vids=d.videos.filter(v=>v.creatorId===req.user.id);
  const subs=d.subscriptions.filter(s=>s.creatorId===req.user.id).length;
  const views=vids.reduce((n,v)=>n+(v.views||0),0);
  const likes=vids.reduce((n,v)=>n+(v.likes||0),0);
  const er=d.earnings.filter(e=>e.creatorId===req.user.id).reduce((n,e)=>n+e.amount,0);
  res.json({videos:vids,subscribers:subs,views,likes,earnings:er});
});

app.post("/api/withdraw",auth,async (req,res)=>{
  const amount=Number(req.body.amount||0);
  if(amount<10)return res.status(400).json({error:"Minimum withdrawal is $10 in this demo"});
  const d=await db(); d.withdrawals.push({id:id("w"),userId:req.user.id,amount,status:"pending",createdAt:new Date().toISOString()}); save(d);
  res.json({message:"Withdrawal request submitted"});
});

app.get("/api/creator/earnings",auth,async (req,res)=>{
  const d=await db();
  const rows=d.earnings.filter(e=>e.creatorId===req.user.id);
  const total=rows.reduce((n,e)=>n+Number(e.amount||0),0);
  const paid=d.withdrawals.filter(w=>w.userId===req.user.id&&w.status==="paid").reduce((n,w)=>n+Number(w.amount||0),0);
  res.json({total,paid,available:Math.max(0,total-paid),ledger:rows});
});


function adEligible(d, placement){
  const now=new Date();
  return d.ads.filter(a=>a.status==='active' && (!a.startAt || new Date(a.startAt)<=now) && (!a.endAt || new Date(a.endAt)>=now) && Number(a.remainingBudget||0)>0 && (!placement || a.placement===placement));
}

app.get('/api/ads/serve',optionalAuth,async (req,res)=>{
  const d=await db();
  const ads=adEligible(d,String(req.query.placement||'watch'));
  if(!ads.length) return res.json({ad:null});
  const a=ads[Math.floor(Math.random()*ads.length)];
  res.json({ad:{id:a.id,title:a.title,creativeUrl:a.creativeUrl,targetUrl:a.targetUrl,placement:a.placement}});
});

app.post('/api/ads/:id/impression',optionalAuth,async (req,res)=>{
  const d=await db(), a=d.ads.find(x=>x.id===req.params.id);
  if(!a || a.status!=='active' || Number(a.remainingBudget||0)<=0) return res.status(404).json({error:'Ad unavailable'});
  const videoId=String(req.body.videoId||'');
  const v=d.videos.find(x=>x.id===videoId);
  const cpm=Number(a.creatorCpm||0);
  const platformCpm=Number(a.platformCpm||0);
  const totalCost=cpm+platformCpm;
  if(totalCost<=0 || Number(a.remainingBudget)<totalCost/1000) return res.status(409).json({error:'Campaign budget exhausted'});
  a.impressions=(a.impressions||0)+1;
  a.remainingBudget=Number((Number(a.remainingBudget)-totalCost/1000).toFixed(6));
  if(v && v.creatorId && cpm>0){
    d.earnings.push({id:id('e'),creatorId:v.creatorId,videoId:v.id,adId:a.id,type:'ad_impression',amount:Number((cpm/1000).toFixed(6)),createdAt:new Date().toISOString()});
  }
  if(a.remainingBudget<=0) a.status='exhausted';
  save(d); res.json({ok:true});
});

app.post('/api/admin/ads',auth,admin,async (req,res)=>{
  const title=String(req.body.title||'').trim();
  const creativeUrl=String(req.body.creativeUrl||'').trim();
  const targetUrl=String(req.body.targetUrl||'').trim();
  const budget=Number(req.body.budget||0);
  const creatorCpm=Number(req.body.creatorCpm||0);
  const platformCpm=Number(req.body.platformCpm||0);
  const placement=String(req.body.placement||'watch');
  if(!title||!creativeUrl||!targetUrl||budget<=0||creatorCpm<0||platformCpm<0) return res.status(400).json({error:'Valid title, creative URL, target URL and budget are required'});
  if(creatorCpm+platformCpm<=0) return res.status(400).json({error:'CPM must be greater than zero'});
  const d=await db();
  const a={id:id('ad'),title,creativeUrl,targetUrl,budget,remainingBudget:budget,creatorCpm,platformCpm,placement,impressions:0,clicks:0,status:'active',createdAt:new Date().toISOString()};
  d.ads.push(a); save(d); res.status(201).json(a);
});

app.get('/api/admin/ads',auth,admin,async (req,res)=>{ const d=await db(); res.json(d.ads); });
app.post('/api/admin/ads/:id/status',auth,admin,async (req,res)=>{
  const d=await db(),a=d.ads.find(x=>x.id===req.params.id); if(!a)return res.status(404).json({error:'Ad not found'});
  const status=['active','paused'].includes(req.body.status)?req.body.status:a.status; a.status=status; save(d); res.json(a);
});

app.get("/api/admin/stats",auth,admin,async (req,res)=>{
  const d=await db();
  res.json({
    users:d.users.length,videos:d.videos.length,views:d.videos.reduce((n,v)=>n+(v.views||0),0),
    comments:d.comments.length,withdrawals:d.withdrawals.filter(w=>w.status==="pending").length,
    adRevenue:d.earnings.reduce((n,e)=>n+e.amount,0)
  });
});
app.get("/api/admin/withdrawals",auth,admin,async (req,res)=>{
  const d=await db(); res.json(d.withdrawals.map(w=>({...w,user:d.users.find(u=>u.id===w.userId)?.username||"Unknown"})));
});
app.post("/api/admin/withdrawals/:id",auth,admin,async (req,res)=>{
  const d=await db(),w=d.withdrawals.find(x=>x.id===req.params.id);
  if(!w)return res.status(404).json({error:"Not found"});
  w.status=req.body.status==="paid"?"paid":"rejected"; save(d); res.json(w);
});

app.post("/api/report",optionalAuth,async (req,res)=>{
  const d=await db(); d.reports.push({id:id("r"),videoId:req.body.videoId||"",reason:req.body.reason||"Other",userId:req.user?.id||null,createdAt:new Date().toISOString()}); save(d);
  res.json({message:"Report received"});
});

app.get("/api/health",async (req,res)=>res.json({ok:true,service:"StreamTube",database:process.env.DATABASE_URL?"postgresql":"json",hls:true}));
app.use((err,req,res,next)=>{
  if(err && err.message === "Unsupported file type") return res.status(400).json({error:err.message});
  console.error(err);
  res.status(500).json({error:"Internal server error"});
});
app.get("*",(req,res)=>res.sendFile(path.join(ROOT,"index.html")));
initDB().then(()=>{
  const server=app.listen(PORT,()=>console.log("StreamTube running on "+PORT));
  const shutdown=()=>server.close(()=>process.exit(0));
  process.on("SIGTERM",shutdown); process.on("SIGINT",shutdown);
}).catch(err=>{console.error("Database initialization failed",err);process.exit(1)});
