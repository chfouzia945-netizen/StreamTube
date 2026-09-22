const fs = require('fs');
const path = require('path');
let pool = null;
const DATA = path.join(__dirname, 'data', 'db.json');
const initial = {
  users: [{id:'u_admin',username:'admin',email:'admin@streamtube.local',password:'',role:'admin',createdAt:new Date().toISOString()}],
  videos: [], subscriptions:[], comments:[], reports:[], earnings:[], withdrawals:[], ads:[]
};
function usePostgres(){ return !!process.env.DATABASE_URL; }
async function initDB(){
  if(usePostgres()){
    const {Pool}=require('pg');
    pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_SSL==='false'?false:{rejectUnauthorized:false}});
    await pool.query(`CREATE TABLE IF NOT EXISTS streamtube_state (id integer PRIMARY KEY, data jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())`);
    const r=await pool.query('SELECT id FROM streamtube_state WHERE id=1');
    if(!r.rowCount){
      const local=fs.existsSync(DATA)?JSON.parse(fs.readFileSync(DATA,'utf8')):initial;
      await pool.query('INSERT INTO streamtube_state(id,data) VALUES(1,$1)',[local]);
    }
    return;
  }
  if(!fs.existsSync(path.dirname(DATA))) fs.mkdirSync(path.dirname(DATA),{recursive:true});
  if(!fs.existsSync(DATA)) fs.writeFileSync(DATA,JSON.stringify(initial,null,2));
}
async function loadDB(){
  if(pool){ const r=await pool.query('SELECT data FROM streamtube_state WHERE id=1'); return r.rows[0].data; }
  return JSON.parse(fs.readFileSync(DATA,'utf8'));
}
async function saveDB(data){
  if(pool){ await pool.query('UPDATE streamtube_state SET data=$1,updated_at=now() WHERE id=1',[data]); return; }
  fs.writeFileSync(DATA,JSON.stringify(data,null,2));
}
module.exports={initDB,loadDB,saveDB};
