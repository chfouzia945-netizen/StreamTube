```javascript
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");

let pool = null;

const DATA = path.join(__dirname, "data", "db.json");

const ADMIN_EMAIL = "admin@streamtube.local";
const ADMIN_USERNAME = "admin";
const ADMIN_PASSWORD = "Admin123!";

const initial = {
  users: [{
    id: "u_admin",
    username: ADMIN_USERNAME,
    email: ADMIN_EMAIL,
    password: bcrypt.hashSync(ADMIN_PASSWORD, 10),
    role: "admin",
    createdAt: new Date().toISOString()
  }],
  videos: [],
  subscriptions: [],
  comments: [],
  reports: [],
  earnings: [],
  withdrawals: [],
  ads: []
};

function usePostgres(){
  return !!process.env.DATABASE_URL;
}

async function ensureAdmin(data){

  if(!data.users) data.users = [];

  let admin = data.users.find(
    u => String(u.email || "").toLowerCase() === ADMIN_EMAIL
  );

  if(!admin){

    admin = {
      id: "u_admin",
      username: ADMIN_USERNAME,
      email: ADMIN_EMAIL,
      password: bcrypt.hashSync(ADMIN_PASSWORD, 10),
      role: "admin",
      createdAt: new Date().toISOString()
    };

    data.users.push(admin);

  }else{

    admin.username = ADMIN_USERNAME;
    admin.role = "admin";

    /*
      Make sure the demo admin password is valid.
      Existing creator accounts and their passwords are untouched.
    */
    if(!admin.password){
      admin.password = bcrypt.hashSync(ADMIN_PASSWORD, 10);
    }

  }

  return data;
}

async function initDB(){

  if(usePostgres()){

    const {Pool} = require("pg");

    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_SSL === "false"
        ? false
        : {rejectUnauthorized:false}
    });

    await pool.query(`
      CREATE TABLE IF NOT EXISTS streamtube_state (
        id integer PRIMARY KEY,
        data jsonb NOT NULL,
        updated_at timestamptz NOT NULL DEFAULT now()
      )
    `);

    const r = await pool.query(
      "SELECT data FROM streamtube_state WHERE id=1"
    );

    if(!r.rowCount){

      let local;

      if(fs.existsSync(DATA)){
        local = JSON.parse(
          fs.readFileSync(DATA,"utf8")
        );
      }else{
        local = initial;
      }

      local = await ensureAdmin(local);

      await pool.query(
        "INSERT INTO streamtube_state(id,data) VALUES(1,$1)",
        [local]
      );

    }else{

      let existing = r.rows[0].data;

      existing = await ensureAdmin(existing);

      await pool.query(
        "UPDATE streamtube_state SET data=$1,updated_at=now() WHERE id=1",
        [existing]
      );

    }

    return;
  }


  if(!fs.existsSync(path.dirname(DATA))){
    fs.mkdirSync(path.dirname(DATA),{recursive:true});
  }

  if(!fs.existsSync(DATA)){

    fs.writeFileSync(
      DATA,
      JSON.stringify(initial,null,2)
    );

  }else{

    const data = JSON.parse(
      fs.readFileSync(DATA,"utf8")
    );

    const fixed = await ensureAdmin(data);

    fs.writeFileSync(
      DATA,
      JSON.stringify(fixed,null,2)
    );

  }
}


async function loadDB(){

  if(pool){

    const r = await pool.query(
      "SELECT data FROM streamtube_state WHERE id=1"
    );

    return r.rows[0].data;
  }

  return JSON.parse(
    fs.readFileSync(DATA,"utf8")
  );
}


async function saveDB(data){

  if(pool){

    await pool.query(
      "UPDATE streamtube_state SET data=$1,updated_at=now() WHERE id=1",
      [data]
    );

    return;
  }

  fs.writeFileSync(
    DATA,
    JSON.stringify(data,null,2)
  );
}


module.exports = {
  initDB,
  loadDB,
  saveDB
};
```
