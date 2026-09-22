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

const SECRET =
  process.env.JWT_SECRET ||
  "change-this-secret-in-production";

if (
  process.env.NODE_ENV === "production" &&
  SECRET === "change-this-secret-in-production"
) {
  throw new Error("JWT_SECRET must be set in production");
}

if (!fs.existsSync(path.dirname(DATA))) {
  fs.mkdirSync(path.dirname(DATA), { recursive: true });
}

if (!fs.existsSync(UPLOADS)) {
  fs.mkdirSync(UPLOADS, { recursive: true });
}

if (!fs.existsSync(MEDIA)) {
  fs.mkdirSync(MEDIA, { recursive: true });
}


/* =========================
   INITIAL DATABASE
========================= */

const initial = {
  users: [
    {
      id: "u_admin",
      username: "admin",
      email: "admin@streamtube.local",
      password: bcrypt.hashSync("Admin123!", 10),
      role: "admin",
      status: "active",
      createdAt: new Date().toISOString()
    }
  ],

  videos: [
    {
      id: "v1",
      title: "Beautiful Places of Pakistan",
      description: "Explore beautiful places across Pakistan.",
      category: "Travel",
      creatorId: "u_demo",
      creatorName: "Pakistan Travel",
      views: 125000,
      likes: 3200,
      createdAt: new Date(Date.now() - 172800000).toISOString(),
      duration: "12:45",
      thumbnail: "",
      status: "published"
    },

    {
      id: "v2",
      title: "Best Gaming Highlights",
      description: "Gaming highlights and entertainment.",
      category: "Gaming",
      creatorId: "u_demo",
      creatorName: "Gaming Zone",
      views: 98000,
      likes: 2500,
      createdAt: new Date(Date.now() - 86400000).toISOString(),
      duration: "18:20",
      thumbnail: "",
      status: "published"
    },

    {
      id: "v3",
      title: "Learn Something New Today",
      description: "Simple educational videos.",
      category: "Education",
      creatorId: "u_demo",
      creatorName: "Learn Academy",
      views: 61000,
      likes: 1800,
      createdAt: new Date(Date.now() - 18000000).toISOString(),
      duration: "09:18",
      thumbnail: "",
      status: "published"
    }
  ],

  subscriptions: [],
  comments: [],
  reports: [],
  earnings: [],
  withdrawals: [],
  ads: []
};

if (!fs.existsSync(DATA)) {
  fs.writeFileSync(
    DATA,
    JSON.stringify(initial, null, 2)
  );
}


/* =========================
   DATABASE HELPERS
========================= */

async function db() {
  return loadDB();
}

async function save(d) {
  return saveDB(d);
}


/* =========================
   ID GENERATOR
========================= */

function id(prefix) {
  return (
    prefix +
    "_" +
    Date.now() +
    "_" +
    Math.random().toString(36).slice(2, 8)
  );
}


/* =========================
   AUTHENTICATION
========================= */

async function auth(req, res, next) {
  const h = req.headers.authorization || "";

  if (!h.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Login required"
    });
  }

  try {
    const token = h.slice(7);

    const decoded = jwt.verify(
      token,
      SECRET
    );

    const d = await db();

    const user = Array.isArray(d.users)
      ? d.users.find(
          u => u.id === decoded.id
        )
      : null;

    if (!user) {
      return res.status(401).json({
        error: "User not found"
      });
    }

    if (user.status === "disabled") {
      return res.status(401).json({
        error: "Account disabled"
      });
    }

    req.user = decoded;

    next();

  } catch (e) {

    return res.status(401).json({
      error: "Invalid session"
    });
  }
}


/* =========================
   OPTIONAL AUTH
========================= */

function optionalAuth(req, res, next) {

  const h =
    req.headers.authorization || "";

  if (h.startsWith("Bearer ")) {

    try {

      req.user = jwt.verify(
        h.slice(7),
        SECRET
      );

    } catch (e) {

      req.user = null;
    }
  }

  next();
}


/* =========================
   ADMIN AUTH
========================= */

function admin(req, res, next) {

  if (req.user?.role !== "admin") {

    return res.status(403).json({
      error: "Admin only"
    });
  }

  next();
}


/* =========================
   FILE UPLOAD
========================= */

const storage = multer.diskStorage({

  destination: (req, file, cb) => {

    cb(null, UPLOADS);
  },

  filename: (req, file, cb) => {

    cb(
      null,
      Date.now() +
        "_" +
        file.originalname.replace(
          /[^a-zA-Z0-9._-]/g,
          "_"
        )
    );
  }
});


const ALLOWED_VIDEO = new Set([
  "video/mp4",
  "video/webm",
  "video/quicktime",
  "video/x-matroska"
]);

const ALLOWED_IMAGE = new Set([
  "image/jpeg",
  "image/png",
  "image/webp"
]);


const upload = multer({

  storage,

  limits: {
    fileSize: 1024 * 1024 * 1024
  },

  fileFilter: (req, file, cb) => {

    const ok =
      file.fieldname === "video"
        ? ALLOWED_VIDEO.has(file.mimetype)

        : file.fieldname === "thumbnail"
        ? ALLOWED_IMAGE.has(file.mimetype)

        : false;

    cb(
      ok
        ? null
        : new Error("Unsupported file type"),
      ok
    );
  }
});


/* =========================
   SECURITY / MIDDLEWARE
========================= */

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false
  })
);

app.use(
  express.json({
    limit: "2mb"
  })
);

app.disable("x-powered-by");


app.use((req, res, next) => {

  res.setHeader(
    "X-Content-Type-Options",
    "nosniff"
  );

  res.setHeader(
    "X-Frame-Options",
    "SAMEORIGIN"
  );

  res.setHeader(
    "Referrer-Policy",
    "strict-origin-when-cross-origin"
  );

  next();
});


app.use(
  express.urlencoded({
    extended: true
  })
);


app.use(
  "/uploads",
  express.static(UPLOADS)
);


app.use(
  "/media",
  express.static(MEDIA, {

    setHeaders: (res, filePath) => {

      if (filePath.endsWith(".m3u8")) {

        res.setHeader(
          "Content-Type",
          "application/vnd.apple.mpegurl"
        );
      }

      if (filePath.endsWith(".ts")) {

        res.setHeader(
          "Content-Type",
          "video/mp2t"
        );
      }

      res.setHeader(
        "Cache-Control",
        "public, max-age=31536000, immutable"
      );
    }
  })
);


app.use(
  express.static(ROOT)
);


/* =========================
   REGISTER
========================= */

app.post(
  "/api/register",
  async (req, res) => {

    try {

      const {
        username,
        email,
        password
      } = req.body;

      const cleanUsername =
        String(username || "").trim();

      const cleanEmail =
        String(email || "")
          .trim()
          .toLowerCase();

      if (
        !cleanUsername ||
        !cleanEmail ||
        !password ||
        password.length < 8
      ) {

        return res.status(400).json({
          error:
            "Username, email and 8+ character password required"
        });
      }

      const d = await db();

      if (!Array.isArray(d.users)) {
        d.users = [];
      }

      const exists = d.users.some(
        u =>
          String(u.email || "")
            .toLowerCase() === cleanEmail ||

          String(u.username || "")
            .toLowerCase() ===
            cleanUsername.toLowerCase()
      );

      if (exists) {

        return res.status(409).json({
          error:
            "Username or email already exists"
        });
      }

      const u = {

        id: id("u"),

        username: cleanUsername,

        email: cleanEmail,

        password:
          bcrypt.hashSync(
            password,
            10
          ),

        role: "creator",

        status: "active",

        createdAt:
          new Date().toISOString()
      };


      /* IMPORTANT:
         Actually save new user
      */

      d.users.push(u);

      await save(d);


      const token = jwt.sign(
        {
          id: u.id,
          username: u.username,
          role: u.role
        },
        SECRET,
        {
          expiresIn: "7d"
        }
      );


      res.json({

        token,

        user: {
          id: u.id,
          username: u.username,
          email: u.email,
          role: u.role,
          status: u.status
        }

      });

    } catch (error) {

      console.error(
        "REGISTER ERROR:",
        error
      );

      res.status(500).json({
        error: "Registration failed"
      });
    }
  }
);


/* =========================
   LOGIN
========================= */

app.post(
  "/api/login",
  async (req, res) => {

    try {

      const d = await db();

      const email =
        String(req.body.email || "")
          .trim()
          .toLowerCase();

      const password =
        req.body.password || "";

      const users =
        Array.isArray(d.users)
          ? d.users
          : [];

      const u = users.find(
        x =>
          String(x.email || "")
            .toLowerCase() === email
      );


      if (!u) {

        return res.status(401).json({
          error:
            "Wrong email or password"
        });
      }


      /* DISABLED USER BLOCK */

      if (u.status === "disabled") {

        return res.status(401).json({
          error:
            "Wrong email or password"
        });
      }


      const passwordOK =
        bcrypt.compareSync(
          password,
          u.password
        );


      if (!passwordOK) {

        return res.status(401).json({
          error:
            "Wrong email or password"
        });
      }


      const token = jwt.sign(

        {
          id: u.id,
          username: u.username,
          role: u.role
        },

        SECRET,

        {
          expiresIn: "7d"
        }
      );


      res.json({

        token,

        user: {
          id: u.id,
          username: u.username,
          email: u.email,
          role: u.role,
          status: u.status || "active"
        }

      });

    } catch (error) {

      console.error(
        "LOGIN ERROR:",
        error
      );

      res.status(500).json({
        error: "Login failed"
      });
    }
  }
);


/* =========================
   CURRENT USER
========================= */

app.get(
  "/api/me",
  auth,
  async (req, res) => {

    const d = await db();

    const u =
      d.users.find(
        x => x.id === req.user.id
      );

    if (!u) {

      return res.status(404).json({
        error: "User not found"
      });
    }


    res.json({

      id: u.id,

      username: u.username,

      email: u.email,

      role: u.role,

      status: u.status || "active"

    });
  }
);


/* =========================
   VIDEOS
========================= */

app.get(
  "/api/videos",
  async (req, res) => {

    const d = await db();

    let v =
      d.videos.filter(
        x => x.status === "published"
      );


    const q =
      String(
        req.query.q || ""
      ).toLowerCase();


    const cat =
      String(
        req.query.category || ""
      );


    if (q) {

      v = v.filter(
        x =>
          (
            x.title +
            " " +
            x.description +
            " " +
            x.creatorName +
            " " +
            x.category
          )
            .toLowerCase()
            .includes(q)
      );
    }


    if (cat) {

      v = v.filter(
        x => x.category === cat
      );
    }


    v.sort(
      (a, b) =>
        new Date(b.createdAt) -
        new Date(a.createdAt)
    );


    res.json(v);
  }
);


app.get(
  "/api/videos/:id",
  async (req, res) => {

    const d = await db();

    const v =
      d.videos.find(
        x => x.id === req.params.id
      );


    if (!v) {

      return res.status(404).json({
        error: "Video not found"
      });
    }


    res.json(v);
  }
);


/* =========================
   VIDEO VIEW
========================= */

app.post(
  "/api/videos/:id/view",
  optionalAuth,
  async (req, res) => {

    const d = await db();

    const v =
      d.videos.find(
        x => x.id === req.params.id
      );


    if (!v) {

      return res.status(404).json({
        error: "Video not found"
      });
    }


    if (!d.videoViews) {
      d.videoViews = [];
    }


    const viewerId =
      req.user?.id || null;


    const ip =
      req.headers[
        "x-forwarded-for"
      ]?.split(",")[0]?.trim() ||

      req.socket.remoteAddress ||

      "";


    const userAgent =
      req.headers["user-agent"] || "";


    const viewerKey =
      viewerId
        ? "user:" + viewerId
        : "guest:" +
          ip +
          ":" +
          userAgent;


    const alreadyViewed =
      d.videoViews.some(
        x =>
          x.videoId === v.id &&
          x.viewerKey === viewerKey
      );


    if (!alreadyViewed) {

      d.videoViews.push({

        id: id("view"),

        videoId: v.id,

        viewerKey,

        createdAt:
          new Date().toISOString()
      });


      v.views =
        (v.views || 0) + 1;


      await save(d);
    }


    res.json({

      views: v.views || 0,

      counted:
        !alreadyViewed

    });
  }
);


/* =========================
   VIDEO LIKE
========================= */

app.post(
  "/api/videos/:id/like",
  auth,
  async (req, res) => {

    const d = await db();

    const v =
      d.videos.find(
        x => x.id === req.params.id
      );


    if (!v) {

      return res.status(404).json({
        error: "Video not found"
      });
    }


    if (!d.videoLikes) {
      d.videoLikes = [];
    }


    const alreadyLiked =
      d.videoLikes.some(
        x =>
          x.videoId === v.id &&
          x.userId === req.user.id
      );


    if (alreadyLiked) {

      return res.json({

        likes: v.likes || 0,

        alreadyLiked: true

      });
    }


    d.videoLikes.push({

      id: id("like"),

      videoId: v.id,

      userId: req.user.id,

      createdAt:
        new Date().toISOString()

    });


    v.likes =
      (v.likes || 0) + 1;


    await save(d);


    res.json({

      likes: v.likes,

      alreadyLiked: false

    });
  }
);


/* =========================
   COMMENTS
========================= */

app.post(
  "/api/videos/:id/comments",
  auth,
  async (req, res) => {

    const d = await db();

    const body =
      String(
        req.body.body || ""
      ).trim();


    if (!body) {

      return res.status(400).json({
        error: "Comment required"
      });
    }


    if (!Array.isArray(d.comments)) {
      d.comments = [];
    }


    const c = {

      id: id("c"),

      videoId:
        req.params.id,

      userId:
        req.user.id,

      username:
        req.user.username,

      body,

      createdAt:
        new Date().toISOString()
    };


    d.comments.push(c);

    await save(d);

    res.json(c);
  }
);


app.get(
  "/api/videos/:id/comments",
  async (req, res) => {

    const d = await db();

    const comments =
      Array.isArray(d.comments)
        ? d.comments
        : [];


    res.json(

      comments

        .filter(
          c =>
            c.videoId ===
            req.params.id
        )

        .sort(
          (a, b) =>
            new Date(b.createdAt) -
            new Date(a.createdAt)
        )
    );
  }
);


/* =========================
   SUBSCRIBE
========================= */

app.post(
  "/api/videos/:id/subscribe",
  auth,
  async (req, res) => {

    const d = await db();

    const v =
      d.videos.find(
        x => x.id === req.params.id
      );


    if (!v) {

      return res.status(404).json({
        error: "Video not found"
      });
    }


    if (
      v.creatorId ===
      req.user.id
    ) {

      return res.status(400).json({
        error:
          "You cannot subscribe to yourself"
      });
    }


    if (!Array.isArray(d.subscriptions)) {
      d.subscriptions = [];
    }


    const exists =
      d.subscriptions.some(
        s =>
          s.userId ===
            req.user.id &&

          s.creatorId ===
            v.creatorId
      );


    if (!exists) {

      d.subscriptions.push({

        id: id("s"),

        userId:
          req.user.id,

        creatorId:
          v.creatorId,

        createdAt:
          new Date().toISOString()

      });

      await save(d);
    }


    res.json({
      subscribed: true
    });
  }
);


/* =========================
   HLS TRANSCODE
========================= */

function transcodeToHls(
  inputPath,
  videoId,
  onDone
) {

  const outDir =
    path.join(
      MEDIA,
      videoId
    );


  fs.mkdirSync(
    outDir,
    {
      recursive: true
    }
  );


  const args = [

    "-y",

    "-i",
    inputPath,

    "-vf",
    "scale=w=1280:h=-2:force_original_aspect_ratio=decrease",

    "-c:v",
    "libx264",

    "-preset",
    "veryfast",

    "-crf",
    "23",

    "-c:a",
    "aac",

    "-b:a",
    "128k",

    "-f",
    "hls",

    "-hls_time",
    "6",

    "-hls_playlist_type",
    "vod",

    "-hls_segment_filename",
    path.join(
      outDir,
      "segment_%03d.ts"
    ),

    path.join(
      outDir,
      "index.m3u8"
    )
  ];


  const ff = spawn(

    process.env.FFMPEG_PATH ||
      "ffmpeg",

    args,

    {
      stdio: [
        "ignore",
        "ignore",
        "pipe"
      ]
    }
  );


  let err = "";


  ff.stderr.on(
    "data",
    d => {
      err +=
        d
          .toString()
          .slice(-2000);
    }
  );


  ff.on(
    "close",
    code => {

      onDone(
        code === 0
          ? null
          : new Error(
              err ||
                "FFmpeg failed"
            ),

        outDir
      );
    }
  );


  ff.on(
    "error",
    e =>
      onDone(
        e,
        outDir
      )
  );
}


/* =========================
   UPLOAD VIDEO
========================= */

app.post(
  "/api/upload",
  auth,

  upload.fields([
    {
      name: "video",
      maxCount: 1
    },

    {
      name: "thumbnail",
      maxCount: 1
    }
  ]),

  async (req, res) => {

    if (
      !req.files?.video?.[0]
    ) {

      return res.status(400).json({
        error:
          "Video file required"
      });
    }


    const d = await db();

    const f =
      req.files.video[0];

    const t =
      req.files.thumbnail?.[0];


    const videoId =
      id("v");


    const v = {

      id: videoId,

      title:
        req.body.title ||
        f.originalname,

      description:
        req.body.description ||
        "",

      category:
        req.body.category ||
        "Entertainment",

      creatorId:
        req.user.id,

      creatorName:
        req.user.username,

      views: 0,

      likes: 0,

      createdAt:
        new Date().toISOString(),

      duration: "",

      thumbnail:
        t
          ? "/uploads/" +
            t.filename
          : "",

      videoUrl:
        "/uploads/" +
        f.filename,

      hlsUrl: "",

      status:
        "processing"
    };


    d.videos.push(v);

    await save(d);


    transcodeToHls(

      path.join(
        UPLOADS,
        f.filename
      ),

      videoId,

      async (
        err
      ) => {

        const latest =
          await db();


        const item =
          latest.videos.find(
            x =>
              x.id ===
              videoId
          );


        if (!item) {
          return;
        }


        if (!err) {

          item.hlsUrl =
            "/media/" +
            videoId +
            "/index.m3u8";

          item.status =
            "published";

        } else {

          item.status =
            "published";

          item.processingError =
            "HLS transcode failed; original video remains available";
        }


        await save(latest);
      }
    );


    res.status(202).json(v);
  }
);


/* =========================
   STUDIO
========================= */

app.get(
  "/api/studio",
  auth,
  async (req, res) => {

    const d = await db();


    const vids =
      d.videos.filter(
        v =>
          v.creatorId ===
          req.user.id
      );


    const subscriptions =
      Array.isArray(
        d.subscriptions
      )
        ? d.subscriptions
        : [];


    const subs =
      subscriptions.filter(
        s =>
          s.creatorId ===
          req.user.id
      ).length;


    const views =
      vids.reduce(
        (n, v) =>
          n +
          Number(
            v.views || 0
          ),
        0
      );


    const likes =
      vids.reduce(
        (n, v) =>
          n +
          Number(
            v.likes || 0
          ),
        0
      );


    const earnings =
      Array.isArray(d.earnings)
        ? d.earnings
        : [];


    const er =
      earnings
        .filter(
          e =>
            e.creatorId ===
            req.user.id
        )
        .reduce(
          (n, e) =>
            n +
            Number(
              e.amount || 0
            ),
          0
        );


    res.json({

      videos: vids,

      subscribers: subs,

      views,

      likes,

      earnings: er

    });
  }
);


/* =========================
   WITHDRAW
========================= */

app.post(
  "/api/withdraw",
  auth,
  async (req, res) => {

    const amount =
      Number(
        req.body.amount || 0
      );


    if (amount < 10) {

      return res.status(400).json({
        error:
          "Minimum withdrawal is $10 in this demo"
      });
    }


    const d = await db();


    if (!Array.isArray(d.withdrawals)) {
      d.withdrawals = [];
    }


    d.withdrawals.push({

      id: id("w"),

      userId:
        req.user.id,

      amount,

      status:
        "pending",

      createdAt:
        new Date().toISOString()

    });


    await save(d);


    res.json({
      message:
        "Withdrawal request submitted"
    });
  }
);


/* =========================
   CREATOR EARNINGS
========================= */

app.get(
  "/api/creator/earnings",
  auth,
  async (req, res) => {

    const d = await db();


    const earnings =
      Array.isArray(d.earnings)
        ? d.earnings
        : [];


    const withdrawals =
      Array.isArray(d.withdrawals)
        ? d.withdrawals
        : [];


    const rows =
      earnings.filter(
        e =>
          e.creatorId ===
          req.user.id
      );


    const total =
      rows.reduce(
        (n, e) =>
          n +
          Number(
            e.amount || 0
          ),
        0
      );


    const paid =
      withdrawals

        .filter(
          w =>
            w.userId ===
              req.user.id &&

            w.status ===
              "paid"
        )

        .reduce(
          (n, w) =>
            n +
            Number(
              w.amount || 0
            ),
          0
        );


    res.json({

      total,

      paid,

      available:
        Math.max(
          0,
          total - paid
        ),

      ledger: rows

    });
  }
);


/* =========================
   ADS
========================= */

function adEligible(
  d,
  placement
) {

  const now =
    new Date();


  const ads =
    Array.isArray(d.ads)
      ? d.ads
      : [];


  return ads.filter(
    a =>

      a.status ===
        "active" &&

      (!a.startAt ||
        new Date(
          a.startAt
        ) <= now) &&

      (!a.endAt ||
        new Date(
          a.endAt
        ) >= now) &&

      Number(
        a.remainingBudget || 0
      ) > 0 &&

      (!placement ||
        a.placement ===
          placement)
  );
}


app.get(
  "/api/ads/serve",
  optionalAuth,
  async (req, res) => {

    const d = await db();


    const ads =
      adEligible(
        d,
        String(
          req.query.placement ||
            "watch"
        )
      );


    if (!ads.length) {

      return res.json({
        ad: null
      });
    }


    const a =
      ads[
        Math.floor(
          Math.random() *
            ads.length
        )
      ];


    res.json({

      ad: {

        id: a.id,

        title: a.title,

        creativeUrl:
          a.creativeUrl,

        targetUrl:
          a.targetUrl,

        placement:
          a.placement

      }

    });
  }
);


/* =========================
   AD IMPRESSION
========================= */

app.post(
  "/api/ads/:id/impression",
  optionalAuth,
  async (req, res) => {

    const d = await db();


    const a =
      d.ads.find(
        x =>
          x.id ===
          req.params.id
      );


    if (
      !a ||
      a.status !==
        "active" ||
      Number(
        a.remainingBudget || 0
      ) <= 0
    ) {

      return res.status(404).json({
        error:
          "Ad unavailable"
      });
    }


    const videoId =
      String(
        req.body.videoId || ""
      );


    const v =
      d.videos.find(
        x =>
          x.id ===
          videoId
      );


    const cpm =
      Number(
        a.creatorCpm || 0
      );


    const platformCpm =
      Number(
        a.platformCpm || 0
      );


    const totalCost =
      cpm +
      platformCpm;


    if (
      totalCost <= 0 ||
      Number(
        a.remainingBudget
      ) <
        totalCost / 1000
    ) {

      return res.status(409).json({
        error:
          "Campaign budget exhausted"
      });
    }


    a.impressions =
      (a.impressions || 0) +
      1;


    a.remainingBudget =
      Number(
        (
          Number(
            a.remainingBudget
          ) -
          totalCost / 1000
        ).toFixed(6)
      );


    if (
      v &&
      v.creatorId &&
      cpm > 0
    ) {

      if (!Array.isArray(d.earnings)) {
        d.earnings = [];
      }


      d.earnings.push({

        id: id("e"),

        creatorId:
          v.creatorId,

        videoId:
          v.id,

        adId:
          a.id,

        type:
          "ad_impression",

        amount:
          Number(
            (
              cpm / 1000
            ).toFixed(6)
          ),

        createdAt:
          new Date().toISOString()

      });
    }


    if (
      a.remainingBudget <= 0
    ) {

      a.status =
        "exhausted";
    }


    await save(d);


    res.json({
      ok: true
    });
  }
);


/* =========================
   ADMIN ADS
========================= */

app.post(
  "/api/admin/ads",
  auth,
  admin,
  async (req, res) => {

    const title =
      String(
        req.body.title || ""
      ).trim();


    const creativeUrl =
      String(
        req.body.creativeUrl ||
          ""
      ).trim();


    const targetUrl =
      String(
        req.body.targetUrl ||
          ""
      ).trim();


    const budget =
      Number(
        req.body.budget || 0
      );


    const creatorCpm =
      Number(
        req.body.creatorCpm || 0
      );


    const platformCpm =
      Number(
        req.body.platformCpm || 0
      );


    const placement =
      String(
        req.body.placement ||
          "watch"
      );


    if (
      !title ||
      !creativeUrl ||
      !targetUrl ||
      budget <= 0 ||
      creatorCpm < 0 ||
      platformCpm < 0
    ) {

      return res.status(400).json({
        error:
          "Valid title, creative URL, target URL and budget are required"
      });
    }


    if (
      creatorCpm +
        platformCpm <=
      0
    ) {

      return res.status(400).json({
        error:
          "CPM must be greater than zero"
      });
    }


    const d = await db();


    if (!Array.isArray(d.ads)) {
      d.ads = [];
    }


    const a = {

      id: id("ad"),

      title,

      creativeUrl,

      targetUrl,

      budget,

      remainingBudget:
        budget,

      creatorCpm,

      platformCpm,

      placement,

      impressions: 0,

      clicks: 0,

      status: "active",

      createdAt:
        new Date().toISOString()

    };


    d.ads.push(a);

    await save(d);


    res.status(201).json(a);
  }
);


app.get(
  "/api/admin/ads",
  auth,
  admin,
  async (req, res) => {

    const d = await db();

    res.json(
      Array.isArray(d.ads)
        ? d.ads
        : []
    );
  }
);


app.post(
  "/api/admin/ads/:id/status",
  auth,
  admin,
  async (req, res) => {

    const d = await db();


    const a =
      d.ads.find(
        x =>
          x.id ===
          req.params.id
      );


    if (!a) {

      return res.status(404).json({
        error:
          "Ad not found"
      });
    }


    const status =
      [
        "active",
        "paused"
      ].includes(
        req.body.status
      )
        ? req.body.status
        : a.status;


    a.status =
      status;


    await save(d);


    res.json(a);
  }
);


/* ==================================================
   ADMIN STATISTICS
================================================== */

app.get(
  "/api/admin/stats",
  auth,
  admin,
  async (req, res) => {

    try {

      const d = await db();


      const users =
        Array.isArray(d.users)
          ? d.users
          : [];


      const videos =
        Array.isArray(d.videos)
          ? d.videos
          : [];


      const comments =
        Array.isArray(d.comments)
          ? d.comments
          : [];


      const withdrawals =
        Array.isArray(
          d.withdrawals
        )
          ? d.withdrawals
          : [];


      const earnings =
        Array.isArray(d.earnings)
          ? d.earnings
          : [];


      const views =
        videos.reduce(
          (total, v) =>
            total +
            Number(
              v.views || 0
            ),
          0
        );


      const pendingWithdrawals =
        withdrawals.filter(
          w =>
            w.status ===
            "pending"
        ).length;


      const adRevenue =
        earnings.reduce(
          (total, e) =>
            total +
            Number(
              e.amount || 0
            ),
          0
        );


      res.json({

        users:
          users.length,

        videos:
          videos.length,

        views,

        comments:
          comments.length,

        withdrawals:
          pendingWithdrawals,

        adRevenue

      });

    } catch (error) {

      console.error(
        "ADMIN STATS ERROR:",
        error
      );


      res.status(500).json({
        error:
          "Failed to load admin statistics"
      });
    }
  }
);


/* ==================================================
   ADMIN USERS LIST
   IMPORTANT: This route is now separate.
================================================== */

app.get(
  "/api/admin/users",
  auth,
  admin,
  async (req, res) => {

    try {

      const d = await db();


      const allUsers =
        Array.isArray(d.users)
          ? d.users
          : [];


      const allVideos =
        Array.isArray(d.videos)
          ? d.videos
          : [];


      const users =
        allUsers.map(
          u => ({

            id:
              u.id,

            username:
              u.username,

            email:
              u.email,

            role:
              u.role ||
              "creator",

            /* IMPORTANT */
            status:
              u.status ||
              "active",

            createdAt:
              u.createdAt ||
              null,

            videos:
              allVideos.filter(
                v =>
                  v.creatorId ===
                  u.id
              ).length

          })
        );


      res.json(users);

    } catch (error) {

      console.error(
        "ADMIN USERS ERROR:",
        error
      );


      res.status(500).json({
        error:
          "Failed to load users"
      });
    }
  }
);


/* ==================================================
   ADMIN USER DISABLE / ENABLE
================================================== */

app.post(
  "/api/admin/users/:id/status",
  auth,
  admin,
  async (req, res) => {

    try {

      const d = await db();


      const u =
        d.users.find(
          x =>
            x.id ===
            req.params.id
        );


      if (!u) {

        return res.status(404).json({
          error:
            "User not found"
        });
      }


      /* ADMIN PROTECTION */

      if (
        u.role ===
        "admin"
      ) {

        return res.status(400).json({
          error:
            "Admin account cannot be disabled"
        });
      }


      const status =
        req.body.status ===
        "disabled"
          ? "disabled"
          : "active";


      u.status =
        status;


      await save(d);


      res.json({

        message:
          status ===
          "disabled"

            ? "User disabled"

            : "User enabled",

        user: {

          id:
            u.id,

          username:
            u.username,

          status:
            u.status

        }

      });

    } catch (error) {

      console.error(
        "ADMIN USER STATUS ERROR:",
        error
      );


      res.status(500).json({
        error:
          "Failed to update user status"
      });
    }
  }
);


/* ==================================================
   ADMIN DELETE USER
================================================== */

app.delete(
  "/api/admin/users/:id",
  auth,
  admin,
  async (req, res) => {

    try {

      const d = await db();


      const index =
        d.users.findIndex(
          x =>
            x.id ===
            req.params.id
        );


      if (index === -1) {

        return res.status(404).json({
          error:
            "User not found"
        });
      }


      const user =
        d.users[index];


      /* ADMIN PROTECTION */

      if (
        user.role ===
        "admin"
      ) {

        return res.status(400).json({
          error:
            "Admin account cannot be deleted"
        });
      }


      /* REMOVE USER */

      d.users.splice(
        index,
        1
      );


      /* REMOVE SUBSCRIPTIONS */

      if (
        Array.isArray(
          d.subscriptions
        )
      ) {

        d.subscriptions =
          d.subscriptions.filter(
            s =>
              s.userId !==
                user.id &&

              s.creatorId !==
                user.id
          );
      }


      /* REMOVE COMMENTS */

      if (
        Array.isArray(
          d.comments
        )
      ) {

        d.comments =
          d.comments.filter(
            c =>
              c.userId !==
              user.id
          );
      }


      /* REMOVE WITHDRAWALS */

      if (
        Array.isArray(
          d.withdrawals
        )
      ) {

        d.withdrawals =
          d.withdrawals.filter(
            w =>
              w.userId !==
              user.id
          );
      }


      /* REMOVE EARNINGS */

      if (
        Array.isArray(
          d.earnings
        )
      ) {

        d.earnings =
          d.earnings.filter(
            e =>
              e.creatorId !==
              user.id
          );
      }


      /* REMOVE LIKES */

      if (
        Array.isArray(
          d.videoLikes
        )
      ) {

        d.videoLikes =
          d.videoLikes.filter(
            l =>
              l.userId !==
              user.id
          );
      }


      /* REMOVE VIEW RECORDS */

      if (
        Array.isArray(
          d.videoViews
        )
      ) {

        d.videoViews =
          d.videoViews.filter(
            v =>
              v.viewerKey !==
              "user:" +
              user.id
          );
      }


      /*
        NOTE:
        User ke videos delete nahi
        kiye ja rahe.
        Existing videos database
        mein rahenge.
      */


      await save(d);


      res.json({

        message:
          "User deleted successfully",

        userId:
          user.id

      });

    } catch (error) {

      console.error(
        "ADMIN DELETE USER ERROR:",
        error
      );


      res.status(500).json({
        error:
          "Failed to delete user"
      });
    }
  }
);


/* ==================================================
   ADMIN WITHDRAWALS
================================================== */

app.get(
  "/api/admin/withdrawals",
  auth,
  admin,
  async (req, res) => {

    try {

      const d = await db();


      const withdrawals =
        Array.isArray(
          d.withdrawals
        )
          ? d.withdrawals
          : [];


      const users =
        Array.isArray(d.users)
          ? d.users
          : [];


      const result =
        withdrawals.map(
          w => ({

            ...w,

            user:
              users.find(
                u =>
                  u.id ===
                  w.userId
              )?.username ||
              "Unknown"

          })
        );


      res.json(result);

    } catch (error) {

      console.error(
        "ADMIN WITHDRAWALS ERROR:",
        error
      );


      res.status(500).json({
        error:
          "Failed to load withdrawals"
      });
    }
  }
);


app.post(
  "/api/admin/withdrawals/:id",
  auth,
  admin,
  async (req, res) => {

    const d = await db();


    const w =
      d.withdrawals.find(
        x =>
          x.id ===
          req.params.id
      );


    if (!w) {

      return res.status(404).json({
        error:
          "Not found"
      });
    }


    w.status =
      req.body.status ===
      "paid"
        ? "paid"
        : "rejected";


    await save(d);


    res.json(w);
  }
);


/* =========================
   REPORT
========================= */

app.post(
  "/api/report",
  optionalAuth,
  async (req, res) => {

    const d = await db();


    if (!Array.isArray(d.reports)) {
      d.reports = [];
    }


    d.reports.push({

      id: id("r"),

      videoId:
        req.body.videoId ||
        "",

      reason:
        req.body.reason ||
        "Other",

      userId:
        req.user?.id ||
        null,

      createdAt:
        new Date().toISOString()

    });


    await save(d);


    res.json({
      message:
        "Report received"
    });
  }
);


/* =========================
   HEALTH
========================= */

app.get(
  "/api/health",
  async (req, res) => {

    res.json({

      ok: true,

      service:
        "StreamTube",

      database:
        process.env.DATABASE_URL
          ? "postgresql"
          : "json",

      hls: true

    });
  }
);


/* =========================
   ERROR HANDLER
========================= */

app.use(
  (err, req, res, next) => {

    if (
      err &&
      err.message ===
        "Unsupported file type"
    ) {

      return res.status(400).json({
        error:
          err.message
      });
    }


    console.error(err);


    res.status(500).json({
      error:
        "Internal server error"
    });
  }
);


/* =========================
   FRONTEND FALLBACK
========================= */

app.get(
  "*",
  (req, res) =>
    res.sendFile(
      path.join(
        ROOT,
        "index.html"
      )
    )
);


/* =========================
   START SERVER
========================= */

initDB()

  .then(() => {

    const server =
      app.listen(
        PORT,
        () =>
          console.log(
            "StreamTube running on " +
            PORT
          )
      );


    const shutdown =
      () =>
        server.close(
          () =>
            process.exit(0)
        );


    process.on(
      "SIGTERM",
      shutdown
    );


    process.on(
      "SIGINT",
      shutdown
    );
  })

  .catch(err => {

    console.error(
      "Database initialization failed",
      err
    );

    process.exit(1);
  });
