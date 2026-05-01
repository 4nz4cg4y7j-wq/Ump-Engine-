const crypto = require("crypto");
const path = require("path");
const express = require("express");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-only-change-this-secret";
const DATABASE_URL = process.env.DATABASE_URL;
const MASTER_CODE = process.env.MASTER_CODE;
const MASTER_EMAIL = process.env.MASTER_EMAIL || "master@officialsengine.local";
const MASTER_NAME = process.env.MASTER_NAME || "Master Admin";

if (!DATABASE_URL) {
  console.warn("DATABASE_URL is not set. Add a Render Postgres database before deploying.");
}

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
    })
  : null;

app.use(express.json({ limit: "2mb" }));

const STATIC_FILES = new Set([
  "index.html",
  "pricing.html",
  "login.html",
  "register.html",
  "dashboard.html"
]);

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/:file", (req, res, next) => {
  if (!STATIC_FILES.has(req.params.file)) {
    return next();
  }
  res.sendFile(path.join(__dirname, req.params.file));
});

function requireDatabase() {
  if (!pool) {
    const error = new Error("Database is not configured.");
    error.status = 503;
    throw error;
  }
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.pbkdf2Sync(password, salt, 120000, 64, "sha512").toString("hex");
  return { salt, hash };
}

function verifyPassword(password, salt, expectedHash) {
  const { hash } = hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(expectedHash, "hex"));
}

function signSession(userId) {
  const payload = Buffer.from(JSON.stringify({
    userId,
    expiresAt: Date.now() + 1000 * 60 * 60 * 24 * 7
  })).toString("base64url");
  const signature = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

function readCookies(header = "") {
  return header.split(";").reduce((cookies, cookie) => {
    const [key, ...value] = cookie.trim().split("=");
    if (key) {
      cookies[key] = decodeURIComponent(value.join("="));
    }
    return cookies;
  }, {});
}

function verifySessionToken(token) {
  if (!token || !token.includes(".")) {
    return null;
  }

  const [payload, signature] = token.split(".");
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("base64url");

  if (Buffer.byteLength(signature) !== Buffer.byteLength(expected)) {
    return null;
  }

  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    return null;
  }

  const session = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  if (!session.expiresAt || session.expiresAt < Date.now()) {
    return null;
  }

  return session;
}

function setSessionCookie(res, userId) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader(
    "Set-Cookie",
    `oe_session=${signSession(userId)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${secure}`
  );
}

function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", "oe_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
}

async function currentUser(req) {
  requireDatabase();
  const cookies = readCookies(req.headers.cookie);
  const session = verifySessionToken(cookies.oe_session);

  if (!session) {
    return null;
  }

  const result = await pool.query(
    "select id, name, email, role, created_at from users where id = $1",
    [session.userId]
  );

  return result.rows[0] || null;
}

async function requireUser(req, res, next) {
  try {
    const user = await currentUser(req);
    if (!user) {
      return res.status(401).json({ error: "Please login first." });
    }
    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
}

async function initDatabase() {
  requireDatabase();

  await pool.query(`
    create table if not exists users (
      id text primary key,
      name text not null,
      email text unique not null,
      role text not null,
      password_hash text not null,
      password_salt text not null,
      created_at timestamptz not null default now()
    );

    create table if not exists groups (
      id text primary key,
      owner_id text not null references users(id) on delete cascade,
      name text not null,
      sport text not null,
      start_date text not null,
      end_date text not null,
      type text not null default 'static',
      created_at timestamptz not null default now()
    );

    create table if not exists umpires (
      id text primary key,
      group_id text not null references groups(id) on delete cascade,
      name text not null,
      contact text,
      availability text,
      conflicts text,
      abilities text,
      superiority integer not null default 3,
      created_at timestamptz not null default now()
    );

    create table if not exists games (
      id text primary key,
      group_id text not null references groups(id) on delete cascade,
      date text,
      time text,
      field text,
      team_one text not null,
      team_two text not null,
      level text,
      umpire_id text references umpires(id) on delete set null,
      source text not null default 'single',
      created_at timestamptz not null default now()
    );

    create table if not exists group_events (
      id text primary key,
      group_id text not null references groups(id) on delete cascade,
      title text not null,
      event_date text,
      event_time text,
      location text,
      notes text,
      created_at timestamptz not null default now()
    );

    create table if not exists group_reports (
      id text primary key,
      group_id text not null references groups(id) on delete cascade,
      report_type text not null,
      title text not null,
      details text,
      created_at timestamptz not null default now()
    );
  `);

  await pool.query("alter table groups add column if not exists type text not null default 'static'");
}

function toPublicUser(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    createdAt: row.created_at
  };
}

function mapGroup(row) {
  return {
    id: row.id,
    ownerEmail: row.owner_email,
    name: row.name,
    sport: row.sport,
    startDate: row.start_date,
    endDate: row.end_date,
    type: row.type,
    createdAt: row.created_at,
    umpires: [],
    games: [],
    events: [],
    reports: []
  };
}

function mapUmpire(row) {
  return {
    id: row.id,
    groupId: row.group_id,
    name: row.name,
    contact: row.contact || "",
    availability: row.availability || "",
    conflicts: row.conflicts || "",
    abilities: row.abilities || "",
    superiority: String(row.superiority || 3),
    createdAt: row.created_at
  };
}

function mapGame(row) {
  return {
    id: row.id,
    groupId: row.group_id,
    date: row.date || "",
    time: row.time || "",
    field: row.field || "",
    teamOne: row.team_one,
    teamTwo: row.team_two,
    level: row.level || "",
    umpireId: row.umpire_id || "",
    source: row.source,
    createdAt: row.created_at
  };
}

function mapEvent(row) {
  return {
    id: row.id,
    groupId: row.group_id,
    title: row.title,
    eventDate: row.event_date || "",
    eventTime: row.event_time || "",
    location: row.location || "",
    notes: row.notes || "",
    createdAt: row.created_at
  };
}

function mapReport(row) {
  return {
    id: row.id,
    groupId: row.group_id,
    reportType: row.report_type,
    title: row.title,
    details: row.details || "",
    createdAt: row.created_at
  };
}

async function fetchGroupsForUser(userId) {
  const groupsResult = await pool.query(
    `select g.*, u.email as owner_email
     from groups g
     join users u on u.id = g.owner_id
     where g.owner_id = $1
     order by g.created_at desc`,
    [userId]
  );

  const groups = groupsResult.rows.map(mapGroup);
  if (!groups.length) {
    return [];
  }

  const ids = groups.map(group => group.id);

  const umpiresResult = await pool.query(
    "select * from umpires where group_id = any($1::text[]) order by created_at asc",
    [ids]
  );

  const gamesResult = await pool.query(
    "select * from games where group_id = any($1::text[]) order by date asc, time asc, created_at asc",
    [ids]
  );

  const eventsResult = await pool.query(
    "select * from group_events where group_id = any($1::text[]) order by event_date asc, event_time asc, created_at asc",
    [ids]
  );

  const reportsResult = await pool.query(
    "select * from group_reports where group_id = any($1::text[]) order by created_at desc",
    [ids]
  );

  const byId = new Map(groups.map(group => [group.id, group]));

  umpiresResult.rows.forEach(row => byId.get(row.group_id)?.umpires.push(mapUmpire(row)));
  gamesResult.rows.forEach(row => byId.get(row.group_id)?.games.push(mapGame(row)));
  eventsResult.rows.forEach(row => byId.get(row.group_id)?.events.push(mapEvent(row)));
  reportsResult.rows.forEach(row => byId.get(row.group_id)?.reports.push(mapReport(row)));

  return groups;
}

async function assertGroupOwner(groupId, userId) {
  const result = await pool.query(
    "select id from groups where id = $1 and owner_id = $2",
    [groupId, userId]
  );
  return Boolean(result.rows[0]);
}

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.post("/api/register", async (req, res, next) => {
  try {
    requireDatabase();

    const firstName = String(req.body.firstName || "").trim();
    const lastName = String(req.body.lastName || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const role = String(req.body.role || "").trim();
    const password = String(req.body.password || "");

    if (!firstName || !lastName || !email || !role || password.length < 6) {
      return res.status(400).json({ error: "Please complete every required field." });
    }

    const existing = await pool.query("select id from users where email = $1", [email]);
    if (existing.rows[0]) {
      return res.status(409).json({ error: "An account with this email already exists." });
    }

    const id = crypto.randomUUID();
    const { salt, hash } = hashPassword(password);

    const result = await pool.query(
      `insert into users (id, name, email, role, password_hash, password_salt)
       values ($1, $2, $3, $4, $5, $6)
       returning id, name, email, role, created_at`,
      [id, `${firstName} ${lastName}`, email, role, hash, salt]
    );

    setSessionCookie(res, id);
    res.status(201).json({ user: toPublicUser(result.rows[0]) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/login", async (req, res, next) => {
  try {
    requireDatabase();

    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const result = await pool.query("select * from users where email = $1", [email]);
    const user = result.rows[0];

    if (!user || !verifyPassword(password, user.password_salt, user.password_hash)) {
      return res.status(401).json({ error: "Email or password is incorrect." });
    }

    setSessionCookie(res, user.id);
    res.json({ user: toPublicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/master-login", async (req, res, next) => {
  try {
    requireDatabase();

    if (!MASTER_CODE) {
      return res.status(503).json({ error: "Master Mode is not configured on the server." });
    }

    const code = String(req.body.code || "");
    if (code !== MASTER_CODE) {
      return res.status(401).json({ error: "Master code is incorrect." });
    }

    const existing = await pool.query("select * from users where email = $1", [MASTER_EMAIL]);
    let user = existing.rows[0];

    if (!user) {
      const password = crypto.randomBytes(32).toString("hex");
      const { salt, hash } = hashPassword(password);

      const result = await pool.query(
        `insert into users (id, name, email, role, password_hash, password_salt)
         values ($1, $2, $3, $4, $5, $6)
         returning id, name, email, role, created_at`,
        [crypto.randomUUID(), MASTER_NAME, MASTER_EMAIL, "master", hash, salt]
      );

      user = result.rows[0];
    }

    setSessionCookie(res, user.id);
    res.json({ user: toPublicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/logout", (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get("/api/me", requireUser, (req, res) => {
  res.json({ user: toPublicUser(req.user) });
});

app.get("/api/groups", requireUser, async (req, res, next) => {
  try {
    res.json({ groups: await fetchGroupsForUser(req.user.id) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/groups", requireUser, async (req, res, next) => {
  try {
    const name = String(req.body.name || "").trim();
    const sport = String(req.body.sport || "").trim();
    const startDate = String(req.body.startDate || "").trim();
    const endDate = String(req.body.endDate || "").trim();
    const type = String(req.body.type || "static").trim();

    if (!name || !sport) {
      return res.status(400).json({ error: "Group name and sport are required." });
    }

    if (!["static", "active"].includes(type)) {
      return res.status(400).json({ error: "Group type must be static or active." });
    }

    const id = crypto.randomUUID();

    await pool.query(
      `insert into groups (id, owner_id, name, sport, start_date, end_date, type)
       values ($1, $2, $3, $4, $5, $6, $7)`,
      [id, req.user.id, name, sport, startDate, endDate, type]
    );

    res.status(201).json({
      groups: await fetchGroupsForUser(req.user.id),
      activeGroupId: id
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/groups/:groupId/umpires", requireUser, async (req, res, next) => {
  try {
    const ownsGroup = await assertGroupOwner(req.params.groupId, req.user.id);

    if (!ownsGroup) {
      return res.status(404).json({ error: "Group not found." });
    }

    const name = String(req.body.name || "").trim();

    if (!name) {
      return res.status(400).json({ error: "Umpire name is required." });
    }

    await pool.query(
      `insert into umpires (id, group_id, name, contact, availability, conflicts, abilities, superiority)
       values ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        crypto.randomUUID(),
        req.params.groupId,
        name,
        String(req.body.contact || "").trim(),
        String(req.body.availability || "").trim(),
        String(req.body.conflicts || "").trim(),
        String(req.body.abilities || "").trim(),
        Number(req.body.superiority || 3)
      ]
    );

    res.status(201).json({ groups: await fetchGroupsForUser(req.user.id) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/groups/:groupId/games", requireUser, async (req, res, next) => {
  try {
    const ownsGroup = await assertGroupOwner(req.params.groupId, req.user.id);

    if (!ownsGroup) {
      return res.status(404).json({ error: "Group not found." });
    }

    const teamOne = String(req.body.teamOne || "").trim();
    const teamTwo = String(req.body.teamTwo || "").trim();

    if (!teamOne || !teamTwo) {
      return res.status(400).json({ error: "Both teams are required." });
    }

    const umpireId = String(req.body.umpireId || "").trim();

    if (umpireId) {
      const umpire = await pool.query(
        "select id from umpires where id = $1 and group_id = $2",
        [umpireId, req.params.groupId]
      );

      if (!umpire.rows[0]) {
        return res.status(400).json({ error: "Selected umpire does not belong to this group." });
      }
    }

    await pool.query(
      `insert into games (id, group_id, date, time, field, team_one, team_two, level, umpire_id, source)
       values ($1, $2, $3, $4, $5, $6, $7, $8, nullif($9, ''), $10)`,
      [
        crypto.randomUUID(),
        req.params.groupId,
        String(req.body.date || "").trim(),
        String(req.body.time || "").trim(),
        String(req.body.field || "").trim(),
        teamOne,
        teamTwo,
        String(req.body.level || "").trim(),
        umpireId,
        "single"
      ]
    );

    res.status(201).json({ groups: await fetchGroupsForUser(req.user.id) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/groups/:groupId/games/bulk", requireUser, async (req, res, next) => {
  try {
    const ownsGroup = await assertGroupOwner(req.params.groupId, req.user.id);

    if (!ownsGroup) {
      return res.status(404).json({ error: "Group not found." });
    }

    const games = Array.isArray(req.body.games) ? req.body.games : [];

    if (!games.length) {
      return res.status(400).json({ error: "No games were provided." });
    }

    for (const game of games) {
      await pool.query(
        `insert into games (id, group_id, date, time, field, team_one, team_two, level, source)
         values ($1, $2, $3, $4, $5, $6, $7, $8, 'bulk')`,
        [
          crypto.randomUUID(),
          req.params.groupId,
          String(game.date || "").trim(),
          String(game.time || "").trim(),
          String(game.field || "").trim(),
          String(game.teamOne || "Team 1").trim(),
          String(game.teamTwo || "Team 2").trim(),
          String(game.level || "").trim()
        ]
      );
    }

    res.status(201).json({
      groups: await fetchGroupsForUser(req.user.id),
      imported: games.length
    });
  } catch (error) {
    next(error);
  }
});

app.patch("/api/groups/:groupId/games/:gameId", requireUser, async (req, res, next) => {
  try {
    const ownsGroup = await assertGroupOwner(req.params.groupId, req.user.id);

    if (!ownsGroup) {
      return res.status(404).json({ error: "Group not found." });
    }

    const umpireId = String(req.body.umpireId || "").trim();

    if (umpireId) {
      const umpire = await pool.query(
        "select id from umpires where id = $1 and group_id = $2",
        [umpireId, req.params.groupId]
      );

      if (!umpire.rows[0]) {
        return res.status(400).json({ error: "Selected umpire does not belong to this group." });
      }
    }

    await pool.query(
      `update games
       set umpire_id = nullif($1, '')
       where id = $2 and group_id = $3`,
      [umpireId, req.params.gameId, req.params.groupId]
    );

    res.json({ groups: await fetchGroupsForUser(req.user.id) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/groups/:groupId/events", requireUser, async (req, res, next) => {
  try {
    const ownsGroup = await assertGroupOwner(req.params.groupId, req.user.id);

    if (!ownsGroup) {
      return res.status(404).json({ error: "Group not found." });
    }

    const title = String(req.body.title || "").trim();

    if (!title) {
      return res.status(400).json({ error: "Event title is required." });
    }

    await pool.query(
      `insert into group_events (id, group_id, title, event_date, event_time, location, notes)
       values ($1, $2, $3, $4, $5, $6, $7)`,
      [
        crypto.randomUUID(),
        req.params.groupId,
        title,
        String(req.body.eventDate || "").trim(),
        String(req.body.eventTime || "").trim(),
        String(req.body.location || "").trim(),
        String(req.body.notes || "").trim()
      ]
    );

    res.status(201).json({ groups: await fetchGroupsForUser(req.user.id) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/groups/:groupId/reports", requireUser, async (req, res, next) => {
  try {
    const ownsGroup = await assertGroupOwner(req.params.groupId, req.user.id);

    if (!ownsGroup) {
      return res.status(404).json({ error: "Group not found." });
    }

    const reportType = String(req.body.reportType || "").trim();
    const title = String(req.body.title || "").trim();

    if (!reportType || !title) {
      return res.status(400).json({ error: "Report type and title are required." });
    }

    await pool.query(
      `insert into group_reports (id, group_id, report_type, title, details)
       values ($1, $2, $3, $4, $5)`,
      [
        crypto.randomUUID(),
        req.params.groupId,
        reportType,
        title,
        String(req.body.details || "").trim()
      ]
    );

    res.status(201).json({ groups: await fetchGroupsForUser(req.user.id) });
  } catch (error) {
    next(error);
  }
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.use((error, req, res, next) => {
  console.error(error);

  res.status(error.status || 500).json({
    error: error.message || "Something went wrong."
  });
});

initDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Officials Engine server running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("Failed to start server:", error);
    process.exit(1);
  });
