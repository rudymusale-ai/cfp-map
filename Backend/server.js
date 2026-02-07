require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { pool } = require('./db');
const path = require('path');
const app = express();
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET || (process.env.NODE_ENV === 'production' ? '' : 'dev_secret');
const allowedOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

if (!jwtSecret) {
  throw new Error('JWT_SECRET is required in production');
}

app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (allowedOrigins.length === 0) {
      if (process.env.NODE_ENV === 'production') return cb(null, false);
      return cb(null, true);
    }
    return cb(null, allowedOrigins.includes(origin));
  }
}));

// Serve the Frontend folder so HTML is available on the same origin (http://localhost:3000)
const frontendPath = path.join(__dirname, '..', 'Frontend');
app.use(express.static(frontendPath));

// Simple health
app.get('/health', (req, res) => res.json({ ok: true }));

// Helpers
async function getActiveCycleId() {
  const [rows] = await pool.query('SELECT id, annee FROM cycles WHERE actif = 1 ORDER BY id DESC LIMIT 1');
  if (rows.length) return rows[0].id;
  const year = new Date().getFullYear();
  const [ins] = await pool.query('INSERT INTO cycles (annee, actif) VALUES (?, 1)', [year]);
  return ins.insertId;
}

async function ensureRoleId(name) {
  const [r] = await pool.query('SELECT id FROM roles WHERE name = ?', [name]);
  if (r.length) return r[0].id;
  const [ins] = await pool.query('INSERT INTO roles (name) VALUES (?)', [name]);
  return ins.insertId;
}

async function logAction(userId, action) {
  try {
    await pool.query('INSERT INTO logs (user_id, action) VALUES (?, ?)', [userId || null, action]);
  } catch (e) {
    // ignore log failures
  }
}

async function isFirstUser() {
  const [rows] = await pool.query('SELECT COUNT(*) AS total FROM users');
  return rows && rows[0] && rows[0].total === 0;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeCsvValue(value) {
  const raw = String(value ?? '');
  const safe = /^[=+\-@]/.test(raw) ? "'" + raw : raw;
  return '"' + safe.replace(/"/g, '""') + '"';
}

// Register (creates role if missing)
app.post('/auth/register', async (req, res) => {
  const { nom, email, password, role } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email & password required' });
  try {
    const firstUser = await isFirstUser();
    const roleName = role || 'viewer';
    const allowedRoles = new Set(['admin', 'superviseur', 'enqueteur', 'viewer']);
    if (!allowedRoles.has(roleName)) return res.status(400).json({ error: 'invalid_role' });

    if (firstUser) {
      const bootstrapKey = process.env.BOOTSTRAP_KEY;
      if (bootstrapKey) {
        const provided = req.headers['x-bootstrap-key'];
        if (provided !== bootstrapKey) return res.status(403).json({ error: 'bootstrap_forbidden' });
      }
    } else {
      const auth = req.headers['authorization'];
      const token = auth && auth.split(' ')[1];
      if (!token) return res.status(401).json({ error: 'no_token' });
      let user;
      try {
        user = jwt.verify(token, jwtSecret);
      } catch (e) {
        return res.status(403).json({ error: 'invalid_token' });
      }
      if (!user || user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
    }

    const roleId = await ensureRoleId(roleName);

    const hash = await bcrypt.hash(password, 10);
    const [result] = await pool.query('INSERT INTO users (role_id, nom, email, password) VALUES (?,?,?,?)', [roleId, nom || null, email, hash]);
    return res.json({ id: result.insertId });
  } catch (err) {
    console.error(err);
    if (err && err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'email_exists' });
    return res.status(500).json({ error: 'register_failed' });
  }
});

// Login -> returns JWT
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email & password required' });
  try {
    const [rows] = await pool.query('SELECT id, nom, email, password, role_id FROM users WHERE email = ?', [email]);
    if (!rows.length) return res.status(401).json({ error: 'invalid_credentials' });
    const u = rows[0];
    const ok = await bcrypt.compare(password, u.password);
    if (!ok) return res.status(401).json({ error: 'invalid_credentials' });

    const [roles] = await pool.query('SELECT name FROM roles WHERE id = ?', [u.role_id]);
    const roleName = (roles && roles[0] && roles[0].name) ? roles[0].name : 'viewer';

    const payload = { id: u.id, nom: u.nom, email: u.email, role: roleName };
    const token = jwt.sign(payload, jwtSecret, { expiresIn: '8h' });
    return res.json({ token });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'login_failed' });
  }
});

function authenticateToken(req, res, next) {
  const auth = req.headers['authorization'];
  const token = auth && auth.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'no_token' });
  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) return res.status(403).json({ error: 'invalid_token' });
    req.user = user;
    next();
  });
}

function requireRole(roles) {
  return (req, res, next) => {
    const role = req.user && req.user.role;
    if (!role || !roles.includes(role)) {
      return res.status(403).json({ error: 'forbidden' });
    }
    next();
  };
}

// /me supports token in Authorization header; if missing, fallback to first user or default role
app.get('/me', async (req, res) => {
  const auth = req.headers['authorization'];
  const token = auth && auth.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'no_token' });
  try {
    const user = jwt.verify(token, jwtSecret);
    return res.json({ id: user.id, nom: user.nom, email: user.email, role: user.role });
  } catch (e) {
    return res.status(401).json({ error: 'invalid_token' });
  }
});

// Dashboard stats
app.get('/dashboard-data', authenticateToken, async (req, res) => {
  try {
    const [totalRows] = await pool.query('SELECT COUNT(*) AS total FROM centres');
    const [publicRows] = await pool.query("SELECT COUNT(*) AS total FROM centres WHERE type='public'");
    const [privateRows] = await pool.query("SELECT COUNT(*) AS total FROM centres WHERE type='prive'");
    return res.json({
      total: totalRows[0].total,
      public: publicRows[0].total,
      private: privateRows[0].total,
      updated: new Date().toLocaleDateString()
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'dashboard_failed' });
  }
});

// Centres CRUD
app.get('/centres', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT c.id, c.nom, c.type, c.capacite, c.statut_agrement, c.adresse,
             sd.nom AS sousdivision,
             cl.latitude AS lat, cl.longitude AS lng
      FROM centres c
      LEFT JOIN sous_divisions sd ON sd.id = c.sous_division_id
      LEFT JOIN centre_locations cl ON cl.centre_id = c.id
      ORDER BY c.id DESC
    `);

    const [filRows] = await pool.query(`
      SELECT cf.centre_id, f.nom AS filiere
      FROM centre_filieres cf
      JOIN filieres f ON f.id = cf.filiere_id
    `);

    const byCentre = {};
    filRows.forEach(r => {
      if (!byCentre[r.centre_id]) byCentre[r.centre_id] = [];
      byCentre[r.centre_id].push(r.filiere);
    });

    const result = rows.map(r => ({
      id: r.id,
      nom: r.nom,
      type: r.type,
      sousdivision: r.sousdivision || '',
      filiere: (byCentre[r.id] && byCentre[r.id][0]) || '',
      filieres: byCentre[r.id] || [],
      statut: r.statut_agrement || '',
      capacite: r.capacite || 0,
      lat: r.lat ? Number(r.lat) : null,
      lng: r.lng ? Number(r.lng) : null,
      adresse: r.adresse || ''
    }));

    return res.json(result);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'centres_failed' });
  }
});

app.get('/centres/:id', authenticateToken, async (req, res) => {
  try {
    const id = req.params.id;
    const [rows] = await pool.query(`
      SELECT c.id, c.nom, c.type, c.capacite, c.statut_agrement, c.adresse,
             sd.nom AS sousdivision,
             cl.latitude AS lat, cl.longitude AS lng
      FROM centres c
      LEFT JOIN sous_divisions sd ON sd.id = c.sous_division_id
      LEFT JOIN centre_locations cl ON cl.centre_id = c.id
      WHERE c.id = ?
    `, [id]);
    if (!rows.length) return res.status(404).json({ error: 'not_found' });

    const [filRows] = await pool.query(`
      SELECT f.nom AS filiere
      FROM centre_filieres cf
      JOIN filieres f ON f.id = cf.filiere_id
      WHERE cf.centre_id = ?
    `, [id]);

    const r = rows[0];
    return res.json({
      id: r.id,
      nom: r.nom,
      type: r.type,
      sousdivision: r.sousdivision || '',
      filiere: (filRows[0] && filRows[0].filiere) || '',
      filieres: filRows.map(f => f.filiere),
      statut: r.statut_agrement || '',
      capacite: r.capacite || 0,
      lat: r.lat ? Number(r.lat) : null,
      lng: r.lng ? Number(r.lng) : null,
      adresse: r.adresse || ''
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'centre_failed' });
  }
});

app.post('/centres', authenticateToken, requireRole(['admin','superviseur']), async (req, res) => {
  try {
    const { nom, type, sousdivision, adresse, capacite, statut, lat, lng, filieres } = req.body;
    const cycleId = await getActiveCycleId();

    let sousId = null;
    if (sousdivision) {
      const [sd] = await pool.query('SELECT id FROM sous_divisions WHERE nom = ?', [sousdivision]);
      if (sd.length) sousId = sd[0].id;
      else {
        const [ins] = await pool.query('INSERT INTO sous_divisions (nom) VALUES (?)', [sousdivision]);
        sousId = ins.insertId;
      }
    }

    const [ins] = await pool.query(
      'INSERT INTO centres (nom, type, sous_division_id, adresse, capacite, statut_agrement, cycle_id) VALUES (?,?,?,?,?,?,?)',
      [nom || null, type || 'public', sousId, adresse || null, capacite || 0, statut || null, cycleId]
    );
    const centreId = ins.insertId;

    if (lat !== undefined && lat !== null && lat !== '' && lng !== undefined && lng !== null && lng !== '') {
      await pool.query('INSERT INTO centre_locations (centre_id, latitude, longitude) VALUES (?,?,?)', [centreId, lat, lng]);
    }

    if (Array.isArray(filieres)) {
      for (const f of filieres) {
        if (!f) continue;
        const [fr] = await pool.query('SELECT id FROM filieres WHERE nom = ?', [f]);
        const filiereId = fr.length ? fr[0].id : (await pool.query('INSERT INTO filieres (nom) VALUES (?)', [f]))[0].insertId;
        await pool.query('INSERT IGNORE INTO centre_filieres (centre_id, filiere_id) VALUES (?,?)', [centreId, filiereId]);
      }
    }

    await logAction(req.user && req.user.id, `CREATE centre:${nom || centreId}`);
    return res.json({ id: centreId });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'centre_create_failed' });
  }
});

app.put('/centres', authenticateToken, requireRole(['admin','superviseur']), async (req, res) => {
  try {
    const { id, nom, type, sousdivision, adresse, capacite, statut, lat, lng, filieres } = req.body;
    if (!id) return res.status(400).json({ error: 'id_required' });

    let sousId = null;
    if (sousdivision) {
      const [sd] = await pool.query('SELECT id FROM sous_divisions WHERE nom = ?', [sousdivision]);
      if (sd.length) sousId = sd[0].id;
      else {
        const [ins] = await pool.query('INSERT INTO sous_divisions (nom) VALUES (?)', [sousdivision]);
        sousId = ins.insertId;
      }
    }

    await pool.query(
      'UPDATE centres SET nom = ?, type = ?, sous_division_id = ?, adresse = ?, capacite = ?, statut_agrement = ? WHERE id = ?',
      [nom || null, type || 'public', sousId, adresse || null, capacite || 0, statut || null, id]
    );

    if (lat !== undefined && lat !== null && lat !== '' && lng !== undefined && lng !== null && lng !== '') {
      const [loc] = await pool.query('SELECT id FROM centre_locations WHERE centre_id = ?', [id]);
      if (loc.length) {
        await pool.query('UPDATE centre_locations SET latitude = ?, longitude = ? WHERE centre_id = ?', [lat, lng, id]);
      } else {
        await pool.query('INSERT INTO centre_locations (centre_id, latitude, longitude) VALUES (?,?,?)', [id, lat, lng]);
      }
    }

    if (Array.isArray(filieres)) {
      await pool.query('DELETE FROM centre_filieres WHERE centre_id = ?', [id]);
      for (const f of filieres) {
        if (!f) continue;
        const [fr] = await pool.query('SELECT id FROM filieres WHERE nom = ?', [f]);
        const filiereId = fr.length ? fr[0].id : (await pool.query('INSERT INTO filieres (nom) VALUES (?)', [f]))[0].insertId;
        await pool.query('INSERT IGNORE INTO centre_filieres (centre_id, filiere_id) VALUES (?,?)', [id, filiereId]);
      }
    }

    await logAction(req.user && req.user.id, `UPDATE centre:${id}`);
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'centre_update_failed' });
  }
});

app.delete('/centres/:id', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const id = req.params.id;
    await pool.query('DELETE FROM centre_filieres WHERE centre_id = ?', [id]);
    await pool.query('DELETE FROM centre_equipements WHERE centre_id = ?', [id]);
    await pool.query('DELETE FROM personnel WHERE centre_id = ?', [id]);
    await pool.query('DELETE FROM centres WHERE id = ?', [id]);
    await logAction(req.user && req.user.id, `DELETE centre:${id}`);
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'centre_delete_failed' });
  }
});

// Users management (minimal)
app.get('/users', authenticateToken, requireRole(['admin','superviseur']), async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT u.id, u.nom, u.email, r.name AS role
      FROM users u
      LEFT JOIN roles r ON r.id = u.role_id
      ORDER BY u.id DESC
    `);
    return res.json(rows.map(u => ({
      id: u.id,
      nom: u.nom,
      email: u.email,
      role: u.role || 'viewer',
      statut: 'Actif'
    })));
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'users_failed' });
  }
});

app.get('/users/:id', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const id = req.params.id;
    const [rows] = await pool.query(`
      SELECT u.id, u.nom, u.email, r.name AS role
      FROM users u
      LEFT JOIN roles r ON r.id = u.role_id
      WHERE u.id = ?
    `, [id]);
    if (!rows.length) return res.status(404).json({ error: 'not_found' });
    return res.json({
      id: rows[0].id,
      nom: rows[0].nom,
      email: rows[0].email,
      role: rows[0].role || 'viewer',
      statut: 'Actif'
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'user_failed' });
  }
});

app.put('/users', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const { id, nom, email, role } = req.body;
    if (!id) return res.status(400).json({ error: 'id_required' });
    const roleId = role ? await ensureRoleId(role) : null;
    await pool.query('UPDATE users SET nom = ?, email = ?, role_id = ? WHERE id = ?', [nom || null, email || null, roleId, id]);
    await logAction(req.user && req.user.id, `UPDATE user:${id}`);
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'user_update_failed' });
  }
});

app.post('/users/:id/disable', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    await logAction(req.user && req.user.id, `DISABLE user:${req.params.id}`);
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'user_disable_failed' });
  }
});

app.delete('/users/:id', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    await pool.query('UPDATE logs SET user_id = NULL WHERE user_id = ?', [req.params.id]);
    await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
    await logAction(req.user && req.user.id, `DELETE user:${req.params.id}`);
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'user_delete_failed' });
  }
});

// Settings
app.get('/settings/filieres', authenticateToken, requireRole(['admin','superviseur']), async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, nom FROM filieres ORDER BY id DESC');
    return res.json(rows);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'filieres_failed' });
  }
});

app.get('/settings/sousdivisions', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, nom FROM sous_divisions ORDER BY id DESC');
    return res.json(rows);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'sousdivisions_failed' });
  }
});

app.get('/settings/equipements', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, nom FROM equipements ORDER BY id DESC');
    return res.json(rows);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'equipements_failed' });
  }
});

app.post('/settings/filieres', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const [ins] = await pool.query('INSERT INTO filieres (nom) VALUES (?)', [req.body.nom]);
    return res.json({ id: ins.insertId });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'filieres_create_failed' });
  }
});

app.post('/settings/sousdivisions', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const [ins] = await pool.query('INSERT INTO sous_divisions (nom) VALUES (?)', [req.body.nom]);
    return res.json({ id: ins.insertId });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'sousdivisions_create_failed' });
  }
});

app.post('/settings/equipements', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const [ins] = await pool.query('INSERT INTO equipements (nom) VALUES (?)', [req.body.nom]);
    return res.json({ id: ins.insertId });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'equipements_create_failed' });
  }
});

app.delete('/settings/filieres/:id', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    await pool.query('DELETE FROM centre_filieres WHERE filiere_id = ?', [req.params.id]);
    await pool.query('DELETE FROM filieres WHERE id = ?', [req.params.id]);
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'filieres_delete_failed' });
  }
});

app.delete('/settings/sousdivisions/:id', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    await pool.query('UPDATE centres SET sous_division_id = NULL WHERE sous_division_id = ?', [req.params.id]);
    await pool.query('DELETE FROM sous_divisions WHERE id = ?', [req.params.id]);
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'sousdivisions_delete_failed' });
  }
});

app.delete('/settings/equipements/:id', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    await pool.query('DELETE FROM centre_equipements WHERE equipement_id = ?', [req.params.id]);
    await pool.query('DELETE FROM equipements WHERE id = ?', [req.params.id]);
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'equipements_delete_failed' });
  }
});

app.get('/settings/year', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT annee FROM cycles WHERE actif = 1 ORDER BY id DESC LIMIT 1');
    if (!rows.length) return res.json(new Date().getFullYear());
    return res.json(rows[0].annee);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'year_failed' });
  }
});

app.post('/settings/year', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const year = Number(req.body.annee);
    await pool.query('UPDATE cycles SET actif = 0');
    await pool.query('INSERT INTO cycles (annee, actif) VALUES (?, 1)', [year]);
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'year_update_failed' });
  }
});

app.get('/settings/backup', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const [centres] = await pool.query('SELECT * FROM centres');
    const [users] = await pool.query('SELECT id, nom, email, role_id FROM users');
    const [filieres] = await pool.query('SELECT * FROM filieres');
    const [sousdivisions] = await pool.query('SELECT * FROM sous_divisions');
    const [equipements] = await pool.query('SELECT * FROM equipements');
    return res.json({ centres, users, filieres, sousdivisions, equipements });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'backup_failed' });
  }
});

// Stats
app.get('/stats', authenticateToken, async (req, res) => {
  try {
    const sousdivision = req.query.sousdivision;
    const params = [];
    let where = '';
    if (sousdivision) {
      where = 'WHERE sd.nom = ?';
      params.push(sousdivision);
    }

    const [territoires] = await pool.query(`
      SELECT sd.nom AS label, COUNT(*) AS value
      FROM centres c
      LEFT JOIN sous_divisions sd ON sd.id = c.sous_division_id
      ${where}
      GROUP BY sd.nom
    `, params);

    const [types] = await pool.query(`
      SELECT c.type AS label, COUNT(*) AS value
      FROM centres c
      LEFT JOIN sous_divisions sd ON sd.id = c.sous_division_id
      ${where}
      GROUP BY c.type
    `, params);

    const [filieres] = await pool.query(`
      SELECT f.nom AS label, COUNT(*) AS value
      FROM centre_filieres cf
      JOIN filieres f ON f.id = cf.filiere_id
      JOIN centres c ON c.id = cf.centre_id
      LEFT JOIN sous_divisions sd ON sd.id = c.sous_division_id
      ${where}
      GROUP BY f.nom
    `, params);

    const [capacites] = await pool.query(`
      SELECT c.nom AS label, c.capacite AS value
      FROM centres c
      LEFT JOIN sous_divisions sd ON sd.id = c.sous_division_id
      ${where}
    `, params);

    const [allSous] = await pool.query('SELECT nom FROM sous_divisions');
    const zones = allSous
      .map(s => s.nom)
      .filter(s => !territoires.some(t => t.label === s));

    const typeMap = { public: 0, prive: 0 };
    types.forEach(t => { typeMap[t.label] = t.value; });

    return res.json({
      territoires: { labels: territoires.map(t => t.label), values: territoires.map(t => t.value) },
      public: typeMap.public || 0,
      prive: typeMap.prive || 0,
      filieres: { labels: filieres.map(f => f.label), values: filieres.map(f => f.value) },
      capacites: { labels: capacites.map(c => c.label), values: capacites.map(c => c.value) },
      zones
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'stats_failed' });
  }
});

// Logs
app.get('/logs', authenticateToken, async (req, res) => {
  try {
    const { user, action, date } = req.query;
    const filters = [];
    const params = [];
    if (user) { filters.push('u.nom LIKE ?'); params.push(`%${user}%`); }
    if (action) { filters.push('l.action LIKE ?'); params.push(`${action}%`); }
    if (date) { filters.push('DATE(l.created_at) = ?'); params.push(date); }
    const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';

    const [rows] = await pool.query(`
      SELECT l.action, l.created_at, u.nom
      FROM logs l
      LEFT JOIN users u ON u.id = l.user_id
      ${where}
      ORDER BY l.id DESC
      LIMIT 200
    `, params);

    const mapped = rows.map(r => {
      const parts = (r.action || '').split(' ');
      const act = parts[0] || 'ACTION';
      const target = parts.slice(1).join(' ') || '';
      return {
        user: r.nom || 'system',
        action: act,
        target,
        date: r.created_at
      };
    });

    return res.json(mapped);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'logs_failed' });
  }
});

// Rapports
app.get('/rapports/generate', authenticateToken, async (req, res) => {
  try {
    const { type, format, sousdivision, filiere } = req.query;
    const params = [];
    let where = 'WHERE 1=1';
    if (sousdivision) { where += ' AND sd.nom = ?'; params.push(sousdivision); }
    if (filiere) { where += ' AND f.nom = ?'; params.push(filiere); }

    const [rows] = await pool.query(`
      SELECT c.nom, c.type, sd.nom AS sousdivision, c.capacite
      FROM centres c
      LEFT JOIN sous_divisions sd ON sd.id = c.sous_division_id
      LEFT JOIN centre_filieres cf ON cf.centre_id = c.id
      LEFT JOIN filieres f ON f.id = cf.filiere_id
      ${where}
      GROUP BY c.id
    `, params);

    if (format === 'excel') {
      const header = 'Nom,Type,Sous-division,Capacite\n';
      const lines = rows
        .map(r => [
          escapeCsvValue(r.nom),
          escapeCsvValue(r.type),
          escapeCsvValue(r.sousdivision || ''),
          escapeCsvValue(r.capacite || 0)
        ].join(','))
        .join('\n');
      res.setHeader('Content-Type', 'text/csv');
      return res.send(header + lines);
    }

    let html = `<h2>Rapport CFP</h2><p>Type: ${escapeHtml(type || 'global')}</p>`;
    html += `<table border="1" cellpadding="6" cellspacing="0"><thead><tr><th>Nom</th><th>Type</th><th>Sous-division</th><th>Capacite</th></tr></thead><tbody>`;
    rows.forEach(r => {
      html += `<tr><td>${escapeHtml(r.nom)}</td><td>${escapeHtml(r.type)}</td><td>${escapeHtml(r.sousdivision || '')}</td><td>${escapeHtml(r.capacite || 0)}</td></tr>`;
    });
    html += `</tbody></table>`;
    res.setHeader('Content-Type', 'text/html');
    return res.send(html);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'rapport_failed' });
  }
});

// Cycle update
app.post('/update-cycle', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const [current] = await pool.query('SELECT id, annee FROM cycles WHERE actif = 1 ORDER BY id DESC LIMIT 1');
    const nextYear = current.length ? current[0].annee + 1 : new Date().getFullYear();
    await pool.query('UPDATE cycles SET actif = 0');
    const [ins] = await pool.query('INSERT INTO cycles (annee, actif) VALUES (?, 1)', [nextYear]);
    await logAction(req.user && req.user.id, `UPDATE cycle:${nextYear}`);
    return res.json({ version: ins.insertId });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'update_cycle_failed' });
  }
});

app.listen(port, () => console.log(`Server listening on http://localhost:${port}`));


