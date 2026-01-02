/**
 * Minimal Express backend that:
 * - verifies Firebase ID tokens
 * - returns presigned PUT URLs for Cloudflare R2 (S3-compatible)
 * - persists profile metadata to Postgres
 *
 * This is an example to run locally or deploy as a small server. Do not hardcode secrets.
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const fs = require('fs');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { Pool } = require('pg');
const dns = require('dns');

// Prefer IPv4 addresses when resolving hostnames to avoid environments
// where IPv6 connectivity is unavailable or times out. This helps when
// the PostgreSQL host returns both A and AAAA records and Node attempts
// IPv6 first which may result in ETIMEDOUT on some networks.
if (typeof dns.setDefaultResultOrder === 'function') {
  try {
    dns.setDefaultResultOrder('ipv4first');
    console.log('DNS resolution set to prefer IPv4 (ipv4first)');
  } catch (e) {
    console.warn('Could not set DNS result order:', e && e.message);
  }
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Init Firebase Admin with robust env handling for Render
(() => {
  try {
    let initialized = false;
    const jsonInline = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
    const jsonB64 = process.env.GOOGLE_SERVICE_ACCOUNT_JSON_BASE64;
    const credPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;

    if (jsonInline) {
      const parsed = JSON.parse(jsonInline);
      admin.initializeApp({ credential: admin.credential.cert(parsed) });
      console.log('Firebase Admin initialized from GOOGLE_SERVICE_ACCOUNT_JSON');
      initialized = true;
    } else if (jsonB64) {
      const decoded = Buffer.from(jsonB64, 'base64').toString('utf8');
      const parsed = JSON.parse(decoded);
      admin.initializeApp({ credential: admin.credential.cert(parsed) });
      console.log('Firebase Admin initialized from GOOGLE_SERVICE_ACCOUNT_JSON_BASE64');
      initialized = true;
    } else if (credPath) {
      if (fs.existsSync(credPath)) {
        const parsed = JSON.parse(fs.readFileSync(credPath, 'utf8'));
        admin.initializeApp({ credential: admin.credential.cert(parsed) });
        console.log('Firebase Admin initialized from GOOGLE_APPLICATION_CREDENTIALS path');
        initialized = true;
      } else {
        console.warn('GOOGLE_APPLICATION_CREDENTIALS set but file not found:', credPath);
      }
    }

    if (!initialized) {
      admin.initializeApp();
      console.warn('Firebase Admin initialized without explicit credentials; suitable for ID token verification');
    }
  } catch (e) {
    console.error('Failed to initialize Firebase Admin; falling back to default init', e && e.message);
    try { admin.initializeApp(); } catch (_) {}
  }
})();

// Ensure default app exists even if the above block didn't initialize
if (!admin.apps || admin.apps.length === 0) {
  try {
    admin.initializeApp();
    console.log('Firebase Admin default app initialized');
  } catch (e) {
    console.error('Firebase Admin default init failed:', e && e.message);
  }
}

// Init S3 client for Cloudflare R2 (S3-compatible)
const r2Endpoint = process.env.R2_ENDPOINT;
const r2Region = process.env.R2_REGION || 'auto';
const s3Client = new S3Client({
  region: r2Region,
  endpoint: r2Endpoint,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY_ID || '',
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY || '',
  },
});   

// Postgres Pool (IPv4-preferred). Build the pool lazily to force IPv4 resolution if needed.
let poolPromise;
async function getPool() {
  if (poolPromise) return poolPromise;
  poolPromise = (async () => {
    const dbUrl = process.env.DATABASE_URL;
    if (!dbUrl) {
      console.warn('DATABASE_URL not set');
      return new Pool();
    }
    try {
      const u = new URL(dbUrl);
      const host = u.hostname;
      const port = parseInt(u.port || '5432', 10);
      const user = decodeURIComponent(u.username || '');
      const password = decodeURIComponent(u.password || '');
      const database = (u.pathname || '').replace(/^\//, '');

      // Resolve IPv4 address explicitly to avoid IPv6 ENETUNREACH
      let ipv4Host = host;
      try {
        ipv4Host = await new Promise((resolve, reject) => {
          dns.lookup(host, { family: 4 }, (err, address) => {
            if (err) return reject(err);
            resolve(address);
          });
        });
        console.log('Postgres host resolved to IPv4:', ipv4Host);
      } catch (e) {
        console.warn('IPv4 DNS lookup failed for host', host, '-', e && e.message, '; using original host');
      }

      const cfg = {
        host: ipv4Host,
        port,
        user,
        password,
        database,
      };
      if (dbUrl.includes('supabase.co')) {
        cfg.ssl = { rejectUnauthorized: false };
      }
      return new Pool(cfg);
    } catch (e) {
      console.warn('Failed to parse DATABASE_URL; falling back to connectionString. Err:', e && e.message);
      const cfg = { connectionString: dbUrl };
      if (dbUrl.includes('supabase.co')) cfg.ssl = { rejectUnauthorized: false };
      return new Pool(cfg);
    }
  })();
  return poolPromise;
}

async function verifyFirebaseToken(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  const idToken = auth.split(' ')[1];
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = decoded;
    next();
  } catch (e) {
    console.error('Token verify failed', e && e.message);
    res.status(401).json({ error: 'Invalid token', detail: (e && e.message) || 'verifyIdToken failed' });
  }
}

// Lightweight health check to verify connectivity from devices/Render
app.get('/health', (_req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

// POST /upload-urls
// Body: { files: [{ name: 'photo.jpg', contentType: 'image/jpeg' }, ...] }
// Response: { uploads: [{ key, uploadUrl, fileUrl }, ...] }
app.post('/upload-urls', verifyFirebaseToken, async (req, res) => {
  const files = req.body.files || [];
  const categoryRaw = (req.body.category || '').toString().trim().toLowerCase();
  const uid = req.user && req.user.uid;
  if (!uid) return res.status(400).json({ error: 'Invalid user' });
  if (!Array.isArray(files) || files.length === 0) return res.status(400).json({ error: 'No files requested' });
  const bucket = process.env.R2_BUCKET;
  if (!bucket) return res.status(500).json({ error: 'R2_BUCKET not configured' });

  try {
    const uploads = [];
    // Allow choosing target folder: 'photos' (default) or 'horoscope'
    const category = ['photos', 'horoscope'].includes(categoryRaw) ? categoryRaw : 'photos';
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const ext = (file.name && file.name.split('.').pop()) || 'jpg';
      const key = `users/${uid}/${category}/${Date.now()}-${i}.${ext}`;

      const putParams = {
        Bucket: bucket,
        Key: key,
        ContentType: file.contentType || 'application/octet-stream',
      };

      const command = new PutObjectCommand(putParams);
      const uploadUrl = await getSignedUrl(s3Client, command, { expiresIn: 60 * 10 }); // 10 minutes

      // Construct public file URL
      // If PUBLIC_R2_BASE (Cloudflare Public Development URL) is set, it is per-bucket, so omit bucket in path.
      // Otherwise, fall back to the account endpoint which requires /<bucket>/<key>.
      const encodedKey = key.split('/').map(encodeURIComponent).join('/');
      const publicDevBase = process.env.PUBLIC_R2_BASE ? process.env.PUBLIC_R2_BASE.replace(/\/$/, '') : '';
      const accountBase = r2Endpoint.replace(/\/$/, '');
      const fileUrl = publicDevBase
        ? `${publicDevBase}/${encodedKey}`
        : `${accountBase}/${bucket}/${encodedKey}`;

      uploads.push({ key, uploadUrl, fileUrl });
    }
    res.json({ uploads });
  } catch (e) {
    console.error('Failed creating upload URLs', e);
    res.status(500).json({ error: 'Failed to create upload URLs' });
  }
});

// POST /profiles
// Body: profile object (will attach uid from token)
app.post('/profiles', verifyFirebaseToken, async (req, res) => {
  const uid = req.user && req.user.uid;
  if (!uid) return res.status(400).json({ error: 'Invalid user' });
  const profile = req.body || {};
  try {
    // Upsert into users_profiles table. Create table with SQL in README.
    const now = new Date().toISOString();
    const photos = profile.photos ? JSON.stringify(profile.photos) : '[]';
    const horoscope = profile.horoscope ? JSON.stringify(profile.horoscope) : 'null';

    const query = `
      INSERT INTO users_profiles(uid, display_name, gender, dob, age, height, weight, kulam, gothram, star, zodiac, community, education, occupation, salary, address, family_description, father_name, mother_name, contact_number, photos, horoscope, country_group, state, city, profile_complete, created_at, updated_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25, true, now(), now())
      ON CONFLICT (uid) DO UPDATE SET
        display_name = EXCLUDED.display_name,
        gender = EXCLUDED.gender,
        dob = EXCLUDED.dob,
        age = EXCLUDED.age,
        height = EXCLUDED.height,
        weight = EXCLUDED.weight,
        kulam = EXCLUDED.kulam,
        gothram = EXCLUDED.gothram,
        star = EXCLUDED.star,
        zodiac = EXCLUDED.zodiac,
        community = EXCLUDED.community,
        education = EXCLUDED.education,
        occupation = EXCLUDED.occupation,
        salary = EXCLUDED.salary,
        address = EXCLUDED.address,
        family_description = EXCLUDED.family_description,
        father_name = EXCLUDED.father_name,
        mother_name = EXCLUDED.mother_name,
        contact_number = EXCLUDED.contact_number,
        photos = EXCLUDED.photos,
        horoscope = EXCLUDED.horoscope,
        country_group = EXCLUDED.country_group,
        state = EXCLUDED.state,
        city = EXCLUDED.city,
        profile_complete = true,
        updated_at = now();
    `;

    // Accept both camelCase and snake_case for display name; normalize gender to lowercase
    const displayName = profile.display_name || profile.displayName || null;
    const genderNormalized = profile.gender ? String(profile.gender).toLowerCase() : null;

    const values = [
      uid,
      displayName,
      genderNormalized,
      profile.dob || null,
      profile.age || null,
      profile.height || null,
      profile.weight || null,
      profile.kulam || null,
      profile.gothram || null,
      profile.star || null,
      profile.zodiac || null,
      profile.community || null,
      profile.education || null,
      profile.occupation || null,
      profile.salary || null,
      profile.address || null,
      profile.familyDescription || null,
      profile.fatherName || null,
      profile.motherName || null,
      profile.contactNumber || null,
      photos,
      horoscope,
      (profile.location && profile.location.countryGroup) ? String(profile.location.countryGroup).toLowerCase() : null,
      (profile.location && profile.location.state) ? String(profile.location.state) : null,
      (profile.location && profile.location.city) ? String(profile.location.city) : null,
    ];

    const pool = await getPool();
    await pool.query(query, values);
    res.json({ ok: true });
  } catch (e) {
    console.error('Failed saving profile', e);
    res.status(500).json({ error: 'Failed to save profile' });
  }
});

// GET /profiles list with filters
// Query params: ageMin, ageMax, gender (filter target), search
// Returns array of limited fields for matches list
app.get('/profiles', verifyFirebaseToken, async (req, res) => {
  const { ageMin, ageMax, gender, search, location, dosham, occupation, countryGroup, state, city } = req.query;
  const tokenUid = req.user && req.user.uid;
  console.log('[GET /profiles] tokenUid=', tokenUid, 'query=', req.query);

  try {
    const values = [];
    const where = [];

    if (ageMin) { values.push(parseInt(ageMin, 10)); where.push(`age >= $${values.length}`); }
    if (ageMax) { values.push(parseInt(ageMax, 10)); where.push(`age <= $${values.length}`); }
    if (gender) { values.push(String(gender).toLowerCase()); where.push(`LOWER(gender) = $${values.length}`); }
    if (tokenUid) { values.push(tokenUid); where.push(`uid <> $${values.length}`); }
    if (search) { values.push(`%${search.toLowerCase()}%`); where.push(`LOWER(display_name) LIKE $${values.length}`); }
    if (location) { values.push(`%${String(location).toLowerCase()}%`); where.push(`LOWER(address) LIKE $${values.length}`); }
    if (occupation) { values.push(`%${String(occupation).toLowerCase()}%`); where.push(`LOWER(occupation) LIKE $${values.length}`); }
    if (dosham) { values.push(`%${String(dosham).toLowerCase()}%`); where.push(`LOWER((horoscope::jsonb ->> 'dosham')) LIKE $${values.length}`); }
    if (countryGroup) { values.push(String(countryGroup).toLowerCase()); where.push(`LOWER(country_group) = $${values.length}`); }
    if (state) { values.push(`%${String(state).toLowerCase()}%`); where.push(`LOWER(state) LIKE $${values.length}`); }
    if (city) { values.push(`%${String(city).toLowerCase()}%`); where.push(`LOWER(city) LIKE $${values.length}`); }

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const sql = `
      SELECT
        uid AS id,
        display_name AS name,
        age,
        height AS heightCms,
        community,
        CASE WHEN LOWER(country_group) = 'india'
             THEN CONCAT(COALESCE(state, ''), CASE WHEN state IS NOT NULL AND city IS NOT NULL THEN ', ' ELSE '' END, COALESCE(city, ''))
             ELSE COALESCE(city, '') END AS location,
        education,
        salary,
        (horoscope::jsonb ->> 'dosham') AS dosham,
        (
          CASE
            WHEN jsonb_typeof(photos::jsonb) = 'array' AND jsonb_array_length(photos::jsonb) > 0
            THEN COALESCE((photos::jsonb -> 0 ->> 'thumbnail_url'), (photos::jsonb -> 0 ->> 'url'))
            ELSE NULL
          END
        ) AS thumbnail_url,
        gender
      FROM users_profiles
      ${whereSql}
      ORDER BY updated_at DESC
      LIMIT 100
    `;

    const pool = await getPool();
    const { rows } = await pool.query(sql, values);
    console.log('[GET /profiles] rows', rows.length);
    // Normalize and rewrite URLs to public base if needed
    const publicBase = (process.env.PUBLIC_R2_BASE || '').replace(/\/$/, '');
    const bucketName = process.env.R2_BUCKET || '';
    const items = rows.map((r) => {
      if (r.thumbnail_url) {
        let url = String(r.thumbnail_url);
        // Decode %2F -> /
        try { url = decodeURIComponent(url); } catch (_) { url = url.replace(/%2F/g, '/'); }
        // If using cloudflarestorage host, rewrite to PUBLIC_R2_BASE for public reads
        try {
          const u = new URL(url);
          if (publicBase && u.hostname.endsWith('r2.cloudflarestorage.com')) {
            const parts = u.pathname.split('/').filter(Boolean);
            const withoutBucket = (parts.length && parts[0] === bucketName) ? parts.slice(1).join('/') : parts.join('/');
            r.thumbnail_url = `${publicBase}/${withoutBucket}`;
          } else {
            r.thumbnail_url = url;
          }
        } catch (_) {
          r.thumbnail_url = url;
        }
      }
      // Normalize gender to lowercase for clients expecting case-insensitive values
      if (r.gender) r.gender = String(r.gender).toLowerCase();
      return r;
    });
    return res.json({ items });
  } catch (err) {
    console.error('[GET /profiles] error', err);
    return res.status(500).json({ error: 'Failed to fetch profiles' });
  }
});

// GET /profiles/:uid - return profile row if exists, else 404
app.get('/profiles/:uid', verifyFirebaseToken, async (req, res) => {
  const tokenUid = req.user && req.user.uid;
  const uid = req.params.uid;
  console.log('[GET /profiles/:uid] tokenUid=', tokenUid, 'paramUid=', uid);
  if (!tokenUid || tokenUid !== uid) {
    console.warn('[GET /profiles/:uid] Forbidden: UID mismatch');
    return res.status(403).json({ error: 'Forbidden: UID mismatch' });
  }
  try {
    const q = 'SELECT uid, display_name, gender, profile_complete, photos FROM users_profiles WHERE uid = $1';
    const pool = await getPool();
    const r = await pool.query(q, [uid]);
    console.log('[GET /profiles/:uid] rows:', r.rows.length);
    if (r.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    console.log('[GET /profiles/:uid] row:', r.rows[0]);
    res.json(r.rows[0]);
  } catch (e) {
    console.error('Failed fetching profile', e);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// GET /profiles/public/:uid - return public profile fields for viewing others
app.get('/profiles/public/:uid', verifyFirebaseToken, async (req, res) => {
  const uid = req.params.uid;
  console.log('[GET /profiles/public/:uid] paramUid=', uid);
  try {
    const q = `
      SELECT
        uid,
        display_name,
        gender,
        age,
        height,
        weight,
        kulam,
        gothram,
        star,
        zodiac,
        community,
        education,
        occupation,
        salary,
        address,
        country_group,
        state,
        city,
        family_description,
        father_name,
        mother_name,
        contact_number,
        photos,
        horoscope
      FROM users_profiles WHERE uid = $1`;
    const pool = await getPool();
    const r = await pool.query(q, [uid]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'Not found' });

    const row = r.rows[0];
    // Normalize URLs in photos array
    const publicBase = (process.env.PUBLIC_R2_BASE || '').replace(/\/$/, '');
    const bucketName = process.env.R2_BUCKET || '';
    try {
      const photos = Array.isArray(row.photos) ? row.photos : JSON.parse(row.photos || '[]');
      row.photos = photos.map((p) => {
        let url = p.thumbnail_url || p.url || '';
        if (url) {
          try { url = decodeURIComponent(url); } catch (_) { url = String(url).replace(/%2F/g, '/'); }
          try {
            const u = new URL(url);
            if (publicBase && u.hostname.endsWith('r2.cloudflarestorage.com')) {
              const parts = u.pathname.split('/').filter(Boolean);
              const withoutBucket = (parts.length && parts[0] === bucketName) ? parts.slice(1).join('/') : parts.join('/');
              p.thumbnail_url = `${publicBase}/${withoutBucket}`;
              p.url = p.url ? `${publicBase}/${withoutBucket}` : p.url;
            }
          } catch (_) {/* ignore */}
        }
        return p;
      });
    } catch (e) {
      console.warn('[GET /profiles/public/:uid] photo normalize failed', e && e.message);
    }
    // Extract birth details from horoscope JSON if present
    try {
      const horo = typeof row.horoscope === 'string' ? JSON.parse(row.horoscope) : (row.horoscope || {});
      if (horo && typeof horo === 'object') {
        if (horo.time_of_birth) row.time_of_birth = horo.time_of_birth;
        if (horo.birth_location) row.birth_location = horo.birth_location;
      }
    } catch (e) {
      console.warn('[GET /profiles/public/:uid] horoscope parse failed', e && e.message);
    }
    if (row.gender) row.gender = String(row.gender).toLowerCase();
    return res.json(row);
  } catch (e) {
    console.error('Failed fetching public profile', e);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// POST /profiles/horoscope-images
// Body: { images: ["https://...", "https://..."] } (max 2)
// Merges images into existing horoscope JSON for the authenticated user
app.post('/profiles/horoscope-images', verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.user && req.user.uid;
    if (!uid) return res.status(400).json({ error: 'Invalid user' });
    let images = Array.isArray(req.body.images) ? req.body.images : [];
    images = images.filter((u) => typeof u === 'string' && u.trim().length > 0).slice(0, 2);
    if (images.length === 0) return res.status(400).json({ error: 'No valid image URLs provided' });

    const pool = await getPool();
    // Fetch existing horoscope JSON
    const sel = await pool.query('SELECT horoscope FROM users_profiles WHERE uid = $1', [uid]);
    let horo = {};
    if (sel.rows.length > 0) {
      const existing = sel.rows[0].horoscope;
      try {
        horo = typeof existing === 'string' ? JSON.parse(existing || '{}') : (existing || {});
      } catch (e) {
        console.warn('[POST /profiles/horoscope-images] failed to parse existing horoscope', e && e.message);
        horo = {};
      }
    }
    horo.images = images;
    const horoStr = JSON.stringify(horo);

    // Update row (assumes profile row exists after registration)
    const upd = await pool.query('UPDATE users_profiles SET horoscope = $2, updated_at = now() WHERE uid = $1', [uid, horoStr]);
    if (upd.rowCount === 0) {
      // If row doesn't exist yet, insert a minimal row to hold horoscope
      await pool.query('INSERT INTO users_profiles(uid, horoscope, profile_complete, created_at, updated_at) VALUES($1, $2, false, now(), now()) ON CONFLICT(uid) DO UPDATE SET horoscope = EXCLUDED.horoscope, updated_at = now()', [uid, horoStr]);
    }
    return res.json({ ok: true, images });
  } catch (e) {
    console.error('[POST /profiles/horoscope-images] error', e);
    return res.status(500).json({ error: 'Failed to save horoscope images' });
  }
});
const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`Backend listening on ${port}`));
