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

// Init Firebase Admin
if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON)),
  });
} else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  admin.initializeApp(); // uses env var path
} else {
  console.warn('Warning: Firebase admin not initialized - set GOOGLE_APPLICATION_CREDENTIALS or GOOGLE_SERVICE_ACCOUNT_JSON');
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

// Postgres pool
// If you use Supabase (or any host requiring TLS), enable ssl with rejectUnauthorized:false
// to allow node-postgres to connect in environments where certificates are not verified.
const pgConfig = { connectionString: process.env.DATABASE_URL };
if (process.env.DATABASE_URL && process.env.DATABASE_URL.includes('supabase.co')) {
  pgConfig.ssl = { rejectUnauthorized: false };
}
const pool = new Pool(pgConfig);

async function verifyFirebaseToken(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  const idToken = auth.split(' ')[1];
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = decoded;
    next();
  } catch (e) {
    console.error('Token verify failed', e);
    res.status(401).json({ error: 'Invalid token' });
  }
}

// POST /upload-urls
// Body: { files: [{ name: 'photo.jpg', contentType: 'image/jpeg' }, ...] }
// Response: { uploads: [{ key, uploadUrl, fileUrl }, ...] }
app.post('/upload-urls', verifyFirebaseToken, async (req, res) => {
  const files = req.body.files || [];
  const uid = req.user && req.user.uid;
  if (!uid) return res.status(400).json({ error: 'Invalid user' });
  if (!Array.isArray(files) || files.length === 0) return res.status(400).json({ error: 'No files requested' });
  const bucket = process.env.R2_BUCKET;
  if (!bucket) return res.status(500).json({ error: 'R2_BUCKET not configured' });

  try {
    const uploads = [];
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const ext = (file.name && file.name.split('.').pop()) || 'jpg';
      const key = `users/${uid}/photos/${Date.now()}-${i}.${ext}`;

      const putParams = {
        Bucket: bucket,
        Key: key,
        ContentType: file.contentType || 'application/octet-stream',
      };

      const command = new PutObjectCommand(putParams);
      const uploadUrl = await getSignedUrl(s3Client, command, { expiresIn: 60 * 10 }); // 10 minutes

      // Construct public file URL - if you configured a custom domain or expose R2 publicly, adjust accordingly
      // Default Cloudflare R2 public URL pattern (when public): https://<account-id>.r2.cloudflarestorage.com/<bucket>/<key>
      // If you front with a CDN or custom domain, use that instead.
      const fileUrl = `${r2Endpoint.replace(/\/$/, '')}/${bucket}/${encodeURIComponent(key)}`;

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
      INSERT INTO users_profiles(uid, display_name, gender, dob, age, height, weight, kulam, gothram, star, zodiac, community, education, occupation, salary, address, family_description, father_name, mother_name, contact_number, photos, horoscope, profile_complete, created_at, updated_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22, true, now(), now())
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
        profile_complete = true,
        updated_at = now();
    `;

    const values = [
      uid,
      profile.displayName || null,
      profile.gender || null,
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
    ];

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
  const { ageMin, ageMax, gender, search } = req.query;
  const tokenUid = req.user && req.user.uid;
  console.log('[GET /profiles] tokenUid=', tokenUid, 'query=', req.query);

  try {
    const values = [];
    const where = [];

    if (ageMin) { values.push(parseInt(ageMin, 10)); where.push(`age >= $${values.length}`); }
    if (ageMax) { values.push(parseInt(ageMax, 10)); where.push(`age <= $${values.length}`); }
    if (gender) { values.push(gender); where.push(`gender = $${values.length}`); }
    if (search) { values.push(`%${search.toLowerCase()}%`); where.push(`LOWER(display_name) LIKE $${values.length}`); }

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const sql = `
      SELECT
        uid AS id,
        display_name AS name,
        age,
        height AS heightCms,
        community,
        address AS location,
        education,
        (CASE WHEN jsonb_typeof(photos::jsonb) = 'array' AND jsonb_array_length(photos::jsonb) > 0 THEN (photos::jsonb -> 0 ->> 'fileUrl') ELSE NULL END) AS thumbnailUrl,
        gender
      FROM users_profiles
      ${whereSql}
      ORDER BY updated_at DESC
      LIMIT 100
    `;

    const { rows } = await pool.query(sql, values);
    console.log('[GET /profiles] rows', rows.length);
    return res.json({ items: rows });
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
    const q = 'SELECT uid, display_name, profile_complete, photos FROM users_profiles WHERE uid = $1';
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
const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`Backend listening on ${port}`));
