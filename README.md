# Cloudflare R2 + Postgres example backend

This folder contains a minimal example Node/Express backend that:

- Verifies Firebase ID tokens (requires a Firebase service account)
- Issues presigned PUT upload URLs for Cloudflare R2 (S3-compatible)
- Stores profile metadata into a Postgres database (upsert)

Files

- index.js - main server
- .env.example - example environment variables
- package.json - dependencies

Setup

1. Copy `.env.example` to `.env` and fill in values.

   - `R2_ENDPOINT` should be your R2 endpoint (e.g. `https://<account-id>.r2.cloudflarestorage.com`)
   - `R2_BUCKET` the R2 bucket name
   - Set `R2_ACCESS_KEY_ID` and `R2_SECRET_ACCESS_KEY`
   - `DATABASE_URL` should be a Postgres connection string
   - Provide Firebase service account: either set `GOOGLE_APPLICATION_CREDENTIALS` to the JSON file path
     or set `GOOGLE_SERVICE_ACCOUNT_JSON` to the JSON text.

2. Install dependencies

   npm install

3. Start server

   npm start

Endpoints

- POST /upload-urls

  - Auth: Bearer <Firebase ID token>
  - Body: { files: [{ name: 'photo.jpg', contentType: 'image/jpeg' }, ...] }
  - Returns: { uploads: [{ key, uploadUrl, fileUrl }, ...] }

  Client steps:

  - Call this endpoint to get presigned PUT URLs.
  - Upload each file with an HTTP PUT to the returned `uploadUrl` (set Content-Type accordingly).
  - After successful upload, the `fileUrl` (or a constructed public URL) can be saved in the profile metadata.

- POST /profiles
  - Auth: Bearer <Firebase ID token>
  - Body: profile object (see code for fields)
  - Stores/updates profile in Postgres (table `users_profiles`)

Postgres schema (example)

Run this SQL to create a `users_profiles` table used by the example:

```sql
CREATE TABLE users_profiles (
  id SERIAL PRIMARY KEY,
  uid TEXT UNIQUE NOT NULL,
  display_name TEXT,
  gender TEXT,
  dob DATE,
  age INT,
  height TEXT,
  weight TEXT,
  kulam TEXT,
  gothram TEXT,
  star TEXT,
  zodiac TEXT,
  community TEXT,
  education TEXT,
  occupation TEXT,
  salary TEXT,
  address TEXT,
  family_description TEXT,
  father_name TEXT,
  mother_name TEXT,
  contact_number TEXT,
  photos JSONB,
  horoscope JSONB,
  profile_complete BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE UNIQUE INDEX idx_users_profiles_uid ON users_profiles(uid);
```

Notes & next steps

- The example returns `fileUrl` constructed from `R2_ENDPOINT` + bucket + key. For production you should front R2 with a CDN or custom domain and/or configure public access appropriately.
- Consider adding server-side thumbnail generation (Cloudflare Workers or a background job) to produce small thumbnails for list pages.
- Make sure your R2 bucket policy and Postgres security rules match your privacy model.
