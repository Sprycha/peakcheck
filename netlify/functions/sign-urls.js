// PeakCheck — signs private storage files (progress photos / test results) for
// the signed-in user. Used as a fallback when the browser's own signing request
// is refused by storage access rules. It re-checks who is asking:
//   - a coach may only sign files in folders of clients in their own org
//   - a client may only sign files in their own folder
// Requires SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY as Netlify env vars.
const { createClient } = require('@supabase/supabase-js');

const ALLOWED_BUCKETS = ['progress-photos', 'test-results'];

exports.handler = async (event) => {
  const headers = { 'Content-Type': 'application/json' };
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };
  }
  let body;
  try { body = JSON.parse(event.body || '{}'); }
  catch (e) { return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid request body' }) }; }

  const bucket = body.bucket;
  const paths = Array.isArray(body.paths) ? body.paths.filter((p) => typeof p === 'string' && p) : [];
  if (!ALLOWED_BUCKETS.includes(bucket) || paths.length === 0 || paths.length > 200) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'bucket and paths are required' }) };
  }

  const authHeader = event.headers.authorization || event.headers.Authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '');
  if (!token) return { statusCode: 401, headers, body: JSON.stringify({ error: 'Missing authorization' }) };

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'Server is missing Supabase configuration' }) };
  }
  const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

  const { data: callerData, error: callerErr } = await admin.auth.getUser(token);
  if (callerErr || !callerData || !callerData.user) {
    return { statusCode: 401, headers, body: JSON.stringify({ error: 'Invalid or expired session' }) };
  }
  const { data: caller } = await admin.from('profiles').select('*').eq('id', callerData.user.id).single();
  if (!caller) return { statusCode: 403, headers, body: JSON.stringify({ error: 'No profile' }) };

  // Work out which client folders this caller may access.
  const folders = Array.from(new Set(paths.map((p) => p.split('/')[0])));
  const allowedFolders = new Set();
  if (caller.role === 'client') {
    if (caller.client_id) allowedFolders.add(String(caller.client_id));
  } else if (caller.role === 'coach') {
    const { data: rows } = await admin.from('clients').select('id, org_id').in('id', folders);
    (rows || []).forEach((r) => {
      const sameOrg = (r.org_id || null) === (caller.org_id || null);
      if (sameOrg) allowedFolders.add(String(r.id));
    });
  }

  const okPaths = paths.filter((p) => allowedFolders.has(p.split('/')[0]));
  const urls = {};
  if (okPaths.length) {
    const { data, error } = await admin.storage.from(bucket).createSignedUrls(okPaths, 3600);
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };
    (data || []).forEach((d) => { urls[d.path] = d.error ? null : d.signedUrl; });
  }
  return { statusCode: 200, headers, body: JSON.stringify({ urls }) };
};
