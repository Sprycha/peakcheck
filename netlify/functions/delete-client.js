// PeakCheck — permanently deletes a client: their auth account (if they've
// signed up), their profile row, any uploaded photo/test files in storage,
// and the client row itself (which cascades to check-ins, PED/supplement
// logs, test results, and daily drafts via the schema's FK constraints).
// Requires SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY as Netlify env vars —
// deleting an auth user requires the service role, so this must run
// server-side rather than in peakcheck_live.html.
const { createClient } = require('@supabase/supabase-js');

exports.handler = async (event) => {
  const headers = { 'Content-Type': 'application/json' };

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch (e) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Invalid request body' }) };
  }

  const clientId = body.clientId;
  if (!clientId) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'clientId is required' }) };
  }

  const authHeader = event.headers.authorization || event.headers.Authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '');
  if (!token) {
    return { statusCode: 401, headers, body: JSON.stringify({ error: 'Missing authorization' }) };
  }

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!SUPABASE_URL || !SERVICE_ROLE_KEY) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: 'Server is missing Supabase configuration (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY env vars)' }) };
  }
  const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

  // Verify the caller is a signed-in coach before deleting anything.
  const { data: callerData, error: callerErr } = await admin.auth.getUser(token);
  if (callerErr || !callerData || !callerData.user) {
    return { statusCode: 401, headers, body: JSON.stringify({ error: 'Invalid or expired session — sign in again and retry' }) };
  }

  const { data: callerProfile, error: profileErr } = await admin
    .from('profiles')
    .select('role')
    .eq('id', callerData.user.id)
    .single();
  if (profileErr || !callerProfile || callerProfile.role !== 'coach') {
    return { statusCode: 403, headers, body: JSON.stringify({ error: 'Only the coach can delete clients' }) };
  }

  const { data: clientRow, error: clientErr } = await admin
    .from('clients')
    .select('id, name')
    .eq('id', clientId)
    .single();
  if (clientErr || !clientRow) {
    return { statusCode: 404, headers, body: JSON.stringify({ error: 'Client not found' }) };
  }

  // If this client has a linked account, delete the auth user first —
  // that cascades to remove their profile row, and frees up their email
  // so a fresh invite can be sent to it later.
  const { data: linkedProfile } = await admin
    .from('profiles')
    .select('id')
    .eq('client_id', clientId)
    .maybeSingle();
  if (linkedProfile) {
    const { error: authDelErr } = await admin.auth.admin.deleteUser(linkedProfile.id);
    if (authDelErr) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: 'Could not delete client account: ' + authDelErr.message }) };
    }
  }

  // Best-effort cleanup of uploaded files — do not fail the whole
  // deletion if storage cleanup has an issue.
  for (const bucket of ['progress-photos', 'test-results']) {
    try {
      const { data: files } = await admin.storage.from(bucket).list(clientId);
      if (files && files.length) {
        const paths = files.map((f) => `${clientId}/${f.name}`);
        await admin.storage.from(bucket).remove(paths);
      }
    } catch (e) {
      // ignore storage cleanup failures
    }
  }

  const { error: delErr } = await admin.from('clients').delete().eq('id', clientId);
  if (delErr) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Could not delete client: ' + delErr.message }) };
  }

  return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
};
