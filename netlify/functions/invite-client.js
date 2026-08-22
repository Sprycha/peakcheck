// PeakCheck — sends a client an invite email so they can set a password and
// start using the app directly, instead of self-registering with a code.
// Requires SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY as Netlify env vars
// (the service role key must never be exposed to the browser — that's why
// this runs server-side as a function instead of in peakcheck_live.html).
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

  const email = (body.email || '').trim();
  const clientId = body.clientId;
  if (!email || !clientId) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'email and clientId are required' }) };
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

  // Verify the caller is a signed-in coach before sending anything.
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
    return { statusCode: 403, headers, body: JSON.stringify({ error: 'Only the coach can send invites' }) };
  }

  const { data: clientRow, error: clientErr } = await admin
    .from('clients')
    .select('id')
    .eq('id', clientId)
    .single();
  if (clientErr || !clientRow) {
    return { statusCode: 404, headers, body: JSON.stringify({ error: 'Client not found' }) };
  }

  const siteUrl = process.env.SITE_URL || `https://${event.headers.host}`;
  const { error: inviteErr } = await admin.auth.admin.inviteUserByEmail(email, {
    data: { role: 'client', client_id: clientId },
    redirectTo: siteUrl
  });
  if (inviteErr) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: inviteErr.message }) };
  }

  await admin
    .from('clients')
    .update({ invited_email: email, invite_sent_at: new Date().toISOString() })
    .eq('id', clientId);

  return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
};
