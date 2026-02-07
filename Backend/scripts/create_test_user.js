// Simple helper to create a test user via the running backend and print the token
(async function(){
  try{
    const base = process.env.BASE_URL || 'http://localhost:3000';
    const nom = process.env.TEST_NOM || 'Dev Test';
    const email = process.env.TEST_EMAIL || 'devtest@example.com';
    const password = process.env.TEST_PASSWORD || 'testpass123';
    const role = process.env.TEST_ROLE || 'admin';

    console.log('Registering', email);
    const r = await fetch(base + '/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nom, email, password, role })
    });
    const regText = await r.text();
    try{ console.log('REGISTER:', JSON.parse(regText)); } catch(e){ console.log('REGISTER (raw):', regText); }

    console.log('Logging in', email);
    const r2 = await fetch(base + '/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const t = await r2.text();
    let token = null;
    try{ const j = JSON.parse(t); token = j.token; console.log('LOGIN:', j); } catch(e){ console.log('LOGIN (raw):', t); }

    if (token){
      console.log('Calling /me with token');
      const r3 = await fetch(base + '/me', { headers: { Authorization: 'Bearer ' + token } });
      const me = await r3.json();
      console.log('ME:', me);
    } else {
      console.error('No token received; aborting');
    }
  }catch(err){
    console.error('Script failed:', err);
    process.exit(1);
  }
})();
