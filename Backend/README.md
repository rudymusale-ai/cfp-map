Backend (minimal)

Files created:
- package.json
- server.js
- db.js
- migrate.js
- schema.sql
- .env.example

Quick start

1. Enter the `Backend` folder:

```powershell
cd "c:\Users\rudym\OneDrive\Documents\Web Dev\New CFP App\Backend"
```

2. Install dependencies:

```powershell
npm install
```

3. Copy `.env.example` to `.env` and fill DB credentials:

```powershell
copy .env.example .env
# edit .env and set DB_USER, DB_PASS, DB_NAME
```

4. Run migrations (will create database if `DB_NAME` set):

```powershell
npm run migrate
```

5. Start server:

```powershell
npm start
```

6. The frontend expects a `/me` endpoint — the server provides `/me` (returns first user from DB if present, otherwise a default role from `DEFAULT_ROLE`).

Notes
- This is a minimal scaffold for local development. Add proper auth, validation and error handling before production use.

Authentication
- The backend implements basic JWT authentication.
- Use `POST /auth/register` to create a user (body JSON: `nom,email,password,role`).
- Use `POST /auth/login` to obtain a token (body JSON: `email,password`). The response contains `{ token }`.
- Store the token in the browser (e.g. `localStorage`) and send it as `Authorization: Bearer <token>` for protected calls.

Notes
- Update `.env` with `JWT_SECRET` (strong random string) before using in production.
