# Teacher Daisy Secure Classroom

A small Node.js + Express app with server-side authentication, session cookies, and teacher/student roles. The private classroom page is served only after login; the shared board is read-only for students and editable by teachers.

## Requirements

- Node.js 18 or newer
- npm

## Run locally

1. Extract this folder.
2. Open a terminal in this folder.
3. Install dependencies:

   ```bash
   npm install
   ```

4. Start the app:

   ```bash
   npm start
   ```

5. Open <http://localhost:3000>.

## Demo accounts

| Role | Username | Password |
|---|---|---|
| Teacher | `teacher` | `TeacherDemo!2026` |
| Student | `student` | `StudentDemo!2026` |

These are public demo credentials, not production credentials. Change them before hosting this app.

## What is protected

- `/classroom` redirects to `/login` when no authenticated session exists.
- `/api/content` requires a valid session.
- `POST /api/content` additionally requires the teacher role and a CSRF token.
- Student dashboard HTML does not contain the teacher editor form or save button.
- Log out destroys the server session and clears the session cookie.
- Password verification uses Node's built-in `crypto.scrypt` with per-user salts and constant-time hash comparison.
- Login attempts are rate-limited.
- Content is written to `data/content.json`, which is ignored by Git.

## Configure a session secret

For local testing, the app has a development fallback. Before deployment, set a strong random secret (at least 32 characters) as `SESSION_SECRET`. You can create one with:

```bash
node -e "console.log(require('node:crypto').randomBytes(48).toString('hex'))"
```

Set `NODE_ENV=production`, use HTTPS, and set `SESSION_SECRET` in your hosting provider's environment variables. The app sets secure session cookies in production.

## Important deployment notes

This is a working local demo, not a complete production hosting setup:

- Express's default in-memory session store is intended for local development only. Replace it with a persistent session store such as Redis or a database-backed store for deployment.
- Replace the demo accounts with unique credentials and a proper user database; never share the demo passwords publicly.
- Put the app behind HTTPS. Do not expose the old standalone `.html` file as a public page. If you previously uploaded that static HTML to a public host, remove it there: adding this backend does not retroactively protect a separate public copy.
- Back up `data/content.json` and consider using a database for multi-user or multi-instance deployments.
- Add account recovery, audit logs, monitoring, and stronger operational controls before using it for sensitive student records.

## Files

- `server.js` — authentication, session handling, role checks, CSRF checks, and content API
- `public/login.html` — login screen
- `public/classroom.html` — protected dashboard template
- `public/classroom.js` — content display and teacher save interaction
- `public/styles.css` — responsive styling
- `data/` — shared content storage created/used by the app
