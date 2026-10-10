# ClaimCompass

**Live Claim Evidence Checker**\n\nThink. Verify. Decide.

ClaimCompass searches web or news results through SerpApi from a FastAPI backend, organizes retrieved sources into reading cues, stores reports as local JSON, and exports a source-linked PDF. It never creates citations or truth scores when evidence is unavailable.

## Windows PowerShell setup

Open PowerShell in the workspace root:

```powershell
Set-Location E:\ClaimCompass
python -m venv backend\.venv
.\backend\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r backend\requirements.txt
Copy-Item backend\.env.example backend\.env
```

Edit `backend\.env` and replace `your_serpapi_key_here` with your SerpApi key. Keep this file private; it is ignored by git.

Set `AUTH_TOKEN_SECRET` to a long random value for local sessions. ClaimCompass stores local users in `backend\storage\users.json`, stores only PBKDF2 password hashes, and keeps reports scoped to the signed-in user. The local password-reset endpoint reports status only because no email provider is configured; it does not claim to send email.

Install and start the frontend in a second PowerShell window:

```powershell
Set-Location E:\ClaimCompass\frontend
npm install
npm run dev
```

Start the backend in the first window:

```powershell
Set-Location E:\ClaimCompass\backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --port 8000
```

Open http://localhost:5173. The backend API is available at http://localhost:8000/docs.

## API key behavior

A missing or placeholder `SERPAPI_API_KEY` returns a clear 503 configuration message. The frontend shows that message and does not fabricate results. Only the backend calls SerpApi.

The public landing page is at `/`. Authentication lives at `/login`, `/signup`, and `/forgot-password`; a signed-in user is redirected to `/dashboard`. The dashboard protects report listing, live search, and PDF export with the backend bearer session.

Judges can use `Explore Demo` on the landing or login page. Demo access creates a separate signed session marked `DEMO MODE`; it does not create a registered account or bypass real password authentication. Demo searches still call SerpApi and show a configuration error when the key is missing.

The frontend build splits icons, motion, and charts into vendor chunks. The Recharts vendor chunk may remain above Vite's 500 kB advisory threshold; this does not block the build and keeps the initial application chunk small.

## Useful checks

```powershell
Set-Location E:\ClaimCompass\backend
python -m py_compile app\main.py
Set-Location ..\frontend
npm run build
```
