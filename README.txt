CODING FROM DOOARS - FIREBASE + BACKBLAZE B2 FIX

Storage architecture:
- Firebase: Authentication, Firestore, Realtime Database and other app data.
- Backblaze B2: customer photos/files and payment screenshots.
- Firebase Storage: NOT USED for media uploads.
- Supabase: NOT USED.

Files:
- index.html
- server.js

Important:
Replace the live index.html and server.js with these files, then restart the Node server.
Keep the existing .env / Firebase service-account configuration and B2 credentials.
Do not put service-account private keys inside index.html.
