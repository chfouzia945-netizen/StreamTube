# StreamTube Complete

A functional YouTube-style starter platform for Railway/Node.js.

## Included
- Home, search and categories
- Registration/login
- Creator channels via user accounts
- Video upload + thumbnail
- Video player
- Views, likes, comments, subscribe
- Creator Studio analytics
- Demo earnings ledger + withdrawal requests
- Admin dashboard + withdrawal approval
- Reports
- Responsive dark UI

## Run locally
1. Install Node.js 18+.
2. Open this folder in terminal.
3. Run `npm install`
4. Run `npm start`
5. Open `http://localhost:3000`

Demo admin:
Email: admin@streamtube.local
Password: Admin123!

## Railway
Upload this project to GitHub and deploy it as a Node service.
Build command: npm install
Start command: npm start
Add environment variable:
JWT_SECRET = a long random secret

## Important production notes
This version is a working foundation/demo, not a finished high-scale YouTube clone.
For real public scale, replace JSON storage and local uploads with a production database + object storage/CDN, add HLS transcoding, virus/file scanning, rate limits, email verification, password reset, moderation, copyright workflow, payment-provider integration, audit logs and a real ad network. Never use the demo admin password in production.
