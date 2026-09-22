# StreamTube Phase 3 — Monetization Core

Added a platform-side ad campaign and creator revenue ledger layer.

## Included
- Admin ad campaign creation/list/status endpoints.
- Ad serving endpoint for watch placement.
- Impression accounting against campaign budget.
- Configurable creator CPM and platform CPM.
- Creator earnings ledger entries tied to video + ad campaign.
- Campaign budget exhaustion handling.
- Existing withdrawal/earnings APIs continue to work.

## Important
This is the **platform monetization core**, not a connected Google AdSense/Ad Manager account and not a payment gateway. Real advertiser billing and creator payouts still require a payment/ad provider and credentials.
