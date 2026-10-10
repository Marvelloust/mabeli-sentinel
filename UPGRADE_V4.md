# Upgrade to Mabeli Sentinel v4

## What v4 fixes

- Removes the unsafe "first public visitor becomes global admin" behavior.
- Adds private organization workspaces.
- Makes Mabeli Technology the platform provider rather than the only monitored company.
- Adds workspace Owner/Admin/Analyst/Viewer roles.
- Adds team Add, Edit, Revoke, Restore and Remove controls.
- Adds workspace switching for users who belong to several organizations.
- Adds guided first-run onboarding.
- Adds a user-facing Help page explaining every major concept and upload format.
- Scopes security records, settings, integrations and audit events by organization.
- Scopes Socket.IO live updates to the active organization.
- Keeps legacy installations usable through automatic workspace migration.

## Upgrade

Replace the modified files with those from v4 and rebuild:

```bash
docker compose down
docker compose up -d --build
```

Then hard refresh the browser (`Ctrl + F5`).

Existing Docker MongoDB data can be retained. Legacy users are migrated into a shared legacy workspace when they next authenticate.

## First public use

A new visitor now chooses **Sign in** or **Create organization**. Creating an organization produces a private workspace and an Owner role only inside that workspace.

## Important deployment note

For a truly public internet deployment, add production email verification, password reset, HTTPS, domain verification where required, backups, rate-limit tuning and a private platform-operator administration surface. These are deployment controls, not required to demonstrate the PSA workflow locally.
