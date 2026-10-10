# Mabeli Sentinel v4 — Multi-Organization & Guided Use

Mabeli Sentinel is a cybersecurity platform **provided by Mabeli Technology**, not a single-company internal application.

## Public entry model

A visitor to a hosted instance sees two choices:

1. **Sign in** — for an existing account or team member.
2. **Create organization** — creates a private customer workspace and makes the creator the **Owner of that organization only**.

A public registrant is never made a Mabeli Sentinel platform administrator.

## Workspace isolation

Every organization has isolated operational records, including:

- traffic events;
- detections;
- alerts;
- incidents;
- benchmark/test runs;
- settings;
- traffic-source API keys;
- audit events.

The active organization is sent to the backend with `X-Organization-Id`. The backend validates that the authenticated user has an active membership before using that workspace. Tenant-aware model middleware automatically scopes organization-owned MongoDB reads, writes, updates, deletes and aggregations.

## Organization roles

- **Owner** — full workspace ownership and access management.
- **Admin** — workspace settings, team, traffic sources and security operations.
- **Analyst** — analysis, detections, alerts and incident investigation.
- **Viewer** — read-only workspace access.

Revoke removes access to one organization without deleting the person's global Sentinel account. Remove deletes the organization membership while preserving the account if it belongs to another organization.

The last active Owner cannot be removed or revoked.

## Multiple organizations

A user can belong to more than one organization and switch workspaces from the sidebar. Data does not cross workspace boundaries.

## Guided first use

New organization owners are sent to **Getting Started**, which explains:

1. the workspace;
2. how to run a safe first analysis;
3. how to add team members;
4. how to connect live monitoring;
5. where to learn the platform.

The **Help & How It Works** page explains the complete flow, the meaning of detections/alerts/incidents, and what file/data format Sentinel expects.

## What to upload

Sentinel analyzes network-flow measurements. It does not classify a URL or normal text directly.

Use the included files when learning:

- `/test-data/single-benign.json`
- `/test-data/single-portscan.json`
- `/test-data/batch-labelled.csv`
- `/test-data/batch-unlabelled.csv`

The Help page explains common fields and provides download buttons.

## Existing v2/v3 installations

Legacy users without memberships are migrated on their first authenticated request into one shared legacy workspace. Existing tenant-owned records without an organization are attached to that workspace. This preserves old local installations while moving them to the v4 access model.

## PSA alignment

The product remains the same PSA project at its core:

`Traffic → Node.js/Express → Python ML → benign/malicious + attack class → MongoDB → alert/dashboard`

Multi-organization workspaces, guided onboarding, RBAC, incident handling and model evaluation extend the system without changing that primary goal.
