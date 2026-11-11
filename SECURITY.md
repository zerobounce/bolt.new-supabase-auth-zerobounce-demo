# Security Policy

## Reporting a Vulnerability

If you think you've found a security issue, please report it privately instead of opening a public issue.

**Email:** integrations@zerobounce.net (use a subject like `[bolt.new-supabase-auth-zerobounce-demo] Security`).

We'll look into reports as we can. If the issue is in the ZeroBounce API or service rather than this demo, we may forward it to the right team.

## Supported Versions

This is a demo, not a versioned package. We fix the current state of `main`; copy the latest `zb_migration.sql` and `example_auth_form.tsx` into your project.

## Tips for Using This Demo

* The migration reads the ZeroBounce API key from the `public.app_secrets` table. It revokes every client role's access to that table and enables row-level security with a deny-all policy; keep both. In production, prefer Supabase Vault.
* Never put the API key in the frontend, in `example_auth_form.tsx`, in the migration file, or in a commit.
* `validate_email_with_zerobounce` is not callable from the client on purpose: each call spends ZeroBounce credits. Keep its `EXECUTE` revoked from `anon` and `authenticated`.
* `zb_email_validation` stores submitted email addresses. Treat it as personal data and add a retention job.
* Keep the GitHub Actions in `.github/workflows/` pinned to a commit SHA, and let Dependabot's security updates move them.

Thanks for helping keep things secure.
