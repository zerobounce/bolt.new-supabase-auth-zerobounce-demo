# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

A demo that adds real-time ZeroBounce email validation to Supabase Auth sign-up in a Bolt.new app. It is two files that a user hands to Bolt.new's AI assistant, plus the README that walks through it. It is not a package and has no build.

## Layout

- `zb_migration.sql`: the Supabase migration. It creates `public.app_secrets` (where the API key lives), `public.zb_email_validation` (the validation log), `validate_email_with_zerobounce`, and a `BEFORE INSERT` trigger on `auth.users` that blocks a sign-up ZeroBounce rejects.
- `example_auth_form.tsx`: the sign-up form, including the "Did you mean…" suggestion.
- `README.md`: the step-by-step guide.

## Commands

There are none to run locally. CI (`.github/workflows/ci.yml`) checks that the migration still defines the validation function and still fails closed.

## Conventions

- **The API key never reaches the client.** It is read inside the database from `public.app_secrets`. Do not move it to the frontend, an environment variable the browser can read, or the migration file.
- **Keep the security controls.** The migration revokes `EXECUTE` on the validation function and all table access from `anon` and `authenticated`, and enables row-level security with deny-all policies. A change must not loosen any of them.
- **Fail closed when there is no key.** Without a key, addresses are not treated as valid.
- **This demo and the Lovable demo share the same `zb_migration.sql`.** Change both together.
