# 💌 ZeroBounce + Supabase Auth Integration (Bolt.new Guide)
This repository is part of the **ZeroBounce Blog Post + Video Tutorial**, showing how to add **real-time email validation** to your **Bolt.new app** using **ZeroBounce** and **Supabase Auth**.

You’ll learn how to build a **production-ready signup flow** that catches typos, blocks disposable emails, and gives helpful “Did you mean…” suggestions — all powered by the ZeroBounce API.

Import our demo into your bolt.new account by clicking  <a href="https://bolt.new/~/sb1-9pfj4hp7"><img src="https://pbs.twimg.com/profile_images/1985788830180655104/wpxEZ8Rp_400x400.jpg" width="10" alt="View in Bolt.new" /> here</a>

---

## 🚀 Getting Started in Bolt.new

### 1. Upload the Two Files

Add this 2 files to the chat:

- [zb_migration.sql](https://github.com/zerobounce/bolt.new-supabase-auth-zerobounce-demo/blob/main/zb_migration.sql)
- [example_auth_form.tsx](https://github.com/zerobounce/bolt.new-supabase-auth-zerobounce-demo/blob/main/example_auth_form.tsx)


Use this setup prompt after files where uploaded:

```
You are my senior engineer programmer. I’m attaching two files:

zb_migration.sql example_auth_form.tsx

Plan

First apply the migration. Then implement a production-ready user signup flow in this repository using the attached files as the source of truth. Make minimal, idiomatic changes that fit the project’s existing stack and conventions.
```

This will apply the database migration and wire up the frontend automatically.

### Required production controls

The migration keeps the original fail-open behavior for ZeroBounce transport failures,
non-2xx responses, and unrecognized statuses. To deny signup in those cases, add a row to
`public.app_secrets` with `name = ZEROBOUNCE_FAIL_CLOSED` and `value = true`. Set it to
`false` (or remove the row) to restore the original behavior. Known invalid statuses and
missing API keys still block signup regardless of this flag. Rejection events are written
to PostgreSQL logs without raw email addresses; configure log retention and access.

For CAPTCHA, enable protection with hCaptcha in **Supabase Dashboard → Authentication →
Bot and Abuse Protection** and enter the hCaptcha secret key there. This Supabase Auth
setting is the server-side enforcement switch. In the app consuming
`example_auth_form.tsx`, set `VITE_ENABLE_AUTH_CAPTCHA=true` and set
`VITE_HCAPTCHA_SITE_KEY` to the public site key. The frontend flag only renders the widget
and sends its token; it cannot enforce CAPTCHA by itself. The example sends tokens for
both sign-up and sign-in because the Supabase setting protects Auth flows. To turn it off,
disable protection in Supabase first, then set the frontend flag to `false`.

Configure Supabase Auth signup rate limits separately. Every signup attempt that reaches
the database trigger can spend a ZeroBounce API credit, whether CAPTCHA is enabled or not.
Verify that repeated automated attempts are stopped before they reach the trigger.

---

### 2. Add Your ZeroBounce API Key (in Bolt.new)

This integration uses your **Supabase database** under the hood — so make sure **Cloud Mode is enabled** in Lovable.

Then:

1. Go to **Database → Tables → app_secrets**
2. Click **Add Row**
3. Add your API key like this:

| name | value | updated_at |
|------|--------|--------|
| ZEROBOUNCE_API_KEY | your_api_key_from_zerobounce.net | 2025-11-14 13:46:58+00

You can find your key at:  
👉 [https://www.zerobounce.net/members/API](https://www.zerobounce.net/members/API)

That’s it — your environment now knows how to talk to ZeroBounce!

---

### 3. Try the Signup Flow

Once the migration runs and your API key is set:

1. Go to "Preview" tab.
2. Try signing up with an email — for example, a typo like `jane@gmial.com`.
3. You’ll see a **“Did you mean…”** prompt appear in the UI.
4. Invalid or disposable emails will be rejected gracefully.

The magic happens automatically through Supabase triggers and functions set up by the migration.

---

## 🧠 How It Works (Behind the Scenes)

- When a user signs up, Supabase runs the **`before_auth_user_insert_validate_email`** trigger.
- This trigger calls **ZeroBounce’s `/validate` API** with your stored key.
- If the email is undeliverable or looks suspicious, it’s blocked before signup completes.
- Accepted validation results are stored in the **`zb_email_validation`** table; rejected attempts appear in PostgreSQL logs.
- The frontend form (`example_auth_form.tsx`) surfaces these results nicely with toast messages and suggestions.

---

## 💻 Code Overview

### 🗂️ `zb_migration.sql`
Sets up the Supabase backend:

- Table `app_secrets` for storing your API key.
- Table `zb_email_validation` for storing validation logs.
- Functions for parsing, validating, and logging results.
- A trigger on `auth.users` that automatically validates every signup.

---

### 💫 `example_auth_form.tsx`
A production-ready signup form component built with:
- React + TypeScript
- Supabase Auth
- shadcn/ui for a clean, modern style

---

## 📺 Watch the Video

🎥 See the full tutorial on how to integrate this in **Bolt.new** step by step:
> *(link video coming soon)*
