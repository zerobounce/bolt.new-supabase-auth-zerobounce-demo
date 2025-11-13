# 💌 ZeroBounce + Supabase Auth Integration (Lovable Cloud Guide)
This repository is part of the **ZeroBounce Blog Post + Video Tutorial**, showing how to add **real-time email validation** to your **Lovable app** using **ZeroBounce** and **Supabase Auth**.

You’ll learn how to build a **production-ready signup flow** that catches typos, blocks disposable emails, and gives helpful “Did you mean…” suggestions — all powered by the ZeroBounce API.

Remix with <a href="https://lovable.dev/projects/53eeac2c-f1a9-4a55-a2b5-b1046abaf21e?magic_link=mc_3adc5f4c-95e3-425c-8fcf-1229d21044a2"><img src="https://lovable.dev/img/logo/lovable-logo-icon.svg" width="10" alt="View in Lovable" /> Lovable</a>

---

## 🚀 Getting Started in Lovable

### 1. Upload the Two Files

Add this 2 files to the chat:

- [zb_migration.sql](https://github.com/zerobounce/lovable-supabase-auth-zerobounce-demo/blob/main/zb_migration.sql)
- [example_auth_form.tsx](https://github.com/zerobounce/lovable-supabase-auth-zerobounce-demo/blob/main/example_auth_form.tsx)


Use this setup prompt after files where uploaded:

```
You are my senior engineer programmer. I’m attaching two files:

zb_migration.sql example_auth_form.tsx

Plan

First apply the migration. Then implement a production-ready user signup flow in this repository using the attached files as the source of truth. Make minimal, idiomatic changes that fit the project’s existing stack and conventions.
```

This will apply the database migration and wire up the frontend automatically.

---

### 2. Add Your ZeroBounce API Key (in Lovable Cloud)

This integration uses your **Supabase database** under the hood — so make sure **Cloud Mode is enabled** in Lovable.

Then:

1. Go to **Cloud → Tables → app_secrets**
2. Click **Insert Row**
3. Add your API key like this:

| name | value |
|------|--------|
| ZEROBOUNCE_API_KEY | your_api_key_from_zerobounce.net |

You can find your key at:  
👉 [https://www.zerobounce.net/members/API](https://www.zerobounce.net/members/API)

That’s it — your Cloud environment now knows how to talk to ZeroBounce!

---

### 3. Try the Signup Flow

Once the migration runs and your API key is set:

1. Go to your Lovable app preview.
2. Try signing up with an email — for example, a typo like `jane@gmial.com`.
3. You’ll see a **“Did you mean…”** prompt appear in the UI.
4. Invalid or disposable emails will be rejected gracefully.

The magic happens automatically through Supabase triggers and functions set up by the migration.

---

## 🧠 How It Works (Behind the Scenes)

- When a user signs up, Supabase runs the **`before_auth_user_insert_validate_email`** trigger.
- This trigger calls **ZeroBounce’s `/validate` API** with your stored key.
- If the email is undeliverable or looks suspicious, it’s blocked before signup completes.
- The validation result is stored in the **`zb_email_validation`** table for analytics or debugging.
- The frontend form (`example_auth_form.tsx`) surfaces these results nicely with toast messages and suggestions.

---

## 💻 File Overview

### 🗂️ `zb_migration.sql`
Sets up the Supabase backend:

- Table `app_secrets` for storing your API key.
- Table `zb_email_validation` for storing validation logs.
- Functions for parsing, validating, and logging results.
- A trigger on `auth.users` that automatically validates every signup.

This migration is idempotent — you can run it safely multiple times in Cloud.

---

### 💫 `example_auth_form.tsx`
A complete, ready-to-use React component for user signup and login.

- Integrates Supabase Auth.
- Displays “Did you mean…” suggestions inline.
- Styled with [shadcn/ui](https://ui.shadcn.com) for production-ready polish.
- Automatically shows ZeroBounce validation feedback through toasts.

---

## 📺 Watch the Video

🎥 See the full tutorial on how to integrate this in **Lovable Cloud** step by step:
> *(link video coming soon)*

---

## 🧩 Tech Stack

- **Lovable Cloud** (Supabase backend)
- **ZeroBounce API**
- **React / TypeScript**
- **shadcn/ui**

---
