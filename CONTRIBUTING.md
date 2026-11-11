# Contributing to the ZeroBounce + Supabase Auth demo (Bolt.new)

Thank you for your interest in contributing. This document explains how to get set up and submit changes.

## Code of Conduct

By participating in this project, you agree to uphold our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

See the [README](README.md) for how the two files are used in Bolt.new with Supabase Auth. There is nothing to build or install; CI checks that the migration still contains the validation function and fails closed.

## How to Contribute

### Reporting Bugs

Open an [issue](https://github.com/zerobounce/bolt.new-supabase-auth-zerobounce-demo/issues) and include:

* What you did, step by step
* Expected vs actual behavior
* Relevant code or error messages

Never paste an API key, a real email address, or a raw API response that contains one into an issue.

### Submitting Changes

1. **Fork** the repository and create a branch from the default branch.
2. **Make your changes.** Keep `zb_migration.sql` and `example_auth_form.tsx` in step with each other, and with the Lovable demo, which uses the same migration. Do not weaken the grants, row-level security or fail-closed behaviour in the migration.
3. **Commit** with a clear message (e.g. `Add X`, `Fix Y`).
4. **Push** your branch and open a **Pull Request**. Explain what changed and why, and link any related issues.

Maintainers will review and may request changes. Once approved, your PR can be merged.

## Releases (maintainers)

There is no package to publish. Readers, including those arriving from the ZeroBounce blog post, use the files on `main`, so a change is live as soon as it is merged.

## Questions

* [ZeroBounce API docs](https://www.zerobounce.net/docs/)
* [Project homepage](https://zerobounce.net)
* Contact: **integrations@zerobounce.net**

Thanks for contributing.
