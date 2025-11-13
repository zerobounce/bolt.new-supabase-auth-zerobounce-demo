-- EXTENSIONS NEEDED
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pgsodium;
CREATE EXTENSION IF NOT EXISTS supabase_vault;
CREATE EXTENSION IF NOT EXISTS http WITH SCHEMA extensions;

-- =====================================================
-- TABLES
-- =====================================================

CREATE TABLE IF NOT EXISTS public.app_secrets (
  name TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE TABLE public.zb_email_validation (
  id UUID NOT NULL DEFAULT uuid_generate_v4(),
  email TEXT NOT NULL,
  status TEXT,
  sub_status TEXT,
  is_free_email BOOLEAN,
  did_you_mean TEXT,
  is_valid BOOLEAN NOT NULL DEFAULT false,
  raw_response JSONB,
  validated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  PRIMARY KEY (id)
);

CREATE INDEX idx_zb_email_validation_email ON public.zb_email_validation(email);
CREATE INDEX idx_zb_email_validation_validated_at ON public.zb_email_validation(validated_at DESC);

-- =====================================================
-- HELPER FUNCTIONS
-- =====================================================

CREATE OR REPLACE FUNCTION public.zb_parse_and_store(p_email TEXT, p_json JSONB)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_status_text TEXT;
  v_sub_status TEXT;
  v_free TEXT;
  v_free_bool BOOLEAN;
  v_did_you_mean TEXT;
  v_valid BOOLEAN;
BEGIN
  IF p_json IS NULL THEN
    RETURN;
  END IF;

  v_status_text := p_json->>'status';
  v_sub_status := p_json->>'sub_status';
  v_free := p_json->>'free_email';
  v_did_you_mean := nullif(p_json->>'did_you_mean', '');

  v_free_bool := CASE
    WHEN lower(coalesce(v_free, '')) IN ('true', 't', '1') THEN true
    WHEN lower(coalesce(v_free, '')) IN ('false', 'f', '0') THEN false
    ELSE NULL
  END;

  v_valid := CASE WHEN v_status_text = 'valid' THEN true ELSE false END;

  -- Insert validation log
  INSERT INTO public.zb_email_validation (
    email,
    status,
    sub_status,
    is_free_email,
    did_you_mean,
    is_valid,
    raw_response
  ) VALUES (
    p_email,
    v_status_text,
    v_sub_status,
    v_free_bool,
    v_did_you_mean,
    v_valid,
    p_json
  );
END;
$$;

-- Helper: returns true if the response indicates signup should be blocked
CREATE OR REPLACE FUNCTION public.zb_should_block_signup(p_json JSONB)
RETURNS BOOLEAN
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
  v_status TEXT;
  v_block_list TEXT;
  v_block_statuses TEXT[];
BEGIN
  IF p_json IS NULL THEN
    RETURN false;
  END IF;

  v_status := p_json->>'status';
  v_block_list := current_setting('app.zerobounce_block_statuses', true);
  IF v_block_list IS NULL OR trim(v_block_list) = '' THEN
    v_block_list := 'invalid,spamtrap,abuse,do_not_mail';
  END IF;
  v_block_statuses := string_to_array(lower(v_block_list), ',');

  RETURN lower(coalesce(v_status, '')) = ANY (v_block_statuses);
END;
$$;

-- Email validator using ZeroBounce (vault-backed, safe search_path)
CREATE OR REPLACE FUNCTION public.validate_email_with_zerobounce(p_email text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  api_key text;
  http_status int;
  http_body text;
  api_response jsonb;
  normalized_email text;
  status text;
  sub_status text;
  suggestion text;
  result_json jsonb;
BEGIN
  -- Normalize email (trim and lowercase)
  normalized_email := lower(trim(p_email));

  -- Get API key from app_secrets
  SELECT s.value INTO api_key
  FROM public.app_secrets s
  WHERE s.name = 'ZEROBOUNCE_API_KEY'
  ORDER BY s.updated_at DESC
  LIMIT 1;

  -- If no API key, return valid and log a skipped entry
  IF coalesce(api_key, '') = '' THEN
    api_response := jsonb_build_object(
      'status', 'skipped',
      'message', 'API key not configured',
      'email', normalized_email
    );
    PERFORM set_config('app.zb_last_validation', api_response::text, true);
    PERFORM public.zb_parse_and_store(normalized_email, api_response);
    RETURN jsonb_build_object(
      'valid', true,
      'email', normalized_email,
      'status', 'skipped',
      'message', 'API key not configured'
    );
  END IF;

  -- Tighten HTTP behavior to avoid long signup delays
  PERFORM set_config('extensions.http.timeout_msec', '3000', true);
  PERFORM set_config('extensions.http.max_redirects', '0', true);
  PERFORM set_config('extensions.http.verify_peer', 'on', true);

  -- Call ZeroBounce API (check HTTP status)
  SELECT r.status, r.content
  INTO http_status, http_body
  FROM extensions.http_post(
    'https://api.zerobounce.net/v2/validate',
    'api_key=' || api_key || '&email=' || normalized_email,
    'application/x-www-form-urlencoded'
  ) AS r;

  IF http_status < 200 OR http_status >= 300 OR http_body IS NULL THEN
    api_response := jsonb_build_object('status','error','message','Upstream validation error','email',normalized_email);
  ELSE
    api_response := http_body::jsonb;
  END IF;

  -- Stash raw API response and log it
  PERFORM set_config('app.zb_last_validation', api_response::text, true);
  PERFORM public.zb_parse_and_store(normalized_email, api_response);

  -- Extract status fields
  status := coalesce(api_response->>'status', '');
  sub_status := coalesce(api_response->>'sub_status', '');
  suggestion := nullif(api_response->>'did_you_mean', '');

  -- Build result json for the client
  IF status = 'valid' THEN
    result_json := jsonb_build_object(
      'valid', true,
      'email', normalized_email,
      'status', status
    );
  ELSIF suggestion IS NOT NULL THEN
    suggestion := lower(trim(suggestion));
    result_json := jsonb_build_object(
      'valid', false,
      'email', normalized_email,
      'status', status,
      'sub_status', sub_status,
      'did_you_mean', suggestion,
      'message', format('Email is not deliverable. Did you mean: %s?', suggestion)
    );
  ELSE
    result_json := jsonb_build_object(
      'valid', false,
      'email', normalized_email,
      'status', status,
      'sub_status', sub_status,
      'message', format('Email is not deliverable (status: %s)', status)
    );
  END IF;

  RETURN result_json;
END;
$$;

-- BEFORE INSERT trigger to validate email and optionally block
CREATE OR REPLACE FUNCTION public.before_auth_user_insert_validate_email()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_api_key TEXT;
  v_url TEXT;
  v_status INT;
  v_body TEXT;
  v_json JSONB;
  v_msg TEXT;
  v_did_you_mean TEXT;
  v_normalized_email TEXT;
BEGIN
  -- Only act if NEW.email is present
  IF NEW.email IS NULL OR length(trim(NEW.email)) = 0 THEN
    RETURN NEW;
  END IF;

  -- Require API key; read from app_secrets. If not set, allow signup
  SELECT s.value INTO v_api_key
  FROM public.app_secrets s
  WHERE s.name = 'ZEROBOUNCE_API_KEY'
  ORDER BY s.updated_at DESC
  LIMIT 1;
  IF v_api_key IS NULL OR v_api_key = '' THEN
    RETURN NEW;
  END IF;

  -- Normalize and quick-reject obvious invalid formats
  v_normalized_email := lower(trim(NEW.email));
  IF position('@' in v_normalized_email) = 0
     OR position('.' in split_part(v_normalized_email, '@', 2)) = 0
     OR v_normalized_email LIKE '% %' THEN
    RAISE EXCEPTION SQLSTATE '22023' USING MESSAGE = 'Email validation failed: invalid_format';
  END IF;

  -- Tighten HTTP behavior to avoid long signup delays
  PERFORM set_config('extensions.http.timeout_msec', '3000', true);
  PERFORM set_config('extensions.http.max_redirects', '0', true);
  PERFORM set_config('extensions.http.verify_peer', 'on', true);

  -- Call ZeroBounce validate endpoint
  v_url := 'https://api.zerobounce.net/v2/validate';

  -- Perform external call in a narrow protected block: swallow infra errors only
  BEGIN
    SELECT r.status, r.content
    INTO v_status, v_body
    FROM extensions.http_post(
      v_url,
      'api_key=' || v_api_key || '&email=' || v_normalized_email,
      'application/x-www-form-urlencoded'
    ) AS r;
  EXCEPTION WHEN OTHERS THEN
    RETURN NEW; -- network/timeouts/etc: allow signup
  END;

  -- Process response and enforce validation decisions (no exception handler here)
  IF v_status >= 200 AND v_status < 300 AND v_body IS NOT NULL THEN
    v_json := v_body::jsonb;

    -- Stash JSON for potential downstream use in this session/tx
    PERFORM set_config('app.zb_last_validation', v_body, true);

    -- Log immediately during signup flow so logging does not depend on AFTER trigger
    PERFORM public.zb_parse_and_store(v_normalized_email, v_json);

    -- If there's a typo suggestion, block with a clear message containing the suggestion
    v_did_you_mean := nullif(v_json->>'did_you_mean', '');
    IF v_did_you_mean IS NOT NULL THEN
      RAISE EXCEPTION SQLSTATE '22023' USING
        MESSAGE = 'Email looks like a typo. Did you mean ' || v_did_you_mean || '?',
        DETAIL = 'did_you_mean=' || v_did_you_mean,
        HINT = 'Update the email to the suggested address or correct the spelling.';
    END IF;

    -- Decide to block or allow based on status/sub_status
    IF public.zb_should_block_signup(v_json) THEN
      v_msg := 'Email validation failed: status=' || coalesce(v_json->>'status', 'unknown') ||
               CASE WHEN v_json ? 'sub_status' AND (v_json->>'sub_status') <> '' THEN ', sub_status=' || v_json->>'sub_status' ELSE '' END;
      RAISE EXCEPTION SQLSTATE '22023' USING MESSAGE = v_msg;
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

-- AFTER INSERT trigger handler to log validation result
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_json_text TEXT;
  v_json JSONB;
BEGIN
  -- Do not log here anymore; logging happens in BEFORE trigger or via RPC
  -- Fallback: call validator (RPC already logs full response; we do nothing here)
  IF NEW.email IS NOT NULL AND length(trim(NEW.email)) > 0 THEN
    PERFORM public.validate_email_with_zerobounce(NEW.email);
  END IF;

  RETURN NEW;
END;
$$;

-- =====================================================
-- TRIGGERS
-- =====================================================

-- Idempotent trigger creation; remove AFTER trigger to avoid double validation/logging
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP TRIGGER IF EXISTS before_auth_user_insert_validate_email ON auth.users;

CREATE TRIGGER before_auth_user_insert_validate_email
  BEFORE INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.before_auth_user_insert_validate_email();

-- =====================================================
-- GRANTS
-- =====================================================

-- Revoke all public and anonymous access to prevent API quota abuse on validate_email_with_zerobounce
REVOKE EXECUTE ON FUNCTION public.validate_email_with_zerobounce(text) FROM public;
REVOKE EXECUTE ON FUNCTION public.validate_email_with_zerobounce(text) FROM anon;

-- Allow authenticated role to call the validator
GRANT EXECUTE ON FUNCTION public.validate_email_with_zerobounce(text) TO authenticated;
-- Also allow anon for pre-auth signup fallback suggestions (consider moving to Edge Function for rate limiting in production)
GRANT EXECUTE ON FUNCTION public.validate_email_with_zerobounce(text) TO anon;

-- Secure helper functions: revoke from public/anon, only allow internal use
REVOKE EXECUTE ON FUNCTION public.zb_parse_and_store(TEXT, JSONB) FROM public;
REVOKE EXECUTE ON FUNCTION public.zb_parse_and_store(TEXT, JSONB) FROM anon;
REVOKE EXECUTE ON FUNCTION public.zb_should_block_signup(JSONB) FROM public;
REVOKE EXECUTE ON FUNCTION public.zb_should_block_signup(JSONB) FROM anon;

-- Secure tables: prevent public/anon access to validation logs and secrets
REVOKE ALL ON TABLE public.zb_email_validation FROM public;
REVOKE ALL ON TABLE public.zb_email_validation FROM anon;
REVOKE ALL ON TABLE public.app_secrets FROM public;
REVOKE ALL ON TABLE public.app_secrets FROM anon;
REVOKE ALL ON TABLE public.app_secrets FROM authenticated;

-- Additional helpful index for latest-per-user queries
CREATE INDEX IF NOT EXISTS idx_zb_email_validation_user_ts ON public.zb_email_validation(validated_at DESC) INCLUDE (status, sub_status);

-- =====================================================
-- ROW LEVEL SECURITY (defense in depth)
-- =====================================================

-- Enable RLS on sensitive tables
ALTER TABLE IF EXISTS public.app_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.zb_email_validation ENABLE ROW LEVEL SECURITY;

-- Deny-all policies to prevent accidental exposure if privileges are granted later
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename = 'app_secrets'
      AND policyname = 'app_secrets_deny_all'
  ) THEN
    CREATE POLICY app_secrets_deny_all
      ON public.app_secrets
      FOR ALL
      USING (false)
      WITH CHECK (false);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename = 'zb_email_validation'
      AND policyname = 'zb_email_validation_deny_all'
  ) THEN
    CREATE POLICY zb_email_validation_deny_all
      ON public.zb_email_validation
      FOR ALL
      USING (false)
      WITH CHECK (false);
  END IF;
END $$;

-- Guarded basic email format check constraint
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'email_basic_format'
      AND conrelid = 'public.zb_email_validation'::regclass
  ) THEN
    ALTER TABLE public.zb_email_validation
      ADD CONSTRAINT email_basic_format CHECK (
        position('@' in email) > 1
        AND position('.' in split_part(email, '@', 2)) > 1
        AND email NOT LIKE '% %'
      );
  END IF;
END $$;
