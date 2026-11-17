-- EXTENSIONS NEEDED
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pgsodium;
CREATE EXTENSION IF NOT EXISTS supabase_vault;
CREATE EXTENSION IF NOT EXISTS http WITH SCHEMA extensions;

-- =====================================================
-- TABLES
-- =====================================================

-- Store secrets via Supabase Vault in production; this table is a demo fallback only.
CREATE TABLE IF NOT EXISTS public.app_secrets (
  name TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Validation log may contain PII; set a retention job in production (e.g. delete rows older than 90 days).
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

-- A real false success flag: boolean false, number 0 (including 0.0), or
-- "false" / "0" in any case, trimmed. "x", 0.4, 5, and a true flag are not.
CREATE OR REPLACE FUNCTION public.zb_false_success(p_json JSONB)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
SET search_path = ''
AS $$
DECLARE
  v_flag jsonb;
  v_text text;
BEGIN
  IF p_json IS NULL OR NOT (p_json ? 'success') THEN
    RETURN false;
  END IF;
  v_flag := p_json->'success';
  IF jsonb_typeof(v_flag) = 'boolean' THEN
    RETURN v_flag = 'false'::jsonb;
  END IF;
  IF jsonb_typeof(v_flag) = 'number' THEN
    RETURN v_flag = '0'::jsonb;
  END IF;
  IF jsonb_typeof(v_flag) = 'string' THEN
    v_text := lower(trim(p_json->>'success'));
    RETURN v_text IN ('false', '0');
  END IF;
  RETURN false;
END;
$$;

-- Controls, Unicode whitespace, and the invisible characters a key must not carry.
-- An ordinary space is refused too, including in the middle of the key.
CREATE OR REPLACE FUNCTION public.zb_api_key_rejected(p_key text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
SET search_path = ''
AS $$
DECLARE
  i int;
  cp int;
BEGIN
  IF p_key IS NULL OR p_key = '' THEN
    RETURN true;
  END IF;
  FOR i IN 1..char_length(p_key) LOOP
    cp := ascii(substr(p_key, i, 1));
    IF cp <= 31
       OR (cp >= 127 AND cp <= 159)
       OR cp IN (32, 160, 173, 1536, 2192, 2193, 5760, 6155, 6156, 6157, 6158, 6159, 8203, 8232, 8233, 8238, 8239, 8287, 8294, 12288, 65279, 65529, 119155)
       OR (cp >= 8192 AND cp <= 8202)
    THEN
      RETURN true;
    END IF;
  END LOOP;
  RETURN false;
END;
$$;

-- One decode step for a body that may quote the key. %u0027 is left as text.
CREATE OR REPLACE FUNCTION public.zb_loosen_encoding(p_text text)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
SET search_path = ''
AS $$
DECLARE
  v text := '';
  i int := 1;
  n int;
  hex text;
  code int;
BEGIN
  IF p_text IS NULL THEN
    RETURN NULL;
  END IF;
  n := char_length(p_text);
  WHILE i <= n LOOP
    IF substr(p_text, i, 1) = '%'
       AND i + 2 <= n
       AND substr(p_text, i + 1, 2) ~ '^[0-9A-Fa-f]{2}$'
    THEN
      code := ('x' || substr(p_text, i + 1, 2))::bit(8)::int;
      v := v || chr(code);
      i := i + 3;
    ELSIF substr(p_text, i, 2) = '\u' OR substr(p_text, i, 2) = '\U' OR substr(p_text, i, 2) = '\x' OR substr(p_text, i, 2) = '\X' THEN
      IF substr(p_text, i + 2, 1) = '{' THEN
        hex := substring(p_text FROM i + 3 FOR 8);
        hex := substring(hex FROM '^[0-9A-Fa-f]+');
        IF hex IS NOT NULL AND char_length(hex) BETWEEN 1 AND 6 AND substr(p_text, i + 3 + char_length(hex), 1) = '}' THEN
          code := ('x' || lpad(hex, 8, '0'))::bit(32)::int;
          IF code <= 1114111 THEN
            v := v || chr(code);
          ELSE
            v := v || substr(p_text, i, 1);
          END IF;
          i := i + 4 + char_length(hex);
        ELSE
          v := v || substr(p_text, i, 1);
          i := i + 1;
        END IF;
      ELSIF substr(p_text, i + 1, 1) = 'U'
            AND substr(p_text, i + 2, 8) ~ '^[0-9A-Fa-f]{8}$' THEN
        code := ('x' || substr(p_text, i + 2, 8))::bit(32)::int;
        IF code <= 1114111 THEN
          v := v || chr(code);
        ELSE
          v := v || substr(p_text, i, 1);
          i := i + 1;
          CONTINUE;
        END IF;
        i := i + 10;
      ELSIF (substr(p_text, i + 1, 1) = 'u' OR substr(p_text, i + 1, 1) = 'U')
            AND substr(p_text, i + 2, 4) ~ '^[0-9A-Fa-f]{4}$' THEN
        code := ('x' || substr(p_text, i + 2, 4))::bit(16)::int;
        v := v || chr(code);
        i := i + 6;
      ELSIF (substr(p_text, i + 1, 1) = 'x' OR substr(p_text, i + 1, 1) = 'X')
            AND substr(p_text, i + 2, 2) ~ '^[0-9A-Fa-f]{2}$' THEN
        code := ('x' || substr(p_text, i + 2, 2))::bit(8)::int;
        v := v || chr(code);
        i := i + 4;
      ELSE
        v := v || substr(p_text, i, 1);
        i := i + 1;
      END IF;
    ELSIF substr(p_text, i, 1) = '\' AND substr(p_text, i + 1, 1) BETWEEN '0' AND '7' THEN
      code := ascii(substr(p_text, i + 1, 1)) - 48;
      i := i + 2;
      IF i <= n AND substr(p_text, i, 1) BETWEEN '0' AND '7' THEN
        code := code * 8 + ascii(substr(p_text, i, 1)) - 48;
        i := i + 1;
        IF i <= n AND substr(p_text, i, 1) BETWEEN '0' AND '7' AND code <= 31 THEN
          code := code * 8 + ascii(substr(p_text, i, 1)) - 48;
          i := i + 1;
        END IF;
      END IF;
      v := v || chr(code);
    ELSE
      v := v || substr(p_text, i, 1);
      i := i + 1;
    END IF;
  END LOOP;
  RETURN v;
END;
$$;

CREATE OR REPLACE FUNCTION public.zb_redact_text(p_text text, p_key text)
RETURNS text
LANGUAGE plpgsql
STABLE
SET search_path = ''
AS $$
DECLARE
  v text;
  decoded text;
  i int;
BEGIN
  IF p_text IS NULL OR p_key IS NULL OR p_key = '' THEN
    RETURN p_text;
  END IF;
  v := replace(p_text, p_key, '***');
  v := replace(v, extensions.urlencode(p_key), '***');
  decoded := v;
  FOR i IN 1..4 LOOP
    IF position(p_key IN decoded) > 0 THEN
      RETURN 'the response text was omitted because it contained a credential';
    END IF;
    decoded := public.zb_loosen_encoding(decoded);
  END LOOP;
  IF position(p_key IN decoded) > 0 OR position(upper(p_key) IN upper(decoded)) > 0 THEN
    RETURN 'the response text was omitted because it contained a credential';
  END IF;
  RETURN v;
END;
$$;

-- Fields the log may keep. Message and error strings are not copied: they are where a body echoes the key.
CREATE OR REPLACE FUNCTION public.zb_stored_response(p_json JSONB, p_key text)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SET search_path = ''
AS $$
DECLARE
  v jsonb := '{}'::jsonb;
  k text;
BEGIN
  IF p_json IS NULL THEN
    RETURN NULL;
  END IF;
  FOREACH k IN ARRAY ARRAY['status', 'sub_status', 'did_you_mean', 'free_email', 'address', 'email']
  LOOP
    IF p_json ? k AND jsonb_typeof(p_json->k) = 'string' THEN
      v := v || jsonb_build_object(k, public.zb_redact_text(p_json->>k, p_key));
    ELSIF p_json ? k THEN
      v := v || jsonb_build_object(k, p_json->k);
    END IF;
  END LOOP;
  IF p_json ? 'success' AND jsonb_typeof(p_json->'success') = 'string' THEN
    v := v || jsonb_build_object('success', public.zb_redact_text(p_json->>'success', p_key));
  ELSIF p_json ? 'success' THEN
    v := v || jsonb_build_object('success', p_json->'success');
  END IF;
  RETURN v;
END;
$$;

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

  v_valid := CASE
    WHEN public.zb_false_success(p_json) THEN false
    WHEN v_status_text = 'valid' THEN true
    ELSE false
  END;

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

  IF public.zb_false_success(p_json) THEN
    RETURN true;
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

  -- Fail closed when the API key is missing or contains a control or invisible character.
  IF coalesce(api_key, '') = '' OR public.zb_api_key_rejected(api_key) THEN
    api_response := jsonb_build_object(
      'status', 'error',
      'message', CASE WHEN coalesce(api_key, '') = '' THEN 'API key not configured' ELSE 'API key is not valid' END,
      'email', normalized_email
    );
    PERFORM set_config('app.zb_last_validation', api_response::text, true);
    PERFORM public.zb_parse_and_store(normalized_email, api_response);
    RETURN jsonb_build_object(
      'valid', false,
      'email', normalized_email,
      'status', 'error',
      'message', CASE
        WHEN coalesce(api_key, '') = '' THEN 'Email validation is unavailable: API key not configured'
        ELSE 'Email validation is unavailable: API key is not valid'
      END
    );
  END IF;

  -- pgsql-http reads http.timeout_msec. It follows up to five redirects for POST
  -- and has no setting that turns that off, so the key in the body can be resent
  -- to a 307/308 Location. Peer verification stays at the extension default (on).
  PERFORM set_config('http.timeout_msec', '3000', true);

  -- Call ZeroBounce API (check HTTP status)
  SELECT r.status, r.content
  INTO http_status, http_body
  FROM extensions.http_post(
    'https://api.zerobounce.net/v2/validate',
    'api_key=' || extensions.urlencode(api_key) || '&email=' || extensions.urlencode(normalized_email),
    'application/x-www-form-urlencoded'
  ) AS r;

  IF http_status < 200 OR http_status >= 300 OR http_body IS NULL THEN
    api_response := jsonb_build_object('status','error','message','Upstream validation error','email',normalized_email);
  ELSE
    api_response := http_body::jsonb;
  END IF;

  -- Stash the status fields, not the raw body.
  PERFORM set_config('app.zb_last_validation', public.zb_stored_response(api_response, api_key)::text, true);
  PERFORM public.zb_parse_and_store(normalized_email, public.zb_stored_response(api_response, api_key));

  -- Extract status fields
  status := public.zb_redact_text(coalesce(api_response->>'status', ''), api_key);
  sub_status := public.zb_redact_text(coalesce(api_response->>'sub_status', ''), api_key);
  suggestion := nullif(public.zb_redact_text(api_response->>'did_you_mean', api_key), '');
  IF suggestion = 'the response text was omitted because it contained a credential' THEN
    suggestion := NULL;
  END IF;

  -- Build result json for the client
  IF status = 'valid' AND NOT public.zb_false_success(api_response) THEN
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
  v_fail_closed BOOLEAN := false;
BEGIN
  -- Only act if NEW.email is present
  IF NEW.email IS NULL OR length(trim(NEW.email)) = 0 THEN
    RETURN NEW;
  END IF;

  -- Require API key; read from app_secrets. Fail closed if not configured.
  SELECT s.value INTO v_api_key
  FROM public.app_secrets s
  WHERE s.name = 'ZEROBOUNCE_API_KEY'
  ORDER BY s.updated_at DESC
  LIMIT 1;
  IF v_api_key IS NULL OR v_api_key = '' THEN
    RAISE EXCEPTION SQLSTATE '22023' USING
      MESSAGE = 'Email validation is unavailable: API key not configured';
  END IF;
  IF public.zb_api_key_rejected(v_api_key) THEN
    RAISE EXCEPTION SQLSTATE '22023' USING
      MESSAGE = 'Email validation is unavailable: API key is not valid';
  END IF;

  -- Opt in to denying signup when the validation service is unavailable.
  SELECT lower(trim(s.value)) IN ('true', '1', 'on') INTO v_fail_closed
  FROM public.app_secrets s
  WHERE s.name = 'ZEROBOUNCE_FAIL_CLOSED';
  v_fail_closed := coalesce(v_fail_closed, false);

  -- Normalize and quick-reject obvious invalid formats
  v_normalized_email := lower(trim(NEW.email));
  IF position('@' in v_normalized_email) = 0
     OR position('.' in split_part(v_normalized_email, '@', 2)) = 0
     OR v_normalized_email LIKE '% %' THEN
    RAISE EXCEPTION SQLSTATE '22023' USING MESSAGE = 'Email validation failed: invalid_format';
  END IF;

  -- pgsql-http reads http.timeout_msec. It follows up to five redirects for POST
  -- and has no setting that turns that off, so the key in the body can be resent
  -- to a 307/308 Location. Peer verification stays at the extension default (on).
  PERFORM set_config('http.timeout_msec', '3000', true);

  -- Call ZeroBounce validate endpoint
  v_url := 'https://api.zerobounce.net/v2/validate';

  -- Perform external call in a narrow protected block: swallow infra errors only
  BEGIN
    SELECT r.status, r.content
    INTO v_status, v_body
    FROM extensions.http_post(
      v_url,
      'api_key=' || extensions.urlencode(v_api_key) || '&email=' || extensions.urlencode(v_normalized_email),
      'application/x-www-form-urlencoded'
    ) AS r;
  EXCEPTION WHEN OTHERS THEN
    RAISE LOG 'ZeroBounce signup validation unavailable; sqlstate=%', SQLSTATE;
    IF v_fail_closed THEN
      RAISE EXCEPTION SQLSTATE '22023' USING MESSAGE = 'Email validation is temporarily unavailable. Please try again later.';
    END IF;
    RETURN NEW;
  END;

  IF v_status IS NULL OR v_status < 200 OR v_status >= 300 OR v_body IS NULL THEN
    RAISE LOG 'ZeroBounce signup validation failed; http_status=%', v_status;
    IF v_fail_closed THEN
      RAISE EXCEPTION SQLSTATE '22023' USING MESSAGE = 'Email validation is temporarily unavailable. Please try again later.';
    END IF;
    RETURN NEW;
  END IF;

  -- Process response and enforce validation decisions (no exception handler here)
  IF v_status >= 200 AND v_status < 300 AND v_body IS NOT NULL THEN
    v_json := v_body::jsonb;

    -- A false success flag is an API error, including when status is "valid".
    -- It is not the documented fail-open path.
    IF public.zb_false_success(v_json) THEN
      RAISE LOG 'ZeroBounce signup rejected status';
      RAISE EXCEPTION SQLSTATE '22023' USING MESSAGE = 'Email validation failed';
    END IF;

    IF coalesce(v_json->>'status', '') NOT IN
       ('valid', 'invalid', 'catch-all', 'unknown', 'spamtrap', 'abuse', 'do_not_mail') THEN
      RAISE LOG 'ZeroBounce signup validation returned unexpected status';
      IF v_fail_closed THEN
        RAISE EXCEPTION SQLSTATE '22023' USING MESSAGE = 'Email validation is temporarily unavailable. Please try again later.';
      END IF;
      RETURN NEW;
    END IF;

    -- Stash JSON for potential downstream use in this session/tx
    PERFORM set_config('app.zb_last_validation', public.zb_stored_response(v_json, v_api_key)::text, true);

    -- Store accepted validations. Rejected signups roll back this row; RAISE LOG
    -- below records rejection events outside the transaction instead.
    -- The log keeps the status fields, not the raw body, so an echoed key is not written.
    PERFORM public.zb_parse_and_store(v_normalized_email, public.zb_stored_response(v_json, v_api_key));

    -- If there's a typo suggestion, block with a clear message containing the suggestion
    v_did_you_mean := nullif(public.zb_redact_text(v_json->>'did_you_mean', v_api_key), '');
    IF v_did_you_mean = 'the response text was omitted because it contained a credential' THEN
      RAISE LOG 'ZeroBounce signup rejected typo';
      RAISE EXCEPTION SQLSTATE '22023' USING
        MESSAGE = 'Email looks like a typo.',
        HINT = 'Correct the spelling.';
    ELSIF v_did_you_mean IS NOT NULL THEN
      RAISE LOG 'ZeroBounce signup rejected typo';
      RAISE EXCEPTION SQLSTATE '22023' USING
        MESSAGE = 'Email looks like a typo. Did you mean ' || v_did_you_mean || '?',
        DETAIL = 'did_you_mean=' || v_did_you_mean,
        HINT = 'Update the email to the suggested address or correct the spelling.';
    END IF;

    -- Decide to block or allow based on status/sub_status
    IF public.zb_should_block_signup(v_json) THEN
      RAISE LOG 'ZeroBounce signup rejected status';
      IF public.zb_false_success(v_json) THEN
        v_msg := 'Email validation failed';
      ELSE
        v_msg := 'Email validation failed: status=' || coalesce(public.zb_redact_text(v_json->>'status', v_api_key), 'unknown');
      END IF;
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
REVOKE EXECUTE ON FUNCTION public.validate_email_with_zerobounce(text) FROM authenticated;

-- Do not grant authenticated or anon: RPC would spend ZeroBounce credits from the client.
-- Use the BEFORE INSERT trigger on auth.users, a service-role Edge Function, or backend only.

-- Secure helper functions: revoke from public/anon, only allow internal use
REVOKE EXECUTE ON FUNCTION public.zb_parse_and_store(TEXT, JSONB) FROM public;
REVOKE EXECUTE ON FUNCTION public.zb_parse_and_store(TEXT, JSONB) FROM anon;
REVOKE EXECUTE ON FUNCTION public.zb_parse_and_store(TEXT, JSONB) FROM authenticated;
REVOKE EXECUTE ON FUNCTION public.zb_should_block_signup(JSONB) FROM public;
REVOKE EXECUTE ON FUNCTION public.zb_should_block_signup(JSONB) FROM anon;
REVOKE EXECUTE ON FUNCTION public.zb_should_block_signup(JSONB) FROM authenticated;
REVOKE EXECUTE ON FUNCTION public.zb_false_success(JSONB) FROM public, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.zb_api_key_rejected(text) FROM public, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.zb_loosen_encoding(text) FROM public, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.zb_redact_text(text, text) FROM public, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.zb_stored_response(JSONB, text) FROM public, anon, authenticated;

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
