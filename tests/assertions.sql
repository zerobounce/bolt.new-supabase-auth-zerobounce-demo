-- Behaviour of the guards extracted from zb_migration.sql. No HTTP.
DO $$
DECLARE
  omitted text := 'the response text was omitted because it contained a credential';
BEGIN
  IF NOT public.zb_false_success('{"status":"valid","success":false}'::jsonb) THEN
    RAISE EXCEPTION 'boolean false must block';
  END IF;
  IF NOT public.zb_false_success('{"success":0}'::jsonb) THEN
    RAISE EXCEPTION 'number 0 must block';
  END IF;
  IF NOT public.zb_false_success('{"success":0.0}'::jsonb) THEN
    RAISE EXCEPTION 'number 0.0 must block';
  END IF;
  IF NOT public.zb_false_success('{"success":"0"}'::jsonb) THEN
    RAISE EXCEPTION 'string 0 must block';
  END IF;
  IF NOT public.zb_false_success('{"success":"FALSE"}'::jsonb) THEN
    RAISE EXCEPTION 'FALSE must block';
  END IF;
  IF NOT public.zb_false_success('{"success":" false "}'::jsonb) THEN
    RAISE EXCEPTION 'padded false must block';
  END IF;
  IF public.zb_false_success('{"success":true}'::jsonb)
     OR public.zb_false_success('{"success":1}'::jsonb)
     OR public.zb_false_success('{"success":1.0}'::jsonb)
     OR public.zb_false_success('{"success":"TRUE"}'::jsonb)
     OR public.zb_false_success('{"success":"x"}'::jsonb)
     OR public.zb_false_success('{"success":0.4}'::jsonb)
     OR public.zb_false_success('{"success":5}'::jsonb)
     OR public.zb_false_success('{"success":""}'::jsonb)
     OR public.zb_false_success('{"status":"valid"}'::jsonb)
     OR public.zb_false_success(NULL) THEN
    RAISE EXCEPTION 'a non-flag was treated as a false success';
  END IF;

  IF NOT public.zb_should_block_signup('{"status":"valid","success":false}'::jsonb) THEN
    RAISE EXCEPTION 'signup block ignored a false success flag';
  END IF;
  IF public.zb_should_block_signup('{"status":"valid","success":true}'::jsonb) THEN
    RAISE EXCEPTION 'a true flag with status valid must not block';
  END IF;
  IF NOT public.zb_should_block_signup('{"status":"invalid"}'::jsonb) THEN
    RAISE EXCEPTION 'status invalid must block';
  END IF;

  IF NOT public.zb_api_key_rejected('') THEN
    RAISE EXCEPTION 'an empty key must be rejected';
  END IF;
  IF public.zb_api_key_rejected('abc-key') THEN
    RAISE EXCEPTION 'a plain key must be accepted';
  END IF;
  IF NOT public.zb_api_key_rejected('ab c')
     OR NOT public.zb_api_key_rejected(E'ab\u202Ecd')
     OR NOT public.zb_api_key_rejected(E'ab\u200Bcd')
     OR NOT public.zb_api_key_rejected(E'ab\u00ADcd')
     OR NOT public.zb_api_key_rejected(E'ab\u2066cd')
     OR NOT public.zb_api_key_rejected(E'ab\u0600cd')
     OR NOT public.zb_api_key_rejected(E'ab\u0890cd')
     OR NOT public.zb_api_key_rejected(E'ab\u0891cd')
     OR NOT public.zb_api_key_rejected(E'ab\u180Bcd')
     OR NOT public.zb_api_key_rejected(E'ab\u180Ccd')
     OR NOT public.zb_api_key_rejected(E'ab\u180Dcd')
     OR NOT public.zb_api_key_rejected(E'ab\u180Ecd')
     OR NOT public.zb_api_key_rejected(E'ab\u180Fcd')
     OR NOT public.zb_api_key_rejected(E'ab\uFFF9cd')
     OR NOT public.zb_api_key_rejected(E'ab\U0001D173cd') THEN
    RAISE EXCEPTION 'an invisible or whitespace key was accepted';
  END IF;

  IF public.zb_loosen_encoding(E'\\u0027') <> ''''
     OR public.zb_loosen_encoding(E'\\u{27}') <> ''''
     OR public.zb_loosen_encoding(E'\\U00000027') <> ''''
     OR public.zb_loosen_encoding(E'\\047') <> ''''
     OR public.zb_loosen_encoding(E'\\x27') <> '''' THEN
    RAISE EXCEPTION 'an escape that quotes the key was left in place';
  END IF;
  IF public.zb_loosen_encoding('%u0027') <> '%u0027' THEN
    RAISE EXCEPTION 'percent-u0027 must stay as text';
  END IF;

  IF public.zb_redact_text('valid', 'secret') <> 'valid' THEN
    RAISE EXCEPTION 'a field without the key was changed';
  END IF;
  IF public.zb_redact_text('key is secret', 'secret') <> 'key is ***' THEN
    RAISE EXCEPTION 'the literal key was not replaced';
  END IF;
  IF public.zb_redact_text(E'key is \\u0073ecret', 'secret') <> omitted THEN
    RAISE EXCEPTION 'an encoded key stayed in the text';
  END IF;
  IF public.zb_redact_text('secret%u0027x', 'secret''x') = omitted THEN
    RAISE EXCEPTION 'percent-u0027 was treated as a quote';
  END IF;
  IF public.zb_redact_text('STRASSE', 'straße') <> omitted THEN
    RAISE EXCEPTION 'a folded key stayed in the text';
  END IF;
  IF public.zb_redact_text(chr(8064) || chr(769), chr(8068)) <> omitted THEN
    RAISE EXCEPTION 'a decomposed key stayed in the text';
  END IF;

  IF public.zb_stored_response(
       '{"status":"valid","success":false,"message":"secret leaked","did_you_mean":"a@b.com"}'::jsonb,
       'secret'
     )::text LIKE '%secret%'
     OR public.zb_stored_response(
       '{"status":"valid","success":false,"message":"secret leaked","did_you_mean":"a@b.com"}'::jsonb,
       'secret'
     )::text LIKE '%message%' THEN
    RAISE EXCEPTION 'the stored response kept the raw message';
  END IF;
END;
$$;
