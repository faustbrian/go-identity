package postgres

// This immutable first forward migration follows the kernel and owned outbox
// schemas, in its own migration namespace. Lease/receipt APIs are not enabled
// by this admission foundation. No migration fabricates provider success.
const intentSchemaSQL = `CREATE TABLE identity.delivery_intents (
 deployment identity.directory_id NOT NULL,
 tenant_id identity.directory_id NOT NULL,
 effect_id text COLLATE "C" NOT NULL CHECK (effect_id ~ '^[0-9a-f]{64}$'),
 command_purpose text COLLATE "C" NOT NULL,
 command_id bytea NOT NULL CHECK (octet_length(command_id)=16),
 effect_index integer NOT NULL CHECK (effect_index BETWEEN 0 AND 65535),
 purpose identity.directory_id NOT NULL,
 subject_id identity.directory_id NOT NULL,
 template_id identity.directory_id NOT NULL,
 template_version bigint NOT NULL CHECK (template_version BETWEEN 1 AND 4294967295),
 provider identity.directory_id NOT NULL,
 provider_version identity.version NOT NULL,
 policy_version identity.version NOT NULL,
 intent_digest bytea NOT NULL CHECK (octet_length(intent_digest)=32),
 digest_key_version bigint NOT NULL CHECK (digest_key_version BETWEEN 1 AND 4294967295),
 no_op boolean NOT NULL,
 binding_aad bytea NOT NULL CHECK (octet_length(binding_aad) BETWEEN 1 AND 16384),
 envelope_key_id identity.directory_id,
 ciphertext bytea CHECK (octet_length(ciphertext) BETWEEN 41 AND 524288),
 payload_erased_at timestamptz CHECK (isfinite(payload_erased_at)),
 state text COLLATE "C" NOT NULL CHECK (state IN ('planned','submitted','retry-wait','outcome-unknown','confirmed','rejected','expired','cancelled','exhausted','superseded')),
 expires_at timestamptz NOT NULL CHECK (isfinite(expires_at) AND expires_at>TIMESTAMPTZ '1970-01-01 00:00:00+00' AND expires_at<TIMESTAMPTZ '10000-01-01 00:00:00+00'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK (isfinite(created_at)),
 PRIMARY KEY(deployment,tenant_id,effect_id),
 UNIQUE(deployment,tenant_id,command_id,effect_index),
 FOREIGN KEY(tenant_id,command_purpose,command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 CHECK ((state IN ('planned','submitted','retry-wait','outcome-unknown') AND ciphertext IS NOT NULL AND envelope_key_id IS NOT NULL AND payload_erased_at IS NULL)
     OR (state IN ('confirmed','rejected','expired','cancelled','exhausted','superseded') AND ciphertext IS NULL AND envelope_key_id IS NULL AND payload_erased_at IS NOT NULL)
     OR (state IN ('submitted','outcome-unknown') AND ciphertext IS NULL AND envelope_key_id IS NULL AND payload_erased_at IS NOT NULL AND payload_erased_at>=expires_at)),
 CHECK (NOT no_op OR state='cancelled')
);

CREATE INDEX identity_delivery_due ON identity.delivery_intents(expires_at,deployment,tenant_id,effect_id)
 WHERE state IN ('planned','retry-wait');

CREATE FUNCTION identity.delivery_intent_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP IN ('DELETE','TRUNCATE') THEN
  RAISE EXCEPTION USING MESSAGE='delivery retained binding cannot be removed', ERRCODE='23514';
 END IF;
 IF ROW(NEW.deployment,NEW.tenant_id,NEW.effect_id,NEW.command_purpose,NEW.command_id,NEW.effect_index,
        NEW.purpose,NEW.subject_id,NEW.template_id,NEW.template_version,NEW.provider,NEW.provider_version,
        NEW.policy_version,NEW.intent_digest,NEW.digest_key_version,NEW.no_op,NEW.binding_aad,NEW.expires_at,NEW.created_at)
 IS DISTINCT FROM ROW(OLD.deployment,OLD.tenant_id,OLD.effect_id,OLD.command_purpose,OLD.command_id,OLD.effect_index,
        OLD.purpose,OLD.subject_id,OLD.template_id,OLD.template_version,OLD.provider,OLD.provider_version,
        OLD.policy_version,OLD.intent_digest,OLD.digest_key_version,OLD.no_op,OLD.binding_aad,OLD.expires_at,OLD.created_at)
 THEN RAISE EXCEPTION USING MESSAGE='delivery binding is immutable', ERRCODE='23514'; END IF;
 IF OLD.state IN ('confirmed','rejected','expired','cancelled','exhausted','superseded') AND NEW.state<>OLD.state
 THEN RAISE EXCEPTION USING MESSAGE='delivery terminal state is immutable', ERRCODE='23514'; END IF;
 IF OLD.payload_erased_at IS NOT NULL AND NEW.payload_erased_at IS DISTINCT FROM OLD.payload_erased_at
 THEN RAISE EXCEPTION USING MESSAGE='delivery erasure checkpoint is immutable', ERRCODE='23514'; END IF;
 IF OLD.ciphertext IS NOT NULL AND NEW.ciphertext IS NULL THEN
  IF NEW.state IN ('submitted','outcome-unknown') AND clock_timestamp()<OLD.expires_at
  THEN RAISE EXCEPTION USING MESSAGE='delivery custody has not expired', ERRCODE='23514'; END IF;
  NEW.payload_erased_at := clock_timestamp();
 END IF;
 IF NEW.state IN ('planned','submitted','retry-wait','outcome-unknown') AND
    ROW(NEW.ciphertext,NEW.envelope_key_id) IS DISTINCT FROM ROW(OLD.ciphertext,OLD.envelope_key_id) AND
    NOT (OLD.ciphertext IS NOT NULL AND NEW.ciphertext IS NULL AND NEW.envelope_key_id IS NULL
         AND NEW.state IN ('submitted','outcome-unknown') AND NEW.payload_erased_at>=OLD.expires_at)
 THEN RAISE EXCEPTION USING MESSAGE='delivery custody is immutable', ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;

CREATE TRIGGER identity_delivery_immutable BEFORE UPDATE OR DELETE ON identity.delivery_intents
 FOR EACH ROW EXECUTE FUNCTION identity.delivery_intent_immutable();
CREATE TRIGGER identity_delivery_no_truncate BEFORE TRUNCATE ON identity.delivery_intents
 FOR EACH STATEMENT EXECUTE FUNCTION identity.delivery_intent_immutable();
`
