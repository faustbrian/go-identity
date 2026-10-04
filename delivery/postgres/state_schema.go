package postgres

// Forward metadata expansion only; original intent/worker/profile/keyed history
// stays immutable. Constant defaults do not decrypt or reinterpret old custody.
// A same-row storage invariant covers older writers too, without a workflow,
// cross-table query or external effect. Application roles must not own DDL.
const stateSchemaSQL = `
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
ALTER TABLE identity.delivery_intents
 ADD COLUMN status_version identity.version NOT NULL DEFAULT 1,
 ADD COLUMN local_stop_state text COLLATE "C",
 ADD COLUMN local_stop_at timestamptz,
 ADD CONSTRAINT identity_delivery_local_stop CHECK (
   (local_stop_state IS NULL AND local_stop_at IS NULL)
   OR (no_op AND local_stop_state IN ('cancelled','expired')
       AND local_stop_state IS NOT NULL AND local_stop_at IS NOT NULL
       AND isfinite(local_stop_at))
 );
CREATE FUNCTION identity.delivery_status_version() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.status_version<>1 OR NEW.local_stop_state IS NOT NULL OR NEW.local_stop_at IS NOT NULL
  THEN RAISE EXCEPTION USING MESSAGE='invalid initial delivery status',ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.status_version IS DISTINCT FROM OLD.status_version
 THEN RAISE EXCEPTION USING MESSAGE='delivery status version is database-owned',ERRCODE='23514'; END IF;
 IF ROW(NEW.local_stop_state,NEW.local_stop_at) IS DISTINCT FROM ROW(OLD.local_stop_state,OLD.local_stop_at) THEN
  IF OLD.local_stop_state IS NOT NULL OR NOT OLD.no_op OR NEW.local_stop_state IS NULL OR NEW.local_stop_at IS NULL
  THEN RAISE EXCEPTION USING MESSAGE='delivery local stop checkpoint is immutable',ERRCODE='23514'; END IF;
  NEW.local_stop_at := clock_timestamp();
 END IF;
 IF OLD.status_version=18446744073709551615
 THEN RAISE EXCEPTION USING MESSAGE='delivery status version exhausted',ERRCODE='22003'; END IF;
 NEW.status_version := OLD.status_version+1;
 RETURN NEW;
END $$;
CREATE TRIGGER identity_delivery_status_version BEFORE INSERT OR UPDATE ON identity.delivery_intents
 FOR EACH ROW EXECUTE FUNCTION identity.delivery_status_version();
`
