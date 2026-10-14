package postgres

// Historical foundation rows remain NULL: upgrading storage cannot invent
// their participant declaration. Only new owned admission freezes a plan.
// DELETE remains the retention owner's operation; the global retired claim
// prevents assigning the command ID a new meaning after journal cleanup.
const commandPlanSchemaSQL = `ALTER TABLE identity.commands
 ADD COLUMN command_plan bytea,
 ADD CONSTRAINT identity_command_plan_bounds
 CHECK (command_plan IS NULL OR octet_length(command_plan) BETWEEN 1 AND 65536);

CREATE FUNCTION identity.guard_command_plan() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
 IF OLD.command_plan IS NOT NULL AND NEW.command_plan IS DISTINCT FROM OLD.command_plan THEN
  RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'identity command plan immutable';
 END IF;
 RETURN NEW;
END;
$$;

CREATE TRIGGER identity_command_plan_immutable
 BEFORE UPDATE OF command_plan ON identity.commands
 FOR EACH ROW EXECUTE FUNCTION identity.guard_command_plan();
`
