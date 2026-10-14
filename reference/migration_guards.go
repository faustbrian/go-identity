package reference

// Presence guards describe newly introduced catalog identities, not SQL or an
// alternate executor. Each guard is checked only when its selected native step
// has no ledger record. Replaced objects are deliberately not new identities:
// an earlier recorded step already owns them. Keep these names aligned with the
// immutable upstream sources when selecting new migration versions.
func sharedSuffixGuards(riskSchema string) []migrationGuard {
	return []migrationGuard{
		{version: 2, schema: "identity", tables: []string{"identity_command_id_claims", "commands"}},
		{version: 3, schema: "identity", tables: []string{"identity_commands_pending_lease"}, columns: []string{"commands.state", "commands.generation", "commands.attempt", "commands.lease_owner", "commands.lease_until", "commands.heartbeat_at", "commands.created_at", "commands.updated_at"}},
		{version: 4, schema: "identity", columns: []string{"commands.result_version", "commands.terminal_class", "commands.result", "commands.terminal_at"}},
		{version: 5, schema: "identity", columns: []string{"commands.command_plan"}, functions: []string{"guard_command_plan"}},
		{version: 6, schema: "identity", tables: []string{"attribute_schemas", "user_attributes"}, functions: []string{"guard_attribute_schema"}},
		{version: 7, schema: "identity", tables: []string{"user_list_snapshots", "user_list_rows", "identity_user_list_retention"}},
		{version: 8, schema: "identity", tables: []string{"user_profiles"}},
		{version: 9, schema: "identity", tables: []string{"identifiers", "identity_identifier_primary_kind"}, columns: []string{"users.identifier_version"}},
		{version: 1002, schema: riskSchema, tables: []string{"risk_reserved_command_order"}, columns: []string{"issued_evidence.reservation_command_id", "issued_evidence.reservation_purpose", "issued_evidence.reservation_fingerprint", "issued_evidence.reservation_generation", "issued_evidence.reserved_at"}},
		{version: 1003, schema: riskSchema, tables: []string{"counter_key_history", "counter_windows", "counter_aliases", "counter_charges", "counter_snapshots", "risk_counter_expiry", "risk_counter_charge_scope"}},
		{version: 1004, schema: riskSchema, tables: []string{"velocity_attempts", "velocity_snapshots", "velocity_aliases", "velocity_epochs", "risk_velocity_active_epoch", "risk_velocity_replay"}},
		{version: 1005, schema: riskSchema, tables: []string{"velocity_targets"}},
		{version: 1006, schema: riskSchema, columns: []string{"velocity_attempts.replay_seal"}},
		{version: 1007, schema: riskSchema, tables: []string{"velocity_replay_position", "risk_velocity_position_unique", "risk_velocity_position_scan", "risk_velocity_position_init"}, columns: []string{"velocity_attempts.replay_position", "velocity_attempts.position_seal"}},
		{version: 1008, schema: riskSchema, columns: []string{"velocity_epochs.applied_generation", "velocity_epochs.applied_position", "velocity_epochs.applied_seal"}},
		{version: 1009, schema: riskSchema, columns: []string{"velocity_epochs.journal_started_at"}},
		{version: 1010, schema: riskSchema, columns: []string{"velocity_epochs.publication_id", "velocity_epochs.publication_confirmed_at"}},
		{version: 1011, schema: riskSchema, columns: []string{"velocity_epochs.activated_at"}},
		{version: 1012, schema: "identity", columns: []string{"commands.preparation_profile", "commands.preparation_started_generation", "commands.preparation_ciphertext_generation", "commands.preparation_ciphertext"}, functions: []string{"guard_command_preparation"}},
		{version: 1014, schema: "identity", tables: []string{"status_policies", "status_cascades", "status_consumers"}, columns: []string{"users.authority_version", "users.status_reason", "users.status_expires_at", "users.legal_hold", "users.legal_hold_version"}},
		{version: 1015, schema: "identity", tables: []string{"credential_references"}, columns: []string{"users.credential_version"}},
		{version: 1016, schema: "identity", tables: []string{"global_authorities", "tenant_authorities"}},
		{version: 1017, schema: "identity", tables: []string{"request_key_namespaces", "request_key_mappings"}, functions: []string{"request_key_immutable"}},
		{version: 1018, schema: "identity", columns: []string{"request_key_mappings.request_preparation_identity", "request_key_mappings.request_preparation_ciphertext"}},
		{version: 1251, schema: "identity", tables: []string{"delivery_processing", "delivery_attempt_history", "identity_delivery_retry_due", "identity_delivery_lease_due", "identity_delivery_pending", "identity_delivery_custody_expiry"}},
		{version: 1252, schema: "identity", tables: []string{"delivery_policy_profiles"}, functions: []string{"guard_delivery_policy_profiles"}},
		{version: 1253, schema: "identity", tables: []string{"delivery_admission_namespaces", "delivery_keyed_commands"}},
		{version: 1254, schema: "identity", columns: []string{"delivery_intents.status_version", "delivery_intents.local_stop_state", "delivery_intents.local_stop_at"}, functions: []string{"delivery_status_version"}},
		{version: 1255, schema: "identity", tables: []string{"delivery_cancellations"}, functions: []string{"delivery_cancellation_immutable"}},
		{version: 1256, schema: "identity", tables: []string{"delivery_receipts", "identity_delivery_receipt_observation"}, functions: []string{"delivery_receipt_immutable"}},
		{version: 1257, schema: "identity", tables: []string{"delivery_receipt_commands"}},
		{version: 1258, schema: "identity", tables: []string{"delivery_reconciliation_checkpoints"}},
		{version: 1259, schema: "identity", tables: []string{"delivery_reconciliation_commands"}},
		{version: 1260, schema: "identity", tables: []string{"delivery_reconciliation_queries", "delivery_reconciliation_cursors"}, functions: []string{"delivery_reconciliation_cursor_cleanup"}},
	}
}
