package postgres

import (
	"bytes"
	"context"
	"slices"
	"strconv"

	identity "github.com/faustbrian/go-identity"
)

func (r *Repository) prepareProfileAttributes(spec identity.ProfileUpdateCommand) (registeredSchema, []byte, error) {
	registered, ok := r.attributeSchemas[r.profileSchema]
	if !ok || spec.Binding.SchemaID != r.profileSchema.id || spec.Binding.SchemaVersion != r.profileSchema.version {
		return registeredSchema{}, nil, attributeStorageError()
	}
	for _, update := range spec.AdditionalFields {
		found := false
		for _, field := range registered.schema.Fields {
			if field.Name == update.Name && field.WriteAuthorization == identity.FieldWriteSelf {
				found = true
				break
			}
		}
		if !found {
			return registeredSchema{}, nil, identity.ForbiddenError{}
		}
	}
	encoded, err := encodeAttributeDocument(registered.schema, spec.AdditionalFields)
	return registered, encoded, err
}

// ApplyProfileUpdate uses only this exact enlisted Repository's coordinator-
// owned Work. The returned profile is provisional, not a durable receipt or
// current authority. The existing tenant lock and an active/version CAS fence
// name, image and individually replaced typed fields with one aggregate bump.
// Omitted values remain unchanged; no defaults are invented. Corrupt/schema-
// mismatched storage fails closed. Unsupported secret/index profiles remain
// rejected. Every error poisons Work; callers must Abort. No policy callback
// runs inside SQL; identity.ProfileService owns admission and output policy.
func (r *Repository) ApplyProfileUpdate(ctx context.Context, w Work, command identity.Command) (identity.UserProfile, error) {
	if r == nil || r.read == nil || ctx == nil {
		return identity.UserProfile{}, invalidWork()
	}
	if err := w.usable(); err != nil {
		return identity.UserProfile{}, err
	}
	fail := func(err error) (identity.UserProfile, error) { return identity.UserProfile{}, w.fail(ctx, err) }
	if w.state.execution == nil || w.state.creation != nil || w.state.profile != nil {
		return fail(invalidWork())
	}
	enlisted := false
	for _, entry := range w.state.execution.reservation.plan.contributors {
		if entry.descriptor.Owner == "identity/postgres" && entry.contributor == r {
			enlisted = true
		}
	}
	if !enlisted {
		return fail(invalidWork())
	}
	spec, ok := command.UpdateProfile()
	if !ok || spec.Binding != w.state.binding {
		return fail(identity.InvalidInputError{Field: "profile_command"})
	}
	q, err := prepareClaim(command, w.state.execution.coordinator.keys.retained[w.state.execution.coordinator.keys.current])
	if err != nil || !bytes.Equal(q.canonical, w.state.execution.reservation.request.canonical) {
		return fail(identity.ConflictError{})
	}
	registered, _, err := r.prepareProfileAttributes(spec)
	if err != nil {
		return fail(err)
	}
	rows, err := w.Query(ctx, profileSelect+" FOR UPDATE OF u", string(spec.Binding.TenantID), string(spec.Binding.UserID))
	if err != nil {
		return identity.UserProfile{}, err
	}
	if !rows.Next() {
		rows.Close()
		return fail(identity.ForbiddenError{})
	}
	row, err := scanProfileRow(rows)
	if err != nil {
		rows.Close()
		return fail(err)
	}
	if rows.Next() {
		rows.Close()
		return fail(identity.UnavailableError{})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return fail(err)
	}
	// Decode all values, including output-denied ones, to preserve the entire
	// document during a partial update. The service reprojects the receipt.
	fields := []string{"name", "image"}
	for _, field := range registered.schema.Fields {
		fields = append(fields, field.Name)
	}
	record, err := r.decodeProfileRow(identity.ProfileQuery{TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID}, fields, registered, row)
	if err != nil {
		return fail(err)
	}
	if record.User.Status != identity.StatusActive {
		return fail(identity.ForbiddenError{})
	}
	if record.User.Version != spec.ExpectedVersion {
		return fail(identity.ConflictError{})
	}
	profile := record.Profile
	if spec.Name != "" {
		profile.Name = spec.Name
	}
	if spec.Image != "" {
		profile.Image = spec.Image
	}
	for _, update := range spec.AdditionalFields {
		at := slices.IndexFunc(profile.AdditionalFields, func(v identity.AttributeUpdate) bool { return v.Name == update.Name })
		if at < 0 {
			profile.AdditionalFields = append(profile.AdditionalFields, update)
		} else {
			profile.AdditionalFields[at] = update
		}
	}
	document, err := encodeAttributeDocument(registered.schema, profile.AdditionalFields)
	if err != nil {
		return fail(err)
	}
	if err := persistCreationSchema(ctx, w, registered); err != nil {
		return identity.UserProfile{}, err
	}
	count, err := w.Exec(ctx, `UPDATE identity.users SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND status='active' AND version=$3::numeric`, string(spec.Binding.TenantID), string(spec.Binding.UserID), strconv.FormatUint(spec.ExpectedVersion, 10))
	if err != nil {
		return identity.UserProfile{}, err
	}
	if count != 1 {
		return fail(identity.ConflictError{})
	}
	if _, err := w.Exec(ctx, `INSERT INTO identity.user_profiles(tenant_id,user_id,name,image) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,user_id) DO UPDATE SET name=excluded.name,image=excluded.image`, string(spec.Binding.TenantID), string(spec.Binding.UserID), profile.Name, profile.Image); err != nil {
		return identity.UserProfile{}, err
	}
	if _, err := w.Exec(ctx, `INSERT INTO identity.user_attributes(tenant_id,user_id,schema_id,schema_version,encoding_version,document) VALUES($1,$2,$3,$4,1,$5) ON CONFLICT(tenant_id,user_id) DO UPDATE SET document=excluded.document`, string(spec.Binding.TenantID), string(spec.Binding.UserID), registered.schema.ID, registered.schema.Version, document); err != nil {
		return identity.UserProfile{}, err
	}
	profile.Version++
	owned := cloneStoredProfile(profile)
	w.state.profile = &owned
	return profile, nil
}

func cloneStoredProfile(p identity.UserProfile) identity.UserProfile {
	p.AdditionalFields = slices.Clone(p.AdditionalFields)
	for i := range p.AdditionalFields {
		p.AdditionalFields[i].Value.List = slices.Clone(p.AdditionalFields[i].Value.List)
	}
	return p
}

func matchesDomainResult(w Work, result identity.CommandResult) bool {
	if w.state.creation != nil {
		return w.state.profile == nil && result.User == *w.state.creation && result.Binding.OperationID == "identity.user.create"
	}
	p := w.state.profile
	if p == nil || result.Profile == nil || result.Binding.OperationID != "identity.profile.update" || result.User != (identity.User{ID: p.ID, TenantID: p.TenantID, Status: identity.StatusActive, Version: p.Version}) || result.ExpectedVersion != w.state.lifecycle.plan.BeforeVersion {
		return false
	}
	supplied := result.Profile
	if supplied.ID != p.ID || supplied.TenantID != p.TenantID || supplied.Version != p.Version || supplied.Name != p.Name || supplied.Image != p.Image {
		return false
	}
	r := w.state.execution.coordinator
	// The exact enlisted repository owns both schema and provisional snapshot.
	for _, entry := range r.registry.state.entries {
		if repo, ok := entry.contributor.(*Repository); ok && entry.descriptor.Owner == "identity/postgres" {
			registered := repo.attributeSchemas[repo.profileSchema]
			a, ea := encodeAttributeDocument(registered.schema, supplied.AdditionalFields)
			b, eb := encodeAttributeDocument(registered.schema, p.AdditionalFields)
			return ea == nil && eb == nil && bytes.Equal(a, b)
		}
	}
	return false
}
