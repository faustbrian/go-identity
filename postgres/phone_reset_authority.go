package postgres

import identity "github.com/faustbrian/go-identity"

// OTP finalization follows the password mutation in this same Work. Only its
// kernel-created replacement receipt can map the original credential epoch;
// today's observed version must never renew the signed recovery authority.
func phoneResetSuccessor(w Work, b identity.CommandBinding) (*CredentialReplacementReceipt, error) {
	if w.state == nil || w.state.feature == nil || w.state.feature.Operation != phonePasswordResetOperation() || !w.state.resetApplied {
		return nil, nil
	}
	s := w.state
	if s.binding != b || s.resetIntent == nil || s.replacementIntent == nil || s.replacementReceipt == nil ||
		s.resetIntent.Replacement != *s.replacementIntent || b.OperationID != phonePasswordResetOperation().OperationID ||
		b.SchemaID != phonePasswordResetOperation().SchemaID || b.SchemaVersion != 1 {
		return nil, invalidCredentialReset()
	}
	i, r := s.replacementIntent, s.replacementReceipt
	c := i.Credential
	if c.Validate(b.TenantID, b.UserID) != nil || b.RecordID != string(c.ID) ||
		c.Kind != identity.CredentialPassword || c.Owner != "identity/password" || c.Version == ^uint64(0) ||
		i.ExpectedUserVersion == 0 || i.ExpectedUserVersion == ^uint64(0) ||
		i.ExpectedAuthorityVersion == 0 || i.ExpectedAuthorityVersion == ^uint64(0) ||
		r.BeforeCredentialVersion != c.Version || r.BeforeUserVersion != i.ExpectedUserVersion ||
		r.AfterUserVersion != i.ExpectedUserVersion+1 || r.BeforeAuthorityVersion != i.ExpectedAuthorityVersion ||
		r.AfterAuthorityVersion != i.ExpectedAuthorityVersion+1 {
		return nil, invalidCredentialReset()
	}
	want := c
	want.Version++
	if r.Credential != want {
		return nil, invalidCredentialReset()
	}
	return r, nil
}

func otpPhoneResetCredential(w Work, b identity.CommandBinding, original CredentialAdmission) (CredentialAdmission, error) {
	r, err := phoneResetSuccessor(w, b)
	if err != nil {
		return CredentialAdmission{}, err
	}
	if r == nil {
		return original, nil
	}
	if original.Credential != w.state.replacementIntent.Credential || original.CredentialAuthorityVersion != r.BeforeAuthorityVersion {
		return CredentialAdmission{}, invalidCredentialReset()
	}
	original.Credential = r.Credential
	original.CredentialAuthorityVersion = r.AfterAuthorityVersion
	return original, nil
}

func otpPhoneResetUser(w Work, b identity.CommandBinding, original UserAuthorityAdmission) (UserAuthorityAdmission, error) {
	r, err := phoneResetSuccessor(w, b)
	if err != nil {
		return UserAuthorityAdmission{}, err
	}
	if r == nil {
		return original, nil
	}
	if original.CredentialAuthorityVersion != r.BeforeAuthorityVersion {
		return UserAuthorityAdmission{}, invalidCredentialReset()
	}
	// Aggregate User.Version advances too, but the independent user-security
	// and identifier-security epochs do not change during password replacement.
	original.CredentialAuthorityVersion = r.AfterAuthorityVersion
	return original, nil
}
