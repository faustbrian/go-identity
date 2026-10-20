package postgres

import identity "github.com/faustbrian/go-identity"

// The existing command owner binds all original submissions, never a caller's
// replacement digest or successful-verification flag. Separate input/execution
// and SMS/TOTP domains prevent relabelling even when bytes happen to match.
// This is replay intent only; no proof is consumed or authority established.
func encodePhonePasswordResetCustody(c identity.Command, key [32]byte, payload map[string][]byte, input bool) error {
	domain := "phone-password-reset"
	var material []byte
	hash, proof, phoneCode, totpCode, ok := c.PhonePasswordResetCustody()
	if input {
		domain += "-input"
		password, original, sms, totp, valid := c.PhonePasswordResetInputCustody()
		if !valid {
			return codecError()
		}
		proof, phoneCode, totpCode = original, sms, totp
		if err := password.Use(func(raw []byte) error {
			var err error
			material, err = commandSecret(key, domain+"-password", raw, 1<<20)
			return err
		}); err != nil {
			return codecError()
		}
	} else {
		if !ok {
			return codecError()
		}
		raw := []byte(hash)
		var err error
		material, err = commandSecret(key, domain+"-hash", raw, 16384)
		clear(raw)
		if err != nil {
			return codecError()
		}
	}
	proofDigest, err := proof.CommandDigest(key, domain+"-proof", 4096)
	if err != nil {
		return codecError()
	}
	smsDigest, err := phoneCode.CommandDigest(key, domain+"-phone-code")
	if err != nil {
		return codecError()
	}
	totpDigest, err := totpCode.CommandDigest(key, domain+"-totp-code")
	if err != nil {
		return codecError()
	}
	if cookie, present := c.PhonePasswordResetPreAuthCookie(); present {
		raw := []byte(cookie.Token())
		cookieDigest, err := commandSecret(key, domain+"-flow-cookie", raw, 86)
		clear(raw)
		if err != nil {
			return codecError()
		}
		payload[domain+"-flow-cookie"] = cborBytes(cookieDigest)
	}
	payload[domain+"-material"] = cborBytes(material)
	payload[domain+"-proof"] = cborBytes(proofDigest[:])
	payload[domain+"-phone-code"] = cborBytes(smsDigest[:])
	payload[domain+"-totp-code"] = cborBytes(totpDigest[:])
	return nil
}
