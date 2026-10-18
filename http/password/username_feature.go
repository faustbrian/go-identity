package passwordhttp

import (
	"fmt"
	"io"
	"log/slog"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/password"
)

// UsernameFeatureConfig explicitly selects username browser authentication.
// Its native owners must select the corresponding username profiles; these
// routes never relabel an email operation or enable unsupported MFA fallback.
// Nil operations expose neither routes nor metadata. Configuration is copied;
// borrowed services and trusted middleware must outlive concurrent requests.
type UsernameFeatureConfig struct {
	Signup    *SignupConfig
	Signin    *SigninConfig
	Available *UsernameAvailabilityConfig
	Rename    *UsernameRenameConfig
}

// NewUsernameFeature contributes only selected username-owned operations.
// Password and username contributions can coexist without aliasing routes,
// original actions, rate inputs or OpenAPI operation identities.
func NewUsernameFeature(c UsernameFeatureConfig) (identityhttp.Feature, error) {
	return NewUsernameFeatureWithMiddleware(c, nil)
}

// NewUsernameFeatureWithMiddleware freezes the selected typed owner phases.
// An invalid selected dependency returns no partial feature and performs no IO.
func NewUsernameFeatureWithMiddleware(c UsernameFeatureConfig, middleware []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	if c.Signup == nil && c.Signin == nil && c.Available == nil && c.Rename == nil {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	var operations []identityhttp.OperationDescriptor
	if c.Rename != nil {
		op, err := usernameRenameOperation(*c.Rename, middleware)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		operations = append(operations, op)
	}
	if c.Available != nil {
		op, err := usernameAvailabilityOperation(*c.Available, middleware)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		operations = append(operations, op)
	}
	if c.Signup != nil {
		op, err := signupOperationProfile(*c.Signup, middleware, true)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		operations = append(operations, op)
	}
	if c.Signin != nil {
		op, err := signinOperationProfile(*c.Signin, middleware, true)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		operations = append(operations, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/username", Operations: operations})
}

// Format redacts borrowed authentication configuration.
func (UsernameFeatureConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordhttp.UsernameFeatureConfig(redacted)")
}

// MarshalJSON refuses implicit runtime configuration export.
func (UsernameFeatureConfig) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText refuses implicit runtime configuration export.
func (UsernameFeatureConfig) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// LogValue omits borrowed authentication owners.
func (UsernameFeatureConfig) LogValue() slog.Value {
	return slog.StringValue("passwordhttp.UsernameFeatureConfig(redacted)")
}
