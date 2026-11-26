package onetap

// PromptContext selects GIS prompt wording, not authentication or linking policy.
// Only the named values are accepted by NewOneTapPromptOptions.
type PromptContext string

const (
	// PromptSignIn selects GIS's sign-in wording.
	PromptSignIn PromptContext = "signin"
	// PromptSignUp selects GIS's sign-up wording.
	PromptSignUp PromptContext = "signup"
	// PromptUse selects GIS's use wording.
	PromptUse PromptContext = "use"
)

// OneTapPromptConfig is copied by NewOneTapPromptOptions. Context is required.
// CancelOnTapOutside is explicit: false disables cancellation on outside taps;
// callers wanting GIS's documented default must supply true.
type OneTapPromptConfig struct {
	Context            PromptContext
	CancelOnTapOutside bool
}

// OneTapPromptOptions is an immutable selected subset of GIS prompt options.
// Its zero value is invalid. It contains no credential or initiation authority.
type OneTapPromptOptions struct {
	config OneTapPromptConfig
	valid  bool
}

// NewOneTapPromptOptions freezes the exact prompt choices without IO. Unknown
// or empty contexts return a redacted InvalidInput error and invalid options.
func NewOneTapPromptOptions(config OneTapPromptConfig) (OneTapPromptOptions, error) {
	switch config.Context {
	case PromptSignIn, PromptSignUp, PromptUse:
		return OneTapPromptOptions{config: config, valid: true}, nil
	default:
		return OneTapPromptOptions{}, failure(InvalidInput, nil)
	}
}

// ButtonType selects a GIS button presentation, not an OAuth response mode.
type ButtonType string

const (
	// ButtonStandard includes GIS text or personalized information.
	ButtonStandard ButtonType = "standard"
	// ButtonIcon selects GIS's icon-only presentation.
	ButtonIcon ButtonType = "icon"
)

// ButtonTheme selects one of GIS's supported button themes.
type ButtonTheme string

const (
	// ButtonOutline selects the standard outline theme.
	ButtonOutline ButtonTheme = "outline"
	// ButtonFilledBlue selects the blue-filled theme.
	ButtonFilledBlue ButtonTheme = "filled_blue"
	// ButtonFilledBlack selects the black-filled theme.
	ButtonFilledBlack ButtonTheme = "filled_black"
	// ButtonOutlineDark selects the dark outline theme.
	ButtonOutlineDark ButtonTheme = "outline_dark"
)

// ButtonSize selects one of GIS's supported button sizes.
type ButtonSize string

const (
	// ButtonSmall selects the small button size.
	ButtonSmall ButtonSize = "small"
	// ButtonMedium selects the medium button size.
	ButtonMedium ButtonSize = "medium"
	// ButtonLarge selects the large button size.
	ButtonLarge ButtonSize = "large"
)

// OneTapButtonConfig is copied by NewOneTapButtonOptions. Type, Theme and Size
// are required closed choices. Width is a minimum in pixels; zero omits the
// setting, while positive values must not exceed GIS's 400-pixel maximum.
// This slice supports popup UX only; there is no redirect or callback input.
type OneTapButtonConfig struct {
	Type  ButtonType
	Theme ButtonTheme
	Size  ButtonSize
	Width uint16
}

// OneTapButtonOptions is an immutable selected subset of GIS popup-button
// options. Its zero value is invalid. It grants no initiation authority.
type OneTapButtonOptions struct {
	config OneTapButtonConfig
	valid  bool
}

// NewOneTapButtonOptions freezes exact button choices without IO. Unknown/empty
// choices or excessive width return redacted InvalidInput and invalid options.
func NewOneTapButtonOptions(config OneTapButtonConfig) (OneTapButtonOptions, error) {
	switch config.Type {
	case ButtonStandard, ButtonIcon:
	default:
		return OneTapButtonOptions{}, failure(InvalidInput, nil)
	}
	switch config.Theme {
	case ButtonOutline, ButtonFilledBlue, ButtonFilledBlack, ButtonOutlineDark:
	default:
		return OneTapButtonOptions{}, failure(InvalidInput, nil)
	}
	switch config.Size {
	case ButtonSmall, ButtonMedium, ButtonLarge:
	default:
		return OneTapButtonOptions{}, failure(InvalidInput, nil)
	}
	// GIS's JS reference defines 400 as the maximum requested minimum width:
	// developers.google.com/identity/gsi/web/reference/js-reference#width.
	if config.Width > 400 {
		return OneTapButtonOptions{}, failure(InvalidInput, nil)
	}
	return OneTapButtonOptions{config: config, valid: true}, nil
}

// BrowserStartExperience distinguishes the selected GIS surface. It is not the
// generic OAuth callback/redirect mode or a native pre-authentication intent.
type BrowserStartExperience string

const (
	// BrowserStartPrompt selects the GIS One Tap prompt.
	BrowserStartPrompt BrowserStartExperience = "prompt"
	// BrowserStartPopupButton selects the GIS button with popup UX.
	BrowserStartPopupButton BrowserStartExperience = "popup_button"
)

// ButtonUXMode is the GIS initialization UX mode used by this button slice.
type ButtonUXMode string

// ButtonPopup is the only supported button UX mode; GIS delivers its credential
// to the application's JavaScript callback, not to a login_uri redirect.
const ButtonPopup ButtonUXMode = "popup"

// BrowserStartOptions is an immutable, closed choice of prompt OR popup-button
// options. Its zero value is invalid; use NewBrowserStartOptions. Concurrent
// reads are safe. It neither starts a transaction nor releases a credential.
type BrowserStartOptions struct {
	prompt OneTapPromptOptions
	button OneTapButtonOptions
}

// NewBrowserStartOptions accepts exactly one constructor-created option and one
// zero option. Selecting neither or both returns redacted InvalidInput.
func NewBrowserStartOptions(prompt OneTapPromptOptions, button OneTapButtonOptions) (BrowserStartOptions, error) {
	if prompt.valid == button.valid {
		return BrowserStartOptions{}, failure(InvalidInput, nil)
	}
	return BrowserStartOptions{prompt: prompt, button: button}, nil
}

// PromptProjection is a detached, non-authoritative typed prompt option copy.
// Changing or decoding it cannot construct OneTapPromptOptions.
type PromptProjection struct {
	Context            PromptContext `json:"context"`
	CancelOnTapOutside bool          `json:"cancel_on_tap_outside"`
}

// ButtonProjection is a detached, non-authoritative typed popup-button option
// copy. UXMode belongs to GIS initialization; the other fields describe button
// rendering. Width is numeric here; GIS documents its render width as a string.
// This is not a complete object to pass directly to either GIS method.
type ButtonProjection struct {
	UXMode ButtonUXMode `json:"ux_mode"`
	Type   ButtonType   `json:"type"`
	Theme  ButtonTheme  `json:"theme"`
	Size   ButtonSize   `json:"size"`
	Width  uint16       `json:"width,omitempty"`
}

// BrowserStartProjection is a detached typed option slice for later native
// binding. Exactly one selected option pointer is present. Public fields and
// JSON are representations only: neither is accepted as validated options,
// provider configuration, a keyed intent or proof of browser interoperability.
type BrowserStartProjection struct {
	Experience BrowserStartExperience `json:"experience"`
	Prompt     *PromptProjection      `json:"prompt,omitempty"`
	Button     *ButtonProjection      `json:"button,omitempty"`
}

// Projection returns fresh selected option storage and stable enum spellings.
// Mutating the returned copy cannot alter the selection. A zero selection
// returns an empty projection and redacted InvalidInput without IO.
func (options BrowserStartOptions) Projection() (BrowserStartProjection, error) {
	if options.prompt.valid == options.button.valid {
		return BrowserStartProjection{}, failure(InvalidInput, nil)
	}
	if options.prompt.valid {
		config := options.prompt.config
		return BrowserStartProjection{
			Experience: BrowserStartPrompt,
			Prompt:     &PromptProjection{Context: config.Context, CancelOnTapOutside: config.CancelOnTapOutside},
		}, nil
	}
	config := options.button.config
	return BrowserStartProjection{
		Experience: BrowserStartPopupButton,
		Button:     &ButtonProjection{UXMode: ButtonPopup, Type: config.Type, Theme: config.Theme, Size: config.Size, Width: config.Width},
	}, nil
}
