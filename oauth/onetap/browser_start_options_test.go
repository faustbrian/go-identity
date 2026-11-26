package onetap_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/faustbrian/go-identity/oauth/onetap"
)

func TestBrowserStartPromptProjectionIsExplicitAndDetached(t *testing.T) {
	for _, context := range []onetap.PromptContext{onetap.PromptSignIn, onetap.PromptSignUp, onetap.PromptUse} {
		for _, cancel := range []bool{false, true} {
			config := onetap.OneTapPromptConfig{Context: context, CancelOnTapOutside: cancel}
			prompt, err := onetap.NewOneTapPromptOptions(config)
			if err != nil {
				t.Fatal(err)
			}
			selected, err := onetap.NewBrowserStartOptions(prompt, onetap.OneTapButtonOptions{})
			if err != nil {
				t.Fatal(err)
			}
			config.Context = onetap.PromptUse
			got, err := selected.Projection()
			if err != nil || got.Experience != onetap.BrowserStartPrompt || got.Prompt == nil || got.Button != nil {
				t.Fatalf("prompt selection = %#v, %v", got, err)
			}
			want := onetap.PromptProjection{Context: context, CancelOnTapOutside: cancel}
			if *got.Prompt != want {
				t.Fatalf("prompt = %#v, want %#v", *got.Prompt, want)
			}
			got.Prompt.Context = "forged"
			got.Prompt.CancelOnTapOutside = !cancel
			again, err := selected.Projection()
			if err != nil || *again.Prompt != want {
				t.Fatal("mutating the projection changed immutable selection", err)
			}
		}
	}
}

func TestBrowserStartButtonProjectionPreservesClosedChoicesAndBounds(t *testing.T) {
	for _, kind := range []onetap.ButtonType{onetap.ButtonStandard, onetap.ButtonIcon} {
		for _, theme := range []onetap.ButtonTheme{onetap.ButtonOutline, onetap.ButtonFilledBlue, onetap.ButtonFilledBlack, onetap.ButtonOutlineDark} {
			for _, size := range []onetap.ButtonSize{onetap.ButtonSmall, onetap.ButtonMedium, onetap.ButtonLarge} {
				for _, width := range []uint16{0, 1, 400} {
					config := onetap.OneTapButtonConfig{Type: kind, Theme: theme, Size: size, Width: width}
					button, err := onetap.NewOneTapButtonOptions(config)
					if err != nil {
						t.Fatal(err)
					}
					selected, err := onetap.NewBrowserStartOptions(onetap.OneTapPromptOptions{}, button)
					if err != nil {
						t.Fatal(err)
					}
					config.Type = onetap.ButtonIcon
					got, err := selected.Projection()
					if err != nil || got.Experience != onetap.BrowserStartPopupButton || got.Prompt != nil || got.Button == nil {
						t.Fatalf("button selection = %#v, %v", got, err)
					}
					want := onetap.ButtonProjection{UXMode: onetap.ButtonPopup, Type: kind, Theme: theme, Size: size, Width: width}
					if *got.Button != want {
						t.Fatalf("button = %#v, want %#v", *got.Button, want)
					}
					got.Button.Type = "forged"
					got.Button.UXMode = "redirect"
					got.Button.Width = 65535
					again, err := selected.Projection()
					if err != nil || *again.Button != want {
						t.Fatal("mutating the projection changed immutable selection", err)
					}
				}
			}
		}
	}
}

func TestBrowserStartRejectsInvalidConfiguration(t *testing.T) {
	for _, config := range []onetap.OneTapPromptConfig{
		{}, {Context: "unknown"}, {Context: " signin"}, {Context: "SIGNIN"},
		{Context: onetap.PromptContext(string(make([]byte, 4096)))},
	} {
		got, err := onetap.NewOneTapPromptOptions(config)
		assertBrowserOptionsInvalid(t, err)
		if _, err := onetap.NewBrowserStartOptions(got, onetap.OneTapButtonOptions{}); err == nil {
			t.Fatal("failed prompt constructor returned usable options")
		}
	}
	valid := onetap.OneTapButtonConfig{Type: onetap.ButtonStandard, Theme: onetap.ButtonOutline, Size: onetap.ButtonLarge}
	for _, mutate := range []func(*onetap.OneTapButtonConfig){
		func(c *onetap.OneTapButtonConfig) { *c = onetap.OneTapButtonConfig{} },
		func(c *onetap.OneTapButtonConfig) { c.Type = "" },
		func(c *onetap.OneTapButtonConfig) { c.Type = "redirect" },
		func(c *onetap.OneTapButtonConfig) { c.Theme = "" },
		func(c *onetap.OneTapButtonConfig) { c.Theme = "unknown" },
		func(c *onetap.OneTapButtonConfig) { c.Size = "" },
		func(c *onetap.OneTapButtonConfig) { c.Size = "huge" },
		func(c *onetap.OneTapButtonConfig) { c.Width = 401 },
		func(c *onetap.OneTapButtonConfig) { c.Width = 65535 },
	} {
		config := valid
		mutate(&config)
		got, err := onetap.NewOneTapButtonOptions(config)
		assertBrowserOptionsInvalid(t, err)
		if _, err := onetap.NewBrowserStartOptions(onetap.OneTapPromptOptions{}, got); err == nil {
			t.Fatal("failed button constructor returned usable options")
		}
	}
}

func TestBrowserStartRejectsNoneBothAndWireForgedOptions(t *testing.T) {
	prompt, err := onetap.NewOneTapPromptOptions(onetap.OneTapPromptConfig{Context: onetap.PromptSignIn, CancelOnTapOutside: true})
	if err != nil {
		t.Fatal(err)
	}
	button, err := onetap.NewOneTapButtonOptions(onetap.OneTapButtonConfig{Type: onetap.ButtonStandard, Theme: onetap.ButtonOutline, Size: onetap.ButtonLarge})
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []struct {
		prompt onetap.OneTapPromptOptions
		button onetap.OneTapButtonOptions
	}{{}, {prompt: prompt, button: button}} {
		got, err := onetap.NewBrowserStartOptions(config.prompt, config.button)
		assertBrowserOptionsInvalid(t, err)
		projection, err := got.Projection()
		assertBrowserOptionsInvalid(t, err)
		if projection.Experience != "" || projection.Prompt != nil || projection.Button != nil {
			t.Fatal("rejected selection exposed a browser configuration")
		}
	}
	var forgedPrompt onetap.OneTapPromptOptions
	var forgedButton onetap.OneTapButtonOptions
	var forgedSelection onetap.BrowserStartOptions
	for _, target := range []any{&forgedPrompt, &forgedButton, &forgedSelection} {
		if err := json.Unmarshal([]byte(`{"valid":true,"Context":"signin","Type":"standard","Experience":"prompt","Prompt":{"Context":"signin"}}`), target); err != nil {
			t.Fatal(err)
		}
	}
	_, err = onetap.NewBrowserStartOptions(forgedPrompt, forgedButton)
	assertBrowserOptionsInvalid(t, err)
	_, err = forgedSelection.Projection()
	assertBrowserOptionsInvalid(t, err)
}

func TestBrowserStartProjectionEncodingIsDeterministic(t *testing.T) {
	prompt, err := onetap.NewOneTapPromptOptions(onetap.OneTapPromptConfig{Context: onetap.PromptSignIn, CancelOnTapOutside: true})
	if err != nil {
		t.Fatal(err)
	}
	button, err := onetap.NewOneTapButtonOptions(onetap.OneTapButtonConfig{Type: onetap.ButtonStandard, Theme: onetap.ButtonOutline, Size: onetap.ButtonLarge, Width: 400})
	if err != nil {
		t.Fatal(err)
	}
	retainedPrompt, err := onetap.NewOneTapPromptOptions(onetap.OneTapPromptConfig{Context: onetap.PromptUse, CancelOnTapOutside: false})
	if err != nil {
		t.Fatal(err)
	}
	defaultWidthButton, err := onetap.NewOneTapButtonOptions(onetap.OneTapButtonConfig{Type: onetap.ButtonIcon, Theme: onetap.ButtonOutlineDark, Size: onetap.ButtonSmall})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		prompt onetap.OneTapPromptOptions
		button onetap.OneTapButtonOptions
		json   string
	}{
		{prompt: prompt, json: `{"experience":"prompt","prompt":{"context":"signin","cancel_on_tap_outside":true}}`},
		{prompt: retainedPrompt, json: `{"experience":"prompt","prompt":{"context":"use","cancel_on_tap_outside":false}}`},
		{button: button, json: `{"experience":"popup_button","button":{"ux_mode":"popup","type":"standard","theme":"outline","size":"large","width":400}}`},
		{button: defaultWidthButton, json: `{"experience":"popup_button","button":{"ux_mode":"popup","type":"icon","theme":"outline_dark","size":"small"}}`},
	} {
		selected, err := onetap.NewBrowserStartOptions(test.prompt, test.button)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			projection, err := selected.Projection()
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(projection)
			if err != nil || string(encoded) != test.json {
				t.Fatalf("projection JSON = %s, %v; want %s", encoded, err, test.json)
			}
		}
	}
}

func assertBrowserOptionsInvalid(t *testing.T, err error) {
	t.Helper()
	var rejected *onetap.Error
	if !errors.As(err, &rejected) || rejected.Kind() != onetap.InvalidInput || err.Error() != "onetap: invalid_input" {
		t.Fatalf("rejection = %v, want redacted invalid_input", err)
	}
}
