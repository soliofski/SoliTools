package tui

import (
	"strings"
	"testing"

	"solitools/internal/httpx"
)

func TestNewFormDefaults(t *testing.T) {
	form := NewForm()
	if !form.Crawl || !form.Forms || !form.Stored {
		t.Fatalf("crawl/forms/stored must default on: %+v", form)
	}
	if form.SkipPath {
		t.Fatal("skip-path must default off")
	}
	if form.Verify {
		t.Fatal("credential verification must default off: it contacts third parties")
	}
	if !form.Mask {
		t.Fatal("masking must default on")
	}
	if form.Threshold != 0 || form.ThresholdValue() != 60 {
		t.Fatalf("threshold = %d/%v, want default 60", form.Threshold, form.ThresholdValue())
	}
	if form.Rate != DefaultRate || form.MaxPages != DefaultMaxPages {
		t.Fatalf("rate/pages = %d/%d", form.Rate, form.MaxPages)
	}
}

func TestFormFocusClamps(t *testing.T) {
	form := NewForm()
	form.MoveFocus(-5)
	if form.Focus != 0 {
		t.Fatalf("focus = %d, want clamped to 0", form.Focus)
	}
	form.MoveFocus(100)
	if form.Focus != rowCount-1 {
		t.Fatalf("focus = %d, want clamped to %d", form.Focus, rowCount-1)
	}
}

func TestFormTogglesCheckboxesAndRadios(t *testing.T) {
	form := NewForm()
	form.Focus = rowCrawl
	form.Toggle()
	if form.Crawl {
		t.Fatal("space must untick crawl")
	}
	form.Focus = rowMask
	form.Toggle()
	if form.Mask {
		t.Fatal("space must untick masking")
	}

	form.Focus = rowVerify
	form.Toggle()
	if !form.Verify {
		t.Fatal("space must tick verification")
	}

	form.Focus = rowThresholdStrict
	form.Toggle()
	if form.Threshold != 1 || form.ThresholdValue() != 75 {
		t.Fatalf("strict threshold = %d/%v", form.Threshold, form.ThresholdValue())
	}
	form.Focus = rowThresholdAll
	form.Toggle()
	if form.Threshold != 2 || form.ThresholdValue() != 0 {
		t.Fatalf("all threshold = %d/%v", form.Threshold, form.ThresholdValue())
	}
}

func TestFormNumericBounds(t *testing.T) {
	form := NewForm()
	form.Focus = rowRate
	for i := 0; i < 5; i++ {
		form.Adjust(-100)
	}
	if form.Rate != MinRate {
		t.Fatalf("rate = %d, want floor %d", form.Rate, MinRate)
	}
	for i := 0; i < 5; i++ {
		form.Adjust(100000)
	}
	if form.Rate != MaxRate {
		t.Fatalf("rate = %d, want ceiling %d", form.Rate, MaxRate)
	}

	form.Focus = rowMaxPages
	form.Adjust(-100)
	if form.MaxPages != MinPages {
		t.Fatalf("pages = %d, want floor %d", form.MaxPages, MinPages)
	}
	form.Adjust(100000)
	if form.MaxPages != MaxPages {
		t.Fatalf("pages = %d, want ceiling %d", form.MaxPages, MaxPages)
	}
}

func TestFormDigitEditing(t *testing.T) {
	form := NewForm()
	form.Focus = rowRate
	form.Rate = 10
	form.Digit(5)
	if form.Rate != 105 {
		t.Fatalf("rate = %d, want 105", form.Rate)
	}
	form.DeleteDigit()
	if form.Rate != 10 {
		t.Fatalf("rate = %d, want 10 after delete", form.Rate)
	}
}

func TestFormTargetEditing(t *testing.T) {
	form := NewForm()
	form.Focus = rowTarget
	for _, r := range "héllo" {
		form.Insert(r)
	}
	if form.Target != "héllo" {
		t.Fatalf("target = %q", form.Target)
	}
	form.MoveCursor(-1)
	form.MoveCursor(-1)
	form.Backspace()
	if form.Target != "hélo" {
		t.Fatalf("target = %q, want the rune before the cursor removed", form.Target)
	}
	if form.Cursor != len("hé") {
		t.Fatalf("cursor = %d", form.Cursor)
	}

	// Typing only lands in the target field.
	form.Focus = rowRate
	form.Insert('x')
	if strings.Contains(form.Target, "x") {
		t.Fatal("typing outside the target row modified the target")
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"https://target.test/", "https://target.test/", false},
		{"target.test", "http://target.test", false},
		{"  target.test/app  ", "http://target.test/app", false},
		{"", "", true},
		{"ftp://target.test", "", true},
		{"http://", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeTarget(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("NormalizeTarget(%q) = %q, want an error", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("NormalizeTarget(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

func TestFormBuildsScanOptions(t *testing.T) {
	form := NewForm()
	form.Target = "target.test/app"
	form.Crawl = false
	form.Forms = true
	form.Stored = true
	form.SkipPath = true
	form.Verify = true
	form.Rate = 50
	form.MaxPages = 5

	client, err := httpx.New(httpx.Options{Rate: 500})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	options := form.ScanOptions(client, nil, nil)
	if options.Target != "http://target.test/app" {
		t.Fatalf("target = %q", options.Target)
	}
	if options.EnableCrawl || !options.EnableForms || !options.EnableStored || !options.SkipPath {
		t.Fatalf("flags = %+v", options)
	}
	if !options.Verify {
		t.Fatal("verification was ticked but not wired into scan options")
	}
	if options.MaxPages != 5 {
		t.Fatalf("max pages = %d", options.MaxPages)
	}
}
