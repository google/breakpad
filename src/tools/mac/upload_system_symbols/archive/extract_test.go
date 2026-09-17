package archive

import (
	"os"
	"path"
	"testing"
)

// imagePatchManifest is the image patch manifest from a macOS 27 installer, whose
// cryptex-system-arm64e.x1 image patches cryptex-system-arm64e rather than containing an
// image of its own.
const imagePatchManifest = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>cryptex-app</key>
	<dict>
		<key>ImagePatchTag</key>
		<string>cryptex-app</string>
	</dict>
	<key>cryptex-system-arm64e</key>
	<dict>
		<key>ImagePatchTag</key>
		<string>cryptex-system-arm64e</string>
	</dict>
	<key>cryptex-system-arm64e.x1</key>
	<dict>
		<key>ImagePatchBaselineTag</key>
		<string>cryptex-system-arm64e</string>
		<key>ImagePatchTag</key>
		<string>cryptex-system-arm64e.x1</string>
	</dict>
	<key>cryptex-system-rosetta</key>
	<dict>
		<key>ImagePatchTag</key>
		<string>cryptex-system-rosetta</string>
	</dict>
</dict>
</plist>
`

func TestIsDeltaImage(t *testing.T) {
	dir := t.TempDir()
	manifestPath := path.Join(dir, "image_patches.plist")
	if err := os.WriteFile(manifestPath, []byte(imagePatchManifest), 0644); err != nil {
		t.Fatalf("couldn't write %s: %v", manifestPath, err)
	}
	e := &installAssistantExtractor{Extractor: &Extractor{}}

	cases := []struct {
		imageName string
		want      bool
	}{
		{"cryptex-system-arm64e", false},
		{"cryptex-system-arm64e.x1", true},
		{"cryptex-system-rosetta", false},
		{"cryptex-app", false},
		{"not-in-the-manifest", false},
	}
	for _, c := range cases {
		t.Run(c.imageName, func(t *testing.T) {
			if got := e.isDeltaImage(manifestPath, c.imageName); got != c.want {
				t.Errorf("isDeltaImage(%s) = %v, want %v", c.imageName, got, c.want)
			}
		})
	}

	t.Run("no manifest", func(t *testing.T) {
		if e.isDeltaImage(path.Join(dir, "does_not_exist.plist"), "cryptex-system-arm64e.x1") {
			t.Error("isDeltaImage with no manifest = true, want false")
		}
	})
}
