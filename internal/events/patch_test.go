package events

import "testing"

func TestParseApplyPatchAffectedPaths(t *testing.T) {
	patch := "*** Begin Patch\n" +
		"*** Add File: new.txt\n+new\n" +
		"*** Update File: old.txt\n@@\n-old\n+updated\n" +
		"*** Delete File: gone.txt\n" +
		"*** Update File: before.txt\n*** Move to: after.txt\n@@\n-old name\n+new name\n" +
		"*** End Patch"
	files, stats, err := ParseApplyPatch(patch)
	if err != nil {
		t.Fatal(err)
	}
	want := []AffectedFile{
		{Path: "new.txt", Operation: "add"},
		{Path: "old.txt", Operation: "update"},
		{Path: "gone.txt", Operation: "delete"},
		{Path: "before.txt", Operation: "move_source"},
		{Path: "after.txt", Operation: "move_destination"},
	}
	if len(files) != len(want) {
		t.Fatalf("files=%#v", files)
	}
	for i := range want {
		if files[i] != want[i] {
			t.Fatalf("file[%d]=%#v want %#v", i, files[i], want[i])
		}
	}
	if stats != "+3/-2" {
		t.Fatalf("stats=%q", stats)
	}
}

func TestParseApplyPatchRejectsMalformedAndUnsupported(t *testing.T) {
	for _, patch := range []string{
		"*** Begin Patch\n*** Add File: .env\n+SECRET=value",
		"*** Begin Patch\n*** Copy File: .env\n+SECRET=value\n*** End Patch",
		"not a patch containing SECRET=value",
	} {
		if _, _, err := ParseApplyPatch(patch); err == nil || err.Error() != "unsupported apply_patch structure" {
			t.Fatalf("unsafe or missing error for malformed patch: %v", err)
		}
	}
}

func TestParseApplyPatchRejectsUnprefixedAddBody(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: safe.txt\nUNPREFIXED_TEST_CONTENT_4f8a21\n*** End Patch"
	if _, _, err := ParseApplyPatch(patch); err == nil {
		t.Fatal("Add File accepted an unprefixed body line")
	}
}

func TestParseApplyPatchValidatesOperationBodies(t *testing.T) {
	tests := map[string]string{
		"add":    "*** Begin Patch\n*** Add File: file.txt\ninvalid\n*** End Patch",
		"update": "*** Begin Patch\n*** Update File: file.txt\n@@\ninvalid\n*** End Patch",
		"delete": "*** Begin Patch\n*** Delete File: file.txt\n-invalid\n*** End Patch",
		"move":   "*** Begin Patch\n*** Update File: old.txt\n*** Move to: new.txt\n@@\ninvalid\n*** End Patch",
	}
	for name, patch := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseApplyPatch(patch); err == nil {
				t.Fatal("invalid operation body was accepted")
			}
		})
	}
}
