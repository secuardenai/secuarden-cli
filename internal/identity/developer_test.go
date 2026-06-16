package identity

import "testing"

func TestCapture_ReturnsStruct(t *testing.T) {
	dev := Capture()
	if dev == nil {
		t.Fatal("Capture() returned nil")
	}
	// OSUser should always be populated (even without git)
	if dev.OSUser == "" {
		t.Error("expected non-empty OSUser")
	}
	// MachineID should be a non-empty hex string
	if len(dev.MachineID) == 0 {
		t.Error("expected non-empty MachineID")
	}
}

func TestMachineID_Stable(t *testing.T) {
	id1 := machineID()
	id2 := machineID()
	if id1 != id2 {
		t.Errorf("machineID not stable: %q != %q", id1, id2)
	}
}

func TestCaptureWithDir_NoGit(t *testing.T) {
	// /tmp is typically not a git repo
	dev := CaptureWithDir("/tmp")
	if dev == nil {
		t.Fatal("CaptureWithDir returned nil")
	}
	// Should not fail even if not in a git repo
	// Name and Email may be empty, but OSUser should be set
	if dev.OSUser == "" {
		t.Error("expected non-empty OSUser")
	}
}
