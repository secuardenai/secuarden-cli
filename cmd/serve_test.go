package cmd

import "testing"

func TestValidateLoopbackAddress(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8743", "localhost:0", "[::1]:8743"} {
		if err := validateLoopbackAddress(address); err != nil {
			t.Errorf("%s rejected: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:8743", ":8743", "example.com:8743", "bad"} {
		if err := validateLoopbackAddress(address); err == nil {
			t.Errorf("unsafe address %s accepted", address)
		}
	}
}
