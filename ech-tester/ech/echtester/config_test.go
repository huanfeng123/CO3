package echtester

import (
	"encoding/binary"
	"testing"
)

func testConfig(name string) []byte {
	contents := []byte{7, 0, 32, 0, 4, 1, 2, 3, 4, 0, 4, 0, 1, 0, 1, 32, byte(len(name))}
	contents = append(contents, name...)
	contents = append(contents, 0, 0)
	config := []byte{0xfe, 0x0d, 0, byte(len(contents))}
	config = append(config, contents...)
	list := []byte{0, byte(len(config))}
	return append(list, config...)
}

func TestRewritePublicName(t *testing.T) {
	input := testConfig("public.example")
	output, original, err := rewritePublicName(input, "outer.example")
	if err != nil {
		t.Fatal(err)
	}
	if original != "public.example" {
		t.Fatalf("original name = %q", original)
	}
	configs, err := parseECHConfigList(output)
	if err != nil {
		t.Fatal(err)
	}
	if configs[0].publicName != "outer.example" {
		t.Fatalf("rewritten name = %q", configs[0].publicName)
	}
	if int(binary.BigEndian.Uint16(output[:2])) != len(output)-2 {
		t.Fatal("rewritten list length is inconsistent")
	}
}

func TestRewriteEmptyKeepsBytes(t *testing.T) {
	input := testConfig("public.example")
	output, original, err := rewritePublicName(input, "")
	if err != nil || original != "public.example" {
		t.Fatalf("rewrite empty: original=%q err=%v", original, err)
	}
	if string(output) != string(input) {
		t.Fatal("empty public_name changed the config")
	}
}

func TestValidateDNSName(t *testing.T) {
	for _, value := range []string{"example.com", "a-b.example", "xn--e-xample.example"} {
		if err := validateDNSName(value, "test"); err != nil {
			t.Errorf("%q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"", "-bad.example", "bad_.example", "127.0.0.1"} {
		if err := validateDNSName(value, "test"); err == nil {
			t.Errorf("%q unexpectedly accepted", value)
		}
	}
}
