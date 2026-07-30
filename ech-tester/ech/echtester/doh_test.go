package echtester

import "testing"

func TestExtractECHFromWireHTTPSRecord(t *testing.T) {
	data := `\# 17 00 01 00 00 00 05 02 68 33 00 05 00 04 01 02 03 04`
	config, err := extractECH(data)
	if err != nil {
		t.Fatal(err)
	}
	if string(config) != string([]byte{1, 2, 3, 4}) {
		t.Fatalf("config = %v", config)
	}
}

func TestExtractECHFromTextHTTPSRecord(t *testing.T) {
	config, err := extractECH(`1 . ech="AQIDBA=="`)
	if err != nil {
		t.Fatal(err)
	}
	if string(config) != string([]byte{1, 2, 3, 4}) {
		t.Fatalf("config = %v", config)
	}
}
