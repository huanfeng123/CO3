package echtester

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

type echConfigMeta struct {
	publicName string
}

// parseECHConfigList mirrors the wire layout used by crypto/tls: a uint16 list
// length followed by ECHConfig records (version, record length, contents).
func parseECHConfigList(data []byte) ([]echConfigMeta, error) {
	if len(data) < 6 || int(binary.BigEndian.Uint16(data[:2])) != len(data)-2 {
		return nil, fmt.Errorf("invalid ECHConfigList length")
	}
	var configs []echConfigMeta
	for offset := 2; offset < len(data); {
		if offset+4 > len(data) {
			return nil, fmt.Errorf("truncated ECHConfig header")
		}
		recordLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		recordEnd := offset + 4 + recordLen
		if recordEnd > len(data) {
			return nil, fmt.Errorf("truncated ECHConfig contents")
		}
		name, err := parseConfigName(data[offset+4:recordEnd])
		if err != nil {
			return nil, err
		}
		configs = append(configs, echConfigMeta{publicName: name})
		offset = recordEnd
	}
	return configs, nil
}

func parseConfigName(contents []byte) (string, error) {
	pos := 0
	if len(contents) < 1+2+2 {
		return "", fmt.Errorf("ECHConfig key is truncated")
	}
	pos++ // config_id
	pos += 2 // kem_id
	keyLen := int(binary.BigEndian.Uint16(contents[pos : pos+2]))
	pos += 2
	if pos+keyLen+2 > len(contents) {
		return "", fmt.Errorf("ECHConfig public key is truncated")
	}
	pos += keyLen
	cipherLen := int(binary.BigEndian.Uint16(contents[pos : pos+2]))
	pos += 2
	if cipherLen%4 != 0 || pos+cipherLen+1+1+2 > len(contents) {
		return "", fmt.Errorf("ECHConfig cipher suites are invalid")
	}
	pos += cipherLen
	pos++ // maximum_name_length
	nameLen := int(contents[pos])
	pos++
	if pos+nameLen+2 > len(contents) {
		return "", fmt.Errorf("ECHConfig public name is truncated")
	}
	name := string(contents[pos : pos+nameLen])
	if err := validateDNSName(name, "ECH public_name"); err != nil {
		return "", err
	}
	return name, nil
}

func rewritePublicName(list []byte, wanted string) ([]byte, string, error) {
	wanted = strings.TrimSpace(strings.TrimSuffix(wanted, "."))
	configs, err := parseECHConfigList(list)
	if err != nil {
		return nil, "", err
	}
	original := make([]string, 0, len(configs))
	for _, config := range configs {
		original = append(original, config.publicName)
	}
	if wanted == "" {
		return append([]byte(nil), list...), strings.Join(original, ", "), nil
	}
	if err := validateDNSName(wanted, "public_name"); err != nil {
		return nil, "", err
	}

	out := make([]byte, 2, len(list)+len(wanted)*len(configs))
	for offset := 2; offset < len(list); {
		recordLen := int(binary.BigEndian.Uint16(list[offset+2 : offset+4]))
		recordEnd := offset + 4 + recordLen
		body, err := rewriteConfigBody(list[offset+4:recordEnd], wanted)
		if err != nil {
			return nil, "", err
		}
		var header [4]byte
		binary.BigEndian.PutUint16(header[:2], binary.BigEndian.Uint16(list[offset : offset+2]))
		binary.BigEndian.PutUint16(header[2:], uint16(len(body)))
		out = append(out, header[:]...)
		out = append(out, body...)
		offset = recordEnd
	}
	if len(out)-2 > 65535 {
		return nil, "", fmt.Errorf("rewritten ECHConfigList is too large")
	}
	binary.BigEndian.PutUint16(out[:2], uint16(len(out)-2))
	return out, strings.Join(original, ", "), nil
}

func rewriteConfigBody(contents []byte, wanted string) ([]byte, error) {
	pos := 0
	if len(contents) < 1+2+2 {
		return nil, fmt.Errorf("ECHConfig key is truncated")
	}
	pos++
	pos += 2
	keyLen := int(binary.BigEndian.Uint16(contents[pos : pos+2]))
	pos += 2
	if pos+keyLen+2 > len(contents) {
		return nil, fmt.Errorf("ECHConfig public key is truncated")
	}
	pos += keyLen
	cipherLen := int(binary.BigEndian.Uint16(contents[pos : pos+2]))
	pos += 2
	if cipherLen%4 != 0 || pos+cipherLen+1+1+2 > len(contents) {
		return nil, fmt.Errorf("ECHConfig cipher suites are invalid")
	}
	pos += cipherLen + 1
	nameLenPos := pos
	oldLen := int(contents[nameLenPos])
	pos++
	if pos+oldLen+2 > len(contents) {
		return nil, fmt.Errorf("ECHConfig public name is truncated")
	}
	result := make([]byte, 0, len(contents)+len(wanted)-oldLen)
	result = append(result, contents[:nameLenPos]...)
	result = append(result, byte(len(wanted)))
	result = append(result, wanted...)
	result = append(result, contents[pos+oldLen:]...)
	return result, nil
}

func validateDNSName(value, label string) error {
	value = strings.TrimSpace(strings.TrimSuffix(value, "."))
	if value == "" || len(value) > 253 || net.ParseIP(value) != nil {
		return fmt.Errorf("%s must be a DNS hostname", label)
	}
	for _, part := range strings.Split(value, ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return fmt.Errorf("%s is not a valid DNS hostname", label)
		}
		for _, r := range part {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') &&
				(r < '0' || r > '9') && r != '-' {
				return fmt.Errorf("%s is not a valid DNS hostname", label)
			}
		}
	}
	return nil
}
