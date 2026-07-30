package echtester

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const defaultDoH = "https://cloudflare-dns.com/dns-query"
const networkTimeout = 20 * time.Second

type dohResponse struct {
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

var echParam = regexp.MustCompile(`(?i)\bech="?([A-Za-z0-9+/=]+)"?`)
var wireRecord = regexp.MustCompile(`(?is)^\\#\s+\d+\s+([0-9a-f\s]+)$`)

func queryDoH(endpoint, host, recordType string) (*dohResponse, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, errors.New("DoH endpoint is empty")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("DoH endpoint must be an HTTPS URL")
	}
	query := parsed.Query()
	query.Set("name", host)
	query.Set("type", recordType)
	parsed.RawQuery = query.Encode()
	req, err := http.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/dns-json")
	client := &http.Client{Timeout: networkTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH returned HTTP %d", resp.StatusCode)
	}
	var result dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("invalid DoH JSON: %w", err)
	}
	return &result, nil
}

func fetchECHConfig(endpoint, host string) ([]byte, error) {
	response, err := queryDoH(endpoint, host, "HTTPS")
	if err != nil {
		return nil, err
	}
	for _, answer := range response.Answer {
		if answer.Type != 65 {
			continue
		}
		config, err := extractECH(answer.Data)
		if err != nil {
			return nil, err
		}
		if len(config) > 0 {
			return config, nil
		}
	}
	return nil, fmt.Errorf("no ech= parameter found for %s", host)
}

func extractECH(data string) ([]byte, error) {
	if match := echParam.FindStringSubmatch(data); match != nil {
		config, err := base64.StdEncoding.DecodeString(match[1])
		if err != nil {
			return nil, fmt.Errorf("ech= is not valid base64: %w", err)
		}
		return config, nil
	}
	match := wireRecord.FindStringSubmatch(strings.TrimSpace(data))
	if match == nil {
		return nil, nil
	}
	var wire []byte
	for _, token := range strings.Fields(match[1]) {
		value, err := strconv.ParseUint(token, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid HTTPS record wire data: %w", err)
		}
		wire = append(wire, byte(value))
	}
	return parseHTTPSWire(wire)
}

func parseHTTPSWire(wire []byte) ([]byte, error) {
	if len(wire) < 3 {
		return nil, fmt.Errorf("HTTPS record wire data is truncated")
	}
	pos := 2 // SvcPriority
	for pos < len(wire) {
		labelLen := int(wire[pos])
		pos++
		if labelLen == 0 {
			break
		}
		if labelLen > 63 || pos+labelLen > len(wire) {
			return nil, fmt.Errorf("HTTPS target name is malformed")
		}
		pos += labelLen
	}
	for pos < len(wire) {
		if pos+4 > len(wire) {
			return nil, fmt.Errorf("HTTPS service parameter is truncated")
		}
		key := uint16(wire[pos])<<8 | uint16(wire[pos+1])
		length := int(uint16(wire[pos+2])<<8 | uint16(wire[pos+3]))
		pos += 4
		if pos+length > len(wire) {
			return nil, fmt.Errorf("HTTPS service parameter length is invalid")
		}
		if key == 5 {
			return append([]byte(nil), wire[pos:pos+length]...), nil
		}
		pos += length
	}
	return nil, nil
}

func resolveHost(endpoint, host string) ([]string, error) {
	var addresses []string
	var firstErr error
	for _, recordType := range []string{"A", "AAAA"} {
		response, err := queryDoH(endpoint, host, recordType)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, answer := range response.Answer {
			if (recordType == "A" && answer.Type != 1) ||
				(recordType == "AAAA" && answer.Type != 28) {
				continue
			}
			if net.ParseIP(answer.Data) != nil {
				addresses = append(addresses, answer.Data)
			}
		}
	}
	if len(addresses) == 0 {
		if firstErr == nil {
			firstErr = errors.New("DoH returned no A/AAAA records")
		}
		return nil, firstErr
	}
	return addresses, nil
}

func parseIPList(raw string) []string {
	var result []string
	for _, item := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	}) {
		if net.ParseIP(item) != nil {
			result = append(result, item)
		}
	}
	return result
}
