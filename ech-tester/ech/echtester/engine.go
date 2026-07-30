package echtester

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Test performs one TLS 1.3 ECH handshake and returns a complete plain-text log.
// The signature intentionally uses only gomobile-friendly basic types.
func Test(target, configSource, publicName, sni, doh, ipList string) string {
	var log strings.Builder
	writeLog := func(format string, args ...any) {
		fmt.Fprintf(&log, format+"\n", args...)
	}

	targetHost, port, err := splitHostPort(target)
	if err != nil {
		writeLog("RESULT=FAIL")
		writeLog("input error: %v", err)
		return log.String()
	}
	sourceHost := strings.TrimSpace(configSource)
	if sourceHost == "" {
		sourceHost = targetHost
	}
	if err := validateDNSName(sourceHost, "config source"); err != nil {
		writeLog("RESULT=FAIL")
		writeLog("input error: %v", err)
		return log.String()
	}
	if sni == "" {
		sni = targetHost
	}
	if err := validateDNSName(sni, "sni"); err != nil {
		writeLog("RESULT=FAIL")
		writeLog("input error: %v", err)
		return log.String()
	}
	doh = strings.TrimSpace(doh)
	if doh == "" {
		doh = defaultDoH
	}
	writeLog("target=%s:%s", targetHost, port)
	writeLog("config_source=%s", sourceHost)
	writeLog("public_name_input=%s", valueOrDefault(publicName, "(from ECHConfigList)"))
	writeLog("sni=%s", sni)
	writeLog("doh=%s", doh)

	rawConfig, err := fetchECHConfig(doh, sourceHost)
	if err != nil {
		writeLog("RESULT=FAIL")
		writeLog("ECH config lookup failed: %v", err)
		return log.String()
	}
	config, originalNames, err := rewritePublicName(rawConfig, publicName)
	if err != nil {
		writeLog("RESULT=FAIL")
		writeLog("ECH config parse/rewrite failed: %v", err)
		return log.String()
	}
	writeLog("ech_config_bytes=%d", len(config))
	writeLog("public_name_original=%s", originalNames)
	writeLog("public_name_used=%s", valueOrDefault(publicName, originalNames))

	addresses, resolveErr := resolveHost(doh, targetHost)
	if resolveErr != nil {
		writeLog("DoH target resolve failed: %v", resolveErr)
		resolved, fallbackErr := net.LookupIP(targetHost)
		if fallbackErr != nil {
			writeLog("system DNS fallback failed: %v", fallbackErr)
			writeLog("RESULT=FAIL")
			return log.String()
		}
		for _, address := range resolved {
			addresses = append(addresses, address.String())
		}
		writeLog("dns_source=system fallback")
	} else {
		writeLog("dns_source=DoH")
	}
	custom := parseIPList(ipList)
	addresses = prependUnique(custom, addresses)
	writeLog("connect_candidates=%s", strings.Join(addresses, ", "))

	state, dialed, retryUsed, err := handshake(targetHost, port, sni, config, addresses)
	if err != nil {
		writeLog("handshake_error=%v", err)
		writeLog("RESULT=FAIL")
		return log.String()
	}
	writeLog("dialed=%s", dialed)
	writeLog("retry_configs_used=%t", retryUsed)
	writeLog("tls_version=%s", tlsVersion(state.Version))
	writeLog("alpn=%s", valueOrDefault(state.NegotiatedProtocol, "(none)"))
	writeLog("ECHAccepted=%t", state.ECHAccepted)
	if state.ECHAccepted {
		writeLog("RESULT=PASS")
	} else {
		writeLog("RESULT=FAIL (TLS connected without accepted ECH)")
	}
	return log.String()
}

func handshake(host, port, sni string, config []byte, addresses []string) (tls.ConnectionState, string, bool, error) {
	var lastErr error
	for _, address := range addresses {
		conn, err := dialTLS(host, port, sni, config, address)
		if err == nil {
			return conn.state, address, conn.retry, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no connection candidates")
	}
	return tls.ConnectionState{}, "", false, lastErr
}

type handshakeResult struct {
	state tls.ConnectionState
	retry bool
}

func dialTLS(host, port, sni string, config []byte, address string) (handshakeResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), networkTimeout)
	defer cancel()
	raw, err := (&net.Dialer{Timeout: networkTimeout}).DialContext(ctx, "tcp", net.JoinHostPort(address, port))
	if err != nil {
		return handshakeResult{}, fmt.Errorf("dial %s: %w", address, err)
	}
	tlsConfig := &tls.Config{
		ServerName:                     sni,
		MinVersion:                     tls.VersionTLS13,
		NextProtos:                     []string{"h2", "http/1.1"},
		EncryptedClientHelloConfigList: config,
	}
	conn := tls.Client(raw, tlsConfig)
	if err := conn.HandshakeContext(ctx); err == nil {
		state := conn.ConnectionState()
		conn.Close()
		return handshakeResult{state: state}, nil
	} else {
		var rejected *tls.ECHRejectionError
		if !errors.As(err, &rejected) || len(rejected.RetryConfigList) == 0 {
			raw.Close()
			return handshakeResult{}, fmt.Errorf("TLS/ECH handshake: %w", err)
		}
		raw.Close()
		raw, retryErr := (&net.Dialer{Timeout: networkTimeout}).DialContext(ctx, "tcp", net.JoinHostPort(address, port))
		if retryErr != nil {
			return handshakeResult{}, fmt.Errorf("retry dial %s: %w", address, retryErr)
		}
		tlsConfig.EncryptedClientHelloConfigList = rejected.RetryConfigList
		conn = tls.Client(raw, tlsConfig)
		if retryErr = conn.HandshakeContext(ctx); retryErr != nil {
			raw.Close()
			return handshakeResult{}, fmt.Errorf("retry TLS/ECH handshake: %w", retryErr)
		}
		state := conn.ConnectionState()
		conn.Close()
		return handshakeResult{state: state, retry: true}, nil
	}
}

func splitHostPort(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "://") {
		return "", "", fmt.Errorf("target must be a hostname, not a URL")
	}
	port := "443"
	host := value
	if parsedHost, parsedPort, err := net.SplitHostPort(value); err == nil {
		host, port = parsedHost, parsedPort
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if err := validateDNSName(host, "target"); err != nil {
		return "", "", err
	}
	return host, port, nil
}

func prependUnique(first, rest []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(first)+len(rest))
	for _, item := range append(append([]string{}, first...), rest...) {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

func tlsVersion(version uint16) string {
	if version == tls.VersionTLS13 {
		return "1.3"
	}
	return fmt.Sprintf("0x%04x", version)
}

func valueOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
