#!/bin/bash
#
# ALPN Negotiation Test Script for Rust Proxy
# Tests HTTP/2 and HTTP/1.1 protocol negotiation
#

set -e

# Configuration
PROXY_HOST="${1:-localhost}"
PROXY_PORT="${2:-443}"
CERT_VERIFY="${3:--no-verify}"  # Use -no-verify for self-signed certs

echo "============================================"
echo "  Rust Proxy ALPN Negotiation Test"
echo "============================================"
echo ""
echo "Target: $PROXY_HOST:$PROXY_PORT"
echo "Certificate Verification: $([ "$CERT_VERIFY" = "-no-verify" ] && echo "Disabled (self-signed)" || echo "Enabled")"
echo ""

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: HTTP/2 (h2) Negotiation
echo "============================================"
echo "Test 1: HTTP/2 (h2) Negotiation"
echo "============================================"
echo ""
echo "Command: openssl s_client -connect $PROXY_HOST:$PROXY_PORT -alpn h2,http/1.1"
echo ""

if [ "$CERT_VERIFY" = "-no-verify" ]; then
    # Skip certificate verification (for self-signed certs)
    ALPN_OUTPUT=$(echo -e "GET / HTTP/1.1\r\nHost: $PROXY_HOST\r\n\r\n" | \
        timeout 5 openssl s_client -connect "$PROXY_HOST:$PROXY_PORT" \
        -alpn h2,http/1.1 2>&1 || true)
else
    # Enforce certificate verification (for Let's Encrypt / production)
    ALPN_OUTPUT=$(echo -e "GET / HTTP/1.1\r\nHost: $PROXY_HOST\r\n\r\n" | \
        timeout 5 openssl s_client -connect "$PROXY_HOST:$PROXY_PORT" \
        -alpn h2,http/1.1 -verify_return_error 2>&1 || true)
fi

# Check for h2 protocol selection
if echo "$ALPN_OUTPUT" | grep -q "ALPN protocol: h2"; then
    echo -e "${GREEN}✓ PASS${NC}: HTTP/2 (h2) protocol successfully negotiated"
    echo ""
    echo "ALPN Details:"
    echo "$ALPN_OUTPUT" | grep "ALPN protocol"
else
    echo -e "${RED}✗ FAIL${NC}: HTTP/2 (h2) protocol NOT negotiated"
    echo ""
    echo "Expected: ALPN protocol: h2"
    echo "Got:"
    echo "$ALPN_OUTPUT" | grep "ALPN" || echo "(No ALPN line found)"
fi

echo ""
echo "Full openssl output:"
echo "$ALPN_OUTPUT" | grep -A5 -B5 "ALPN" || echo "(No ALPN information found)"
echo ""

# Test 2: HTTP/1.1 Negotiation (Fallback)
echo "============================================"
echo "Test 2: HTTP/1.1 Negotiation (Fallback)"
echo "============================================"
echo ""
echo "Command: openssl s_client -connect $PROXY_HOST:$PROXY_PORT -alpn http/1.1"
echo ""

if [ "$CERT_VERIFY" = "-no-verify" ]; then
    # Skip certificate verification (for self-signed certs)
    ALPN_OUTPUT_HTTP1=$(echo -e "GET / HTTP/1.1\r\nHost: $PROXY_HOST\r\n\r\n" | \
        timeout 5 openssl s_client -connect "$PROXY_HOST:$PROXY_PORT" \
        -alpn http/1.1 2>&1 || true)
else
    # Enforce certificate verification (for Let's Encrypt / production)
    ALPN_OUTPUT_HTTP1=$(echo -e "GET / HTTP/1.1\r\nHost: $PROXY_HOST\r\n\r\n" | \
        timeout 5 openssl s_client -connect "$PROXY_HOST:$PROXY_PORT" \
        -alpn http/1.1 -verify_return_error 2>&1 || true)
fi

# Check for http/1.1 protocol selection
if echo "$ALPN_OUTPUT_HTTP1" | grep -q "ALPN protocol: http/1.1"; then
    echo -e "${GREEN}✓ PASS${NC}: HTTP/1.1 protocol successfully negotiated"
    echo ""
    echo "ALPN Details:"
    echo "$ALPN_OUTPUT_HTTP1" | grep "ALPN protocol"
else
    echo -e "${RED}✗ FAIL${NC}: HTTP/1.1 protocol NOT negotiated"
    echo ""
    echo "Expected: ALPN protocol: http/1.1"
    echo "Got:"
    echo "$ALPN_OUTPUT_HTTP1" | grep "ALPN" || echo "(No ALPN line found)"
fi

echo ""

# Test 3: Certificate Information
echo "============================================"
echo "Test 3: TLS Certificate Information"
echo "============================================"
echo ""

CERT_INFO=$(echo | openssl s_client -connect "$PROXY_HOST:$PROXY_PORT" -showcerts 2>&1 || true)

echo "Subject:"
echo "$CERT_INFO" | grep "subject=" | head -1

echo ""
echo "Issuer:"
echo "$CERT_INFO" | grep "issuer=" | head -1

echo ""
echo "Validity:"
echo "$CERT_INFO" | grep -A2 "Validity"

echo ""
echo "TLS Version:"
echo "$CERT_INFO" | grep "Protocol" | head -1

echo ""

# Test 4: Supported Cipher Suites
echo "============================================"
echo "Test 4: TLS Configuration"
echo "============================================"
echo ""

echo "Cipher Suite:"
echo "$CERT_INFO" | grep "Cipher" | head -1

echo ""
echo "SSL Handshake:"
if echo "$CERT_INFO" | grep -q "Verify return code: 0"; then
    echo -e "${GREEN}✓ Certificate verification: SUCCESS${NC}"
elif echo "$CERT_INFO" | grep -q "self signed certificate"; then
    echo -e "${YELLOW}⚠ Self-signed certificate (expected in development)${NC}"
else
    echo -e "${YELLOW}⚠ Certificate verification status:${NC}"
    echo "$CERT_INFO" | grep "Verify return code"
fi

echo ""

# Summary
echo "============================================"
echo "  Test Summary"
echo "============================================"
echo ""

H2_PASS=$(echo "$ALPN_OUTPUT" | grep -q "ALPN protocol: h2" && echo "PASS" || echo "FAIL")
HTTP1_PASS=$(echo "$ALPN_OUTPUT_HTTP1" | grep -q "ALPN protocol: http/1.1" && echo "PASS" || echo "FAIL")

if [ "$H2_PASS" = "PASS" ] && [ "$HTTP1_PASS" = "PASS" ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED${NC}"
    echo ""
    echo "✓ HTTP/2 (h2) negotiation: WORKING"
    echo "✓ HTTP/1.1 negotiation: WORKING"
    echo "✓ TLS handshake: SUCCESSFUL"
    echo ""
    echo "Rust Proxy is correctly configured for dual-protocol support!"
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    echo ""
    echo "HTTP/2 (h2): $H2_PASS"
    echo "HTTP/1.1: $HTTP1_PASS"
    echo ""
    echo "Please check server logs for details"
    exit 1
fi
