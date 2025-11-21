# Phase 1 Engineering Review - Required Fixes

## Critical Issues

### 1. Header Sanitization (CRITICAL)
- **Issue**: format_http_request doesn't normalize Connection, strip duplicates, or reject conflicting headers
- **Fix**: Explicit header filter with normalization before formatting
- **Impact**: Security (header injection, smuggling)

### 2. Response Parsing (CRITICAL)
- **Issue**: Single 8KB read assumes headers arrive complete; chunked bodies unhandled
- **Fix**: Looped read-until-headers-complete + chunked dechunking
- **Impact**: Correctness (hangs, incomplete parses)

### 3. Write Timeout Missing (HIGH)
- **Issue**: Only connect timeout; writes can hang indefinitely
- **Fix**: Add write timeout around request body streaming
- **Impact**: Availability (stuck connections)

### 4. Chunked Encoding (HIGH)
- **Issue**: Manual client doesn't handle Transfer-Encoding: chunked upstream
- **Fix**: Implement chunked dechunking, convert to Content-Length or forward chunks correctly
- **Impact**: Correctness (malformed responses)

### 5. Metrics Missing (MEDIUM)
- **Issue**: No retry/failure counters, DNS metrics, IP limit hit counters
- **Fix**: Add Prometheus metrics throughout
- **Impact**: Ops visibility

### 6. Alert Client Inconsistency (MEDIUM)
- **Issue**: Plan says "NO reqwest" but alert webhook uses reqwest
- **Fix**: Remove reqwest from alerts OR accept it explicitly for backend API only
- **Impact**: Consistency

### 7. Hostname Blocklist Gaps (MEDIUM)
- **Issue**: Only covers metadata domains, not .local, .internal wildcards
- **Fix**: Expand blocklist, make configurable
- **Impact**: Security (SSRF coverage)

### 8. DNS Empty Results (LOW)
- **Issue**: No policy for NXDOMAIN, no metrics
- **Fix**: Return error on empty IP list, meter failures
- **Impact**: Correctness

### 9. DISABLE_TLS_VERIFY (LOW)
- **Issue**: Present but not gated/logged
- **Fix**: Log warning, gate to non-prod
- **Impact**: Security awareness

## Implementation Order

**Immediate (before Phase 2):**
1. Header sanitization with explicit filter
2. Response parsing with looped read + max header size
3. Write timeout addition
4. Chunked encoding support

**Phase 2 Integration:**
5. Metrics throughout
6. Alert client decision (keep reqwest for backend API only)

**Phase 3:**
7. Expanded hostname blocklist
8. DNS empty result handling
9. TLS verify logging

## Decisions Needed

**Q1: Alert webhook client?**
- Option A: Keep reqwest (only for backend API + alerts) ✓ RECOMMENDED
- Option B: Manual client for alerts (adds complexity)

**Recommendation: Keep reqwest for backend communication only, clarify in docs**

**Q2: Chunked encoding strategy?**
- Option A: Dechunk upstream, send Content-Length to client ✓ RECOMMENDED
- Option B: Forward chunks (requires proper framing)

**Recommendation: Dechunk for simplicity**

**Q3: Error response format?**
- Request over-limit: 413 + Connection: close
- Response over-limit: 502 + Connection: close
- Parse/timeout errors: 502 + Connection: close
- All errors: text/plain body

**Confirmed - document this**
