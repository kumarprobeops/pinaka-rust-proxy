# JWT Validation Deployment Guide - Phase 2.2

## Overview

The Rust forward proxy implements JWT authentication with **configurable** issuer and audience validation. This guide explains the security implications and deployment requirements.

## Security Posture Change

### Previous Behavior (Phase 2.0/2.1)
- **Hard-coded validation**: All tokens MUST have `iss: "probeops"` and `aud: "forward-proxy"`
- **Strict enforcement**: Tokens without these claims were rejected
- **Single-tenant**: Only one issuer/audience pair supported

### Current Behavior (Phase 2.2)
- **Configurable validation**: Issuer and audience are validated ONLY if environment variables are set
- **Default behavior**: **Validation is DISABLED** if `JWT_ISSUER` and `JWT_AUDIENCE` are not set
- **Multi-tenant ready**: Different deployments can enforce different issuers/audiences

## Critical Security Warning

⚠️ **DEFAULT BEHAVIOR IS LESS RESTRICTIVE**

If you deploy without setting `JWT_ISSUER` and `JWT_AUDIENCE` environment variables:
- **Any valid JWT signed with the correct secret will be accepted**
- **Issuer claim is NOT validated** (tokens from any issuer are accepted)
- **Audience claim is NOT validated** (tokens for any audience are accepted)

This is a **posture change** from Phase 2.0/2.1 and could allow broader access than intended.

## Recommended Deployment Configuration

### Secure Production Deployment (RECOMMENDED)

**Always set both `JWT_ISSUER` and `JWT_AUDIENCE` in production environments:**

```bash
# .env or environment configuration
JWT_SECRET=your_production_secret_at_least_32_characters_long
JWT_ISSUER=probeops
JWT_AUDIENCE=forward-proxy
JWT_ALGORITHM=HS256  # Optional, defaults to HS256
```

This configuration enforces:
- ✅ Tokens must be signed with the correct secret
- ✅ Tokens must have `"iss": "probeops"` claim
- ✅ Tokens must have `"aud": "forward-proxy"` claim
- ✅ Tokens must include `allowed_regions` with the current node's region

### Development/Testing Deployment

For development or testing environments where you want **relaxed validation**:

```bash
# .env for development
JWT_SECRET=dev_secret_at_least_32_characters
# JWT_ISSUER not set - issuer validation disabled
# JWT_AUDIENCE not set - audience validation disabled
```

This configuration enforces:
- ✅ Tokens must be signed with the correct secret
- ✅ Tokens must include `allowed_regions` with the current node's region
- ⚠️ Any issuer accepted
- ⚠️ Any audience accepted

### Multi-Tenant Deployment

For multi-tenant scenarios with different issuers per deployment:

```bash
# Tenant A deployment
JWT_SECRET=shared_secret_at_least_32_characters
JWT_ISSUER=tenant-a
JWT_AUDIENCE=forward-proxy

# Tenant B deployment
JWT_SECRET=shared_secret_at_least_32_characters
JWT_ISSUER=tenant-b
JWT_AUDIENCE=forward-proxy
```

Each deployment will only accept tokens issued for that specific tenant.

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `JWT_SECRET` | ✅ Yes | None | Signing secret (minimum 32 chars) |
| `JWT_ISSUER` | ❌ No | None (disabled) | Expected issuer claim (`iss`) |
| `JWT_AUDIENCE` | ❌ No | None (disabled) | Expected audience claim (`aud`) |
| `JWT_ALGORITHM` | ❌ No | HS256 | HMAC algorithm (HS256/HS384/HS512) |

## Validation Logic

### When `JWT_ISSUER` is set:
```rust
// Token must have "iss" claim matching JWT_ISSUER
// Example: JWT_ISSUER="probeops" requires token to have "iss": "probeops"
```

### When `JWT_ISSUER` is NOT set:
```rust
// Issuer claim is NOT validated
// Tokens with any "iss" value (or no "iss" claim) are accepted
```

### When `JWT_AUDIENCE` is set:
```rust
// Token must have "aud" claim matching JWT_AUDIENCE
// Example: JWT_AUDIENCE="forward-proxy" requires token to have "aud": "forward-proxy"
```

### When `JWT_AUDIENCE` is NOT set:
```rust
// Audience claim is NOT validated
// Tokens with any "aud" value (or no "aud" claim) are accepted
```

## Migration Guide

### From Phase 2.0/2.1 to Phase 2.2

If you are upgrading from Phase 2.0/2.1 and want to **maintain the same security posture**:

1. **Add environment variables** to your deployment configuration:
   ```bash
   JWT_ISSUER=probeops
   JWT_AUDIENCE=forward-proxy
   ```

2. **Restart the proxy** to pick up the new configuration

3. **Verify validation** is active:
   ```bash
   # Check logs on startup
   docker logs probe-node-2-probe-node-1 2>&1 | grep -i "jwt"

   # Test with invalid token
   curl -v -x https://staging.probeops.com:443 \
     -H "Proxy-Authorization: Bearer invalid_token" \
     https://example.com
   # Should see 407 Proxy Authentication Required
   ```

### Testing Validation Behavior

**Test 1: Validate issuer/audience enforcement**
```bash
# Create token WITH correct issuer/audience
# Should succeed

# Create token WITHOUT issuer claim
# Should fail with 407 if JWT_ISSUER is set

# Create token WITH wrong issuer
# Should fail with 407 if JWT_ISSUER is set
```

**Test 2: Validate secret enforcement**
```bash
# Create token with wrong secret
# Should ALWAYS fail with 407 (secret validation is always enforced)
```

**Test 3: Validate region enforcement**
```bash
# Create token with allowed_regions: ["us-west"]
# Access probe node in us-east region
# Should fail with 407 (region validation is always enforced)
```

## Security Best Practices

1. **Always set JWT_ISSUER and JWT_AUDIENCE in production**
2. **Use strong secrets** (minimum 32 characters, random, high entropy)
3. **Rotate secrets regularly** (every 90 days recommended)
4. **Monitor authentication failures** in logs
5. **Test validation behavior** after every deployment
6. **Document your token claims** (issuer, audience, allowed_regions)

## Common Deployment Scenarios

### Scenario 1: ProbeOps Production (Recommended)
```bash
JWT_SECRET=<strong-production-secret>
JWT_ISSUER=probeops
JWT_AUDIENCE=forward-proxy
PROBE_NODE_REGION=us-east
```
**Result**: Strict validation, single-tenant, production-ready

### Scenario 2: Development/Testing
```bash
JWT_SECRET=<dev-secret-at-least-32-chars>
# JWT_ISSUER and JWT_AUDIENCE not set
PROBE_NODE_REGION=us-east
```
**Result**: Relaxed validation, easier testing, NOT production-ready

### Scenario 3: Multi-Region Deployment
```bash
# Probe Node 2 (us-east)
JWT_SECRET=<shared-secret>
JWT_ISSUER=probeops
JWT_AUDIENCE=forward-proxy
PROBE_NODE_REGION=us-east

# Probe Node 3 (eu-west)
JWT_SECRET=<shared-secret>
JWT_ISSUER=probeops
JWT_AUDIENCE=forward-proxy
PROBE_NODE_REGION=eu-west
```
**Result**: Tokens with `allowed_regions: ["us-east", "eu-west"]` work on both nodes

## Troubleshooting

### Issue: Tokens rejected with "Invalid issuer"
**Cause**: Token `iss` claim doesn't match `JWT_ISSUER` environment variable
**Solution**: Either update token to include correct issuer, or remove `JWT_ISSUER` env var

### Issue: Tokens rejected with "Invalid audience"
**Cause**: Token `aud` claim doesn't match `JWT_AUDIENCE` environment variable
**Solution**: Either update token to include correct audience, or remove `JWT_AUDIENCE` env var

### Issue: Tokens accepted with unexpected issuer/audience
**Cause**: `JWT_ISSUER` and/or `JWT_AUDIENCE` environment variables are not set
**Solution**: Set both environment variables and restart the proxy

### Issue: All tokens rejected
**Cause**: Multiple possible causes:
1. Wrong JWT_SECRET
2. Expired tokens
3. Wrong region in allowed_regions
**Solution**: Check logs for specific error message, verify token claims

## References

- Source code: `src/auth.rs:57-135` (JwtValidator implementation)
- Configuration: `src/config.rs:72-120` (Environment variable loading)
- Tests: `src/auth.rs:458-521`, `src/config.rs:274-320` (Validation behavior)
