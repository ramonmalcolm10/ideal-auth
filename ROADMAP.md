# ideal-auth — Roadmap

## Shipped

- Session auth (login, logout, check, user, id)
- Password hashing (bcrypt)
- Credential-based login (Laravel-style attempt)
- Crypto utilities (tokens, HMAC signing, AES encryption, timing-safe compare)
- Rate limiting (in-memory + custom store interface)
- Remember me (persistent / session cookies)
- Token verifier — password reset, email verification, magic links (`createTokenVerifier`)
- Build step (tsc → dist, npm publish workflow)
- Two-Factor Authentication — TOTP (RFC 6238) with `createTOTP()`, recovery codes with hashed storage

## Planned

## Recommended Third-Party

### Passkeys (WebAuthn)
Too much surface area for core (CBOR parsing, COSE keys, attestation formats). Use [@simplewebauthn/server](https://github.com/MasterKale/SimpleWebAuthn) alongside ideal-auth — verify the passkey, then `auth().login(user)`.

### Social Auth (OAuth)
Use [arctic](https://github.com/pilcrowonpaper/arctic) alongside ideal-auth — get the user from the OAuth provider, then `auth().login(user)`.
