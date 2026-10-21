# JWT Decoder and Inspector — specification

**Tagline:** Decode a JWT and read its claims and expiry in your browser, the token never leaves the page.

**Category:** Developer Tools

**Free alternative to:** jwt.io (token pasted into a third party site, ad and vendor promotion, people worry about leaking live tokens)

**Search phrases:** jwt decoder, decode jwt online, jwt.io alternative, jwt parser, jwt expiration checker, decode json web token, jwt viewer

**Allowed libraries:** none (browser APIs only)

**Published at:** https://turhe123.github.io/jwt-decoder-local/

## Acceptance checks (each must have a test)

- pasting the bundled sample token shows the header and payload as formatted JSON
- the exp claim is shown as a readable date with a label such as expired or valid for 2 hours
- entering the correct shared secret for the sample HS256 token shows signature verified
- a wrong secret shows signature invalid
- a malformed token shows a clear error naming which part is broken
- works at 390px wide

## Spec

jwt decoder and decode jwt online are among the most searched developer utilities. The incumbent is jwt.io, which also sells and promotes an identity platform. Search results and security articles repeatedly warn that many online decoders send tokens to a server and that a live token can be used to impersonate a user, so people look for something they can trust to stay local. A tool that is plainly offline answers that worry.

Our version does one job: take a JSON Web Token and show what is inside, and optionally check its signature. Features: a single input for the token, three colored sections for header, payload and signature, the header and payload shown as pretty JSON, a claims table that explains registered claims such as iss, sub, aud, exp, nbf and iat in plain words, with timestamps converted to local time and UTC, a live status chip showing not yet valid, valid or expired with a countdown, and an optional verify panel. Verification supports HS256, HS384 and HS512 with a shared secret, and RS256, RS384, RS512, ES256, ES384 with a pasted public key in PEM or a JWK. Tokens are only decoded and verified, never created.

UI: above the fold is a big paste box with a Paste from clipboard button and a Load sample button. Once something valid is pasted, the three parts appear beneath with matching colors. The verify panel is collapsed by default and says clearly that the secret stays on the device. Warnings appear for the none algorithm, for missing exp, and for tokens that look encrypted (five segments) which can only be partly shown. Copy buttons exist for each part. Keyboard: Control or Command plus V on the page focuses and pastes into the box.

Technical approach: split on dots, base64url decode each part to bytes then to UTF-8 text using TextDecoder, and parse JSON with friendly errors. Use the WebCrypto subtle API for HMAC verification, RSASSA-PKCS1-v1_5 and ECDSA, importing keys from PEM by stripping the header lines and decoding [removed], or from JWK directly. ECDSA signatures in JWT are raw r and s concatenations, which is the format WebCrypto expects, so no conversion is needed. Clear any pasted secret from memory variables after use and never write tokens to storage, local or session. No network calls at all.

Edge cases: tokens pasted with a Bearer prefix, quotes, line breaks or surrounding whitespace should be cleaned automatically. Base64url padding may be missing. Non ASCII claim values must display correctly. Numeric dates may be milliseconds by mistake, so flag values that would be far in the future. Clock skew is mentioned in a note. Mobile Safari supports the needed crypto but requires a secure context, so say so if crypto is unavailable.

Demo data: a fictional token for user maya.rivera at a made up company issuer, with role claims, an expiry two hours after issue, and the secret shown in the sample as demo-secret-not-real.
