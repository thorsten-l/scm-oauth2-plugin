# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.2] - 2026-08-17
### Security
- **Signature verification of the id token** (OIDC Core 3.1.3.7): the signature is checked against the JSON Web Key Set of the identity provider (`RS`/`PS`/`ES` families) or against the client secret (`HS` family), together with `iss`, `aud`/`azp`, `exp`/`nbf`/`iat` (60 s clock skew) and the nonce of the login. An id token which is present but invalid aborts the login. `alg: none` and unknown algorithms are rejected, and the algorithm determines the accepted key type, which rules out algorithm confusion; a `crit` header is rejected as well. New classes `TokenVerifier`, `Jws`, `JwsAlgorithm`, `JwksClient`, `JwksProvider`, `JsonWebKeys` — implemented with the crypto primitives of the JDK, so the plugin still has no runtime dependencies of its own.
- **Nonce per login**: a fresh nonce is sent with every authorization request and checked in the id token, which binds the token to that very login and makes the replay of a foreign id token useless.
- **Roles are only imported from a verified access token.** Signature, issuer and lifetime are checked; an opaque token, an invalid signature or a missing key set now means no roles instead of roles from unverified data. An anomaly of the access token costs the roles, not the login.
- **Nothing unverified is used anymore**: an id token which cannot be verified is not stored either, so the sso logout then works without `id_token_hint`. The principal of the logout is taken from the access token cookie through the `AccessTokenResolver` of the core (signature and expiry checked) instead of parsing the token payload unverified; the helper `JwtPayload` is gone.
- New configuration field `jwksUrl` for manually configured endpoints; with a discovery url the key set url and the issuer come from the document (`jwks_uri`, `issuer`).
- The mail claim is no longer written to the log: if it is not a valid mail address, the message names the user id and the length of the value instead of the address itself (finding B-02 of the compliance report).

### Added
- German translation of the documentation in [README_de.md](README_de.md), cross linked with the English [README.md](README.md).
- Package overview `de/l9g/scm/oauth2/plugin/package-info.java` describing the complete login, group synchronization and logout flow, the class map and the extension points used, as entry point for new developers.
- Class, method and field level javadoc for the whole backend, comments for the react components and a short description of the scenario covered by every test class.
- Build switch `-Pstage=release`: the generated api documentation is written to `docs/javadoc` next to the sources instead of into the build directory, so it can be committed with the release (`./gradlew javadoc -Pstage=release`, or as part of `./gradlew build -Pstage=release`). The directory is emptied before it is regenerated.
- Compliance documentation in German below `docs/`, derived from the source code: `PROZESS_BESCHREIBUNG.md` (processing operations, data categories, storage locations and retention, recipients — basis for a record of processing activities under art. 30 GDPR), `COMPLIANCE_BERICHT.md` (assessment against GDPR and the NIS2 risk management measures of art. 21(2), with 19 implemented technical measures, 2 open findings and 3 documented residual risks), `DATENSCHUTZ_FOLGEABSCHAETZUNG.md` (threshold analysis and voluntary data protection impact assessment under art. 35 GDPR with 11 assessed risks) and `SOURCECODE_STATISTIK.md` (size, test coverage, documentation ratio and dependencies, with reproducible measurement commands).

### Changed
- Plugin metadata: `author` is now `Thorsten Ludewig`.

## [1.0.1] - 2026-08-09
First released version. Authentication for SCM-Manager against an OAuth2/OIDC identity provider (developed and tested against Keycloak).

### Added
- **Authorization code flow** with PKCE (S256, RFC 7636): login endpoint `/api/v2/oauth2/auth`, callback endpoint `/api/v2/oauth2/auth/callback`, `OAuth2Realm` as shiro realm and an access token cookie issued by the core.
- **CSRF protection**: single use `state` values with a ten minute lifetime, additionally bound to the browser which started the flow through the `X-SCM-OAuth2-State` cookie (RFC 9700, section 4.7); the number of pending authorization requests is capped.
- **OIDC discovery**: all endpoints can be resolved from `.well-known/openid-configuration` (cached for one hour, invalidated when the discovery url changes); manual configuration of the single endpoints stays possible.
- **User provisioning**: username, display name and mail address are taken from the configurable userinfo claims; users are stored as external users.
- **Migration of existing users**: accounts which already exist under the same name (for example from a previous ldap authentication) are taken over including their permissions, repository ownership and api keys; attributes the identity provider does not deliver keep their stored value. Accounts which still have a local password are only taken over if `migrateLocalUsers` is enabled.
- **Group synchronization**: groups from the group claim are created if missing, memberships are added and revoked on every login, empty groups are never deleted and external groups are left untouched. Names which are invalid for SCM-Manager (for example a keycloak full group path `/developers`) are sanitized by replacing the invalid characters with `_`.
- **Realm roles from the access token**: optional import of roles from a configurable json path inside the access token (default `realm_access.roles`), for providers which do not expose roles through the userinfo endpoint.
- **Global administrator by group**: if the configured admin group (default `scmadmin`) is part of the claim, the global `*` permission is assigned on login and revoked again when the group is gone.
- **Forced single sign on**: optional filter which redirects unauthenticated browser requests to the identity provider (`forceLogin`).
- **RP-initiated logout**: optional termination of the SSO session at the identity provider (`ssoLogout`), passing `id_token_hint` and `post_logout_redirect_uri` so the provider does not ask for confirmation and returns to SCM-Manager afterwards.
- **Administration ui**: configuration page with provider name, endpoints, client credentials, claim mapping and the feature flags; the client secret is write only and stored encrypted.
- **Login ui**: "Login with &lt;provider name&gt;" button on the login page and in the primary navigation.
- REST configuration endpoint `/api/v2/oauth2/configuration` (permission `configuration:read,write:oauth2`) including OpenAPI documentation.
- Documentation in [README.md](README.md) with a complete Keycloak setup walkthrough and the sample client export `scm-server.json`.
