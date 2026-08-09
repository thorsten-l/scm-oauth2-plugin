<p align="center">
  <a href="https://scm-manager.org/">
    <img alt="SCM-Manager" src="https://download.scm-manager.org/images/logo/scm-manager_logo.png" width="500" />
  </a>
</p>
<h1 align="center">
  OAuth2/OIDC Authentication Plugin
</h1>

SSO authentication for [SCM-Manager](https://scm-manager.org/) (3.x) via OAuth2 / OpenID Connect
using the authorization code flow. Tested with [Keycloak](https://www.keycloak.org/), but works with
any spec compliant identity provider (IdP).

## Features

* **Authorization code flow** with a confidential client (client id + client secret) and
  **PKCE** (S256)
* **OIDC discovery**: all endpoints can be resolved automatically from the
  `.well-known/openid-configuration` document of the IdP — alternatively all endpoints can be
  configured manually
* **Login button** on the login page: "Login with &lt;provider name&gt;", in addition to the
  conventional username/password form
* **User synchronization**: users are created as *external* users on first login; display name and
  email are updated from the configured userinfo claims on every login
* **Migration of existing users**: an instance which already authenticates against LDAP (or any
  other source) can be switched over without losing permissions, ownership or memberships, as long
  as the IdP delivers the same user names
* **Group synchronization**: groups from the group claim are created as SCM groups if missing and
  the user is added to/removed from them on every login — groups are never deleted
* **Roles from the access token** (optional): read additional roles from a configurable JSON path
  inside the access token, e.g. the Keycloak realm roles at `realm_access.roles`
* **Administrator group**: members of a configurable group get the global administrator
  permission assigned on login (and revoked again, if the group membership is gone)
* **Force login** (optional): unauthenticated browser requests are redirected to the IdP
  automatically, conventional login is disabled
* **Full SSO logout** (optional): RP-initiated logout at the IdP with `id_token_hint` and
  `post_logout_redirect_uri`, so the complete SSO session ends without a confirmation prompt and
  the browser returns to the SCM login page
* The client secret is stored **encrypted** and is never returned by the API

## How it works

### Login

1. The user clicks "Login with &lt;provider&gt;" (or is redirected by the force login filter) —
   `GET /api/v2/oauth2/auth?from=<original url>`
2. The plugin creates a random `state` (CSRF protection, valid once, 10 minutes) plus a PKCE
   verifier, stores the `state` in an `HttpOnly` cookie of this browser and redirects to the
   authorization endpoint of the IdP (with `code_challenge`, if the IdP supports S256)
3. After authentication the IdP redirects back to the callback
   `GET /api/v2/oauth2/auth/callback?code=...&state=...`
4. The plugin checks that the `state` belongs to the state cookie of this browser, exchanges the
   authorization code for tokens at the token endpoint (server-to-server, `client_secret_post`,
   with `code_verifier`) and fetches the user claims from the **userinfo endpoint**
5. The user is created/updated/migrated, groups and permissions are synchronized, the id token is
   kept in memory for a later SSO logout and an SCM access token cookie is issued
6. The browser is redirected to the originally requested url

> **Important:** the plugin reads the claims (username, display name, email, groups) from the
> **userinfo endpoint** — not from the access or id token. Make sure your IdP adds the claims to
> the userinfo response (in Keycloak: protocol mapper setting *Add to userinfo*). The only
> exception is the optional [role import](#roles-from-the-access-token) from the access token.

### Logout (optional, `ssoLogout`)

On logout SCM-Manager redirects the browser to the end session endpoint of the IdP with:

* `id_token_hint` — the id token of the login (kept in memory per user, consumed on logout), so
  the IdP can end the matching SSO session without asking for confirmation
* `client_id`
* `post_logout_redirect_uri` — the SCM-Manager base url, so the browser returns to the SCM login
  page afterwards; **must be registered at the IdP client** as a valid post logout redirect uri

If the id token is not available (e.g. after a server restart), the logout still works — the IdP
may then show a confirmation page.

## Configuration

Administration → Settings → OAuth2 / OIDC, or via REST (see below).

| Setting | Key | Default | Description |
|---|---|---|---|
| Enabled | `enabled` | `false` | Master switch for the plugin |
| Force login | `forceLogin` | `false` | Redirect unauthenticated browsers to the IdP automatically; conventional login is no longer possible |
| Full SSO logout | `ssoLogout` | `false` | RP-initiated logout at the IdP (see above) |
| Take over local accounts | `migrateLocalUsers` | `false` | Allows the IdP to take over accounts which still have a local password, see [Migration of existing users](#migration-of-existing-users) |
| Provider name | `providerName` | — | Display name of the IdP, shown as "Login with &lt;provider name&gt;". **Required** if the plugin is enabled |
| OIDC Discovery URL | `discoveryUrl` | — | Issuer url or complete url of the `.well-known/openid-configuration` document. If set, all four endpoints below are resolved automatically (cached for one hour) and the manual entries are ignored |
| Authorization endpoint | `authorizationUrl` | — | Manual endpoint configuration (only used without discovery url) |
| Token endpoint | `tokenUrl` | — | " |
| Userinfo endpoint | `userinfoUrl` | — | " |
| End session endpoint | `endSessionUrl` | — | ", optional; only needed for `ssoLogout` |
| Client ID | `clientId` | — | Client registered at the IdP |
| Client secret | `clientSecret` | — | Secret of the (confidential) client. Stored encrypted, never returned by `GET`; send an empty value on update to keep the stored secret (the read-only flag `clientSecretSet` tells whether one is stored) |
| Scopes | `scopes` | `openid profile email` | Space separated list of requested scopes |
| Username claim | `usernameAttribute` | `preferred_username` | Userinfo claim used as SCM username (falls back to `sub`) |
| Display name claim | `displayNameAttribute` | `name` | Userinfo claim for the display name |
| Mail claim | `mailAttribute` | `email` | Userinfo claim for the email address (invalid addresses are ignored) |
| Group claim | `groupAttribute` | `groups` | Userinfo claim for group memberships (string or array of strings) |
| Import realm roles from access token | `importRealmRoles` | `false` | Additionally read roles from the access token, see below |
| JSON path of the roles | `realmRolesPath` | `realm_access.roles` | Path to the roles inside the access token, field names separated by dots |
| Administrator group | `adminGroup` | `scmadmin` | Members of this group get the global administrator permission on login, non-members get it revoked. Empty = permissions are never touched |

### Redirect URI

Register the following redirect uri at the IdP client:

    <scm-base-url>/api/v2/oauth2/auth/callback

e.g. `http://scm-server.localhost:8080/scm/api/v2/oauth2/auth/callback`. For the SSO logout the
SCM base url (e.g. `http://scm-server.localhost:8080/scm`) has to be registered as valid **post
logout redirect uri** additionally.

### Configuration via REST

```bash
curl -u "scmadmin:secret" -H "Content-Type: application/vnd.scmm-oauth2Config+json;v=2" -XPUT -d '{
  "providerName": "Sonia",
  "discoveryUrl": "https://id.dev.sonia.de/realms/sonia",
  "clientId": "scm-server",
  "clientSecret": "<secret>",
  "scopes": "openid profile email",
  "usernameAttribute": "preferred_username",
  "displayNameAttribute": "name",
  "mailAttribute": "email",
  "groupAttribute": "groups",
  "adminGroup": "scmadmin",
  "importRealmRoles": false,
  "realmRolesPath": "realm_access.roles",
  "migrateLocalUsers": false,
  "forceLogin": false,
  "ssoLogout": true,
  "enabled": true
}' http://scm-server.localhost:8080/scm/api/v2/oauth2/configuration
```

`GET` on the same url returns the current configuration. Setting `enabled: true` without a
`providerName` is rejected with `400 Bad Request`.

## Migration of existing users

Users are identified by the username claim, so an instance which already
authenticates against another source (e.g. LDAP) can be switched to OAuth2
without losing anything, as long as the identity provider delivers the **same
user names**. On the first OAuth2 login the existing account is reused, which
keeps everything that is bound to the user name:

* assigned permissions and repository ownership
* group memberships (existing memberships are never removed on the first login,
  because the plugin only removes a user from groups which it added itself in a
  previous login)
* api keys and public keys

Attributes which the identity provider does **not** deliver keep their stored
value — a missing mail claim does not wipe the mail address of a migrated user.
The stored `active` flag is preserved as well, so a deactivated account is not
reactivated by a login.

Accounts which can still be used for a **local password login** are not taken
over by default: the login is rejected with a warning in the log, because
otherwise a user of the identity provider could seize a local account (e.g. the
initial `scmadmin`) just by using its name. Users of other external
authentications (LDAP, CAS) have no local password and are migrated silently.
To migrate local accounts as well, enable *Take over local accounts*
(`migrateLocalUsers`) — their local password is removed in that case, because
the account is authenticated by the identity provider from then on.

To check upfront how an existing user is stored:

```bash
curl -u "scmadmin:secret" https://scm.example.com/scm/api/v2/users/<username> | grep -o '"external":[a-z]*'
```

## Group and permission synchronization

On **every** login the group claim is compared with the state of the previous login:

* Groups from the claim which do not exist in SCM-Manager yet are **created** (internal groups,
  description "Synchronized by scm-oauth2-plugin") with the user as first member
* The user is **added** as member to existing groups from the claim
* The user is **removed** from groups which were synchronized on a previous login but are no
  longer part of the claim
* Groups are **never deleted**, even if they become empty
* Memberships which were assigned manually in other groups are **not** touched — only groups
  that came from the claim of this user are considered for removal
* *External* groups are skipped, their members are not managed by SCM-Manager
* A failure while synchronizing a group never prevents the login itself

Characters which SCM-Manager does not allow in a name (`/ : ? # ; & = % \`, a leading `@` and
leading/trailing whitespace) are **replaced by an underscore**, so no group is lost. A Keycloak
group mapper with *Full group path* enabled therefore results in:

| Claim | SCM group |
|---|---|
| `/developers` | `_developers` |
| `/team/backend` | `_team_backend` |
| `SCM RZ-intern` | `SCM RZ-intern` (unchanged, internal blanks are allowed) |

The sanitized name is used consistently — for the created group, for the membership and for the
authorization — so permissions granted to the group really apply. Keep that in mind for the
**administrator group**: if the identity provider sends `/scmadmin`, the setting has to be
`_scmadmin`. Two claim values which only differ in invalid characters (`a/b` and `a:b`) end up in
the same SCM group.

Additionally the effective groups of the user are resolved directly from the claim at
authorization time (group resolver), so permissions assigned to a group name work even before the
group entity exists.

### Roles from the access token

Some identity providers deliver roles only in the access token and not in the
userinfo response — Keycloak realm roles are the typical example. With
*Import realm roles from access token* (`importRealmRoles`) these roles are read
from the token and **added** to the groups of the userinfo response. The
location is configured as a dot separated path (`realmRolesPath`):

| Path | Reads |
|---|---|
| `realm_access.roles` | Keycloak realm roles (default) |
| `resource_access.<client-id>.roles` | Keycloak client roles of that client |
| `groups` | a top level claim of the token |

The path may also contain array indexes (`realm_access.roles.0`). Both arrays
and single string values are accepted. If the access token is not a JWT (some
providers issue opaque tokens) or the path does not exist, no roles are
imported and the login continues normally.

The signature of the access token is not verified for this, which is safe
because the token was received directly from the token endpoint of the
configured identity provider over TLS — the same trust level as the userinfo
response.

> **Note:** every imported role becomes an SCM group (see below). Keycloak realm
> roles often include many technical roles (`offline_access`,
> `uma_authorization`, `default-roles-<realm>`, …), so the group list can grow
> considerably. If only a few roles are relevant, a client role mapper with
> `resource_access.<client-id>.roles` is the more targeted choice.

If the group claim contains the configured **administrator group** (default `scmadmin`), the user
gets the *global administrator* permission (`*`) assigned; if the group is missing, a previously
assigned permission is revoked on the next login. With a configured admin group the claim is the
single source of truth for this one permission — manually granting it to an OAuth2 user without
the group does not survive the next login. Leave the field empty to disable this mechanism.

## Security notes

The plugin implements the current recommendations for the authorization code flow
(RFC 6749/9700):

* the `state` is bound to the browser which started the flow via an `HttpOnly`, `SameSite=Lax`
  cookie (`Secure` as soon as the instance runs on HTTPS), so an authorization code of a foreign
  session cannot be replayed into somebody else's browser
* **PKCE** with S256; the verifier never leaves the server. It is omitted only if the discovery
  document explicitly advertises no support for it
* the client secret is stored encrypted and is write-only in the API
* only absolute `http`/`https` urls are accepted as endpoints
* the forced login only lets requests pass whose access token cookie can actually be validated
  (signature, expiry)
* error details of the identity provider are written to the log only, never into the response

Two points to keep in mind when operating the plugin:

* **Whoever controls the group names in the IdP controls the permissions in SCM-Manager** — the
  claim decides about group memberships and, via the administrator group, about global admin
  rights. Groups/roles should therefore be maintained by IdP administrators only (Keycloak client
  roles are a good fit).
* **The permission `configuration:write:oauth2` has to be treated like global admin**: whoever may
  change the configuration can point the endpoints at a different host and thereby both receive the
  client secret and take over the authentication completely.

Run the instance behind TLS — the client secret is transmitted in the body when the configuration
is saved, and the session cookie is only marked `Secure` on an HTTPS connection.

## Keycloak example

[`scm-server.json`](scm-server.json) contains an export of a working sample client for the setup
described above (SCM-Manager reachable at `http://scm-server.localhost:8080/scm`). Import it in
the Keycloak admin console via *Clients → Import client* and generate a client secret afterwards —
the file contains the placeholder `GENERATE_YOUR_OWN_SECRET_IN_KEYCLOAK` instead of a real secret.

The important settings of the sample client:

* **Confidential client**: `publicClient: false`, `clientAuthenticatorType: client-secret`,
  only the standard flow (authorization code) is enabled — no implicit flow, no direct access
  grants, no service account
* **Redirect uri**: `/scm/api/v2/oauth2/auth/callback` (relative to the root url
  `http://scm-server.localhost:8080`)
* **Post logout redirect uri** (`attributes."post.logout.redirect.uris"`):
  `http://scm-server.localhost:8080/scm` — required for the full SSO logout (adjust it to your
  base url; avoid wildcards in production)
* **Logout confirmation disabled** (`attributes."logout.confirmation.enabled": "false"`), so the
  RP-initiated logout runs without user interaction
* **Groups claim via client roles**: the protocol mapper `client roles`
  (`oidc-usermodel-client-role-mapper`) maps the **client roles of `scm-server`** to the claim
  `groups` — with `"userinfo.token.claim": "true"`, which is essential because the plugin reads
  the claims from the userinfo endpoint
* **Scopes**: `profile` is a default scope, `email` an optional one — the plugin requests
  `openid profile email`, so the email claim is delivered if the email scope is granted

With this mapper setup, SCM groups are managed as **Keycloak client roles** of the `scm-server`
client:

1. Keycloak → Clients → `scm-server` → *Roles* → create role, e.g. `scmadmin` or `developers`
2. Assign the role to users (Users → *Role mapping* → Assign role → filter by client)
3. On the next SCM login the role shows up in the `groups` claim, the corresponding SCM group is
   created/updated and — in case of `scmadmin` — the global administrator permission is assigned

Alternatively a Keycloak *Group Membership* mapper (claim `groups`, *Add to userinfo* enabled,
*Full group path* disabled) can be used to map real Keycloak groups instead of client roles.

## Build and testing

The plugin can be compiled and packaged with the following tasks:

* clean - `gradle clean` - deletes the build directory
* run - `gradle run` - starts an SCM-Manager with the plugin pre-installed and with livereload for the ui
* build - `gradle build` - executes all checks, tests and builds the smp inclusive javadoc and source jar
* test - `gradle test` - run all java tests
* ui-test - `gradle ui-test` - run all ui tests
* check - `gradle check` - executes all registered checks and tests (java and ui)
* fix - `gradle fix` - fixes all fixable findings of the check task
* smp - `gradle smp` - Builds the smp file, without the execution of checks and tests

For the development and testing the `run` task of the plugin can be used:

* run - `gradle run` - starts scm-manager with the plugin pre-installed.

If the plugin was started with `gradle run`, the default browser of the os should be automatically opened.
If the browser does not start automatically, start it manually and go to [http://localhost:8081/scm](http://localhost:8081/scm).

In this mode each change to web files (src/main/js or src/main/webapp), should trigger reload of the browser with the made changes.

## Directory & File structure

A quick look at the files and directories you'll see in an SCM-Manager project.

    .
    ├── node_modules/
    ├── src/
    |   ├── main/
    |   |   ├── java/
    |   |   ├── js/
    |   |   └── resources/
    |   └── test/
    |       ├── java/
    |       └── resources/
    ├── .editorconfig
    ├── .gitignore
    ├── build.gradle
    ├── CHANGELOG.md
    ├── gradle.properties
    ├── gradlew
    ├── LICENSE.txt
    ├── package.json
    ├── README.md
    ├── scm-server.json
    ├── settings.gradle
    ├── tsconfig.json
    └── yarn.lock

1.  **`node_modules/`**: This directory contains all modules of code that your project depends on (npm packages) are automatically installed.

2.  **`src/`**: This directory will contain all code related to what you see or not. `src` is a convention for “source code”.
    1. **`main/`**
        1. **`java/`**: This directory contains the Java code.
        2. **`js/`**: This directory contains the JavaScript code for the web ui, inclusive unit tests: suffixed with `.test.ts`
        3. **`resources/`**: This directory contains the classpath resources.
    2. **`test/`**
        1. **`java/`**: This directory contains the Java unit tests.
        2. **`resources/`**: This directory contains classpath resources for unit tests.

3.  **`.editorconfig`**: This is a configuration file for your editor using [EditorConfig](https://editorconfig.org/). The file specifies a style that IDEs use for code.

4.  **`.gitignore`**: This file tells git which files it should not track / not maintain a version history for.

5.  **`build.gradle`**: Gradle build configuration, which also includes things like metadata.

6.  **`CHANGELOG.md`**: All notable changes to this project will be documented in this file.

7.  **`gradle.properties`**: Defines the module version.

8.  **`gradlew`**: Bundled gradle wrapper if you don't have gradle installed.

9.  **`LICENSE.txt`**: This project is licensed under AGPLv3.

10.  **`package.json`**: Here you can find the dependency/build configuration and dependencies for the frontend.

11.  **`README.md`**: This file, containing useful reference information about the project.

12.  **`scm-server.json`**: Export of the Keycloak sample client (see [Keycloak example](#keycloak-example)).

13.  **`settings.gradle`**: Gradle settings configuration.

14. **`tsconfig.json`** This is the typescript configuration file.

15. **`yarn.lock`**: This is the ui dependency configuration.

## Need help?

Looking for more guidance? Full documentation lives on the SCM-Manager [homepage](https://scm-manager.org/docs/) or the dedicated pages for the [plugins](https://scm-manager.org/plugins/).
