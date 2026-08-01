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

* **Authorization code flow** with a confidential client (client id + client secret)
* **OIDC discovery**: all endpoints can be resolved automatically from the
  `.well-known/openid-configuration` document of the IdP — alternatively all endpoints can be
  configured manually
* **Login button** on the login page: "Login with &lt;provider name&gt;", in addition to the
  conventional username/password form
* **User synchronization**: users are created as *external* users on first login; display name and
  email are updated from the configured userinfo claims on every login
* **Group synchronization**: groups from the group claim are created as SCM groups if missing and
  the user is added to/removed from them on every login — groups are never deleted
* **Administrator group**: members of a configurable group get the global administrator
  permission assigned on login (and revoked again, if the group membership is gone)
* **Force login** (optional): unauthenticated browser requests are redirected to the IdP
  automatically, conventional login is disabled
* **Full SSO logout** (optional): RP-initiated logout at the IdP with `id_token_hint` and
  `post_logout_redirect_uri`, so the complete SSO session ends without a confirmation prompt and
  the browser returns to the SCM login page

## How it works

### Login

1. The user clicks "Login with &lt;provider&gt;" (or is redirected by the force login filter) —
   `GET /api/v2/oauth2/auth?from=<original url>`
2. The plugin stores a random `state` (CSRF protection, valid once, 10 minutes) and redirects the
   browser to the authorization endpoint of the IdP
3. After authentication the IdP redirects back to the callback
   `GET /api/v2/oauth2/auth/callback?code=...&state=...`
4. The plugin validates the `state`, exchanges the authorization code for tokens at the token
   endpoint (server-to-server, `client_secret_post`) and fetches the user claims from the
   **userinfo endpoint**
5. The user is created/updated, groups and permissions are synchronized, the id token is kept in
   memory for a later SSO logout and an SCM access token cookie is issued
6. The browser is redirected to the originally requested url

> **Important:** the plugin reads all claims (username, display name, email, groups) from the
> **userinfo endpoint** — not from the access or id token. Make sure your IdP adds the claims to
> the userinfo response (in Keycloak: protocol mapper setting *Add to userinfo*).

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
| Provider name | `providerName` | — | Display name of the IdP, shown as "Login with &lt;provider name&gt;". **Required** if the plugin is enabled |
| OIDC Discovery URL | `discoveryUrl` | — | Issuer url or complete url of the `.well-known/openid-configuration` document. If set, all four endpoints below are resolved automatically (cached for one hour) and the manual entries are ignored |
| Authorization endpoint | `authorizationUrl` | — | Manual endpoint configuration (only used without discovery url) |
| Token endpoint | `tokenUrl` | — | " |
| Userinfo endpoint | `userinfoUrl` | — | " |
| End session endpoint | `endSessionUrl` | — | ", optional; only needed for `ssoLogout` |
| Client ID | `clientId` | — | Client registered at the IdP |
| Client secret | `clientSecret` | — | Secret of the (confidential) client |
| Scopes | `scopes` | `openid profile email` | Space separated list of requested scopes |
| Username claim | `usernameAttribute` | `preferred_username` | Userinfo claim used as SCM username (falls back to `sub`) |
| Display name claim | `displayNameAttribute` | `name` | Userinfo claim for the display name |
| Mail claim | `mailAttribute` | `email` | Userinfo claim for the email address (invalid addresses are ignored) |
| Group claim | `groupAttribute` | `groups` | Userinfo claim for group memberships (string or array of strings) |
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
  "forceLogin": false,
  "ssoLogout": true,
  "enabled": true
}' http://scm-server.localhost:8080/scm/api/v2/oauth2/configuration
```

`GET` on the same url returns the current configuration. Setting `enabled: true` without a
`providerName` is rejected with `400 Bad Request`.

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

Additionally the effective groups of the user are resolved directly from the claim at
authorization time (group resolver), so permissions assigned to a group name work even before the
group entity exists.

If the group claim contains the configured **administrator group** (default `scmadmin`), the user
gets the *global administrator* permission (`*`) assigned; if the group is missing, a previously
assigned permission is revoked on the next login. With a configured admin group the claim is the
single source of truth for this one permission — manually granting it to an OAuth2 user without
the group does not survive the next login. Leave the field empty to disable this mechanism.

## Keycloak example

[`scm-server.json`](scm-server.json) contains an export of a working sample client for the setup
described above (SCM-Manager reachable at `http://scm-server.localhost:8080/scm`). Import it in
the Keycloak admin console via *Clients → Import client* and regenerate the client secret —
**the secret contained in the file is a sample and must not be used in production**.

The important settings of the sample client:

* **Confidential client**: `publicClient: false`, `clientAuthenticatorType: client-secret`,
  only the standard flow (authorization code) is enabled — no implicit flow, no direct access
  grants, no service account
* **Redirect uri**: `/scm/api/v2/oauth2/auth/callback` (relative to the root url
  `http://scm-server.localhost:8080`)
* **Post logout redirect uri** (`attributes."post.logout.redirect.uris"`):
  `http://scm-server.localhost:8080/scm*` — required for the full SSO logout
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
