<p align="center">
  <a href="https://scm-manager.org/">
    <img alt="SCM-Manager" src="https://download.scm-manager.org/images/logo/scm-manager_logo.png" width="500" />
  </a>
</p>
<h1 align="center">
  OAuth2/OIDC Authentication Plugin
</h1>

*[English version](README.md)*

SSO-Authentifizierung für [SCM-Manager](https://scm-manager.org/) (3.x) über OAuth2 / OpenID
Connect mit dem Authorization Code Flow. Getestet mit [Keycloak](https://www.keycloak.org/),
funktioniert aber mit jedem spezifikationskonformen Identity Provider (IdP).

## Funktionen

* **Authorization Code Flow** mit einem vertraulichen Client (Client ID + Client Secret) und
  **PKCE** (S256)
* **OIDC Discovery**: Alle Endpunkte können automatisch aus dem
  `.well-known/openid-configuration`-Dokument des IdP bezogen werden — alternativ lassen sich alle
  Endpunkte manuell konfigurieren
* **Login-Schaltfläche** auf der Anmeldeseite: „Anmelden mit &lt;Provider-Name&gt;", zusätzlich zum
  gewohnten Formular für Benutzername und Passwort
* **Benutzer-Synchronisation**: Benutzer werden bei der ersten Anmeldung als *externe* Benutzer
  angelegt; Anzeigename und E-Mail werden bei jeder Anmeldung aus den konfigurierten
  Userinfo-Claims aktualisiert
* **Migration bestehender Benutzer**: Eine Instanz, die sich bereits gegen LDAP (oder eine andere
  Quelle) authentifiziert, kann ohne Verlust von Berechtigungen, Eigentümerschaften oder
  Mitgliedschaften umgestellt werden, solange der IdP dieselben Benutzernamen liefert
* **Gruppen-Synchronisation**: Gruppen aus dem Gruppen-Claim werden als SCM-Gruppen angelegt, falls
  sie fehlen, und die Mitgliedschaft wird bei jeder Anmeldung gepflegt — Gruppen werden nie gelöscht
* **Rollen aus dem Access Token** (optional): zusätzliche Rollen aus einem konfigurierbaren
  JSON-Pfad im Access Token lesen, z. B. die Keycloak-Realm-Rollen unter `realm_access.roles`
* **Administrator-Gruppe**: Mitglieder einer konfigurierbaren Gruppe erhalten bei der Anmeldung die
  globale Administrator-Berechtigung (und verlieren sie wieder, wenn die Mitgliedschaft entfällt)
* **Login erzwingen** (optional): Nicht angemeldete Browser-Anfragen werden automatisch zum IdP
  weitergeleitet, die konventionelle Anmeldung ist deaktiviert
* **Vollständiger SSO-Logout** (optional): RP-initiated Logout beim IdP mit `id_token_hint` und
  `post_logout_redirect_uri`, sodass die komplette SSO-Sitzung ohne Rückfrage endet und der Browser
  zur SCM-Anmeldeseite zurückkehrt
* **Geprüfte Tokens**: Signatur- und Claim-Prüfung von ID Token und Access Token gegen den JSON Web
  Key Set des IdP, inklusive Nonce je Anmeldung
* Das Client Secret wird **verschlüsselt** gespeichert und von der API nie zurückgegeben

## Installation

Das Plugin ist nicht Teil des offiziellen Plugin Centers und wird daher manuell installiert. Es
setzt **SCM-Manager 3.9.0 oder neuer** voraus.

1. `scm-oauth2-plugin.smp` von der
   [Releases-Seite](https://github.com/thorsten-l/scm-oauth2-plugin/releases) herunterladen
2. Die Datei in das Verzeichnis `plugins` des SCM-Manager-Home kopieren, z. B.

   ```bash
   cp scm-oauth2-plugin.smp /var/lib/scm/plugins/
   ```

3. SCM-Manager neu starten. Das Archiv wird beim Start entpackt — danach existiert das Verzeichnis
   `plugins/scm-oauth2-plugin/` und die `.smp`-Datei ist verschwunden, das ist so gewollt.
4. Installation prüfen unter *Administration → Plugins → Installiert* oder per REST:

   ```bash
   curl -u "scmadmin:secret" http://localhost:8080/scm/api/v2/plugins/installed \
     | grep -o '"name":"scm-oauth2-plugin","version":"[^"]*"'
   ```

Anschließend das Plugin wie unter [Konfiguration](#konfiguration) beschrieben einrichten.

### Home-Verzeichnis finden

Das Home-Verzeichnis ist jenes, das `config/`, `repositories/` und `plugins/` enthält. Verlässlich
findet man es über den Log-Eintrag, der bei jedem Start geschrieben wird:

```bash
grep "scm home directory" /var/log/scm/scm-manager.log
# using directory /var/lib/scm as scm home directory
```

Übliche Standardpfade, sofern sie nicht über die Umgebungsvariable `SCM_HOME` oder die
System-Property `scm.home` überschrieben werden:

| Installation | Home-Verzeichnis |
|---|---|
| Linux-Paket / Docker | `/var/lib/scm` |
| macOS | `~/Library/Application Support/SCM-Manager` |
| Windows | `%APPDATA%\SCM-Manager` |

### Update

Da das Archiv entpackt wird, muss eine alte Version zuerst entfernt werden, sonst bleibt das
bisherige Plugin-Verzeichnis bestehen:

```bash
# SCM-Manager zuerst stoppen
rm -rf /var/lib/scm/plugins/scm-oauth2-plugin
cp scm-oauth2-plugin.smp /var/lib/scm/plugins/
# SCM-Manager starten
```

Die Konfiguration liegt in `config/oauth2.xml` und übersteht ein Update. Zum Deinstallieren das
Plugin-Verzeichnis löschen und neu starten.

## Funktionsweise

### Anmeldung

1. Der Benutzer klickt auf „Anmelden mit &lt;Provider&gt;" (oder wird vom Force-Login-Filter
   weitergeleitet) — `GET /api/v2/oauth2/auth?from=<ursprüngliche URL>`
2. Das Plugin erzeugt einen zufälligen `state` (CSRF-Schutz, einmalig gültig, 10 Minuten), einen
   PKCE-Verifier und einen Nonce, legt den `state` in einem `HttpOnly`-Cookie dieses Browsers ab und
   leitet zum Authorization Endpoint des IdP weiter (mit `code_challenge`, sofern der IdP S256
   unterstützt)
3. Nach der Authentifizierung leitet der IdP zurück zum Callback
   `GET /api/v2/oauth2/auth/callback?code=...&state=...`
4. Das Plugin prüft, ob der `state` zum State-Cookie dieses Browsers gehört, tauscht den
   Authorization Code am Token Endpoint gegen Tokens (Server-zu-Server, `client_secret_post`, mit
   `code_verifier`), **prüft das ID Token** (Signatur, Aussteller, Audience, Laufzeit, Nonce) und
   holt die Benutzer-Claims vom **Userinfo Endpoint**
5. Der Benutzer wird angelegt/aktualisiert/migriert, Gruppen und Berechtigungen werden
   synchronisiert, das ID-Token wird für einen späteren SSO-Logout im Speicher gehalten und ein
   SCM-Access-Token-Cookie wird ausgestellt
6. Der Browser wird auf die ursprünglich angeforderte URL weitergeleitet

> **Wichtig:** Das Plugin liest die Claims (Benutzername, Anzeigename, E-Mail, Gruppen) vom
> **Userinfo Endpoint** — nicht aus dem Access oder ID Token. Der IdP muss die Claims also in die
> Userinfo-Antwort aufnehmen (in Keycloak: Protocol-Mapper-Einstellung *Add to userinfo*). Einzige
> Ausnahme ist der optionale [Rollen-Import](#rollen-aus-dem-access-token) aus dem Access Token.

### Abmeldung (optional, `ssoLogout`)

Beim Abmelden leitet der SCM-Manager den Browser zum End Session Endpoint des IdP weiter, mit:

* `id_token_hint` — das ID-Token der Anmeldung (pro Benutzer im Speicher gehalten, beim Logout
  verbraucht), damit der IdP die zugehörige SSO-Sitzung ohne Rückfrage beenden kann
* `client_id`
* `post_logout_redirect_uri` — die SCM-Manager-Basis-URL, damit der Browser anschließend zur
  SCM-Anmeldeseite zurückkehrt; **muss beim IdP-Client** als gültige Post-Logout-Redirect-URI
  hinterlegt sein

Ist das ID-Token nicht verfügbar (z. B. nach einem Server-Neustart), funktioniert der Logout
weiterhin — der IdP zeigt dann gegebenenfalls eine Bestätigungsseite.

## Konfiguration

Administration → Einstellungen → OAuth2 / OIDC, oder per REST (siehe unten).

| Einstellung | Schlüssel | Standard | Beschreibung |
|---|---|---|---|
| Aktiviert | `enabled` | `false` | Hauptschalter für das Plugin |
| Login erzwingen | `forceLogin` | `false` | Leitet nicht angemeldete Browser automatisch zum IdP; die konventionelle Anmeldung ist dann nicht mehr möglich |
| Vollständiger SSO-Logout | `ssoLogout` | `false` | RP-initiated Logout beim IdP (siehe oben) |
| Lokale Konten übernehmen | `migrateLocalUsers` | `false` | Erlaubt dem IdP, Konten mit lokalem Passwort zu übernehmen, siehe [Migration bestehender Benutzer](#migration-bestehender-benutzer) |
| Provider-Name | `providerName` | — | Anzeigename des IdP, erscheint als „Anmelden mit &lt;Provider-Name&gt;". **Pflichtfeld**, wenn das Plugin aktiviert ist |
| OIDC Discovery URL | `discoveryUrl` | — | Issuer-URL oder vollständige URL des `.well-known/openid-configuration`-Dokuments. Wenn gesetzt, werden die vier folgenden Endpunkte automatisch bezogen (eine Stunde gecacht) und die manuellen Einträge ignoriert |
| Authorization Endpoint | `authorizationUrl` | — | Manuelle Endpunkt-Konfiguration (nur ohne Discovery URL genutzt) |
| Token Endpoint | `tokenUrl` | — | " |
| Userinfo Endpoint | `userinfoUrl` | — | " |
| End Session Endpoint | `endSessionUrl` | — | ", optional; nur für `ssoLogout` nötig |
| JWKS Endpoint | `jwksUrl` | — | ", öffentliche Schlüssel zur Prüfung der Signaturen von ID Token und Access Token. Ohne ihn (und ohne Discovery URL) wird kein Token geprüft und keines verwendet |
| Client ID | `clientId` | — | Der beim IdP registrierte Client |
| Client Secret | `clientSecret` | — | Secret des (vertraulichen) Clients. Verschlüsselt gespeichert, wird von `GET` nie zurückgegeben; beim Aktualisieren einen leeren Wert senden, um das gespeicherte Secret beizubehalten (das schreibgeschützte Feld `clientSecretSet` zeigt an, ob eines hinterlegt ist) |
| Scopes | `scopes` | `openid profile email` | Durch Leerzeichen getrennte Liste der angeforderten Scopes |
| Benutzername-Claim | `usernameAttribute` | `preferred_username` | Userinfo-Claim für den SCM-Benutzernamen (Fallback: `sub`) |
| Anzeigename-Claim | `displayNameAttribute` | `name` | Userinfo-Claim für den Anzeigenamen |
| E-Mail-Claim | `mailAttribute` | `email` | Userinfo-Claim für die E-Mail-Adresse (ungültige Adressen werden ignoriert) |
| Gruppen-Claim | `groupAttribute` | `groups` | Userinfo-Claim für Gruppenzugehörigkeiten (String oder Array von Strings) |
| Realm-Rollen aus Access Token importieren | `importRealmRoles` | `false` | Liest zusätzlich Rollen aus dem Access Token, siehe unten |
| JSON-Pfad der Rollen | `realmRolesPath` | `realm_access.roles` | Pfad zu den Rollen im Access Token, Feldnamen durch Punkte getrennt |
| Administrator-Gruppe | `adminGroup` | `scmadmin` | Mitglieder dieser Gruppe erhalten bei der Anmeldung die globale Administrator-Berechtigung, Nicht-Mitglieder verlieren sie. Leer = Berechtigungen werden nie angefasst |

### Redirect URI

Beim IdP-Client ist folgende Redirect URI zu hinterlegen:

    <scm-basis-url>/api/v2/oauth2/auth/callback

z. B. `http://scm-server.localhost:8080/scm/api/v2/oauth2/auth/callback`. Für den SSO-Logout muss
zusätzlich die SCM-Basis-URL (z. B. `http://scm-server.localhost:8080/scm`) als gültige
**Post-Logout-Redirect-URI** eingetragen werden.

### Konfiguration per REST

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

`GET` auf dieselbe URL liefert die aktuelle Konfiguration. Ein `enabled: true` ohne `providerName`
wird mit `400 Bad Request` abgelehnt.

## Migration bestehender Benutzer

Benutzer werden über den Benutzername-Claim identifiziert. Eine Instanz, die sich bereits gegen
eine andere Quelle (z. B. LDAP) authentifiziert, kann daher ohne Verluste auf OAuth2 umgestellt
werden, solange der Identity Provider die **gleichen Benutzernamen** liefert. Bei der ersten
OAuth2-Anmeldung wird das bestehende Konto weiterverwendet, wodurch alles erhalten bleibt, was am
Benutzernamen hängt:

* zugewiesene Berechtigungen und Repository-Eigentümerschaften
* Gruppenmitgliedschaften (bestehende Mitgliedschaften werden bei der ersten Anmeldung nie
  entfernt, da das Plugin nur aus Gruppen entfernt, in die es den Benutzer bei einer früheren
  Anmeldung selbst aufgenommen hat)
* API-Schlüssel und öffentliche Schlüssel

Attribute, die der Identity Provider **nicht** liefert, behalten ihren gespeicherten Wert — ein
fehlender Mail-Claim löscht also nicht die E-Mail-Adresse eines migrierten Benutzers. Auch das
gespeicherte `active`-Flag bleibt erhalten, ein deaktiviertes Konto wird durch eine Anmeldung nicht
reaktiviert.

Konten, die noch für eine **lokale Passwort-Anmeldung** genutzt werden können, werden
standardmäßig nicht übernommen: Die Anmeldung wird mit einer Warnung im Log abgelehnt, da sich
sonst ein Benutzer des Identity Providers allein über den Namen ein lokales Konto (z. B. das
ursprüngliche `scmadmin`) aneignen könnte. Benutzer aus anderen externen Anmeldungen (LDAP, CAS)
haben kein lokales Passwort und werden stillschweigend migriert. Um auch lokale Konten zu
migrieren, die Option *Lokale Konten übernehmen* (`migrateLocalUsers`) aktivieren — deren lokales
Passwort wird dabei entfernt, da das Konto fortan vom Identity Provider authentifiziert wird.

Vorab prüfen, wie ein bestehender Benutzer gespeichert ist:

```bash
curl -u "scmadmin:secret" https://scm.example.com/scm/api/v2/users/<benutzername> | grep -o '"external":[a-z]*'
```

## Gruppen- und Berechtigungs-Synchronisation

Bei **jeder** Anmeldung wird der Gruppen-Claim mit dem Stand der vorherigen Anmeldung verglichen:

* Gruppen aus dem Claim, die es im SCM-Manager noch nicht gibt, werden **angelegt** (interne
  Gruppen, Beschreibung „Synchronized by scm-oauth2-plugin") mit dem Benutzer als erstem Mitglied
* Der Benutzer wird bestehenden Gruppen aus dem Claim als Mitglied **hinzugefügt**
* Der Benutzer wird aus Gruppen **entfernt**, die bei einer früheren Anmeldung synchronisiert
  wurden, aber nicht mehr Teil des Claims sind
* Gruppen werden **nie gelöscht**, auch wenn sie leer werden
* Manuell vergebene Mitgliedschaften in anderen Gruppen bleiben **unberührt** — nur Gruppen, die
  aus dem Claim dieses Benutzers stammen, kommen für ein Entfernen in Frage
* *Externe* Gruppen werden übersprungen, ihre Mitglieder verwaltet der SCM-Manager nicht
* Ein Fehler beim Synchronisieren einer Gruppe verhindert nie die Anmeldung selbst

Zeichen, die der SCM-Manager in einem Namen nicht erlaubt (`/ : ? # ; & = % \`, ein führendes `@`
sowie führende/abschließende Leerzeichen), werden **durch einen Unterstrich ersetzt**, sodass keine
Gruppe verloren geht. Ein Keycloak-Gruppen-Mapper mit aktiviertem *Full group path* führt daher zu:

| Claim | SCM-Gruppe |
|---|---|
| `/developers` | `_developers` |
| `/team/backend` | `_team_backend` |
| `SCM RZ-intern` | `SCM RZ-intern` (unverändert, Leerzeichen im Inneren sind erlaubt) |

Der bereinigte Name wird durchgängig verwendet — für die angelegte Gruppe, für die Mitgliedschaft
und für die Autorisierung — damit Berechtigungen auf der Gruppe auch wirklich greifen. Das ist bei
der **Administrator-Gruppe** zu beachten: Sendet der Identity Provider `/scmadmin`, muss die
Einstellung `_scmadmin` lauten. Zwei Claim-Werte, die sich nur in ungültigen Zeichen unterscheiden
(`a/b` und `a:b`), landen in derselben SCM-Gruppe.

Zusätzlich werden die effektiven Gruppen des Benutzers zur Autorisierungszeit direkt aus dem Claim
aufgelöst (Group Resolver), sodass Berechtigungen auf einen Gruppennamen schon greifen, bevor die
Gruppe als Objekt existiert.

### Rollen aus dem Access Token

Manche Identity Provider liefern Rollen ausschließlich im Access Token und nicht in der
Userinfo-Antwort — Keycloak-Realm-Rollen sind das typische Beispiel. Mit *Realm-Rollen aus Access
Token importieren* (`importRealmRoles`) werden diese Rollen aus dem Token gelesen und zu den
Gruppen der Userinfo-Antwort **hinzugefügt**. Die Stelle wird als punktgetrennter Pfad
konfiguriert (`realmRolesPath`):

| Pfad | Liest |
|---|---|
| `realm_access.roles` | Keycloak-Realm-Rollen (Standard) |
| `resource_access.<client-id>.roles` | Keycloak-Client-Rollen dieses Clients |
| `groups` | einen Claim auf oberster Ebene des Tokens |

Der Pfad darf auch Array-Indizes enthalten (`realm_access.roles.0`). Sowohl Arrays als auch
einzelne Zeichenketten werden akzeptiert. Ist das Access Token kein JWT (manche Provider stellen
opake Tokens aus) oder existiert der Pfad nicht, werden keine Rollen importiert und die Anmeldung
läuft normal weiter.

Die Signatur des Access Tokens wird dabei nicht geprüft. Das ist unbedenklich, da das Token per TLS
direkt vom Token Endpoint des konfigurierten Identity Providers stammt — dieselbe
Vertrauensstellung wie die Userinfo-Antwort.

> **Hinweis:** Jede importierte Rolle wird zu einer SCM-Gruppe (siehe oben). Keycloak-Realm-Rollen
> enthalten häufig viele technische Rollen (`offline_access`, `uma_authorization`,
> `default-roles-<realm>`, …), wodurch die Gruppenliste deutlich anwachsen kann. Wenn nur wenige
> Rollen relevant sind, ist ein Client-Rollen-Mapper mit `resource_access.<client-id>.roles` die
> gezieltere Wahl.

Enthält der Gruppen-Claim die konfigurierte **Administrator-Gruppe** (Standard `scmadmin`), erhält
der Benutzer die Berechtigung *Globaler Administrator* (`*`); fehlt die Gruppe, wird eine zuvor
erteilte Berechtigung bei der nächsten Anmeldung wieder entzogen. Bei konfigurierter
Administrator-Gruppe ist der Claim die alleinige Quelle der Wahrheit für genau diese Berechtigung —
eine manuelle Vergabe an einen OAuth2-Benutzer ohne die Gruppe übersteht die nächste Anmeldung
nicht. Das Feld leer lassen, um diesen Mechanismus abzuschalten.

## Sicherheitshinweise

Das Plugin setzt die aktuellen Empfehlungen für den Authorization Code Flow um
(RFC 6749/9700):

* Der `state` ist über ein `HttpOnly`-Cookie mit `SameSite=Lax` an den Browser gebunden, der den
  Flow gestartet hat (`Secure`, sobald die Instanz über HTTPS läuft). Ein Authorization Code einer
  fremden Sitzung kann so nicht in den Browser eines anderen eingespielt werden
* **PKCE** mit S256; der Verifier verlässt den Server nie. Er entfällt nur, wenn das
  Discovery-Dokument ausdrücklich keine Unterstützung dafür angibt
* Das **ID Token wird kryptografisch geprüft**: Signatur gegen den JSON Web Key Set des IdP
  (RS-/PS-/ES-Familie) bzw. gegen das Client Secret (HS-Familie), dazu `iss`, `aud`/`azp`, Laufzeit
  und der `nonce` genau dieser Anmeldung. `alg: none` und unbekannte Verfahren werden abgewiesen, und
  der Algorithmus bestimmt den zulässigen Schlüsseltyp (kein Algorithm Confusion). Ein vorhandenes,
  aber ungültiges ID Token bricht die Anmeldung ab
* Mit jeder Autorisierungsanfrage wird ein frischer **Nonce** gesendet, sodass ein ID Token einer
  anderen Sitzung nicht wiederverwendet werden kann
* **Rollen werden nur aus einem geprüften Access Token importiert**; ein opakes Token, eine ungültige
  Signatur oder ein fehlender Schlüsselsatz bedeuten keine Rollen statt ungeprüfter Rollen
* Das Client Secret wird verschlüsselt gespeichert und ist in der API write-only
* Als Endpunkte werden nur absolute `http`/`https`-URLs akzeptiert
* Der erzwungene Login lässt nur Anfragen passieren, deren Access-Token-Cookie tatsächlich
  validiert werden kann (Signatur, Ablauf)
* Fehlerdetails des Identity Providers landen ausschließlich im Log, nie in der Antwort

Zwei Punkte, die im Betrieb zu beachten sind:

* **Wer im IdP die Gruppennamen kontrolliert, kontrolliert die Berechtigungen im SCM-Manager** —
  der Claim entscheidet über Gruppenmitgliedschaften und, über die Administrator-Gruppe, über
  globale Admin-Rechte. Gruppen bzw. Rollen sollten daher ausschließlich von IdP-Administratoren
  gepflegt werden (Keycloak-Client-Rollen eignen sich dafür gut).
* **Die Berechtigung `configuration:write:oauth2` ist wie globaler Admin zu behandeln**: Wer die
  Konfiguration ändern darf, kann die Endpunkte auf einen anderen Host umbiegen und damit sowohl
  das Client Secret erhalten als auch die Authentifizierung vollständig übernehmen.

* **Für die Tokenprüfung ist eine Schlüsselquelle nötig.** Mit einer Discovery URL wird sie
  automatisch aus dem Dokument übernommen (`jwks_uri`). Bei manuell konfigurierten Endpunkten muss
  zusätzlich `jwksUrl` gesetzt werden — sonst protokolliert das Plugin eine Warnung, verwirft das ID
  Token (der SSO-Logout läuft dann ohne `id_token_hint`) und importiert keine Rollen aus dem Access
  Token. Wichtiger Unterschied: Eine fehlende Schlüsselquelle kostet nur das ID Token, ein
  konfigurierter Schlüsselsatz, der nicht erreichbar ist oder den Schlüssel des Tokens nicht enthält,
  lässt die Anmeldung dagegen scheitern — ein vorhandenes ID Token muss überprüfbar sein (fail
  closed). Der Schlüsselsatz wird eine Stunde gecacht und bei einem unbekannten Schlüssel neu
  geholt, eine Schlüsselrotation im IdP erfordert also kein Eingreifen.

Die Instanz sollte hinter TLS betrieben werden — beim Speichern der Konfiguration wird das Client
Secret im Body übertragen, und das Session-Cookie wird nur über eine HTTPS-Verbindung als `Secure`
markiert.

## Keycloak-Beispiel

[`scm-server.json`](scm-server.json) enthält den Export eines funktionierenden Beispiel-Clients für
das oben beschriebene Setup (SCM-Manager erreichbar unter `http://scm-server.localhost:8080/scm`).
In der Keycloak-Administrationskonsole über *Clients → Import client* importieren und anschließend
ein Client Secret erzeugen — die Datei enthält statt eines echten Secrets den Platzhalter
`GENERATE_YOUR_OWN_SECRET_IN_KEYCLOAK`.

Die wichtigen Einstellungen des Beispiel-Clients:

* **Vertraulicher Client**: `publicClient: false`, `clientAuthenticatorType: client-secret`, nur
  der Standard Flow (Authorization Code) ist aktiviert — kein Implicit Flow, keine Direct Access
  Grants, kein Service Account
* **Redirect URI**: `/scm/api/v2/oauth2/auth/callback` (relativ zur Root-URL
  `http://scm-server.localhost:8080`)
* **Post-Logout-Redirect-URI** (`attributes."post.logout.redirect.uris"`):
  `http://scm-server.localhost:8080/scm` — für den vollständigen SSO-Logout erforderlich (an die
  eigene Basis-URL anpassen; in Produktion Platzhalter vermeiden)
* **Logout-Bestätigung deaktiviert** (`attributes."logout.confirmation.enabled": "false"`), damit
  der RP-initiated Logout ohne Benutzerinteraktion abläuft
* **Gruppen-Claim über Client-Rollen**: Der Protocol Mapper `client roles`
  (`oidc-usermodel-client-role-mapper`) bildet die **Client-Rollen von `scm-server`** auf den Claim
  `groups` ab — mit `"userinfo.token.claim": "true"`, was entscheidend ist, da das Plugin die
  Claims vom Userinfo Endpoint liest
* **Scopes**: `profile` ist ein Default Scope, `email` ein optionaler — das Plugin fordert
  `openid profile email` an, sodass der E-Mail-Claim geliefert wird, sofern der Scope gewährt ist

Mit diesem Mapper-Setup werden SCM-Gruppen als **Keycloak-Client-Rollen** des Clients `scm-server`
verwaltet:

1. Keycloak → Clients → `scm-server` → *Roles* → Rolle anlegen, z. B. `scmadmin` oder `developers`
2. Die Rolle Benutzern zuweisen (Users → *Role mapping* → Assign role → nach Client filtern)
3. Bei der nächsten SCM-Anmeldung taucht die Rolle im `groups`-Claim auf, die entsprechende
   SCM-Gruppe wird angelegt bzw. aktualisiert und — im Fall von `scmadmin` — die globale
   Administrator-Berechtigung vergeben

Alternativ lässt sich ein Keycloak-*Group Membership*-Mapper verwenden (Claim `groups`, *Add to
userinfo* aktiviert, *Full group path* deaktiviert), um echte Keycloak-Gruppen statt Client-Rollen
abzubilden.

## Bauen und Testen

Das Plugin lässt sich mit den folgenden Tasks kompilieren und paketieren:

* clean - `gradle clean` - löscht das Build-Verzeichnis
* run - `gradle run` - startet einen SCM-Manager mit vorinstalliertem Plugin und Livereload für die UI
* build - `gradle build` - führt alle Checks und Tests aus und baut das smp inklusive Javadoc- und Source-Jar
* test - `gradle test` - führt alle Java-Tests aus
* ui-test - `gradle ui-test` - führt alle UI-Tests aus
* check - `gradle check` - führt alle registrierten Checks und Tests aus (Java und UI)
* fix - `gradle fix` - behebt alle automatisch behebbaren Befunde des check-Tasks
* smp - `gradle smp` - baut die smp-Datei ohne Checks und Tests
* javadoc - `gradle javadoc` - erzeugt die API-Dokumentation unter `build/docs/javadoc`

Gradle kennt keine Profile wie Maven; stattdessen wertet der Build die Projekt-Property `stage`
aus. Mit `-Pstage=release` wird die API-Dokumentation nach [docs/javadoc](docs/javadoc) neben die
Quellen geschrieben statt in das Build-Verzeichnis, damit sie mit dem Release eingecheckt wird:

```bash
# nur die Dokumentation neu erzeugen
./gradlew javadoc -Pstage=release

# vollständiger Release-Build inklusive eingecheckter Dokumentation
./gradlew build -Pstage=release
```

Das Verzeichnis wird vor dem Neuerzeugen geleert, damit keine Seiten entfernter Klassen
zurückbleiben. Ohne die Property bleibt alles im Build-Verzeichnis und `docs/javadoc` wird nicht
angefasst.

Für Entwicklung und Test kann der `run`-Task genutzt werden:

* run - `gradle run` - startet den SCM-Manager mit vorinstalliertem Plugin.

Wurde das Plugin mit `gradle run` gestartet, sollte sich der Standardbrowser des Betriebssystems
automatisch öffnen. Falls nicht, manuell [http://localhost:8081/scm](http://localhost:8081/scm)
aufrufen.

In diesem Modus löst jede Änderung an Web-Dateien (src/main/js oder src/main/webapp) einen Reload
des Browsers mit den vorgenommenen Änderungen aus.

## Verzeichnis- und Dateistruktur

Ein kurzer Blick auf die Dateien und Verzeichnisse eines SCM-Manager-Projekts.

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

1.  **`node_modules/`**: Dieses Verzeichnis enthält alle Code-Module, von denen das Projekt abhängt (npm-Pakete); sie werden automatisch installiert.

2.  **`src/`**: Dieses Verzeichnis enthält den gesamten Code. `src` ist die übliche Konvention für „source code".
    1. **`main/`**
        1. **`java/`**: Dieses Verzeichnis enthält den Java-Code.
        2. **`js/`**: Dieses Verzeichnis enthält den JavaScript-Code für die Web-UI, inklusive Unit-Tests mit der Endung `.test.ts`
        3. **`resources/`**: Dieses Verzeichnis enthält die Classpath-Ressourcen.
    2. **`test/`**
        1. **`java/`**: Dieses Verzeichnis enthält die Java-Unit-Tests.
        2. **`resources/`**: Dieses Verzeichnis enthält Classpath-Ressourcen für die Unit-Tests.

3.  **`.editorconfig`**: Konfigurationsdatei für den Editor gemäß [EditorConfig](https://editorconfig.org/). Die Datei legt einen Stil fest, den IDEs für den Code verwenden.

4.  **`.gitignore`**: Diese Datei teilt Git mit, welche Dateien es nicht verfolgen soll.

5.  **`build.gradle`**: Gradle-Build-Konfiguration, die auch Metadaten enthält.

6.  **`CHANGELOG.md`**: Alle nennenswerten Änderungen des Projekts werden hier dokumentiert.

7.  **`gradle.properties`**: Definiert die Version des Moduls.

8.  **`gradlew`**: Mitgelieferter Gradle-Wrapper, falls Gradle nicht installiert ist.

9.  **`LICENSE.txt`**: Dieses Projekt steht unter der AGPLv3.

10.  **`package.json`**: Hier finden sich die Abhängigkeits- und Build-Konfiguration sowie die Abhängigkeiten für das Frontend.

11.  **`README.md`**: Die englische Fassung dieser Datei mit nützlichen Referenzinformationen zum Projekt.

12.  **`scm-server.json`**: Export des Keycloak-Beispiel-Clients (siehe [Keycloak-Beispiel](#keycloak-beispiel)).

13.  **`settings.gradle`**: Gradle-Settings-Konfiguration.

14. **`tsconfig.json`** Die TypeScript-Konfigurationsdatei.

15. **`yarn.lock`**: Die Konfiguration der UI-Abhängigkeiten.

## Weitere Dokumentation

Unter `docs/` liegen neben der generierten API-Dokumentation vier Dokumente, die das Plugin aus
Sicht von Datenschutz und Informationssicherheit beschreiben:

| Dokument | Inhalt |
|---|---|
| [PROZESS_BESCHREIBUNG.md](docs/PROZESS_BESCHREIBUNG.md) | Verarbeitungsvorgänge, Datenkategorien, Speicherorte, Speicherdauer und Empfänger — Grundlage für das Verzeichnis von Verarbeitungstätigkeiten (Art. 30 DSGVO) |
| [COMPLIANCE_BERICHT.md](docs/COMPLIANCE_BERICHT.md) | Prüfung gegen DSGVO und die NIS2-Risikomanagementmaßnahmen (Art. 21 Abs. 2), mit umgesetzten Maßnahmen, Befunden und Restrisiken |
| [DATENSCHUTZ_FOLGEABSCHAETZUNG.md](docs/DATENSCHUTZ_FOLGEABSCHAETZUNG.md) | Schwellwertanalyse und Datenschutz-Folgenabschätzung (Art. 35 DSGVO) |
| [SOURCECODE_STATISTIK.md](docs/SOURCECODE_STATISTIK.md) | Umfang, Testabdeckung, Dokumentationsgrad und Abhängigkeiten |
| [docs/javadoc](docs/javadoc) | API-Dokumentation, neu erzeugt mit `./gradlew javadoc -Pstage=release` |

Die Dokumente beschreiben die Software; die organisatorischen Teile (Rechtsgrundlage, Löschfristen,
Verantwortlichkeiten) sind vom Betreiber der Instanz zu ergänzen.

## Weitere Hilfe

Weitere Informationen finden sich auf der [Homepage](https://scm-manager.org/docs/) des
SCM-Managers oder auf den Seiten der [Plugins](https://scm-manager.org/plugins/).
