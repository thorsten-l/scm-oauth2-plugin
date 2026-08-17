# Prozessbeschreibung — scm-oauth2-plugin

**Dokumentversion:** 1.1 · **Stand:** 17.08.2026 · **Softwarestand:** scm-oauth2-plugin 1.0.2

Technische Beschreibung der Verarbeitungsvorgänge des Plugins als Grundlage für das Verzeichnis von
Verarbeitungstätigkeiten (Art. 30 DSGVO), für die Risikoanalyse nach Art. 21 Abs. 2 NIS2 und für die
[Datenschutz-Folgenabschätzung](DATENSCHUTZ_FOLGEABSCHAETZUNG.md).

> **Hinweis zur Verwendung:** Dieses Dokument beschreibt ausschließlich das Verhalten der Software.
> Alle organisatorischen Festlegungen (Rechtsgrundlage, Löschfristen, Verantwortlichkeiten,
> Auftragsverarbeitung, Mitbestimmung) trifft der Verantwortliche für seine Instanz. Es handelt sich
> nicht um Rechtsberatung.

## Inhalt

1. [Rollen und Abgrenzung](#1-rollen-und-abgrenzung)
2. [Zweck der Verarbeitung](#2-zweck-der-verarbeitung)
3. [Datenkategorien](#3-datenkategorien)
4. [Prozess 1 — Anmeldung (Authorization Code Flow)](#4-prozess-1--anmeldung-authorization-code-flow)
5. [Prozess 2 — Benutzerbereitstellung und Migration](#5-prozess-2--benutzerbereitstellung-und-migration)
6. [Prozess 3 — Gruppen- und Berechtigungssynchronisation](#6-prozess-3--gruppen--und-berechtigungssynchronisation)
7. [Prozess 4 — Autorisierung im laufenden Betrieb](#7-prozess-4--autorisierung-im-laufenden-betrieb)
8. [Prozess 5 — Abmeldung (RP-initiated Logout)](#8-prozess-5--abmeldung-rp-initiated-logout)
9. [Prozess 6 — Administration der Konfiguration](#9-prozess-6--administration-der-konfiguration)
10. [Speicherorte und Speicherdauer](#10-speicherorte-und-speicherdauer)
11. [Protokollierung](#11-protokollierung)
12. [Empfänger und Datenflüsse nach außen](#12-empfänger-und-datenflüsse-nach-außen)
13. [Schnittstellen](#13-schnittstellen)

## 1. Rollen und Abgrenzung

| Rolle | Zuordnung |
|---|---|
| Verantwortlicher (Art. 4 Nr. 7 DSGVO) | Betreiber der SCM-Manager-Instanz |
| Weiterer Verantwortlicher | Betreiber des Identity Providers (IdP), sofern organisatorisch getrennt |
| Auftragsverarbeiter | **keiner durch das Plugin** — die Software wird lokal betrieben, es findet kein Datenfluss zum Autor oder zu Dritten statt |
| Datenquelle | IdP (OAuth2/OIDC), mittelbar das dahinterliegende Verzeichnis (z. B. LDAP/AD) |

Das Plugin ist eine lokal installierte Softwarekomponente (`.smp`-Paket, 96 KB) innerhalb des
SCM-Manager-Prozesses. Es betreibt keinen eigenen Dienst, öffnet keine ausgehenden Verbindungen
außer zu den konfigurierten IdP-Endpunkten und enthält keine Telemetrie.

**Abgrenzung zum SCM-Manager-Kern:** Benutzerkonten, Gruppen, Berechtigungen, Sitzungs-Cookies und
das Logging werden vom Kern verwaltet und persistiert. Das Plugin ruft dessen Schnittstellen auf
(`UserManager`, `GroupManager`, `SecuritySystem`, `SyncingRealmHelper`, `AccessTokenCookieIssuer`).
Eigene Datenhaltung des Plugins: die Datei je Benutzer unter `var/data/oauth2Groups/` sowie zwei
flüchtige Speicher im Arbeitsspeicher (siehe [Abschnitt 10](#10-speicherorte-und-speicherdauer)).

## 2. Zweck der Verarbeitung

| Zweck | Verarbeitungsschritte |
|---|---|
| Authentifizierung von Benutzern an SCM-Manager über einen zentralen IdP (Single Sign-on) | Prozess 1 |
| Bereitstellung und Aktualisierung des lokalen Benutzerkontos | Prozess 2 |
| Zugriffssteuerung anhand der im IdP gepflegten Gruppen und Rollen | Prozesse 3 und 4 |
| Beendigung der Sitzung, optional auch der IdP-Sitzung | Prozess 5 |
| Betrieb und Administration der Kopplung | Prozess 6 |

Es findet **kein Profiling** und keine Verhaltens- oder Leistungsbewertung statt. Die einzige
automatisierte Entscheidung ist die Zuweisung bzw. der Entzug von Zugriffsrechten anhand der
Gruppenzugehörigkeit (siehe [DSFA, Abschnitt zu Art. 22](DATENSCHUTZ_FOLGEABSCHAETZUNG.md)).

## 3. Datenkategorien

Welche Claims gelesen werden, ist konfigurierbar; die Spalte „Standard" nennt die Vorbelegung.

| Nr. | Datum | Quelle (Claim) | Standard | Personenbezug |
|---|---|---|---|---|
| D1 | Benutzerkennung | `usernameAttribute`, ersatzweise `sub` | `preferred_username` | ja, identifizierend |
| D2 | Anzeigename | `displayNameAttribute` | `name` | ja, identifizierend |
| D3 | E-Mail-Adresse | `mailAttribute` | `email` | ja, identifizierend |
| D4 | Gruppenzugehörigkeiten | `groupAttribute` | `groups` | ja, ggf. aussagekräftig (s. u.) |
| D5 | Rollen aus dem Access Token | JSON-Pfad, nur bei `importRealmRoles` | `realm_access.roles` | ja, ggf. aussagekräftig |
| D6 | Access Token | Token-Endpunkt des IdP | — | mittelbar; **nicht gespeichert** |
| D7 | ID Token | Token-Endpunkt des IdP | — | enthält `sub`; im Arbeitsspeicher, max. 12 h |
| D8 | `state`, PKCE-Verifier und Nonce | im Plugin erzeugt | — | kein Personenbezug, im Arbeitsspeicher, max. 10 min |
| D9 | Anmeldezeitpunkt, Vorgangsausgang | implizit im Protokoll | — | ja, in Verbindung mit D1 |

> **Datenminimierung, Hinweis D4/D5:** Gruppen- und Rollenlisten produktiver IdP-Installationen
> enthalten häufig weit mehr als Zugriffsgruppen — etwa Organisationseinheit, Fakultät,
> Beschäftigtenart oder Standort. Diese Angaben werden vollständig in
> `var/data/oauth2Groups/<kennung>.xml` abgelegt. Der Verantwortliche sollte den Gruppen-Claim im
> IdP auf die für SCM-Manager erforderlichen Gruppen einschränken (Mapper-/Scope-Konfiguration);
> siehe [Compliance-Bericht, Befund B-03](COMPLIANCE_BERICHT.md#4-befunde-und-maßnahmen).

Besondere Kategorien nach Art. 9 DSGVO werden nicht verarbeitet, **sofern** der Gruppen-Claim keine
entsprechenden Angaben transportiert (z. B. Gewerkschafts- oder Gesundheitsbezug in Gruppennamen).
Die Prüfung dieser Bedingung obliegt dem Verantwortlichen.

## 4. Prozess 1 — Anmeldung (Authorization Code Flow)

Auslöser: Klick auf „Anmelden mit &lt;Provider&gt;", oder automatische Umleitung durch
`ForceOAuth2LoginFilter` bei aktiviertem `forceLogin`.

| Schritt | Vorgang | Komponente | Verarbeitete Daten |
|---|---|---|---|
| 1 | `GET /api/v2/oauth2/auth?from=<Ziel>` | `OAuth2AuthenticationResource` | Zielpfad (validiert: nur instanzinterne Pfade) |
| 2 | `state` (24 Byte Zufall), PKCE-Verifier (32 Byte) und Nonce (24 Byte) erzeugen, mit Zielpfad hinterlegen | `StateStore`, `Pkce` | D8 |
| 3 | `state` als Cookie `X-SCM-OAuth2-State` setzen (`HttpOnly`, `SameSite=Lax`, `Secure` bei HTTPS, 600 s) | `StateCookie` | D8 |
| 4 | Endpunkte ermitteln: manuell konfiguriert oder aus dem Discovery-Dokument (1 h Cache) | `EndpointResolver`, `DiscoveryClient` | keine personenbezogenen Daten |
| 5 | HTTP 303 zum Authorization-Endpunkt mit `client_id`, `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge` | `OAuth2AuthenticationResource` | D8 |
| 6 | **Authentifizierung beim IdP** (Passwort, MFA, Zertifikat …) | außerhalb des Plugins | — |
| 7 | Rücksprung `GET /api/v2/oauth2/auth/callback?code=…&state=…` | `OAuth2AuthenticationResource` | `code`, D8 |
| 8 | Prüfung: `state` stimmt mit dem Cookie dieses Browsers überein (zeitkonstanter Vergleich) | `OAuth2AuthenticationResource` | D8 |
| 9 | `state` einlösen — einmalig, danach ungültig | `StateStore` | D8 |
| 10 | Code gegen Tokens tauschen (Server-zu-Server, `client_secret` + `code_verifier`) | `OAuth2RestClient` | D6, D7 |
| 10a | **ID Token prüfen**: Signatur gegen den JWKS des IdP bzw. gegen das Client-Secret, dazu `iss`, `aud`/`azp`, Laufzeit und Nonce dieser Anmeldung; ein ungültiges Token bricht die Anmeldung ab | `TokenVerifier`, `JwksProvider` | D7 |
| 11 | Claims vom Userinfo-Endpunkt abrufen | `OAuth2RestClient` | D1–D4 |
| 12 | Benutzer, Gruppen und Rechte bereitstellen | Prozesse 2 und 3 | D1–D5 |
| 13 | ID Token für einen späteren Logout vorhalten — nur wenn es geprüft werden konnte | `IdTokenStore` | D7 |
| 14 | SCM-Access-Token-Cookie (JWT) ausstellen | `LoginHandler` (Kern) | D1 |
| 15 | HTTP 303 auf den Zielpfad, `state`-Cookie löschen | `OAuth2AuthenticationResource` | — |

**Abbruchbedingungen** — jeweils HTTP 401 mit statischem Text, ohne Rückgabe von IdP-Details:
fehlendes oder abweichendes `state`-Cookie, unbekanntes oder abgelaufenes `state`, fehlender Code,
Fehlermeldung des IdP, ungültiges ID Token, fehlgeschlagene Authentifizierung.

**Grundsatz zur Tokenprüfung:** Verwendet wird nur, was geprüft werden konnte. Steht keine
Schlüsselquelle zur Verfügung (weder Discovery-URL noch konfigurierte `jwksUrl`), wird das ID Token
verworfen und es werden keine Rollen aus dem Access Token übernommen — mit einer Warnung im
Protokoll. Die Anmeldung selbst bleibt möglich, da die Identität aus dem über TLS abgerufenen
Userinfo-Endpunkt stammt.

## 5. Prozess 2 — Benutzerbereitstellung und Migration

| Fall | Verhalten | Komponente |
|---|---|---|
| Konto existiert nicht | Neuanlage als *externes* Konto ohne Passwort | `UserInfoMapper`, `SyncingRealmHelper` |
| Konto existiert und ist extern (z. B. bisher LDAP) | Übernahme; D2/D3 werden aktualisiert, alle übrigen Attribute bleiben erhalten | `UserMigration` |
| Konto existiert mit lokalem Passwort | Anmeldung wird **abgelehnt**, sofern `migrateLocalUsers` nicht gesetzt ist | `UserMigration` |
| Konto existiert mit lokalem Passwort, `migrateLocalUsers` gesetzt | Übernahme; das lokale Passwort wird entfernt | `UserMigration` |

Nicht gelieferte Claims überschreiben keine gespeicherten Werte (z. B. bleibt eine vorhandene
E-Mail-Adresse erhalten, wenn der Claim fehlt). Eine syntaktisch ungültige E-Mail-Adresse wird
verworfen, damit die Anmeldung nicht scheitert.

Da das Konto und damit die Benutzerkennung erhalten bleibt, bleiben auch alle daran gebundenen
Zuordnungen bestehen: Berechtigungen, Repository-Eigentümerschaft, API-Schlüssel, manuell gepflegte
Gruppenmitgliedschaften.

## 6. Prozess 3 — Gruppen- und Berechtigungssynchronisation

Bei jeder Anmeldung, nach der Bereitstellung des Benutzers:

1. **Zusammenführen** von D4 und — falls aktiviert — D5. D5 wird nur aus einem signatur- und
   claimgeprüften Access Token übernommen; andernfalls bleibt die Rollenliste leer.
2. **Normalisieren** der Namen: in SCM-Manager unzulässige Zeichen werden durch `_` ersetzt
   (`GroupNameSanitizer`), damit z. B. ein voller Keycloak-Gruppenpfad `/entwickler` als
   `_entwickler` nutzbar bleibt und nicht verloren geht.
3. **Ablegen** der normalisierten Liste in `var/data/oauth2Groups/<kennung>.xml` (`GroupStore`) —
   diese Liste ist die Grundlage der Autorisierung.
4. **Abgleich der Gruppenobjekte** (`GroupSynchronizer`): fehlende Gruppen werden angelegt
   (Typ `xml`, Beschreibung „Synchronized by scm-oauth2-plugin"), Mitgliedschaften werden ergänzt
   und für Gruppen entzogen, die bei der vorherigen Anmeldung vorhanden waren und jetzt fehlen.
   **Gruppen werden nie gelöscht**, auch nicht wenn sie leer werden. Externe Gruppen bleiben
   unberührt.
5. **Administratorrecht** (`AdminGroupSynchronizer`): enthält die Liste die konfigurierte
   `adminGroup`, wird die Berechtigung `*` zugewiesen, andernfalls eine früher zugewiesene entzogen.
   Betroffen ist ausschließlich die Einzelberechtigung `*` dieses Benutzers.

Schritte 4 und 5 laufen mit erweiterten Rechten (`AdministrationContext.runAsAdmin`), da der
Benutzer während der Anmeldung noch nicht authentifiziert ist. Fehler in diesen Schritten werden
protokolliert und brechen die Anmeldung **nicht** ab.

## 7. Prozess 4 — Autorisierung im laufenden Betrieb

Der Kern fragt bei jeder Anfrage alle registrierten `GroupResolver`. `OAuth2GroupResolver` liefert
die bei der letzten Anmeldung gespeicherte Liste aus `var/data/oauth2Groups/`. Dadurch wirken
Gruppenrechte auch bei Zugriffen ohne Browser-Sitzung (Git über HTTP, API-Schlüssel).

**Konsequenz für die Aktualität:** Änderungen im IdP wirken erst mit der nächsten Anmeldung. Ein
Entzug von Rechten im IdP beendet keine laufende SCM-Sitzung.

## 8. Prozess 5 — Abmeldung (RP-initiated Logout)

Nur bei aktiviertem `ssoLogout`. Der Kern beendet zuerst die lokale Sitzung, danach liefert
`AfterLogoutRedirectToIdp` das Umleitungsziel:

* `client_id`
* `id_token_hint` — das ID Token der Anmeldung aus dem `IdTokenStore`; es wird dabei entfernt.
  Da der Kern die Sitzung bereits beendet hat, wird die Benutzerkennung ersatzweise aus dem
  `sub`-Claim des noch vorhandenen Access-Token-Cookies gelesen.
* `post_logout_redirect_uri` — die Basis-URL der Instanz; muss am IdP registriert sein.

Ohne verfügbares ID Token (z. B. nach einem Neustart) funktioniert die Abmeldung weiterhin, der IdP
zeigt dann ggf. eine Bestätigungsseite. Fehler führen zu „keine Umleitung"; die lokale Abmeldung
ist in jedem Fall erfolgt.

## 9. Prozess 6 — Administration der Konfiguration

`GET`/`PUT` auf `/api/v2/oauth2/configuration`, geschützt durch
`configuration:read:oauth2` bzw. `configuration:write:oauth2`.

* Das Client-Secret wird **verschlüsselt** in `config/oauth2.xml` gespeichert, von der API **nie
  ausgeliefert** und bei leerer Übergabe unverändert beibehalten.
* Endpunkt-URLs werden auf absolute `http`/`https`-URLs mit Host geprüft.
* Bei aktiviertem Plugin ist ein Provider-Name verpflichtend.

Die Konfiguration enthält keine personenbezogenen Daten (Ausnahme: die Angaben zum IdP-Client sind
Zugangsdaten der Instanz, keine Personendaten).

## 10. Speicherorte und Speicherdauer

Pfade relativ zum SCM-Manager-Heimatverzeichnis (Linux/Docker typisch `/var/lib/scm`).

| Ort | Inhalt | Verwaltet von | Dauer / Löschung |
|---|---|---|---|
| `config/oauth2.xml` | Konfiguration inkl. verschlüsseltem Client-Secret | Plugin | bis zur Änderung; Löschung mit dem Plugin |
| `var/data/oauth2Groups/<kennung>.xml` | normalisierte Gruppen-/Rollenliste; **der Dateiname ist die Benutzerkennung** | Plugin | wird bei jeder Anmeldung überschrieben; **keine automatische Löschung**, s. Befund B-01 |
| Benutzerdatenbank des Kerns | D1–D3, Kennzeichen „extern" | Kern | Löschung mit dem Benutzerkonto |
| Gruppendatenbank des Kerns | Gruppen und Mitgliedschaften | Kern | Mitgliedschaft wird bei Wegfall entzogen; Gruppenobjekt bleibt |
| Berechtigungen des Kerns | Einzelberechtigung `*` bei Admin-Gruppe | Kern | Entzug bei Wegfall der Gruppe |
| Arbeitsspeicher — `StateStore` | offene Anmeldevorgänge (`state`, PKCE-Verifier, Nonce), max. 10.000 | Plugin | 10 Minuten oder Einlösung; Verlust bei Neustart |
| Arbeitsspeicher — `JwksProvider` | öffentliche Schlüssel des IdP, keine personenbezogenen Daten | Plugin | 1 Stunde, danach erneuter Abruf |
| Arbeitsspeicher — `IdTokenStore` | ID Token je Benutzer | Plugin | Abmeldung oder 12 Stunden; Verlust bei Neustart |
| Protokolldateien | siehe Abschnitt 11 | Kern (Logback) | nach Protokollierungskonzept des Betreibers |
| Browser des Benutzers | `X-SCM-OAuth2-State` (600 s), Access-Token-Cookie des Kerns | Plugin / Kern | Ablauf bzw. Abmeldung |

Die beiden Arbeitsspeicher sind bewusst nicht persistent und **nicht clusterfähig**: In einem
Verbund ohne Sitzungsbindung muss ein Anmeldevorgang, der auf einem anderen Knoten endet,
wiederholt werden; die Abmeldung erfolgt dann ohne `id_token_hint`.

## 11. Protokollierung

Das Plugin schreibt über SLF4J in das Log des Kerns. 14 Ausgaben enthalten Kennungen:

| Stufe | Anzahl | Inhalt |
|---|---|---|
| `INFO` | 7 | Benutzerkennung bei Gruppenanlage, Mitgliedschaftsänderung, Rechtezuweisung/-entzug, Kontoübernahme; bei einer ungültigen Mail-Adresse nur Kennung und Länge des Wertes, nicht die Adresse selbst |
| `WARN` / `ERROR` | 4 | Benutzerkennung und Gruppenname bei fehlgeschlagener Synchronisation, abgelehnte Übernahme eines lokalen Kontos |
| `DEBUG` | 3 | Kontoname bei Wiederverwendung, Gruppennamen bei Normalisierung |

Nicht protokolliert werden: Tokens, `code`, `state`, Nonce, PKCE-Verifier, Client-Secret,
E-Mail-Adressen. Fehlermeldungen
des IdP werden ausschließlich protokolliert und nie an den Browser zurückgegeben.

## 12. Empfänger und Datenflüsse nach außen

| Richtung | Empfänger | Daten | Kanal |
|---|---|---|---|
| ausgehend, Browser | IdP | `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge` | HTTP-Umleitung |
| ausgehend, Server | IdP Token-Endpunkt | `code`, `redirect_uri`, `client_id`, `client_secret`, `code_verifier` | HTTPS, Server-zu-Server |
| ausgehend, Server | IdP Userinfo-Endpunkt | Access Token als Bearer | HTTPS, Server-zu-Server |
| ausgehend, Server | IdP Discovery-Endpunkt | keine personenbezogenen Daten | HTTPS |
| ausgehend, Server | IdP JWKS-Endpunkt | keine personenbezogenen Daten (öffentliche Schlüssel, 1 h Cache) | HTTPS |
| ausgehend, Browser | IdP End-Session-Endpunkt | `client_id`, `id_token_hint` (enthält `sub`), `post_logout_redirect_uri` | HTTP-Umleitung |
| eingehend | vom IdP | D1–D5, D6, D7 | HTTPS |

Weitere Empfänger gibt es nicht. **Drittlandübermittlung:** Liegt der IdP außerhalb des EWR, ist
Kapitel V DSGVO (Art. 44 ff.) durch den Verantwortlichen zu prüfen; das Plugin selbst nimmt keine
Übermittlung an andere Stellen vor.

## 13. Schnittstellen

| Endpunkt | Methode | Authentifizierung | Zweck |
|---|---|---|---|
| `/api/v2/oauth2/auth` | GET | anonym (`@AllowAnonymousAccess`) | Anmeldung starten; HTTP 404 solange deaktiviert |
| `/api/v2/oauth2/auth/callback` | GET | anonym | Rücksprung des IdP |
| `/api/v2/oauth2/configuration` | GET | `configuration:read:oauth2` | Konfiguration lesen (ohne Secret) |
| `/api/v2/oauth2/configuration` | PUT | `configuration:write:oauth2` | Konfiguration schreiben |

Registrierte Erweiterungspunkte des Kerns: Shiro-Realm, `GroupResolver`, `LogoutRedirection`,
Index-Enricher, `ExternalAuthenticationAvailableNotifier`, Guice-Modul, sowie ein Servlet-Filter
(`@WebElement("/*")`) für die erzwungene Anmeldung.

---

**Weiterführend:** [Compliance-Bericht](COMPLIANCE_BERICHT.md) ·
[Datenschutz-Folgenabschätzung](DATENSCHUTZ_FOLGEABSCHAETZUNG.md) ·
[Sourcecode-Statistik](SOURCECODE_STATISTIK.md) · [Benutzerdokumentation](../README_de.md)
