# Compliance-Bericht — scm-oauth2-plugin

**Dokumentversion:** 1.1 · **Stand:** 17.08.2026 · **Softwarestand:** scm-oauth2-plugin 1.0.2
**Prüfgegenstand:** Quellcode und Konfigurationsverhalten des Plugins
**Prüfmaßstab:** DSGVO (VO (EU) 2016/679) und NIS2-Richtlinie (RL (EU) 2022/2555)

> **Geltungsbereich und Grenzen:** Geprüft wurde die Software. Ob eine Instanz insgesamt konform
> betrieben wird, hängt zusätzlich von Konfiguration, IdP, Betriebsumgebung und organisatorischen
> Festlegungen des Betreibers ab. Dieser Bericht ersetzt keine Rechtsberatung und keine Prüfung
> durch die zuständige Datenschutzaufsicht.

## 1. Zusammenfassung

Das Plugin verarbeitet ausschließlich die für Authentifizierung und Zugriffssteuerung
erforderlichen Identitätsdaten, hält keine Tokens dauerhaft vor und überträgt Daten
ausschließlich an den vom Betreiber konfigurierten Identity Provider. Datenschutzrechtlich
relevante Schutzmaßnahmen sind im Code umgesetzt und durch 185 automatisierte Tests abgedeckt.

**Gesamteinschätzung:** Aus Sicht der Softwareprüfung stehen der konformen Nutzung keine
strukturellen Mängel entgegen. Es verbleiben **zwei Befunde**, beide mit Handlungsbedarf beim
Verantwortlichen (B-01, B-03), sowie **drei Restrisiken**, die durch Konfiguration bzw.
Betriebsvorgaben zu behandeln sind.

**Erledigt gegenüber Version 1.0 dieses Berichts:** B-02 (E-Mail-Adresse im Protokoll) sowie die
Restrisiken R-01 und R-02 — ID Token und Access Token werden jetzt kryptografisch geprüft
(Abschnitt 2.4, Maßnahmen M-16 bis M-19).

| Kategorie | Anzahl |
|---|---|
| Umgesetzte technische Maßnahmen (Art. 32 DSGVO / Art. 21 NIS2) | 19 |
| Befunde mit Handlungsbedarf | 2 |
| Dokumentierte Restrisiken | 3 |
| Automatisierte Tests, davon fehlgeschlagen | 185 / 0 |

## 2. Prüfung nach DSGVO

### 2.1 Grundsätze, Art. 5

| Grundsatz | Bewertung | Nachweis im Code |
|---|---|---|
| Rechtmäßigkeit, Art. 5 Abs. 1 lit. a | **offen beim Verantwortlichen** — die Rechtsgrundlage (regelmäßig Art. 6 Abs. 1 lit. b/f, im Beschäftigungsverhältnis ggf. § 26 BDSG) ist instanzabhängig | — |
| Zweckbindung, lit. b | erfüllt: die gelesenen Claims werden ausschließlich für Kontoführung und Zugriffssteuerung verwendet | `UserInfoMapper`, `AuthenticationInfoBuilder` |
| Datenminimierung, lit. c | **teilweise** — nur die konfigurierten Claims werden gelesen, Tokens nicht gespeichert; der Gruppen-Claim wird jedoch unverändert vollständig übernommen → Befund **B-03** | `UserInfoMapper`, `GroupStore` |
| Richtigkeit, lit. d | erfüllt: Anzeigename, E-Mail und Gruppen werden bei jeder Anmeldung aus der führenden Quelle aktualisiert | `UserMigration`, `GroupSynchronizer` |
| Speicherbegrenzung, lit. e | **teilweise** — flüchtige Speicher mit 10 min / 12 h Frist; die Gruppendatei je Benutzer wird bei Kontolöschung nicht entfernt → Befund **B-01** | `StateStore`, `IdTokenStore`, `GroupStore` |
| Integrität und Vertraulichkeit, lit. f | erfüllt, siehe Abschnitt 2.4; die Identitätsdaten werden nur aus kryptografisch geprüften Tokens übernommen | mehrere, u. a. `TokenVerifier` |
| Rechenschaftspflicht, Abs. 2 | unterstützt durch [Prozessbeschreibung](PROZESS_BESCHREIBUNG.md), diesen Bericht und die [DSFA](DATENSCHUTZ_FOLGEABSCHAETZUNG.md) | — |

### 2.2 Datenschutz durch Technikgestaltung, Art. 25

| Maßnahme | Umsetzung |
|---|---|
| Voreinstellungen datenschutzfreundlich | Plugin ist nach Installation **deaktiviert** (`enabled = false`); `forceLogin`, `ssoLogout`, `importRealmRoles` und `migrateLocalUsers` sind standardmäßig aus |
| Übernahme lokaler Konten nur nach ausdrücklicher Freigabe | `UserMigration` verweigert die Anmeldung, wenn ein Konto mit lokalem Passwort existiert, solange `migrateLocalUsers` nicht gesetzt ist |
| Keine Tokenhaltung über das Notwendige hinaus | Access Token wird nicht gespeichert; ID Token nur im Arbeitsspeicher und nur bis zur Abmeldung |
| Keine Datenweitergabe an den Hersteller | keine Telemetrie, keine ausgehenden Verbindungen außer zum konfigurierten IdP |
| Zweckgebundene Speicherstruktur | eine Datei je Benutzer, ausschließlich mit Gruppennamen — gezielt löschbar |

### 2.3 Verzeichnis von Verarbeitungstätigkeiten, Art. 30

Die für einen Eintrag erforderlichen technischen Angaben liefert die
[Prozessbeschreibung](PROZESS_BESCHREIBUNG.md): Zwecke (Abschnitt 2), Kategorien betroffener
Personen und Daten (3), Empfänger (12), Speicherfristen (10), technische Maßnahmen (siehe unten).
Zu ergänzen sind durch den Verantwortlichen: Name und Kontakt des Verantwortlichen und des
Datenschutzbeauftragten, Rechtsgrundlage, ggf. Drittlandbezug des IdP.

### 2.4 Sicherheit der Verarbeitung, Art. 32

| Nr. | Maßnahme | Umsetzung im Code |
|---|---|---|
| M-01 | Authorization Code Flow mit vertraulichem Client; kein Token im Browser-Umlauf | `OAuth2AuthenticationResource`, `OAuth2RestClient` |
| M-02 | PKCE (S256, RFC 7636); Verifier verlässt den Server nicht | `Pkce`, `StateStore` |
| M-03 | `state` als CSRF-Schutz, 24 Byte aus `SecureRandom`, **einmalig einlösbar** | `StateStore` |
| M-04 | Bindung des `state` an den Browser über `HttpOnly`-Cookie; zeitkonstanter Vergleich — verhindert Login-CSRF (RFC 9700 Abschn. 4.7) | `StateCookie`, `MessageDigest.isEqual` |
| M-05 | Cookie-Attribute: `HttpOnly`, `SameSite=Lax`, `Secure` bei HTTPS, Pfad auf den Kontextpfad begrenzt | `StateCookie` |
| M-06 | Begrenzung offener Anmeldevorgänge auf 10.000 mit Verdrängung der ältesten — begrenzt Speichererschöpfung über den anonymen Endpunkt | `StateStore` |
| M-07 | Umleitungsziele nur instanzintern; abgewiesen werden fehlende, protokollrelative (`//host`), `/\`-präfixierte sowie CR/LF-behaftete Werte | `OAuth2AuthenticationResource.sanitizeRedirect` |
| M-08 | Keine Rückgabe von IdP-Meldungen oder internen Fehlertexten an den Browser (statische 401-Texte) | `OAuth2AuthenticationResource.unauthorized` |
| M-09 | Client-Secret verschlüsselt gespeichert, von der API nie ausgeliefert, leere Eingabe erhält den Bestand | `OAuth2Configuration`, `ConfigurationResource` |
| M-10 | Endpunkt-URLs auf absolute `http`/`https`-URLs mit Host beschränkt — begrenzt SSRF-Fläche des Schreibrechts | `ConfigurationResource.isHttpUrl` |
| M-11 | TLS-Zertifikatsprüfung aktiv; Abschaltung ausschließlich in der Entwicklungs-Stage | `OAuth2RestClient`, `DiscoveryClient` |
| M-12 | Erzwungene Anmeldung nur mit **signaturgeprüftem** Access-Token-Cookie umgehbar | `ForceOAuth2LoginFilter` |
| M-13 | Rechteänderungen nur über die Kern-API mit erweiterten Rechten, begrenzt auf die Einzelberechtigung `*` des betroffenen Benutzers | `AdminGroupSynchronizer` |
| M-14 | Gruppennamen werden normalisiert statt ungeprüft übernommen; identische Namen kollabieren | `GroupNameSanitizer` |
| M-15 | Keine Protokollierung von Tokens, `code`, `state`, Verifier oder Secret; keine personenbezogenen Inhalte über die Benutzerkennung hinaus | durchgängig, `UserInfoMapper` |
| M-16 | **Signaturprüfung des ID Tokens** gegen den JSON Web Key Set des IdP (RS/PS/ES-Familie) bzw. gegen das Client-Secret (HS-Familie); ein vorhandenes, aber ungültiges Token bricht die Anmeldung ab | `TokenVerifier`, `Jws`, `JwsAlgorithm`, `JwksClient`, `JwksProvider` |
| M-17 | Algorithmen-Allowlist: `alg: none` und unbekannte Verfahren werden abgewiesen, der Algorithmus bestimmt den zulässigen Schlüsseltyp (Schutz vor Algorithm Confusion), ein `crit`-Header wird abgewiesen | `JwsAlgorithm`, `Jws` |
| M-18 | **Nonce** je Anmeldung: wird an den Authorization-Endpunkt gesendet und im ID Token geprüft — bindet das Token an genau diese Anmeldung (OIDC Core 3.1.3.7 (11)) | `StateStore`, `OAuth2AuthenticationResource`, `TokenVerifier` |
| M-19 | Claim-Prüfung: `iss` gegen den Issuer der Discovery, `aud`/`azp` gegen die Client-ID, `exp`/`nbf`/`iat` mit 60 s Toleranz; Rollen werden ausschließlich aus einem geprüften Access Token importiert | `TokenVerifier`, `AccessTokenRoleReader` |

### 2.5 Betroffenenrechte, Art. 15–22

| Recht | Erfüllbarkeit | Fundstellen der Daten |
|---|---|---|
| Auskunft, Art. 15 | gegeben | Benutzerkonto (Kern), `var/data/oauth2Groups/<kennung>.xml`, Gruppenmitgliedschaften (Kern), Protokolldateien |
| Berichtigung, Art. 16 | über den IdP als führende Quelle; Übernahme mit der nächsten Anmeldung | — |
| Löschung, Art. 17 | gegeben, **jedoch nicht vollständig automatisiert** → Befund **B-01**: die Gruppendatei ist zusätzlich manuell zu entfernen |
| Einschränkung, Art. 18 | organisatorisch: Konto deaktivieren (Kern) | — |
| Datenübertragbarkeit, Art. 20 | regelmäßig nicht anwendbar (keine auf Einwilligung oder Vertrag mit der betroffenen Person gestützte Verarbeitung im Sinne der Norm) | — |
| Automatisierte Entscheidung, Art. 22 | Zuweisung/Entzug von Zugriffsrechten anhand der Gruppenzugehörigkeit; nach hiesiger Einschätzung kein Fall des Art. 22 Abs. 1, da keine Entscheidung mit rechtlicher Wirkung oder ähnlich erheblicher Beeinträchtigung — Bewertung im Einsatzkontext beim Verantwortlichen | `AdminGroupSynchronizer`, `GroupSynchronizer` |

### 2.6 Meldung von Verletzungen, Art. 33/34

Das Plugin liefert die für eine Bewertung nötigen Spuren: fehlgeschlagene Anmeldungen und
abgelehnte Kontoübernahmen auf `WARN`, Rechtezuweisungen und Mitgliedschaftsänderungen auf `INFO`.
Zu beachten: **abgewiesene `state`-Prüfungen** (`state does not match`) sind der Indikator für einen
Login-CSRF-Versuch und sollten in die Auswertung aufgenommen werden.

## 3. Prüfung nach NIS2

Das Plugin ist keine „Einrichtung" im Sinne der Richtlinie; Adressat der Pflichten ist der
Betreiber. Die Tabelle weist nach, welchen Beitrag die Software zu den Risikomanagement-Maßnahmen
nach **Art. 21 Abs. 2** leistet und welche Aufgabe beim Betreiber bleibt.

| Lit. | Maßnahme nach Art. 21 Abs. 2 | Beitrag des Plugins | Aufgabe des Betreibers |
|---|---|---|---|
| a | Risikoanalyse, Sicherheit für Informationssysteme | dokumentierte Datenflüsse, Angriffsflächen und Restrisiken ([Prozessbeschreibung](PROZESS_BESCHREIBUNG.md), Abschnitt 4 dieses Berichts) | Einordnung in das eigene ISMS |
| b | Bewältigung von Sicherheitsvorfällen | Protokollierung sicherheitsrelevanter Ereignisse (Abschnitt 2.6) | Auswertung, Alarmierung, Meldewege nach Art. 23 |
| c | Betriebskontinuität, Backup, Krisenmanagement | zustandsarme Auslegung: nur `config/oauth2.xml` und `var/data/oauth2Groups/` sind sicherungsrelevant; flüchtige Speicher sind nach einem Neustart entbehrlich (Anmeldung wiederholen, Abmeldung ohne Hint) | Backup dieser Pfade, Wiederanlaufprüfung, Verfügbarkeit des IdP als **Single Point of Failure** |
| d | Sicherheit der Lieferkette | **keine eigenen Laufzeitabhängigkeiten** — alle genutzten Bibliotheken stellt der SCM-Manager-Kern bereit; Lizenz AGPL-3.0-only, Quellcode vollständig einsehbar; Build über den offiziellen `org.scm-manager.smp`-Gradle-Plugin | Bezugsquelle des `.smp` prüfen, Kern aktuell halten, IdP-Anbieter bewerten |
| e | Sicherheit bei Entwicklung und Wartung, Schwachstellenmanagement | 185 automatisierte Tests (0 Fehler), drei durchgeführte Sicherheitsprüfungen mit umgesetzten Maßnahmen, vollständige Quellcodedokumentation, [Sourcecode-Statistik](SOURCECODE_STATISTIK.md) | Update-Prozess, Meldeweg für Schwachstellen, Beobachtung des Projekts |
| f | Bewertung der Wirksamkeit | Tests decken die Schutzmaßnahmen gezielt ab (u. a. `state`-Bindung, gefälschtes Cookie, Umleitung auf Fremdhost, PKCE, Secret-Handhabung sowie 28 Fälle zur Signatur- und Claim-Prüfung gegen echte Schlüsselpaare) | regelmäßige Wirksamkeitsprüfung, ggf. Penetrationstest |
| g | Cyberhygiene und Schulung | Administrationsoberfläche mit Hilfetexten zu jedem Feld, ausführliche Betriebsdokumentation in zwei Sprachen | Schulung der Administratoren |
| h | Kryptografie und Verschlüsselung | TLS mit Zertifikatsprüfung, PKCE mit SHA-256, `SecureRandom` für `state`, Verifier und Nonce, verschlüsseltes Client-Secret, signaturgeprüfte Access Tokens des Kerns sowie Signatur- und Claim-Prüfung der IdP-Tokens gegen den JWKS-Endpunkt | TLS-Konfiguration und Zertifikatsverwaltung, Schlüsselmaterial des Kerns |
| i | Personalsicherheit, Zugriffskontrolle, Anlagenverwaltung | rechtebasierter Zugang zur Konfiguration (`configuration:read/write:oauth2`), zentrale Rechtevergabe über IdP-Gruppen, automatischer Entzug bei Wegfall | Vergabe des Schreibrechts nach Vier-Augen-Prinzip (siehe **R-04**), Pflege der Gruppen im IdP |
| j | MFA, gesicherte Kommunikation, Notfallkommunikation | Mehrfaktor-Authentifizierung wird an den IdP delegiert und damit für SCM-Manager wirksam; SSO ist der Zweck der Komponente | MFA im IdP erzwingen, Notfallzugang ohne SSO vorhalten (siehe **R-05**) |

### Meldepflichten, Art. 23

Für die Fristen (Frühwarnung 24 h, Meldung 72 h) sind die in Abschnitt 2.6 genannten Ereignisse die
technische Grundlage. Das Plugin selbst versendet keine Meldungen.

## 4. Befunde und Maßnahmen

| ID | Befund | Einstufung | Maßnahme | Zuständig |
|---|---|---|---|---|
| **B-01** | Bei Löschung eines Benutzerkontos bleibt `var/data/oauth2Groups/<kennung>.xml` bestehen; das Plugin registriert keinen Listener auf Löschereignisse. Der Dateiname ist die Benutzerkennung, der Inhalt sind Gruppenzugehörigkeiten. | mittel — Art. 5 Abs. 1 lit. e, Art. 17 DSGVO | kurzfristig: Löschung in den Offboarding-Prozess aufnehmen (Datei entfernen). Mittelfristig: Ereignis-Listener im Plugin ergänzen, der die Datei beim Löschen des Benutzers entfernt. | Betreiber / Entwicklung |
| ~~**B-02**~~ | ~~`UserInfoMapper` protokolliert bei syntaktisch ungültiger Adresse die E-Mail-Adresse samt Benutzerkennung auf `INFO`.~~ | gering — Datenminimierung in Protokollen | **Erledigt in 1.0.2:** die Adresse wird nicht mehr protokolliert, die Meldung nennt nur noch Benutzerkennung und Länge des Wertes. | — |
| **B-03** | Der Gruppen-Claim wird vollständig übernommen. Produktive IdP-Installationen liefern dort häufig auch Organisations-, Beschäftigungs- oder Standortmerkmale, die für SCM-Manager nicht erforderlich sind. | mittel — Art. 5 Abs. 1 lit. c DSGVO | Gruppen-/Rollen-Claim im IdP auf die für SCM-Manager benötigten Gruppen beschränken (dedizierter Client-Scope bzw. gefilterter Mapper). Zusätzlich prüfen, ob `importRealmRoles` benötigt wird. | Betreiber |

## 5. Dokumentierte Restrisiken

| ID | Restrisiko | Bewertung | Behandlung |
|---|---|---|---|
| ~~**R-01**~~ | ~~Das ID Token wird nicht signaturgeprüft, ein `nonce` wird nicht verwendet.~~ | **Erledigt in 1.0.2:** Signatur, Issuer, Audience, Laufzeit und Nonce werden geprüft; ein ungültiges Token bricht die Anmeldung ab | — |
| ~~**R-02**~~ | ~~Der Payload des Access Tokens wird für den Rollenimport ohne Signaturprüfung gelesen.~~ | **Erledigt in 1.0.2:** Rollen werden nur aus einem signatur- und claimgeprüften Access Token importiert; andernfalls keine Rollen | — |
| **R-06** | Ohne JWKS-Endpunkt (manuelle Endpunkt-Konfiguration ohne `jwksUrl`) kann kein Token geprüft werden. In diesem Fall wird das ID Token verworfen und es werden keine Rollen aus dem Access Token importiert; der SSO-Logout erfolgt dann ohne `id_token_hint`. Ist ein Schlüsselsatz konfiguriert, aber nicht erreichbar, scheitert die Anmeldung (fail closed) — neue Abhängigkeit der Verfügbarkeit vom JWKS-Endpunkt. | bewusst gewählt: nicht überprüfbare Daten werden nicht verwendet | Discovery-URL nutzen oder `jwksUrl` konfigurieren; Erreichbarkeit des JWKS-Endpunkts überwachen (liegt in der Regel auf demselben Host wie der Authorization-Endpunkt); Warnungen des Plugins auswerten |
| **R-03** | In der Entwicklungs-Stage ist die TLS-Zertifikatsprüfung abgeschaltet. | im Produktivbetrieb nicht wirksam | Betriebsvorgabe: Produktivsysteme nie in der Entwicklungs-Stage betreiben |
| **R-04** | Wer `configuration:write:oauth2` besitzt, kann den IdP umkonfigurieren und damit faktisch Administratorrechte erlangen. | strukturell, nicht auflösbar | Recht wie ein Administratorrecht behandeln, restriktiv vergeben, Änderungen protokollieren/reviewen |
| **R-05** | Vertrauensmodell: Wer Gruppen im IdP pflegen kann, steuert über die Admin-Gruppe die Administratorrechte in SCM-Manager. Fällt der IdP aus, ist bei aktiviertem `forceLogin` keine Anmeldung möglich. | inhärent für SSO | Änderungen an der Admin-Gruppe im IdP der Änderungskontrolle unterwerfen; lokales Notfallkonto vorhalten und `forceLogin` bewusst wählen |

## 6. Nachweise

| Nachweis | Fundstelle |
|---|---|
| Datenflüsse, Speicherorte, Fristen | [PROZESS_BESCHREIBUNG.md](PROZESS_BESCHREIBUNG.md) |
| Risikobetrachtung für betroffene Personen | [DATENSCHUTZ_FOLGEABSCHAETZUNG.md](DATENSCHUTZ_FOLGEABSCHAETZUNG.md) |
| Umfang, Testabdeckung, Dokumentationsgrad | [SOURCECODE_STATISTIK.md](SOURCECODE_STATISTIK.md) |
| Sicherheitshinweise für den Betrieb | [../README_de.md](../README_de.md), Abschnitt „Sicherheitshinweise" |
| Änderungsverlauf | [../CHANGELOG.md](../CHANGELOG.md) |
| API-Dokumentation | [javadoc/index.html](javadoc/index.html) |
| Testergebnisse | `./gradlew test`, Berichte unter `build/reports/tests/test/` |
| Wirksamkeitsnachweis der Tokenprüfung (Art. 21 Abs. 2 lit. f NIS2) | Live-Verifikation am 17.08.2026 gegen die Keycloak-Testinstanz: Anmeldung, Prüfung von ID Token und Access Token (RS256), Rollenimport und RP-initiated Logout mit `id_token_hint` erfolgreich; der Verschlüsselungsschlüssel des Schlüsselsatzes wurde erwartungsgemäß übersprungen. Protokollauszug bei aktivem `DEBUG`-Level |

**Nächste Überprüfung:** bei jeder Änderung der verarbeiteten Claims, der Speicherorte oder der
Datenflüsse, mindestens jedoch bei jedem Minor-Release.
