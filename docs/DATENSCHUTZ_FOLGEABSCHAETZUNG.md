# Datenschutz-Folgenabschätzung — scm-oauth2-plugin

**Dokumentversion:** 1.1 · **Stand:** 17.08.2026 · **Softwarestand:** scm-oauth2-plugin 1.0.2
**Verarbeitung:** Authentifizierung und Zugriffssteuerung für SCM-Manager über einen
OAuth2/OIDC-Identity-Provider
**Rechtsgrundlage der Prüfung:** Art. 35 DSGVO

> **Status dieses Dokuments:** Bereitgestellt wird die **technische Hälfte** einer DSFA — Beschreibung
> der Verarbeitung, Risikobetrachtung aus Sicht der betroffenen Personen und die im Produkt
> umgesetzten Abhilfemaßnahmen. Eine DSFA ist nach Art. 35 Abs. 1 DSGVO Aufgabe des
> **Verantwortlichen**; die in Abschnitt 7 offen gelassenen Felder (Rechtsgrundlage,
> Erforderlichkeitsprüfung im konkreten Kontext, Fristen, Beteiligung des
> Datenschutzbeauftragten nach Art. 35 Abs. 2, ggf. Standpunkt der betroffenen Personen nach
> Art. 35 Abs. 9) sind dort auszufüllen. Kein Ersatz für Rechtsberatung.

## 1. Schwellwertanalyse — ist eine DSFA verpflichtend?

| Prüfpunkt | Ergebnis |
|---|---|
| Systematische umfassende Bewertung persönlicher Aspekte, automatisierte Entscheidung mit erheblicher Auswirkung (Art. 35 Abs. 3 lit. a) | **nein** — kein Profiling, keine Bewertung von Verhalten oder Leistung; die einzige Automatik ist die Zuordnung von Zugriffsrechten anhand vorhandener Gruppenzugehörigkeiten |
| Umfangreiche Verarbeitung besonderer Kategorien (lit. b) | **nein**, sofern der Gruppen-Claim keine Angaben nach Art. 9 transportiert (Bedingung, siehe Risiko **RI-05**) |
| Systematische umfangreiche Überwachung öffentlich zugänglicher Bereiche (lit. c) | **nein** |
| Einsatz neuer Technologien mit hohem Risiko | **nein** — etablierte Standards (RFC 6749, 7636, 9700, OIDC Core) |
| Kriterien der DSK-Liste („Muss-Liste") | keines der Regelbeispiele erfüllt; die Verarbeitung ist eine Zugangskontrolle im Rahmen der IT-Nutzung |
| Betroffene Personen | Beschäftigte bzw. berechtigte Nutzer der Instanz — abgrenzbarer, dem Verantwortlichen bekannter Personenkreis |

**Ergebnis:** Eine DSFA ist nach hiesiger Einschätzung **nicht zwingend erforderlich**. Die
Verarbeitung erfolgt jedoch im Beschäftigungskontext, betrifft alle Nutzer der Instanz und steuert
Zugriffsrechte auf Quellcode; die nachfolgende Betrachtung wird daher **freiwillig** durchgeführt
und dient zugleich der Erfüllung der Rechenschaftspflicht (Art. 5 Abs. 2 DSGVO). Fällt die Prüfung
in Abschnitt 7 beim Verantwortlichen anders aus (etwa wegen Art. 9-Bezug im Gruppen-Claim), ist sie
als vollwertige DSFA fortzuschreiben.

## 2. Systematische Beschreibung der Verarbeitung (Art. 35 Abs. 7 lit. a)

Die vollständige technische Beschreibung ist ausgelagert:
**[PROZESS_BESCHREIBUNG.md](PROZESS_BESCHREIBUNG.md)**. Kurzfassung:

| Merkmal | Angabe |
|---|---|
| Verarbeitungsvorgänge | Anmeldung (Authorization Code Flow mit PKCE), Kontobereitstellung/-migration, Gruppen- und Rechtesynchronisation, Autorisierung, Abmeldung, Administration |
| Datenkategorien | Benutzerkennung, Anzeigename, E-Mail-Adresse, Gruppen-/Rollenzugehörigkeiten, technische Tokens, Anmeldezeitpunkte in Protokollen |
| Betroffene Personen | alle Nutzer der SCM-Manager-Instanz |
| Verarbeitungsort | ausschließlich die Instanz des Verantwortlichen; keine Übermittlung an den Hersteller, keine Telemetrie |
| Empfänger | ausschließlich der konfigurierte IdP |
| Speicherdauer | Konfiguration und Gruppenliste bis zur Änderung/Löschung; ID Token max. 12 h im Arbeitsspeicher; Anmeldevorgänge max. 10 min; Protokolle nach Konzept des Betreibers |
| Automatisierte Einzelentscheidung | Zuweisung/Entzug von Zugriffsrechten anhand der Gruppenzugehörigkeit (kein Fall des Art. 22 Abs. 1 nach hiesiger Einschätzung) |

## 3. Erforderlichkeit und Verhältnismäßigkeit (Art. 35 Abs. 7 lit. b)

| Frage | Bewertung |
|---|---|
| Ist die Verarbeitung zur Zweckerreichung erforderlich? | Ja. Ein Zugriff auf Repositories ohne Authentifizierung und Autorisierung ist nicht möglich; die verarbeiteten Daten sind das Minimum für Kontoidentität und Rechtezuordnung. |
| Gibt es ein milderes Mittel? | Die lokale Benutzerverwaltung wäre kein milderes Mittel: sie erfordert dieselben Daten, zusätzlich lokale Passwörter (eigenes Risiko) und verhindert den zentralen Rechteentzug beim Offboarding. SSO reduziert die Zahl der Stellen, an denen Anmeldedaten verarbeitet werden. |
| Ist die Datenmenge angemessen? | Grundsätzlich ja — mit **Einschränkung** bei Gruppen-/Rollenlisten, die über Zugriffsgruppen hinausgehen (Befund B-03, Risiko **RI-05**). |
| Ist die Speicherdauer angemessen? | Ja für alle flüchtigen Daten. **Einschränkung** bei der Gruppendatei nach Kontolöschung (Befund B-01, Risiko **RI-04**). |
| Transparenz | Der Anmeldevorgang ist für die betroffene Person sichtbar (Umleitung zum IdP, benannter Provider auf der Schaltfläche). Informationspflichten nach Art. 13 erfüllt der Verantwortliche. |

## 4. Risikobetrachtung (Art. 35 Abs. 7 lit. c)

Bewertet wird das Risiko **für die Rechte und Freiheiten der betroffenen Personen**, jeweils nach
Umsetzung der im Produkt vorhandenen Maßnahmen (Restrisiko). Skala: gering / mittel / hoch.

| ID | Risiko / Schadensszenario | Ursache | Eintritt | Schwere | Restrisiko |
|---|---|---|---|---|---|
| **RI-01** | Fremdübernahme des Kontos: Angreifer verknüpft seine IdP-Identität mit der Sitzung der betroffenen Person (Login-CSRF) und handelt unter deren Namen | manipulierter Rücksprung auf den Callback | gering | hoch | **gering** |
| **RI-02** | Abfangen des Autorisierungscodes und Einlösung durch Dritte | offener Redirect, Code-Interception | gering | hoch | **gering** |
| **RI-03** | Unbefugte Rechteausweitung: eine Person erhält Administratorrechte und damit Zugriff auf fremden Quellcode | fehlerhafte Gruppenpflege im IdP, kompromittiertes Konto mit Konfigurationsschreibrecht | mittel | hoch | **mittel** |
| **RI-04** | Weiterverarbeitung nach Ausscheiden: Gruppenzugehörigkeiten bleiben nach Kontolöschung gespeichert | keine Kaskadenlöschung der Datei je Benutzer | hoch | gering | **mittel** |
| **RI-05** | Zweckentfremdung von Organisations- und Beschäftigungsmerkmalen, die über den Gruppen-Claim mitgeliefert werden (z. B. Fakultät, Beschäftigtenart, Standort); im Extremfall Merkmale nach Art. 9 | Gruppen-Claim des IdP nicht auf Zugriffsgruppen begrenzt | mittel | mittel | **mittel** |
| **RI-06** | Offenlegung von Benutzerkennungen und Gruppennamen gegenüber Personen mit Log-Zugriff | Protokollierung auf `INFO` | mittel | gering | **gering** |
| **RI-07** | Übernahme eines lokalen Kontos durch eine gleichnamige IdP-Identität | Namenskollision zwischen lokaler und IdP-Kennung | gering | hoch | **gering** |
| **RI-08** | Vertraulichkeitsverlust der Identitätsdaten auf dem Transportweg | fehlende oder unwirksame TLS-Prüfung | gering | hoch | **gering** |
| **RI-09** | Aussperrung berechtigter Personen (Verfügbarkeit als Betroffenenbelang) | Ausfall des IdP bei aktiviertem `forceLogin`; nicht erreichbarer JWKS-Endpunkt bei vorhandenem ID Token (fail closed) | mittel | mittel | **mittel** |
| **RI-10** | Offenlegung des Client-Secrets und damit Angriff auf die Kopplung | Auslesen der Konfiguration oder eines Backups | gering | hoch | **gering** |
| **RI-11** | Untergeschobenes oder wiederverwendetes Token: eine gefälschte oder aus einer anderen Sitzung stammende Identitätsaussage führt zur Anmeldung unter fremdem Namen oder zu fremden Rollen | fehlende Signatur-, Aussteller- oder Nonce-Prüfung | gering | hoch | **gering** |

## 5. Abhilfemaßnahmen (Art. 35 Abs. 7 lit. d)

### 5.1 Im Produkt umgesetzt

| Risiko | Maßnahme im Code |
|---|---|
| RI-01 | `state` wird an den Browser gebunden (`HttpOnly`-Cookie `X-SCM-OAuth2-State`), zeitkonstant verglichen und ist **einmalig** einlösbar; abweichende oder unbekannte Werte führen zu HTTP 401 |
| RI-02 | PKCE mit S256 — der Verifier verlässt den Server nie; Umleitungsziele werden auf instanzinterne Pfade begrenzt (`//host`, `/\`, CR/LF werden abgewiesen); der Code wird ausschließlich Server-zu-Server eingelöst |
| RI-03 | Rechtevergabe beschränkt auf die Einzelberechtigung `*` des betroffenen Benutzers; **automatischer Entzug**, sobald die Gruppe fehlt; Zugriff auf die Konfiguration nur mit dedizierter Berechtigung; Endpunkt-URLs auf `http`/`https` mit Host begrenzt |
| RI-04 | Speicherstruktur ist gezielt löschbar (eine Datei je Benutzer, Dateiname = Kennung); flüchtige Speicher laufen selbsttätig ab (10 min / 12 h) |
| RI-05 | Nur die konfigurierten Claims werden gelesen; der Rollenimport aus dem Access Token ist standardmäßig **aus** |
| RI-06 | Die E-Mail-Adresse wird nicht mehr protokolliert; bei einer ungültigen Adresse nennt die Meldung nur Benutzerkennung und Länge des Wertes |
| RI-06 | Tokens, `code`, `state`, Verifier und Secret werden nie protokolliert; IdP-Fehlertexte gelangen nicht zum Browser |
| RI-07 | Konten mit lokalem Passwort werden **nicht** übernommen, solange `migrateLocalUsers` nicht ausdrücklich gesetzt ist; bei Übernahme wird das lokale Passwort entfernt, damit kein zweiter Zugangsweg bestehen bleibt |
| RI-08 | TLS-Zertifikatsprüfung im Produktivbetrieb immer aktiv (Abschaltung nur in der Entwicklungs-Stage) |
| RI-09 | `forceLogin` ist standardmäßig **aus**, die klassische Anmeldung bleibt damit als Rückfallweg verfügbar; die Abmeldung funktioniert auch ohne verfügbares ID Token |
| RI-10 | Client-Secret wird verschlüsselt gespeichert, von der API nie ausgeliefert und bei leerer Eingabe unverändert beibehalten |
| RI-11 | Signatur des ID Tokens wird gegen den JWKS des IdP bzw. das Client-Secret geprüft, `alg: none` und unbekannte Verfahren werden abgewiesen, der Algorithmus bestimmt den Schlüsseltyp; zusätzlich werden `iss`, `aud`/`azp`, Laufzeit und der Nonce dieser Anmeldung geprüft. Rollen werden nur aus einem geprüften Access Token übernommen. Ein vorhandenes, aber ungültiges ID Token bricht die Anmeldung ab. |

Die Wirksamkeit ist durch gezielte Tests belegt (u. a. fehlendes/abweichendes `state`-Cookie,
Wiederverwendung eines `state`, Umleitung auf einen Fremdhost, gefälschtes Access-Token-Cookie,
Ablehnung lokaler Konten, Geheimnisbehandlung) — siehe
[SOURCECODE_STATISTIK.md](SOURCECODE_STATISTIK.md).

### 5.2 Vom Verantwortlichen umzusetzen

| Risiko | Erforderliche Maßnahme | Priorität |
|---|---|---|
| RI-04 | Löschung von `var/data/oauth2Groups/<kennung>.xml` in den Offboarding-Prozess aufnehmen; Umsetzung einer automatischen Löschung im Plugin anstoßen (Befund B-01) | hoch |
| RI-05 | Gruppen-/Rollen-Claim im IdP auf die für SCM-Manager erforderlichen Gruppen begrenzen (eigener Client-Scope bzw. gefilterter Mapper); prüfen, ob `importRealmRoles` benötigt wird (Befund B-03) | hoch |
| RI-03 | `configuration:write:oauth2` wie ein Administratorrecht behandeln; Änderungen an der Admin-Gruppe im IdP der Änderungskontrolle unterwerfen | hoch |
| RI-06 | Log-Level, Zugriff auf Protokolldateien und Aufbewahrungsfrist festlegen | mittel |
| RI-11 | Discovery-URL verwenden oder `jwksUrl` konfigurieren, damit die Tokenprüfung greifen kann; Warnungen des Plugins zur fehlenden Schlüsselquelle auswerten | hoch |
| RI-09 | Notfallzugang ohne SSO vorhalten (lokales Administratorkonto), Verfügbarkeit von IdP und JWKS-Endpunkt im Notfallkonzept berücksichtigen | mittel |
| RI-08 | Produktivsysteme nie in der Entwicklungs-Stage betreiben; Zertifikatsverwaltung des IdP prüfen | mittel |
| RI-10 | Zugriffsschutz auf das Heimatverzeichnis und die Backups; Secret bei Verdacht im IdP rotieren | mittel |
| alle | Informationspflichten nach Art. 13, Eintrag im Verzeichnis nach Art. 30, ggf. Beteiligung des Betriebs-/Personalrats (in Deutschland regelmäßig § 87 Abs. 1 Nr. 6 BetrVG bzw. landesrechtliche Entsprechung) | hoch |

## 6. Bewertung des Restrisikos

Nach Umsetzung der Maßnahmen aus 5.1 und 5.2 verbleiben **keine hohen Risiken**. Die drei
mittleren Restrisiken (RI-03, RI-04, RI-05) sind sämtlich durch Konfiguration und
Betriebsorganisation beherrschbar; RI-04 und RI-05 werden mit den Befunden B-01 und B-03
adressiert.

Gegenüber Version 1.0 dieses Dokuments ist RI-11 (untergeschobene Tokens) neu aufgenommen und
unmittelbar auf **gering** gesenkt, weil die Tokenprüfung in 1.0.2 implementiert wurde; RI-06 ist
durch den Verzicht auf die Protokollierung der E-Mail-Adresse weiter reduziert. Voraussetzung für
die Wirksamkeit der Tokenprüfung ist eine erreichbare Schlüsselquelle (Discovery-URL oder
`jwksUrl`).

Eine **vorherige Konsultation der Aufsichtsbehörde nach Art. 36 DSGVO** ist danach nicht
erforderlich.

## 7. Auszufüllen durch den Verantwortlichen

| Feld | Eintrag |
|---|---|
| Verantwortlicher (Name, Anschrift, Kontakt) | |
| Datenschutzbeauftragte(r), Datum der Beteiligung nach Art. 35 Abs. 2 | |
| Bezeichnung der Instanz, Basis-URL | |
| Identity Provider (Produkt, Betreiber, Standort der Verarbeitung) | |
| Drittlandbezug, Übermittlungsgrundlage nach Kapitel V | |
| Rechtsgrundlage der Verarbeitung (Art. 6 Abs. 1; ggf. § 26 BDSG / landesrechtliche Norm) | |
| Kreis der betroffenen Personen, Anzahl | |
| Löschfristen: Benutzerkonto, Gruppendatei, Protokolldateien | |
| Beteiligung des Betriebs-/Personalrats | |
| Standpunkt der betroffenen Personen (Art. 35 Abs. 9), soweit eingeholt | |
| Ergebnis der Erforderlichkeitsprüfung im konkreten Kontext | |
| Abweichungen von Abschnitt 1 (Schwellwert) mit Begründung | |
| Freigabe (Name, Funktion, Datum) | |
| Termin der Überprüfung (Art. 35 Abs. 11) | |

## 8. Überprüfung

Die Abschätzung ist fortzuschreiben bei:

* Änderung der gelesenen Claims oder der Speicherorte (siehe [CHANGELOG](../CHANGELOG.md))
* Wechsel des Signaturverfahrens des IdP oder Wegfall der Schlüsselquelle (`jwksUrl`)
* Aktivierung von `forceLogin`, `ssoLogout`, `importRealmRoles` oder `migrateLocalUsers`
* Wechsel des Identity Providers oder Verlagerung seiner Verarbeitung in ein Drittland
* Erweiterung des Gruppen-/Rollen-Claims im IdP
* mindestens jedoch alle zwei Jahre

---

**Weiterführend:** [Prozessbeschreibung](PROZESS_BESCHREIBUNG.md) ·
[Compliance-Bericht](COMPLIANCE_BERICHT.md) · [Sourcecode-Statistik](SOURCECODE_STATISTIK.md)
