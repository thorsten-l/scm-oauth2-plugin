# Sourcecode-Statistik — scm-oauth2-plugin

**Dokumentversion:** 1.1 · **Stand:** 17.08.2026 · **Softwarestand:** scm-oauth2-plugin 1.0.2
**Erhebungsbasis:** Arbeitskopie des Projektverzeichnisses, letzter Commit vom 10.08.2026

Quantitativer Nachweis über Umfang, Testabdeckung und Dokumentationsgrad der Codebasis. Dient als
Belegdokument für die Maßnahmen nach Art. 21 Abs. 2 lit. e und f NIS2
([Compliance-Bericht, Abschnitt 3](COMPLIANCE_BERICHT.md#3-prüfung-nach-nis2)). Alle Zahlen sind mit
den in [Abschnitt 8](#8-reproduktion-der-messung) angegebenen Befehlen reproduzierbar.

## 1. Umfang auf einen Blick

| Kennzahl | Wert |
|---|---|
| Quelldateien insgesamt (ohne generierte Artefakte) | 69 |
| Zeilen insgesamt | 8.970 |
| davon Code | 4.835 |
| davon Kommentar | 2.740 |
| davon leer | 1.228 |
| Java-Typen (Top-Level) | 40 |
| Öffentliche Member im Produktivcode | 71 |
| Automatisierte Tests | 185 (0 Fehler, 0 übersprungen) |
| Paketgröße `.smp` | 116 KB |

## 2. Verteilung nach Bereich

| Bereich | Dateien | Zeilen | Code | Kommentar | Leer | Kommentarquote |
|---|---|---|---|---|---|---|
| Java, Produktivcode | 42 | 5.236 | 2.513 | 2.122 | 601 | 45,8 % |
| Java, Tests | 18 | 2.982 | 1.929 | 460 | 593 | 19,3 % |
| Frontend (TypeScript/TSX) | 6 | 585 | 393 | 158 | 34 | 28,7 % |
| Ressourcen (JSON, XML) | 3 | 167 | — | — | — | — |
| **Summe** | **69** | **8.970** | **4.835** | **2.740** | **1.228** | **36,2 %** |

### Kommentarquote ohne Lizenzkopf

Jede Java- und TypeScript-Datei trägt einen 15-zeiligen AGPL-Lizenzkopf (66 Dateien = 990 Zeilen).
Ohne diesen Pflichtanteil ergibt sich der tatsächliche Dokumentationsgrad:

| Bereich | Fachkommentar | Code | Quote |
|---|---|---|---|
| Java, Produktivcode | 1.492 | 2.513 | **37,3 %** |
| Frontend | 68 | 393 | 14,8 % |
| Java, Tests | 190 | 1.929 | 9,0 % |

Der Produktivcode ist damit auf rund 3 Codezeilen mit 1 Zeile Erläuterung dokumentiert. **Alle 40
Java-Typen** besitzen Javadoc; von den 71 öffentlichen Membern sind 45 dokumentiert — die
verbleibenden sind überwiegend Injektions-Konstruktoren, deren Parameter sich unmittelbar aus
den Feldern ergeben. Zusätzlich beschreiben zwei `package-info.java` die Gesamtarchitektur
(180 Zeilen). Bei den Tests trägt der sprechende Methodenname den größten Teil der Dokumentation,
ergänzt um je eine Szenario-Beschreibung pro Testklasse.

## 3. Produktivcode nach Datei

| Datei | Zeilen | Aufgabe |
|---|---|---|
| `TokenVerifier.java` | 326 | Signatur- und Claim-Prüfung von ID Token und Access Token |
| `OAuth2AuthenticationResource.java` | 299 | Login- und Callback-Endpunkt, `state`-Prüfung, Nonce, Umleitungsvalidierung |
| `JwksClient.java` | 220 | Abruf des JSON Web Key Sets, Rekonstruktion der öffentlichen Schlüssel |
| `ConfigurationResource.java` | 205 | REST-API der Konfiguration, Secret- und URL-Behandlung |
| `AfterLogoutRedirectToIdp.java` | 200 | RP-initiated Logout |
| `JwsAlgorithm.java` | 185 | Algorithmen-Allowlist mit Bindung an den Schlüsseltyp |
| `OAuth2RestClient.java` | 183 | Token-Tausch und Userinfo-Abruf |
| `ForceOAuth2LoginFilter.java` | 169 | erzwungene Anmeldung |
| `StateStore.java` | 165 | offene Anmeldevorgänge: `state`, PKCE-Verifier, Nonce |
| `OAuth2Configuration.java` | 162 | Konfigurationsobjekt (21 Felder) |
| `GroupSynchronizer.java` | 161 | Gruppen und Mitgliedschaften |
| `Jws.java` | 159 | Zerlegen und Signaturprüfung eines Kompakt-JWS |
| `UserInfoMapper.java` | 153 | Claims → Benutzer und Gruppen |
| `DiscoveryClient.java` | 152 | OIDC-Discovery |
| `UserMigration.java` | 151 | Übernahme bestehender Konten |
| `package-info.java` (Hauptpaket) | 139 | Architektur- und Ablaufübersicht |
| `JwksProvider.java` | 137 | Schlüssel-Cache mit Erneuerung bei Schlüsselrotation |
| `AuthenticationInfoBuilder.java` | 132 | Orchestrierung der Anmeldung |
| `IndexConfigurationEnricher.java` | 128 | Verlinkung für das Frontend |
| `AccessTokenRoleReader.java` | 128 | Rollen aus dem geprüften Access Token |
| *weitere 22 Dateien* | je ≤ 117 | Endpunktauflösung, Wertobjekte, Stores, Erweiterungspunkte |

## 4. Struktur

| Merkmal | Anzahl | Bestandteile |
|---|---|---|
| Erweiterungspunkte des Kerns (`@Extension`) | 6 | Shiro-Realm, `GroupResolver`, `LogoutRedirection`, Index-Enricher, `ExternalAuthenticationAvailableNotifier`, Guice-Modul |
| Servlet-Filter (`@WebElement`) | 1 | `ForceOAuth2LoginFilter` |
| JAX-RS-Ressourcen | 2 | Authentifizierung, Konfiguration |
| REST-Endpunkte | 4 | 2 × anonym (Login, Callback), 2 × rechtegeschützt (Konfiguration lesen/schreiben) |
| Konfigurationsfelder | 21 | siehe [README](../README_de.md#konfiguration) |
| Berechtigungen | 2 | `configuration:read:oauth2`, `configuration:write:oauth2` |
| Persistente Speicher | 2 | `config/oauth2.xml`, `var/data/oauth2Groups/` |
| Flüchtige Speicher | 3 | `StateStore` (10 min), `IdTokenStore` (12 h), `JwksProvider` (1 h, keine personenbezogenen Daten) |
| Frontend-Komponenten | 4 | Login-Formular, Navigationslink, Konfigurationsseite, Konfigurationsformular |
| Übersetzungsschlüssel | 57 je Sprache | Deutsch und Englisch, vollständig paritätisch |

## 5. Tests

185 Tests in 17 Klassen, alle grün, keine übersprungen. Verhältnis Testcode zu Produktivcode:
**1.929 : 2.513 Zeilen = 0,77 : 1**.

| Testklasse | Tests | Prüfschwerpunkt |
|---|---|---|
| `GroupNameSanitizerTest` | 35 | Namensnormalisierung, Gegenprüfung gegen die Namensvalidierung des Kerns |
| `TokenVerifierTest` | 28 | Signatur- und Claim-Prüfung gegen echte RSA-, EC- und HMAC-Signaturen |
| `GroupSynchronizerTest` | 22 | Anlage, Mitgliedschaften, Robustheit bei Einzelfehlern |
| `OAuth2AuthenticationResourceTest` | 16 | `state`-Bindung, Einmaligkeit, Umleitungsziele, PKCE, Nonce, Fehlerbehandlung |
| `ConfigurationResourceTest` | 13 | Secret write-only, URL-Validierung, Pflichtfelder |
| `AccessTokenRoleReaderTest` | 9 | JSON-Pfade; keine Rollen ohne geprüftes Token |
| `JwksClientTest` | 8 | Rekonstruktion von RSA- und EC-Schlüsseln, Überspringen unbrauchbarer Schlüssel |
| `UserMigrationTest` | 9 | Kontoübernahme, Erhalt gespeicherter Attribute |
| `UserInfoMapperTest` | 7 | Claim-Auswertung, `sub`-Fallback, ungültige E-Mail |
| `ForceOAuth2LoginFilterTest` | 7 | Durchlass, gefälschtes Cookie, XHR-Behandlung |
| `AdminGroupSynchronizerTest` | 7 | Zuweisung und Entzug des Administratorrechts |
| `StateStoreTest` | 5 | Einmaligkeit, Ablauf, Eindeutigkeit |
| `JwksProviderTest` | 5 | Schlüssel-Cache, Erneuerung bei Schlüsselrotation, Ratenbegrenzung |
| `EndpointResolverTest` | 5 | manuelle Konfiguration, Discovery, Cache-Verhalten |
| `AfterLogoutRedirectToIdpTest` | 4 | Logout-URL mit und ohne `id_token_hint` |
| `DiscoveryClientTest` | 3 | Normalisierung der Discovery-URL |
| `AuthenticationInfoBuilderTest` | 2 | Zusammenspiel aller Anmeldeschritte; kein Aufbewahren eines ungeprüften ID Tokens |
| Frontend (Jest) | 1 | Testinfrastruktur |

**Abdeckung der Schutzmaßnahmen:** Für jede der 19 im
[Compliance-Bericht](COMPLIANCE_BERICHT.md#24-sicherheit-der-verarbeitung-art-32) genannten
Maßnahmen existiert mindestens ein Test oder eine strukturelle Zusicherung; die sicherheitsnahen
Tests machen mit 96 Fällen (`TokenVerifierTest`, `OAuth2AuthenticationResourceTest`,
`JwksClientTest`, `ForceOAuth2LoginFilterTest`, `ConfigurationResourceTest`, `StateStoreTest`,
`JwksProviderTest`, `AdminGroupSynchronizerTest`, `UserMigrationTest`) rund 52 % der Testfälle aus.

Die Signaturprüfung wird nicht gegen Mocks getestet, sondern gegen **echte Signaturen**: die Tests
erzeugen RSA- und EC-Schlüsselpaare, signieren die Tokens selbst und bauen den JSON Web Key Set
dazu nach (`TestTokens`). Damit sind auch die Angriffsfälle abgedeckt — `alg: none`, fremder
Schlüssel, fremdes Secret, manipulierte Signatur, fremder Aussteller, fremde Audience, abgelaufenes
Token, falscher und fehlender Nonce.

## 6. Abhängigkeiten und Lieferkette

| Ebene | Umfang |
|---|---|
| Laufzeit (Java) | **keine eigenen Abhängigkeiten** — der `dependencies`-Block ist leer; genutzt werden ausschließlich die vom SCM-Manager-Kern bereitgestellten Bibliotheken (Shiro, Jackson, Guava, Guice, JAX-RS). Die Signaturprüfung ist bewusst mit den Krypto-Primitiven des JDK umgesetzt (`java.security`, `javax.crypto`) statt mit einer JWT-Bibliothek, damit diese Eigenschaft erhalten bleibt |
| Build (Java) | `org.scm-manager.smp` 0.18.0, Ziel-Kernversion 3.9.0, Lombok 1.18.46 (bewusst auf eine JDK-taugliche Version fixiert), MapStruct über das smp-Plugin |
| Frontend | 19 Laufzeit- und 19 Entwicklungsabhängigkeiten laut `package.json`, 1 Resolution; alle aus dem SCM-Manager-UI-Ökosystem bzw. dem React-Umfeld |
| Lizenz | AGPL-3.0-only; Lizenzkopf in allen 66 Java- und TypeScript-Dateien sowie in `permissions.xml`, geprüft durch `./gradlew checkLicenses` |

Die leere Laufzeit-Abhängigkeitsliste ist für die Lieferkettensicherheit (Art. 21 Abs. 2 lit. d
NIS2) der wesentliche Punkt: das Plugin vergrößert die Angriffsfläche des Kerns nicht um
zusätzliche Fremdbibliotheken.

## 7. Artefakte und Historie

| Artefakt | Wert |
|---|---|
| Plugin-Paket `scm-oauth2-plugin.smp` | 116 KB |
| API-Dokumentation `docs/javadoc` | 47 HTML-Seiten, 67 Dateien, 920 KB |
| Betriebsdokumentation | `README.md` (englisch), `README_de.md` (deutsch), inhaltlich paritätisch |
| Compliance-Dokumentation | 4 Dokumente in `docs/` |
| Commits | 9 Commits bis 10.08.2026 plus die Änderungen des Release 1.0.2 |
| Freigaben | Tag `v1.0.1`, Release 1.0.2 vom 17.08.2026 |
| Qualitätssicherung im Build | `checkLicenses`, `validate`, `validatePluginJson`, `test`, `ui-test`, Javadoc ohne Warnungen |

## 8. Reproduktion der Messung

Alle Zahlen dieses Dokuments entstehen aus der Arbeitskopie. Ausführung im Plugin-Verzeichnis:

```bash
# Zeilen je Bereich
find src/main/java -name '*.java' | wc -l
find src/main/java -name '*.java' -exec cat {} + | wc -l

# Klassifikation Code / Kommentar / Leerzeile
find src/main/java -name '*.java' -exec cat {} + | awk '
  BEGIN{code=0;com=0;blank=0;inblock=0}
  {
    line=$0; gsub(/^[ \t]+|[ \t]+$/,"",line);
    if (inblock) { com++; if (line ~ /\*\//) inblock=0; next }
    if (line == "") { blank++; next }
    if (line ~ /^\/\*/) { com++; if (line !~ /\*\//) inblock=1; next }
    if (line ~ /^\/\//) { com++; next }
    if (line ~ /^\*/)  { com++; next }
    code++
  }
  END{printf "code=%d comment=%d blank=%d\n", code, com, blank}'

# Testanzahl und Ergebnis
./gradlew test
grep -h -o 'tests="[0-9]*"' build/test-results/test/*.xml | awk -F'"' '{s+=$2} END {print s}'

# Struktur
grep -rl "@Extension" src/main/java --include='*.java' | grep -v package-info | wc -l
grep -cE "^  private (String|boolean) " src/main/java/de/l9g/scm/oauth2/plugin/OAuth2Configuration.java

# Artefakte
./gradlew smp && ls -lh build/libs/*.smp
./gradlew javadoc -Pstage=release && find docs/javadoc -type f | wc -l
```

**Methodische Hinweise:** Die Klassifikation ist zeilenbasiert und ordnet eine Zeile mit Code und
nachgestelltem Kommentar dem Code zu; Kommentare innerhalb von Zeichenketten werden nicht erkannt
(im vorliegenden Code nicht vorhanden). Generierte Artefakte (`build/`, `node_modules/`,
`docs/javadoc/`) sind in den Zeilenzahlen der Abschnitte 1 bis 3 nicht enthalten.

---

**Weiterführend:** [Prozessbeschreibung](PROZESS_BESCHREIBUNG.md) ·
[Compliance-Bericht](COMPLIANCE_BERICHT.md) ·
[Datenschutz-Folgenabschätzung](DATENSCHUTZ_FOLGEABSCHAETZUNG.md)
