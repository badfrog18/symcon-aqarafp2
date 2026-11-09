# Aqara FP2 für IP-Symcon (HomeKit lokal)

Bindet den Aqara Präsenzsensor FP2 **direkt und lokal** über das HomeKit Accessory Protocol (HAP) in IP-Symcon ein – ohne Cloud, ohne Home Assistant, ohne Apple-Gerät. Das Modul ist selbst ein HomeKit-Controller (Pair-Setup mit SRP-6a, Pair-Verify mit X25519/Ed25519, verschlüsselte Sitzung mit ChaCha20-Poly1305).

## Was angelegt wird

Beim Koppeln liest das Modul die HomeKit-Struktur des FP2 und legt für **jeden lesbaren Wert** eine Variable an:

- **Anwesenheit je Zone** (inkl. Gesamtbereich) – `~Presence`, Name = Zonenname aus der Aqara-App
- **Helligkeit** in Lux – `~Illumination.F`
- Status-Werte, falls vom Gerät angeboten (Aktiv, Störung, …)
- Geräteinformation: Hersteller, Modell, Seriennummer, Firmware, Hardware-Version
- **Erreichbar** – Verbindungsstatus

Werte mit Ereignis-Fähigkeit werden zyklisch gelesen (Standard: alle 2 s), statische Werte einmalig. Unbekannte (herstellerspezifische) Werte werden generisch angelegt. Variablen werden nie gelöscht, nur angelegt bzw. aktualisiert.

> Personenanzahl und Positionsdaten liefert der FP2 nicht über HomeKit, sondern nur über die Aqara-Cloud.

## Voraussetzungen

- IP-Symcon ab 7.0 (PHP-Erweiterungen `gmp` und `sodium`, sind enthalten)
- FP2 im selben Netz, mDNS (UDP 5353) und der HAP-Port erreichbar
- HomeKit-Setup-Code des FP2 (Aufkleber am Gerät/Verpackung oder Aqara-App)

## Einrichtung

1. **FP2 aus bestehendem HomeKit-Controller entfernen** (Home Assistant: Gerät der Integration *HomeKit Device* löschen; Apple Home: Gerät entfernen). Ein HomeKit-Gerät nimmt nur eine Erstkopplung an.
2. Instanz *AqaraFP2* anlegen, IP-Adresse prüfen.
3. **Gerät suchen (mDNS)** → Kopplungsstatus muss „frei – bereit zum Koppeln“ zeigen.
4. Unter *Kopplung* den Setup-Code eingeben und **Koppeln** drücken. Die Variablen werden automatisch angelegt.

Der HAP-Port ändert sich nach einem Neustart des FP2; das Modul findet ihn per mDNS selbst (Port = 0).

## Funktionen

| Funktion | Beschreibung |
|---|---|
| `AQFP2_Update(int $id)` | Werte sofort lesen |
| `AQFP2_RebuildVariables(int $id)` | Struktur neu einlesen (z. B. nach neuen Zonen in der Aqara-App) |
| `AQFP2_Discover(int $id)` | mDNS-Suche, zeigt Port und Kopplungsstatus |
| `AQFP2_Pair(int $id, string $SetupCode)` | Koppeln |
| `AQFP2_Unpair(int $id)` | Kopplung am Gerät entfernen |
| `AQFP2_ForgetPairing(int $id)` | Kopplungsdaten nur lokal löschen |

## Hinweise

- Neue oder umbenannte Zonen in der Aqara-App → **Variablen neu einlesen**.
- Status 203 „Kopplung ungültig“: Der FP2 wurde zurückgesetzt oder anderweitig entkoppelt → Kopplungsdaten verwerfen und neu koppeln.
