<?php

declare(strict_types=1);

require_once __DIR__ . '/../libs/HAPClient.php';

class AqaraFP2 extends IPSModule
{
    private const STATUS_NOT_PAIRED = 201;
    private const STATUS_UNREACHABLE = 202;
    private const STATUS_PAIRING_INVALID = 203;

    // HomeKit-Service-Typen
    private const SERVICES = [
        '3E'  => 'Geräteinformation',
        '86'  => 'Anwesenheit',
        '84'  => 'Helligkeit',
        '85'  => 'Bewegung',
        '96'  => 'Batterie',
        'A2'  => 'Protokoll',
    ];

    // HomeKit-Characteristic-Typen: [Name, Profil, Variablentyp erzwingen (null = aus Format), primär]
    private const CHARS = [
        '20'  => ['Hersteller', '', null, false],
        '21'  => ['Modell', '', null, false],
        '23'  => ['Name', '', null, false],
        '30'  => ['Seriennummer', '', null, false],
        '52'  => ['Firmware', '', null, false],
        '53'  => ['Hardware-Version', '', null, false],
        '37'  => ['HAP-Version', '', null, false],
        'E3'  => ['Konfigurierter Name', '', null, false],
        '71'  => ['Anwesenheit', '~Presence', VARIABLETYPE_BOOLEAN, true],
        '22'  => ['Bewegung', '~Motion', VARIABLETYPE_BOOLEAN, true],
        '6B'  => ['Helligkeit', '~Illumination.F', VARIABLETYPE_FLOAT, true],
        '75'  => ['Aktiv', '', VARIABLETYPE_BOOLEAN, false],
        '77'  => ['Störung', '~Alert', VARIABLETYPE_BOOLEAN, false],
        '7A'  => ['Manipulation', '~Alert', VARIABLETYPE_BOOLEAN, false],
        '79'  => ['Batterie schwach', '~Battery', VARIABLETYPE_BOOLEAN, false],
        '68'  => ['Batteriestand', '~Battery.100', VARIABLETYPE_INTEGER, true],
        '11'  => ['Temperatur', '~Temperature', VARIABLETYPE_FLOAT, true],
        '10'  => ['Luftfeuchte', '~Humidity.F', VARIABLETYPE_FLOAT, true],
    ];

    // Nicht als Variable abbilden
    private const SKIP_CHARS = ['14', 'A6', '220', 'A5'];

    public function Create()
    {
        parent::Create();

        $this->RegisterPropertyString('Host', '192.168.178.28');
        $this->RegisterPropertyInteger('Port', 0);
        $this->RegisterPropertyInteger('Interval', 2);

        $this->RegisterAttributeString('ControllerID', '');
        $this->RegisterAttributeString('ControllerLTSK', '');
        $this->RegisterAttributeString('ControllerLTPK', '');
        $this->RegisterAttributeString('AccessoryID', '');
        $this->RegisterAttributeString('AccessoryLTPK', '');
        $this->RegisterAttributeInteger('CachedPort', 0);
        $this->RegisterAttributeString('PollList', '[]');

        $this->RegisterTimer('Update', 0, 'AQFP2_Update($_IPS[\'TARGET\']);');
    }

    public function ApplyChanges()
    {
        parent::ApplyChanges();

        $this->RegisterVariableBoolean('Reachable', $this->Translate('Erreichbar'), '~Alert.Reversed', 0);

        if ($this->IsPaired()) {
            $this->SetTimerInterval('Update', max(1, $this->ReadPropertyInteger('Interval')) * 1000);
            if ($this->GetStatus() === self::STATUS_NOT_PAIRED || $this->GetStatus() < 102) {
                $this->SetStatus(IS_ACTIVE);
            }
        } else {
            $this->SetTimerInterval('Update', 0);
            $this->SetStatus(self::STATUS_NOT_PAIRED);
        }
    }

    public function GetConfigurationForm()
    {
        $form = json_decode(file_get_contents(__DIR__ . '/form.json'), true);
        $info = $this->IsPaired()
            ? sprintf('Gekoppelt mit Gerät %s (Controller-ID %s)', $this->ReadAttributeString('AccessoryID'), $this->ReadAttributeString('ControllerID'))
            : 'Nicht gekoppelt – Setup-Code eingeben und „Koppeln“ drücken.';
        foreach ($form['actions'] as &$a) {
            if (($a['name'] ?? '') === 'PairingInfo') {
                $a['caption'] = $info;
            }
        }
        return json_encode($form);
    }

    // ------------------------------------------------------------------ öffentliche Funktionen

    /** Sucht den FP2 per mDNS und zeigt Port und Kopplungsstatus. */
    public function Discover(): string
    {
        $q = FP2mDNS::query($this->ReadPropertyString('Host'));
        if ($q === null) {
            return 'Keine HomeKit-Antwort von ' . $this->ReadPropertyString('Host') . ' (mDNS/UDP 5353).';
        }
        $this->WriteAttributeInteger('CachedPort', $q['port']);
        $t = $q['txt'];
        return sprintf(
            "Gefunden: %s\nHAP-Port: %d\nModell: %s\nGeräte-ID: %s\nKonfig.-Nummer: %s\nKopplungsstatus: %s",
            $q['name'],
            $q['port'],
            $t['md'] ?? '?',
            $t['id'] ?? '?',
            $t['c#'] ?? '?',
            (($t['sf'] ?? '') === '1') ? 'frei – bereit zum Koppeln' : 'bereits mit einem Controller gekoppelt'
        );
    }

    /** Koppelt den FP2 mit diesem Modul (HomeKit-Setup-Code, z. B. 123-45-678). */
    public function Pair(string $SetupCode): string
    {
        $digits = preg_replace('/\D/', '', $SetupCode);
        if (strlen($digits) !== 8) {
            return 'Der Setup-Code muss 8 Ziffern haben (Format 123-45-678).';
        }
        $code = substr($digits, 0, 3) . '-' . substr($digits, 3, 2) . '-' . substr($digits, 5, 3);

        // Controller-Identität (einmalig)
        if ($this->ReadAttributeString('ControllerID') === '') {
            $kp = sodium_crypto_sign_keypair();
            $this->WriteAttributeString('ControllerID', $this->uuid());
            $this->WriteAttributeString('ControllerLTSK', bin2hex(sodium_crypto_sign_secretkey($kp)));
            $this->WriteAttributeString('ControllerLTPK', bin2hex(sodium_crypto_sign_publickey($kp)));
        }

        if (!IPS_SemaphoreEnter($this->sem(), 15000)) {
            return 'Modul beschäftigt, bitte erneut versuchen.';
        }
        try {
            $port = $this->resolvePort(true);
            $s = new FP2HAPSession($this->ReadPropertyString('Host'), $port, 10.0);
            $acc = $s->pairSetup(
                $code,
                $this->ReadAttributeString('ControllerID'),
                hex2bin($this->ReadAttributeString('ControllerLTSK')),
                hex2bin($this->ReadAttributeString('ControllerLTPK'))
            );
            $s->close();
            $this->WriteAttributeString('AccessoryID', $acc['id']);
            $this->WriteAttributeString('AccessoryLTPK', bin2hex($acc['ltpk']));
        } catch (Throwable $e) {
            $this->SendDebug('Pair', $e->getMessage(), 0);
            return 'Kopplung fehlgeschlagen: ' . $e->getMessage();
        } finally {
            IPS_SemaphoreLeave($this->sem());
        }

        $msg = 'Erfolgreich gekoppelt mit ' . $acc['id'] . '.';
        try {
            $msg .= "\n" . $this->RebuildVariables();
        } catch (Throwable $e) {
            $msg .= "\nVariablen konnten noch nicht angelegt werden: " . $e->getMessage();
        }
        $this->ApplyChanges();
        $this->ReloadForm();
        return $msg;
    }

    /** Entfernt die Kopplung am Gerät und lokal. */
    public function Unpair(): string
    {
        if (!$this->IsPaired()) {
            return 'Nicht gekoppelt.';
        }
        try {
            $this->withSession(function (FP2HAPSession $s) {
                $s->removePairing($this->ReadAttributeString('ControllerID'));
            });
        } catch (Throwable $e) {
            return 'Entkoppeln am Gerät fehlgeschlagen: ' . $e->getMessage() . "\nMit „Kopplungsdaten verwerfen“ kann die Kopplung nur lokal gelöscht werden.";
        }
        $this->ForgetPairing();
        return 'Kopplung entfernt. Der FP2 kann jetzt wieder in Home Assistant oder Apple Home eingebunden werden.';
    }

    /** Löscht nur die lokal gespeicherten Kopplungsdaten (z. B. wenn der FP2 zurückgesetzt wurde). */
    public function ForgetPairing(): void
    {
        $this->WriteAttributeString('AccessoryID', '');
        $this->WriteAttributeString('AccessoryLTPK', '');
        $this->WriteAttributeString('PollList', '[]');
        $this->ApplyChanges();
        $this->ReloadForm();
    }

    /** Liest die Gerätestruktur und legt für alle Werte Variablen an (nichts wird gelöscht). */
    public function RebuildVariables(): string
    {
        $accessories = $this->withSession(function (FP2HAPSession $s) {
            return $s->getAccessories();
        });
        $this->SendDebug('Accessories', json_encode($accessories), 0);

        $poll = [];
        $count = 0;
        $pos = 10;
        $multiAcc = count($accessories) > 1;
        foreach ($accessories as $acc) {
            $aid = (int) $acc['aid'];
            foreach ($acc['services'] ?? [] as $svc) {
                $sType = $this->normType((string) ($svc['type'] ?? ''));
                if ($sType === 'A2') {
                    continue; // Protokollinformation
                }
                $label = $this->serviceLabel($svc, $sType);
                if ($multiAcc) {
                    $label = 'Zubehör ' . $aid . ' ' . $label;
                }
                foreach ($svc['characteristics'] ?? [] as $ch) {
                    $cType = $this->normType((string) ($ch['type'] ?? ''));
                    $perms = $ch['perms'] ?? [];
                    $format = $ch['format'] ?? 'string';
                    if (!in_array('pr', $perms) || in_array($cType, self::SKIP_CHARS) || in_array($format, ['tlv8', 'data'])) {
                        continue;
                    }
                    $def = self::CHARS[$cType] ?? null;
                    $charName = $def[0] ?? ($ch['description'] ?? ('Wert ' . $cType));
                    if ($sType === '3E') {
                        $name = $charName;
                    } elseif ($def !== null && $def[3]) {
                        $name = $label;
                    } else {
                        $name = $label . ' – ' . $charName;
                    }
                    if ($sType !== '3E' && $cType === '23') {
                        continue; // Name der Zone steckt bereits im Variablennamen
                    }
                    $vType = $def[2] ?? $this->formatToType($format);
                    $profile = $def[1] ?? '';
                    $ident = sprintf('C%d_%d', $aid, (int) $ch['iid']);
                    $this->MaintainVariable($ident, $name, $vType, $profile, $pos++, true);
                    $count++;
                    if (array_key_exists('value', $ch)) {
                        $this->setVal($ident, $vType, $ch['value']);
                    }
                    if (in_array('ev', $perms)) {
                        $poll[] = ['id' => $aid . '.' . (int) $ch['iid'], 'ident' => $ident, 'type' => $vType];
                    }
                }
            }
        }
        $this->WriteAttributeString('PollList', json_encode($poll));
        return sprintf('%d Variablen angelegt/aktualisiert, davon %d werden zyklisch gelesen.', $count, count($poll));
    }

    /** Liest alle veränderlichen Werte vom FP2 (wird vom Timer aufgerufen). */
    public function Update(): void
    {
        if (!$this->IsPaired()) {
            return;
        }
        $poll = json_decode($this->ReadAttributeString('PollList'), true) ?: [];
        if (count($poll) === 0) {
            try {
                $this->RebuildVariables();
                $poll = json_decode($this->ReadAttributeString('PollList'), true) ?: [];
            } catch (Throwable $e) {
                $this->handleError($e);
                return;
            }
        }
        try {
            $values = $this->withSession(function (FP2HAPSession $s) use ($poll) {
                return $s->getCharacteristics(array_column($poll, 'id'));
            });
            $map = [];
            foreach ($poll as $p) {
                $map[$p['id']] = $p;
            }
            foreach ($values as $v) {
                $key = $v['aid'] . '.' . $v['iid'];
                if (isset($map[$key]) && array_key_exists('value', $v)) {
                    $this->setVal($map[$key]['ident'], $map[$key]['type'], $v['value']);
                }
            }
            $this->setReachable(true);
            if ($this->GetStatus() !== IS_ACTIVE) {
                $this->SetStatus(IS_ACTIVE);
            }
            $this->SetBuffer('LastError', '');
        } catch (Throwable $e) {
            $this->handleError($e);
        }
    }

    // ------------------------------------------------------------------ intern

    private function IsPaired(): bool
    {
        return $this->ReadAttributeString('AccessoryLTPK') !== '' && $this->ReadAttributeString('ControllerLTSK') !== '';
    }

    private function sem(): string
    {
        return 'AQFP2_' . $this->InstanceID;
    }

    private function resolvePort(bool $refresh): int
    {
        $fixed = $this->ReadPropertyInteger('Port');
        if ($fixed > 0) {
            return $fixed;
        }
        $cached = $this->ReadAttributeInteger('CachedPort');
        if (!$refresh && $cached > 0) {
            return $cached;
        }
        $q = FP2mDNS::query($this->ReadPropertyString('Host'));
        if ($q === null) {
            if ($cached > 0) {
                return $cached;
            }
            throw new FP2ConnectException('HomeKit-Port nicht gefunden (mDNS ohne Antwort)');
        }
        $this->WriteAttributeInteger('CachedPort', $q['port']);
        return $q['port'];
    }

    /** Öffnet eine verifizierte, verschlüsselte Sitzung und führt $fn aus. */
    private function withSession(callable $fn)
    {
        if (!$this->IsPaired()) {
            throw new FP2PairingException('Nicht gekoppelt');
        }
        if (!IPS_SemaphoreEnter($this->sem(), 10000)) {
            throw new FP2ConnectException('Semaphore belegt');
        }
        $s = null;
        try {
            $host = $this->ReadPropertyString('Host');
            try {
                $s = new FP2HAPSession($host, $this->resolvePort(false));
            } catch (FP2ConnectException $e) {
                // Port hat sich evtl. geändert (Neustart des FP2)
                $s = new FP2HAPSession($host, $this->resolvePort(true));
            }
            $s->pairVerify(
                $this->ReadAttributeString('ControllerID'),
                hex2bin($this->ReadAttributeString('ControllerLTSK')),
                hex2bin($this->ReadAttributeString('AccessoryLTPK')),
                $this->ReadAttributeString('AccessoryID')
            );
            return $fn($s);
        } finally {
            if ($s !== null) {
                $s->close();
            }
            IPS_SemaphoreLeave($this->sem());
        }
    }

    private function handleError(Throwable $e): void
    {
        $msg = $e->getMessage();
        $this->SendDebug('Fehler', $msg, 0);
        $status = ($e instanceof FP2PairingException) ? self::STATUS_PAIRING_INVALID : self::STATUS_UNREACHABLE;
        if ($this->GetBuffer('LastError') !== $msg) {
            $this->LogMessage($msg, KL_WARNING);
            $this->SetBuffer('LastError', $msg);
        }
        $this->setReachable(false);
        if ($this->GetStatus() !== $status) {
            $this->SetStatus($status);
        }
    }

    private function setReachable(bool $ok): void
    {
        if ($this->GetValue('Reachable') !== $ok) {
            $this->SetValue('Reachable', $ok);
        }
    }

    private function setVal(string $ident, int $type, $value): void
    {
        switch ($type) {
            case VARIABLETYPE_BOOLEAN:
                $value = (bool) $value;
                break;
            case VARIABLETYPE_INTEGER:
                $value = (int) $value;
                break;
            case VARIABLETYPE_FLOAT:
                $value = (float) $value;
                break;
            default:
                $value = is_scalar($value) ? (string) $value : json_encode($value);
        }
        if (@$this->GetIDForIdent($ident) === false) {
            return;
        }
        if ($this->GetValue($ident) !== $value) {
            $this->SetValue($ident, $value);
        }
    }

    private function serviceLabel(array $svc, string $sType): string
    {
        foreach ($svc['characteristics'] ?? [] as $ch) {
            $t = $this->normType((string) ($ch['type'] ?? ''));
            if (($t === '23' || $t === 'E3') && is_string($ch['value'] ?? null) && $ch['value'] !== '') {
                return $ch['value'];
            }
        }
        return (self::SERVICES[$sType] ?? 'Dienst ' . $sType) . ' ' . (int) ($svc['iid'] ?? 0);
    }

    private function normType(string $t): string
    {
        if (preg_match('/^([0-9A-F]{1,8})-0000-1000-8000-0026BB765291$/i', $t, $m)) {
            return strtoupper(ltrim($m[1], '0'));
        }
        return strtoupper($t);
    }

    private function formatToType(string $format): int
    {
        switch ($format) {
            case 'bool':
                return VARIABLETYPE_BOOLEAN;
            case 'uint8':
            case 'uint16':
            case 'uint32':
            case 'uint64':
            case 'int':
                return VARIABLETYPE_INTEGER;
            case 'float':
                return VARIABLETYPE_FLOAT;
            default:
                return VARIABLETYPE_STRING;
        }
    }

    private function uuid(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        return strtoupper(vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4)));
    }
}
