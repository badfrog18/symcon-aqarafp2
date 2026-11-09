<?php

declare(strict_types=1);

/*
 * Minimaler HomeKit-Accessory-Protocol-Controller (HAP über IP) in PHP.
 * Benötigt die PHP-Erweiterungen gmp und sodium (in IP-Symcon vorhanden).
 *
 * Umfang: TLV8, SRP-6a (3072 bit, SHA-512), Pair-Setup, Pair-Verify,
 * verschlüsselte HTTP-Sitzung (ChaCha20-Poly1305), Remove-Pairing, mDNS-Erkennung.
 */

if (!class_exists('FP2TLV')) {

    class FP2TLV
    {
        public const METHOD = 0x00;
        public const IDENTIFIER = 0x01;
        public const SALT = 0x02;
        public const PUBLICKEY = 0x03;
        public const PROOF = 0x04;
        public const ENCRYPTEDDATA = 0x05;
        public const STATE = 0x06;
        public const ERROR = 0x07;
        public const SIGNATURE = 0x0A;
        public const PERMISSIONS = 0x0B;

        /** @param array<int, array{0:int,1:int|string}> $items */
        public static function encode(array $items): string
        {
            $out = '';
            foreach ($items as $item) {
                [$type, $value] = $item;
                if (is_int($value)) {
                    $value = chr($value);
                }
                $len = strlen($value);
                if ($len === 0) {
                    $out .= chr($type) . "\x00";
                    continue;
                }
                for ($o = 0; $o < $len; $o += 255) {
                    $chunk = substr($value, $o, 255);
                    $out .= chr($type) . chr(strlen($chunk)) . $chunk;
                }
            }
            return $out;
        }

        /** @return array<int, string> */
        public static function decode(string $data): array
        {
            $res = [];
            $last = -1;
            $i = 0;
            $n = strlen($data);
            while ($i + 2 <= $n) {
                $type = ord($data[$i]);
                $len = ord($data[$i + 1]);
                $value = substr($data, $i + 2, $len);
                $i += 2 + $len;
                if ($type === $last && isset($res[$type])) {
                    $res[$type] .= $value; // Fragment fortsetzen
                } else {
                    $res[$type] = $value;
                }
                $last = $type;
            }
            return $res;
        }

        public static function errorText(int $code): string
        {
            $map = [
                1 => 'Unbekannter Fehler',
                2 => 'Authentifizierung fehlgeschlagen (Setup-Code falsch?)',
                3 => 'Zu viele Versuche, bitte warten (Backoff)',
                4 => 'Maximale Anzahl Controller erreicht',
                5 => 'Maximale Anzahl Kopplungsversuche erreicht – Gerät neu starten',
                6 => 'Gerät ist bereits gekoppelt (zuerst aus Home Assistant/Apple Home entfernen)',
                7 => 'Gerät ist beschäftigt (läuft gerade eine andere Kopplung?)',
            ];
            return $map[$code] ?? ('HAP-Fehler ' . $code);
        }
    }

    class FP2SRP
    {
        // RFC 5054 3072-bit Gruppe, g = 5
        public const N_HEX =
            'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' .
            '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' .
            '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' .
            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' .
            '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' .
            '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' .
            'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' .
            '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33' .
            'A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' .
            'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864' .
            'D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2' .
            '08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF';

        public static function bin(\GMP $x): string
        {
            $h = gmp_strval($x, 16);
            if (strlen($h) % 2) {
                $h = '0' . $h;
            }
            return hex2bin($h);
        }

        public static function num(string $b): \GMP
        {
            return gmp_init(bin2hex($b) === '' ? '0' : bin2hex($b), 16);
        }

        public static function H(string ...$parts): string
        {
            return hash('sha512', implode('', $parts), true);
        }

        /**
         * Client-Seite von SRP-6a, wie von HomeKit verwendet.
         * @param string|null $aBin optionaler privater Wert (für Tests)
         * @return array{A:string,M1:string,M2:string,K:string}
         */
        public static function client(string $salt, string $Bbin, string $user, string $pass, ?string $aBin = null): array
        {
            $N = gmp_init(self::N_HEX, 16);
            $g = gmp_init(5);
            $Nbin = self::bin($N);
            $L = strlen($Nbin);
            $gbin = self::bin($g);

            $k = self::num(self::H($Nbin, str_pad($gbin, $L, "\0", STR_PAD_LEFT)));
            $x = self::num(self::H($salt, self::H($user . ':' . $pass)));
            $a = self::num($aBin ?? random_bytes(32));
            $A = gmp_powm($g, $a, $N);
            $Abin = self::bin($A);
            $B = self::num($Bbin);
            if (gmp_cmp(gmp_mod($B, $N), 0) === 0) {
                throw new Exception('SRP: ungültiger Server-Schlüssel B');
            }
            $Bmin = self::bin($B);
            $u = self::num(self::H($Abin, $Bmin));
            if (gmp_cmp($u, 0) === 0) {
                throw new Exception('SRP: u = 0');
            }
            $base = gmp_mod(gmp_sub($B, gmp_mul($k, gmp_powm($g, $x, $N))), $N);
            $S = gmp_powm($base, gmp_add($a, gmp_mul($u, $x)), $N);
            $K = self::H(self::bin($S));
            $hNg = self::H($Nbin) ^ self::H($gbin);
            $M1 = self::H($hNg, self::H($user), $salt, $Abin, $Bmin, $K);
            $M2 = self::H($Abin, $M1, $K);
            return ['A' => $Abin, 'M1' => $M1, 'M2' => $M2, 'K' => $K];
        }

        /** Server-Seite – nur für den Selbsttest. */
        public static function serverTest(string $user, string $pass): array
        {
            $N = gmp_init(self::N_HEX, 16);
            $g = gmp_init(5);
            $Nbin = self::bin($N);
            $L = strlen($Nbin);
            $salt = random_bytes(16);
            $x = self::num(self::H($salt, self::H($user . ':' . $pass)));
            $v = gmp_powm($g, $x, $N);
            $k = self::num(self::H($Nbin, str_pad(self::bin($g), $L, "\0", STR_PAD_LEFT)));
            $b = self::num(random_bytes(32));
            $B = gmp_mod(gmp_add(gmp_mul($k, $v), gmp_powm($g, $b, $N)), $N);
            return ['salt' => $salt, 'B' => self::bin($B), 'b' => $b, 'v' => $v];
        }

        public static function serverKey(array $srv, string $Abin): string
        {
            $N = gmp_init(self::N_HEX, 16);
            $A = self::num($Abin);
            $u = self::num(self::H($Abin, $srv['B']));
            $S = gmp_powm(gmp_mul($A, gmp_powm($srv['v'], $u, $N)), $srv['b'], $N);
            return self::H(self::bin($S));
        }
    }

    class FP2HAPSession
    {
        /** @var resource|null */
        private $sock = null;
        private string $host;
        private int $port;
        private bool $encrypted = false;
        private string $writeKey = '';
        private string $readKey = '';
        private int $writeCount = 0;
        private int $readCount = 0;
        private string $rawBuf = '';
        private string $plainBuf = '';
        private float $timeout;

        public function __construct(string $host, int $port, float $timeout = 5.0)
        {
            $this->host = $host;
            $this->port = $port;
            $this->timeout = $timeout;
            $errno = 0;
            $errstr = '';
            $s = @stream_socket_client('tcp://' . $host . ':' . $port, $errno, $errstr, $timeout);
            if ($s === false) {
                throw new FP2ConnectException('Verbindung zu ' . $host . ':' . $port . ' fehlgeschlagen: ' . $errstr);
            }
            stream_set_timeout($s, (int) ceil($timeout));
            $this->sock = $s;
        }

        public function __destruct()
        {
            $this->close();
        }

        public function close(): void
        {
            if (is_resource($this->sock)) {
                @fclose($this->sock);
            }
            $this->sock = null;
        }

        private function writeRaw(string $data): void
        {
            while ($data !== '') {
                $n = @fwrite($this->sock, $data);
                if ($n === false || $n === 0) {
                    throw new FP2ConnectException('Senden fehlgeschlagen');
                }
                $data = substr($data, $n);
            }
        }

        private function readRaw(): string
        {
            $d = @fread($this->sock, 8192);
            if ($d === false || $d === '') {
                $meta = stream_get_meta_data($this->sock);
                if (!empty($meta['timed_out'])) {
                    throw new FP2ConnectException('Zeitüberschreitung beim Lesen');
                }
                if (feof($this->sock)) {
                    throw new FP2ConnectException('Verbindung vom Gerät geschlossen');
                }
                return '';
            }
            return $d;
        }

        private static function nonce(int $counter): string
        {
            return "\0\0\0\0" . pack('P', $counter);
        }

        private function send(string $plain): void
        {
            if (!$this->encrypted) {
                $this->writeRaw($plain);
                return;
            }
            $out = '';
            for ($o = 0, $n = strlen($plain); $o < $n; $o += 1024) {
                $chunk = substr($plain, $o, 1024);
                $aad = pack('v', strlen($chunk));
                $out .= $aad . sodium_crypto_aead_chacha20poly1305_ietf_encrypt($chunk, $aad, self::nonce($this->writeCount++), $this->writeKey);
            }
            $this->writeRaw($out);
        }

        /** Liest weitere Klartextdaten in den Puffer. */
        private function fill(): void
        {
            if (!$this->encrypted) {
                $this->plainBuf .= $this->readRaw();
                return;
            }
            while (true) {
                if (strlen($this->rawBuf) >= 2) {
                    $len = unpack('v', substr($this->rawBuf, 0, 2))[1];
                    if (strlen($this->rawBuf) >= 2 + $len + 16) {
                        $aad = substr($this->rawBuf, 0, 2);
                        $ct = substr($this->rawBuf, 2, $len + 16);
                        $this->rawBuf = (string) substr($this->rawBuf, 2 + $len + 16);
                        $pt = sodium_crypto_aead_chacha20poly1305_ietf_decrypt($ct, $aad, self::nonce($this->readCount++), $this->readKey);
                        if ($pt === false) {
                            throw new FP2ConnectException('Entschlüsselung fehlgeschlagen');
                        }
                        $this->plainBuf .= $pt;
                        return;
                    }
                }
                $this->rawBuf .= $this->readRaw();
            }
        }

        /** @return array{status:int, headers:array<string,string>, body:string} */
        public function request(string $method, string $path, string $body = '', string $contentType = ''): array
        {
            $req = $method . ' ' . $path . " HTTP/1.1\r\nHost: " . $this->host . ':' . $this->port . "\r\n";
            if ($body !== '' || $method === 'POST' || $method === 'PUT') {
                if ($contentType !== '') {
                    $req .= 'Content-Type: ' . $contentType . "\r\n";
                }
                $req .= 'Content-Length: ' . strlen($body) . "\r\n";
            }
            $req .= "\r\n" . $body;
            $this->send($req);
            return $this->readResponse();
        }

        private function readResponse(): array
        {
            $deadline = microtime(true) + $this->timeout;
            while (($p = strpos($this->plainBuf, "\r\n\r\n")) === false) {
                if (microtime(true) > $deadline) {
                    throw new FP2ConnectException('Zeitüberschreitung (Header)');
                }
                $this->fill();
            }
            $head = substr($this->plainBuf, 0, $p);
            $this->plainBuf = (string) substr($this->plainBuf, $p + 4);
            $lines = explode("\r\n", $head);
            $statusLine = array_shift($lines);
            if (!preg_match('#^(HTTP|EVENT)/1\.[01] (\d{3})#', (string) $statusLine, $m)) {
                throw new Exception('Ungültige Antwort: ' . $statusLine);
            }
            $headers = [];
            foreach ($lines as $l) {
                $kv = explode(':', $l, 2);
                if (count($kv) === 2) {
                    $headers[strtolower(trim($kv[0]))] = trim($kv[1]);
                }
            }
            $body = '';
            if (isset($headers['transfer-encoding']) && stripos($headers['transfer-encoding'], 'chunked') !== false) {
                while (true) {
                    while (($q = strpos($this->plainBuf, "\r\n")) === false) {
                        $this->fill();
                    }
                    $size = hexdec(trim(explode(';', substr($this->plainBuf, 0, $q))[0]));
                    while (strlen($this->plainBuf) < $q + 2 + $size + 2) {
                        $this->fill();
                    }
                    $body .= substr($this->plainBuf, $q + 2, (int) $size);
                    $this->plainBuf = (string) substr($this->plainBuf, $q + 2 + (int) $size + 2);
                    if ($size == 0) {
                        break;
                    }
                }
            } else {
                $len = (int) ($headers['content-length'] ?? 0);
                while (strlen($this->plainBuf) < $len) {
                    if (microtime(true) > $deadline) {
                        throw new FP2ConnectException('Zeitüberschreitung (Body)');
                    }
                    $this->fill();
                }
                $body = substr($this->plainBuf, 0, $len);
                $this->plainBuf = (string) substr($this->plainBuf, $len);
            }
            if ($m[1] === 'EVENT') {
                // Ereignisse werden nicht abonniert – überspringen und auf die eigentliche Antwort warten
                return $this->readResponse();
            }
            return ['status' => (int) $m[2], 'headers' => $headers, 'body' => $body];
        }

        private function tlvRequest(string $path, array $items): array
        {
            $r = $this->request('POST', $path, FP2TLV::encode($items), 'application/pairing+tlv8');
            $tlv = FP2TLV::decode($r['body']);
            if (isset($tlv[FP2TLV::ERROR])) {
                throw new FP2PairingException(FP2TLV::errorText(ord($tlv[FP2TLV::ERROR])), ord($tlv[FP2TLV::ERROR]));
            }
            if ($r['status'] >= 400 && $r['status'] !== 470) {
                throw new Exception('HTTP ' . $r['status'] . ' bei ' . $path);
            }
            return $tlv;
        }

        private static function sealed(string $data, string $key, string $label): string
        {
            return sodium_crypto_aead_chacha20poly1305_ietf_encrypt($data, '', "\0\0\0\0" . $label, $key);
        }

        private static function open(string $data, string $key, string $label): string
        {
            $pt = sodium_crypto_aead_chacha20poly1305_ietf_decrypt($data, '', "\0\0\0\0" . $label, $key);
            if ($pt === false) {
                throw new Exception('Entschlüsselung ' . $label . ' fehlgeschlagen');
            }
            return $pt;
        }

        /**
         * Pair-Setup. Liefert die Kopplungsdaten des Geräts.
         * @return array{id:string, ltpk:string}
         */
        public function pairSetup(string $setupCode, string $ctrlId, string $ctrlLTSK, string $ctrlLTPK): array
        {
            // M1 -> M2
            $m2 = $this->tlvRequest('/pair-setup', [[FP2TLV::STATE, 1], [FP2TLV::METHOD, 0]]);
            if (!isset($m2[FP2TLV::SALT], $m2[FP2TLV::PUBLICKEY])) {
                throw new Exception('Pair-Setup M2 unvollständig');
            }
            $srp = FP2SRP::client($m2[FP2TLV::SALT], $m2[FP2TLV::PUBLICKEY], 'Pair-Setup', $setupCode);

            // M3 -> M4
            $m4 = $this->tlvRequest('/pair-setup', [[FP2TLV::STATE, 3], [FP2TLV::PUBLICKEY, $srp['A']], [FP2TLV::PROOF, $srp['M1']]]);
            if (!isset($m4[FP2TLV::PROOF]) || !hash_equals($srp['M2'], $m4[FP2TLV::PROOF])) {
                throw new Exception('Pair-Setup: Gerätebeweis ungültig');
            }

            // M5 -> M6
            $K = $srp['K'];
            $encKey = hash_hkdf('sha512', $K, 32, 'Pair-Setup-Encrypt-Info', 'Pair-Setup-Encrypt-Salt');
            $ctrlX = hash_hkdf('sha512', $K, 32, 'Pair-Setup-Controller-Sign-Info', 'Pair-Setup-Controller-Sign-Salt');
            $sig = sodium_crypto_sign_detached($ctrlX . $ctrlId . $ctrlLTPK, $ctrlLTSK);
            $sub = FP2TLV::encode([[FP2TLV::IDENTIFIER, $ctrlId], [FP2TLV::PUBLICKEY, $ctrlLTPK], [FP2TLV::SIGNATURE, $sig]]);
            $m6 = $this->tlvRequest('/pair-setup', [[FP2TLV::STATE, 5], [FP2TLV::ENCRYPTEDDATA, self::sealed($sub, $encKey, 'PS-Msg05')]]);
            if (!isset($m6[FP2TLV::ENCRYPTEDDATA])) {
                throw new Exception('Pair-Setup M6 unvollständig');
            }
            $acc = FP2TLV::decode(self::open($m6[FP2TLV::ENCRYPTEDDATA], $encKey, 'PS-Msg06'));
            $accId = $acc[FP2TLV::IDENTIFIER] ?? '';
            $accLTPK = $acc[FP2TLV::PUBLICKEY] ?? '';
            $accX = hash_hkdf('sha512', $K, 32, 'Pair-Setup-Accessory-Sign-Info', 'Pair-Setup-Accessory-Sign-Salt');
            if (strlen($accLTPK) !== 32 || !sodium_crypto_sign_verify_detached($acc[FP2TLV::SIGNATURE] ?? str_repeat("\0", 64), $accX . $accId . $accLTPK, $accLTPK)) {
                throw new Exception('Pair-Setup: Gerätesignatur ungültig');
            }
            return ['id' => $accId, 'ltpk' => $accLTPK];
        }

        /**
         * Pair-Verify. Danach ist die Sitzung verschlüsselt.
         * $accLTPK = null: nur Handshake-Test bis M2 (Debug), es wird nicht verifiziert.
         */
        public function pairVerify(string $ctrlId, string $ctrlLTSK, ?string $accLTPK, ?string $accId = null): array
        {
            $kp = sodium_crypto_box_keypair();
            $priv = sodium_crypto_box_secretkey($kp);
            $pub = sodium_crypto_box_publickey($kp);

            $m2 = $this->tlvRequest('/pair-verify', [[FP2TLV::STATE, 1], [FP2TLV::PUBLICKEY, $pub]]);
            $accPub = $m2[FP2TLV::PUBLICKEY] ?? '';
            if (strlen($accPub) !== 32 || !isset($m2[FP2TLV::ENCRYPTEDDATA])) {
                throw new Exception('Pair-Verify M2 unvollständig');
            }
            $shared = sodium_crypto_scalarmult($priv, $accPub);
            $key = hash_hkdf('sha512', $shared, 32, 'Pair-Verify-Encrypt-Info', 'Pair-Verify-Encrypt-Salt');
            $sub = FP2TLV::decode(self::open($m2[FP2TLV::ENCRYPTEDDATA], $key, 'PV-Msg02'));
            $gotId = $sub[FP2TLV::IDENTIFIER] ?? '';
            if ($accLTPK === null) {
                return ['handshakeOnly' => true, 'accessoryId' => $gotId];
            }
            if ($accId !== null && $accId !== '' && $gotId !== $accId) {
                throw new FP2PairingException('Pair-Verify: falsches Gerät (' . $gotId . ')', 2);
            }
            if (!sodium_crypto_sign_verify_detached($sub[FP2TLV::SIGNATURE] ?? str_repeat("\0", 64), $accPub . $gotId . $pub, $accLTPK)) {
                throw new FP2PairingException('Pair-Verify: Gerätesignatur ungültig – Kopplung nicht mehr gültig?', 2);
            }

            $sig = sodium_crypto_sign_detached($pub . $ctrlId . $accPub, $ctrlLTSK);
            $enc = self::sealed(FP2TLV::encode([[FP2TLV::IDENTIFIER, $ctrlId], [FP2TLV::SIGNATURE, $sig]]), $key, 'PV-Msg03');
            $this->tlvRequest('/pair-verify', [[FP2TLV::STATE, 3], [FP2TLV::ENCRYPTEDDATA, $enc]]);

            $this->writeKey = hash_hkdf('sha512', $shared, 32, 'Control-Write-Encryption-Key', 'Control-Salt');
            $this->readKey = hash_hkdf('sha512', $shared, 32, 'Control-Read-Encryption-Key', 'Control-Salt');
            $this->writeCount = 0;
            $this->readCount = 0;
            $this->encrypted = true;
            return ['handshakeOnly' => false, 'accessoryId' => $gotId];
        }

        public function removePairing(string $ctrlId): void
        {
            $this->tlvRequest('/pairings', [[FP2TLV::STATE, 1], [FP2TLV::METHOD, 4], [FP2TLV::IDENTIFIER, $ctrlId]]);
        }

        public function getAccessories(): array
        {
            $r = $this->request('GET', '/accessories');
            if ($r['status'] !== 200) {
                throw new Exception('GET /accessories: HTTP ' . $r['status']);
            }
            $j = json_decode($r['body'], true);
            if (!is_array($j)) {
                throw new Exception('GET /accessories: ungültiges JSON');
            }
            return $j['accessories'] ?? [];
        }

        /** @param string[] $ids z.B. ["1.10","1.13"] */
        public function getCharacteristics(array $ids): array
        {
            if (count($ids) === 0) {
                return [];
            }
            $r = $this->request('GET', '/characteristics?id=' . implode(',', $ids));
            if ($r['status'] !== 200 && $r['status'] !== 207) {
                throw new Exception('GET /characteristics: HTTP ' . $r['status']);
            }
            $j = json_decode($r['body'], true);
            return $j['characteristics'] ?? [];
        }
    }

    class FP2ConnectException extends Exception
    {
    }

    class FP2PairingException extends Exception
    {
    }

    class FP2mDNS
    {
        private static function readName(string $p, int &$o): string
        {
            $labels = [];
            $jumped = false;
            $ret = 0;
            $guard = 0;
            while ($o < strlen($p) && $guard++ < 128) {
                $len = ord($p[$o]);
                if ($len === 0) {
                    $o++;
                    break;
                }
                if (($len & 0xC0) === 0xC0) {
                    $ptr = (($len & 0x3F) << 8) | ord($p[$o + 1]);
                    if (!$jumped) {
                        $ret = $o + 2;
                    }
                    $jumped = true;
                    $o = $ptr;
                    continue;
                }
                $labels[] = substr($p, $o + 1, $len);
                $o += 1 + $len;
            }
            if ($jumped) {
                $o = $ret;
            }
            return implode('.', $labels);
        }

        /**
         * Fragt den Dienst _hap._tcp direkt beim Gerät ab (Unicast-mDNS).
         * @return array{name:string, port:int, txt:array<string,string>}|null
         */
        public static function query(string $host, float $timeout = 2.0): ?array
        {
            $qname = '';
            foreach (explode('.', '_hap._tcp.local') as $l) {
                $qname .= chr(strlen($l)) . $l;
            }
            $pkt = pack('nnnnnn', 0, 0, 1, 0, 0, 0) . $qname . "\0" . pack('nn', 12, 0x8001);
            $s = @socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
            if ($s === false) {
                return null;
            }
            socket_set_option($s, SOL_SOCKET, SO_RCVTIMEO, ['sec' => (int) $timeout, 'usec' => (int) (fmod($timeout, 1) * 1e6)]);
            @socket_sendto($s, $pkt, strlen($pkt), 0, $host, 5353);
            $buf = '';
            $from = '';
            $port = 0;
            $n = @socket_recvfrom($s, $buf, 9000, 0, $from, $port);
            socket_close($s);
            if ($n === false || $n < 12) {
                return null;
            }
            $h = unpack('nid/nflags/nqd/nan/nns/nar', substr($buf, 0, 12));
            $o = 12;
            for ($i = 0; $i < $h['qd']; $i++) {
                self::readName($buf, $o);
                $o += 4;
            }
            $res = ['name' => '', 'port' => 0, 'txt' => []];
            $total = $h['an'] + $h['ns'] + $h['ar'];
            for ($i = 0; $i < $total && $o < strlen($buf); $i++) {
                $name = self::readName($buf, $o);
                $rr = unpack('ntype/nclass/Nttl/nlen', substr($buf, $o, 10));
                $o += 10;
                $rdOff = $o;
                $o += $rr['len'];
                if ($rr['type'] === 12 && $res['name'] === '') {
                    $t = $rdOff;
                    $res['name'] = self::readName($buf, $t);
                } elseif ($rr['type'] === 33) {
                    $res['port'] = unpack('n', substr($buf, $rdOff + 4, 2))[1];
                } elseif ($rr['type'] === 16) {
                    $t = $rdOff;
                    while ($t < $rdOff + $rr['len']) {
                        $l = ord($buf[$t]);
                        $kv = explode('=', substr($buf, $t + 1, $l), 2);
                        $res['txt'][$kv[0]] = $kv[1] ?? '';
                        $t += 1 + $l;
                    }
                }
            }
            return $res['port'] > 0 ? $res : null;
        }
    }
}
