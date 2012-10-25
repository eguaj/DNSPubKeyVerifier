<?php

/**
 * DNSPubKeyVerifier/DNSPubKeySigner
 *
 * Verify signatures with public key obtained through DNS TXT records.
 */

class DNSPubKeyVerifier
{
    private $publicKey = null;

    public function __construct($domainName)
    {
        $res = dns_get_record($domainName, DNS_TXT);
        if ($res === false) {
            $err = sprintf("Could not get TXT record for domain '%s'.\n", $domainName);
            throw new Exception($err);
        }
        if (!isset($res[0]['txt'])) {
            $err = sprintf("Found no TXT record for domain '%s'.\n", $domainName);
            throw new Exception($err);
        }
        $publicKey = openssl_pkey_get_public("-----BEGIN PUBLIC KEY-----\n" . $this->foldKey($res[0]['txt']) . "\n-----END PUBLIC KEY-----");
        if ($publicKey === false) {
            $err = sprintf("Error loading public key '%s'.", $res[0]['txt']);
            throw new Exception($err);
        }
        $this->publicKey = $publicKey;
    }

    public function verify($data, $signature)
    {
        $signature = base64_decode($signature);
        $res = openssl_verify($data, $signature, $this->publicKey);
        if ($res <= 0) {
            return false;
        }
        return true;
    }

    private function foldKey($key)
    {
        $key = trim($key);
        $keyFold = "";
        $keyLen = strlen($key);
        $i = 0;
        while ($i < $keyLen) {
            $keyFold = $keyFold . "\n" . substr($key, $i, 64);
            $i += 64;
        }
        return $keyFold;
    }
}

class DNSPubKeySigner
{
    private $privateKey = null;

    public function __construct($privatePemKey)
    {
        $privateKey = openssl_pkey_get_private($privatePemKey);
        if ($privateKey === false) {
            $err = sprintf("Error loading private key from '%s'.", $privatePemKey);
            throw new Exception($err);
        }
        $this->privateKey = $privateKey;
    }

    public function sign($data)
    {
        $signature = null;
        $res = openssl_sign($data, $signature, $this->privateKey);
        if ($res === false) {
            $err = sprintf("Error signing data.\n");
            throw new Exception($err);
        }
        return base64_encode($signature);
    }
}
