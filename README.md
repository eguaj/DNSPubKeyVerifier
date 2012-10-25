DNSPubKeyVerifier
=================

Verify signatures with public key obtained through DNS TXT records.

Usage
=====

Alice wants to send a message to Bob and prevent Carol from altering the message.

Alice generates an RSA key:

    $ openssl genrsa -out private.key 1024

Alice extracts the public key:

    $ openssl rsa -in private.key -text -pubout

... and stores it in a DNS TXT record of her domain:

    $ORIGIN example.net.
    [...]
    foo IN TXT "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyvgpjWK2w6FmlFxdxcSBwP0P50jsIUB3ZV0xYXolLF0jipXdjN/TgZjBAlRYlF7u/iXW7WmrbU/mwpdlyiK0+dZvwZMGUzqBOC1ULz5i8xPVidutkBhMMWFovipibnvU6TePJjMdeBTlEDpi1p4/V66yOxJ8sU1nYCTYJIqaX1QIDAQAB"

Alice signs the message with the private key:

    $ php <<'EOT'
    <?php
    include_once("DNSPubKeyVerifier.php");

    $message = "I love you!";

    $signer = new DNSPubKeySigner("file://private.key");
    $signature = $signer->sign($message);

    printf("* Signature = '%s'\n", $signature);
    EOT

    * Signature = 'gbpMyBy6TiWzHB3IGPk4eQQMCrKxSDbi2CdN9+anbyuS/nHzAO3s/TDkTZP1d68qVOSs1f/fBxJDr84tSlCeYDInrpMl00Y5PPXKMXT8ce3O7IzBb6cz8IZ6IzbB4G+vyLV7LlmJ7TONxb8dngl+ZwuVJE/CKT8i2pXqAtcc4h0='

Alice sends the message and the signature to Bob.

Bob verifies the message signature with the public key from Alice's TXT DNS record of "foo.example.net":

    $ php <<'EOT'
    <?php
    include_once("DNSPubKeyVerifier.php");

    $message = "I love you!";
    $signature = "gbpMyBy6TiWzHB3IGPk4eQQMCrKxSDbi2CdN9+anbyuS/nHzAO3s/TDkTZP1d68qVOSs1f/fBxJDr84tSlCeYDInrpMl00Y5PPXKMXT8ce3O7IzBb6cz8IZ6IzbB4G+vyLV7LlmJ7TONxb8dngl+ZwuVJE/CKT8i2pXqAtcc4h0=";

    $verifier = new DNSPubKeyVerifier("foo.example.net");
    $res = $verifier->verify($message, $signature);

    printf("* Message is %s.\n", $res ? 'authentic' : 'NOT authentic');
    EOT

    * Message is authentic.

If Carol tampered the message, then verification will fail:

    $ php <<'EOT'
    <?php
    include_once("DNSPubKeyVerifier.php");

    $message = "I hate you!";
    $signature = "gbpMyBy6TiWzHB3IGPk4eQQMCrKxSDbi2CdN9+anbyuS/nHzAO3s/TDkTZP1d68qVOSs1f/fBxJDr84tSlCeYDInrpMl00Y5PPXKMXT8ce3O7IzBb6cz8IZ6IzbB4G+vyLV7LlmJ7TONxb8dngl+ZwuVJE/CKT8i2pXqAtcc4h0=";

    $verifier = new DNSPubKeyVerifier("foo.example.net");
    $res = $verifier->verify($message, $signature);

    printf("* Message is %s.\n", $res ? 'authentic' : 'NOT authentic');
    EOT

    * Message is NOT authentic.
