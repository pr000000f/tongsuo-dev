#! /usr/bin/env perl
#
# Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# Build CSR / SPKAC / self-signed cert with RSA e=1 and a forged-but-verifying
# PKCS#1 v1.5 signature (fixed real modulus; no private key needed).


package invalid_pubkey_utils;

use strict;
use warnings;

use Exporter 'import';
use Digest::SHA qw(sha256);
use MIME::Base64 qw(encode_base64);

our @EXPORT_OK = qw(make_e1_csr make_e1_spkac make_e1_selfsigned);

# Fixed 2048-bit RSA modulus (valid modulus; only e=1 is wrong).
our $MODULUS_HEX =
    "E06674D12CD9C3CA49F267F9911FFD743A364964D1449622F9B7F172BE4CCB91EE" .
    "F82FC51C666F48E8DC5F7E44BC6C2CE94ED7C28955E4BE0C8794D08076409A2D9C" .
    "E4A41AA927CBD021402A28124B57642DD744AC031245D8E5511B2FC0D5D027C0CC" .
    "5AA22E9214A2F27B3C2B22B75F740FA6EB63214C994F844D9E171E2E6E4CE4D799" .
    "4036E51462BCADE1752018140447D805D8295714BDF00437D4DD15EEE6CA0B3CAFB" .
    "514035F67B9E4F3F5307E3E943ECFA3A1C093289A7D4610E93ECA8009998171B78" .
    "F9EC9FA64A4E61BE54B7A304B8EE47BF9773F51AA09BB5AF578F9CC35F93C353A5" .
    "C902900CBC02776EBFAF3BFD2D31A352520614F7768C240D3";

# DigestInfo prefix for SHA-256, RFC 8017 section 9.2 note 1
my $SHA256_DIGESTINFO = pack("H*", "3031300d060960864801650304020105000420");

my $ALG_SHA256_RSA = pack("H*", "300d06092a864886f70d01010b0500");
my $OID_RSA = pack("H*", "06092a864886f70d010101");
my $OID_CN = pack("H*", "0603550403");

sub der_len {
    my ($n) = @_;

    return chr($n) if $n < 0x80;
    return "\x81" . chr($n) if $n < 0x100;
    return "\x82" . pack("n", $n) if $n < 0x10000;
    die "length too large: $n";
}

sub tlv {
    my ($tag, $content) = @_;

    return chr($tag) . der_len(length($content)) . $content;
}

sub seq { return tlv(0x30, join("", @_)); }

sub integer {
    my ($bytes) = @_;

    $bytes = "\x00" . $bytes if ord(substr($bytes, 0, 1)) & 0x80;
    return tlv(0x02, $bytes);
}

# SPKI for fixed modulus + e=1; returns (DER, modulus byte length).
sub e1_spki {
    my $n = pack("H*", $MODULUS_HEX);
    my $rsa_pub = seq(integer($n), integer("\x01"));

    return (seq(seq($OID_RSA, "\x05\x00"), tlv(0x03, "\x00" . $rsa_pub)),
            length($n));
}

# PKCS#1 v1.5 EM; with e=1 this is itself a verifying signature.
sub forge_signature {
    my ($tbs, $k) = @_;

    my $di = $SHA256_DIGESTINFO . sha256($tbs);
    my $pad = $k - 3 - length($di);
    die "modulus too small for SHA-256" if $pad < 8;

    return "\x00\x01" . ("\xff" x $pad) . "\x00" . $di;
}

sub named_cn {
    my ($cn) = @_;

    return seq(tlv(0x31, seq($OID_CN, tlv(0x0c, $cn))));
}

# PEM CSR with e=1 key and verifying forged self-signature.
sub make_e1_csr {
    my (%args) = @_;
    my $cn = $args{cn} // "e1-invalid";
    my ($spki, $k) = e1_spki();

    my $cri = seq(integer("\x00"),      # version
                  named_cn($cn),
                  $spki,
                  tlv(0xa0, ""));       # attributes, empty
    my $sig = forge_signature($cri, $k);

    my $csr = seq($cri, $ALG_SHA256_RSA, tlv(0x03, "\x00" . $sig));
    my $b64 = encode_base64($csr, "");

    return "-----BEGIN CERTIFICATE REQUEST-----\n"
         . join("\n", $b64 =~ /(.{1,64})/g) . "\n"
         . "-----END CERTIFICATE REQUEST-----\n";
}

# SPKAC input body for "openssl ca -spkac" with e=1 key.
sub make_e1_spkac {
    my (%args) = @_;
    my $cn = $args{cn} // "e1-spkac";
    my $challenge = $args{challenge} // "0123456789abcdef";
    my ($spki, $k) = e1_spki();

    my $tbs = seq($spki, tlv(0x16, $challenge));
    my $sig = forge_signature($tbs, $k);
    my $spki_der = seq($tbs, $ALG_SHA256_RSA, tlv(0x03, "\x00" . $sig));

    return "countryName = CN\n"
         . "organizationName = Tongsuo test\n"
         . "commonName = $cn\n"
         . "SPKAC = " . encode_base64($spki_der, "") . "\n";
}

# PEM self-signed cert with e=1 key and verifying forged signature.
sub make_e1_selfsigned {
    my (%args) = @_;
    my $cn = $args{cn} // "e1-selfsigned";
    my ($spki, $k) = e1_spki();
    my $name = named_cn($cn);

    my $tbs = seq(tlv(0xa0, integer("\x02")),           # version v3
                  integer("\x01"),                       # serial
                  $ALG_SHA256_RSA,
                  $name,                                 # issuer
                  seq(tlv(0x17, "250101000000Z"),
                      tlv(0x17, "491231235959Z")),       # validity
                  $name,                                 # subject
                  $spki);
    my $sig = forge_signature($tbs, $k);
    my $cert = seq($tbs, $ALG_SHA256_RSA, tlv(0x03, "\x00" . $sig));

    my $b64 = encode_base64($cert, "");
    return "-----BEGIN CERTIFICATE-----\n"
         . join("\n", $b64 =~ /(.{1,64})/g) . "\n"
         . "-----END CERTIFICATE-----\n";
}

1;
