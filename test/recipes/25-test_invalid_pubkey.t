#! /usr/bin/env perl
#
# Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

# CLI issuing paths must reject unusable public keys (e.g. RSA e=1).


use strict;
use warnings;

use File::Path qw(mkpath);
use OpenSSL::Test qw/:DEFAULT srctop_file/;
use OpenSSL::Test::Utils;

setup("test_invalid_pubkey");

plan skip_all => "RSA is not supported by this OpenSSL build"
    if disabled("rsa");

plan tests => 10;

require_ok(srctop_file("test", "recipes", "invalid_pubkey_utils.pl"));
invalid_pubkey_utils->import(qw(make_e1_csr make_e1_spkac make_e1_selfsigned));

my $cakey = "cakey.pem";
my $cacert = "cacert.pem";
my $index = "demoCA/index.txt";
my $serial = "demoCA/serial";
my $fh;

mkpath("demoCA/newcerts");
open($fh, ">", $index) or die "cannot write $index: $!";
close($fh);
open($fh, ">", $serial) or die "cannot write $serial: $!";
print $fh "1000\n";
close($fh);

ok(run(app(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", $cakey, "-out", $cacert, "-days", "2",
            "-subj", "/CN=Invalid Pubkey Test CA"])),
   "create a CA for the test");

open($fh, ">", "ca.cnf") or die "cannot write ca.cnf: $!";
print $fh <<"EOF";
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = ./demoCA
database = \$dir/index.txt
serial = \$dir/serial
new_certs_dir = \$dir/newcerts
certificate = ./$cacert
private_key = ./$cakey
default_md = sha256
policy = policy_any
[ policy_any ]
commonName = supplied
EOF
close($fh);

# A key of a different (smaller) quietly legitimate size, used only to prove
# that valid requests are still certified.
my $goodkey = "good.key";
ok(run(app(["openssl", "genpkey", "-algorithm", "RSA",
            "-pkeyopt", "rsa_keygen_bits:2048", "-out", $goodkey])),
   "generate a genuine 2048 bit key");

open($fh, ">", "e1.csr") or die "cannot write e1.csr: $!";
print $fh make_e1_csr(cn => "e1-invalid");
close($fh);

open($fh, ">", "e1-spkac.txt") or die "cannot write e1-spkac.txt: $!";
print $fh make_e1_spkac(cn => "e1-spkac");
close($fh);

open($fh, ">", "e1-selfsigned.pem") or die "cannot write e1-selfsigned.pem: $!";
print $fh make_e1_selfsigned(cn => "e1-selfsigned");
close($fh);

# Sanity: forged CSR signature verifies (so rejection must come from pubkey check).
ok(run(app(["openssl", "req", "-in", "e1.csr", "-noout", "-verify"])),
   "the e=1 request self-signature verifies without any private key");

# ca exits 0 even when declining; assert no outfile + stderr diagnostic.
sub file_contains {
    my ($file, $needle) = @_;
    my $data = "";

    open(my $in, "<", $file) or return 0;
    local $/;
    $data = <$in>;
    close($in);
    return index($data // "", $needle) >= 0;
}

sub rejected_ca {
    my ($outfile, @args) = @_;
    my $errfile = "$outfile.err";

    unlink $outfile, $errfile;
    run(app(["openssl", "ca", "-batch", "-config", "ca.cnf",
             @args, "-out", $outfile, "-days", "1"], stderr => $errfile));
    return !-e $outfile && file_contains($errfile, "public key is not valid");
}

sub rejected_x509 {
    my ($outfile, @args) = @_;
    my $errfile = "$outfile.err";

    unlink $outfile, $errfile;
    return !run(app(["openssl", "x509", @args, "-out", $outfile, "-days", "1"],
                    stderr => $errfile))
        && !-e $outfile
        && file_contains($errfile, "public key is not valid");
}

ok(rejected_x509("e1-x509.pem", "-req", "-in", "e1.csr",
                 "-CA", $cacert, "-CAkey", $cakey, "-CAcreateserial"),
   "openssl x509 -req rejects the e=1 request");

ok(rejected_ca("e1-ca.pem", "-in", "e1.csr"),
   "openssl ca rejects the e=1 request");

ok(rejected_ca("e1-spkac.pem", "-spkac", "e1-spkac.txt"),
   "openssl ca -spkac rejects the e=1 SPKAC");

ok(rejected_ca("e1-ss.pem", "-ss_cert", "e1-selfsigned.pem"),
   "openssl ca -ss_cert rejects the e=1 self-signed certificate");

# Usable requests must still be issued.
ok(run(app(["openssl", "req", "-new", "-key", $goodkey, "-out", "good.csr",
            "-subj", "/CN=good"])),
   "create a normal request");
ok(run(app(["openssl", "ca", "-batch", "-config", "ca.cnf",
            "-in", "good.csr", "-out", "good-ca.pem", "-days", "1"])),
   "openssl ca still issues for a normal request");
