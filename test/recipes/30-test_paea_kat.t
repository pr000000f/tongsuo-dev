#! /usr/bin/env perl
# Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
# Licensed under the Apache License 2.0. See LICENSE.txt.
use strict;
use warnings;
use OpenSSL::Test qw/:DEFAULT srctop_dir/;
use OpenSSL::Test::Utils;
setup("test_paea_kat");
plan skip_all => "PAEA is disabled" if disabled("paea");
plan tests => 1;
ok(run(test(["paea_kat_test", srctop_dir("test", "recipes", "30-test_paea_kat_data")])),
   "PAEA fixed-input known-answer tests");
