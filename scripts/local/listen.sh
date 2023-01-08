#!/bin/bash

set -ex

rm -rf /var/db/net-snmp
mkdir -p $HOME/.snmp/mibs
ln -s $PWD/../mibs/SNMP-NOTIFIER-MIB.my $HOME/.snmp/mibs/SNMP-NOTIFIER-MIB.my
snmptrapd -m ALL -m +SNMP-NOTIFIER-MIB -f -Of -Lo -c snmptrapd.conf -x 127.0.0.1 "::1"
