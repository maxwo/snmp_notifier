#!/bin/bash

set -ex

rm -rf /var/db/net-snmp
snmptrapd -m ALL -f -Of -Lo -c snmptrapd.conf
