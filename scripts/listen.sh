#!/bin/bash

set -ex

rm -rf /var/db/net-snmp
snmptrapd -m ALL -m +SNMP-NOTIFIER-MIB -f -Of -Lo -c snmptrapd.conf
