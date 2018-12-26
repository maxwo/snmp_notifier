# SNMP Notifier [![Build Status](https://travis-ci.org/maxwo/snmp_notifier.svg?branch=master)](https://travis-ci.org/maxwo/snmp_notifier)

[![CircleCI](https://circleci.com/gh/maxwo/snmp_notifier/tree/master.svg?style=svg)](https://circleci.com/gh/maxwo/snmp_notifier/tree/master)
![Docker Pulls](https://img.shields.io/docker/pulls/maxwo/snmp-notifier.svg?maxAge=604800)

`snmp_notifier` receives alerts from the Prometheus' Alertmanager and routes them as SNMP traps.

## Overview

The SNMP notifier receives alerts, and send them as SNMP traps to any given SNMP poller.

It has been created to handle older monitoring and alerting systems such as Nagios or Centreon.

Prometheus' Alertmanager sends the alerts to the SNMP notifier on its HTTP API. The SNMP notifier then looks for OID in the given alerts' labels. Each trap is sent with a unique ID, which allows, if the alert is updated or once the it is resolved, to send additional traps with updated status or data.

## Install

There are various ways to install the SNMP notifier

### Precompiled binaries

Precompiled binaries are available in the [*release* section](https://github.com/maxwo/snmp_notifier/releases) of this repository.

### Docker Images

Docker images are available on the [Docker Hub](https://cloud.docker.com/u/maxwo/repository/docker/maxwo/snmp-notifier).

### Compiling the binary

Check out the source code and build it manually:

```
$ git clone https://github.com/maxwo/snmp_notifier.git
$ cd snmp_notifier
$ make build
$ ./snmp_notifier
```

## Running and configuration

### Prometheus' alerts configuration

OID may be added to the alert labels to identify the kind of trap to be sent:

```
groups:
- name: service
  rules:

  - alert: ServiceIsDown
    expr: up == 0
    for: 5m
    labels:
      severity: "critical"
      type: "service"
      oid: "1.3.6.1.4.1.123.0.10.1.1.1.5.1"
      environment: "production"
    annotations:
      description: "Service {{`{{ $labels.job }}`}} on {{`{{ $labels.instance }}`}} is down"
      summary: "A service is down."
```

Note that a default OID may be specified in the SNMP notifier if none is provided in the alert.

### Alertmanager configuration

The Alertmanager should be configured with the SNMP notifier as alert receiver:

```
receivers:

- name: 'snmp_notifier'
  webhook_configs:
  - send_resolved: true
    url: http://snmp.notifier.service:9464/alerts
```

Note that the `send_resolved` option allows the notifier to update the trap status to normal.

### SNMP notifier configuration

Launch the `snmp_notifier` executable with the help flag to see the available options.

```
$ ./snmp_notifier --help
usage: snmp_notifier [<flags>]

A tool to relay Prometheus alerts as SNMP traps

Flags:
  -h, --help                     Show context-sensitive help (also try --help-long and --help-man).
      --web.listen-address=":9464"
                                 Address to listen on for web interface and telemetry.
      --alert.severity-label="severity"
                                 Label where to find the alert severity.
      --alert.severities="critical,warning,info"
                                 The ordered list of alert severities, from more prioritary to less prioritary.
      --alert.default-severity="critical"
                                 The alert severity if none is provided via labels.
      --snmp.destination="127.0.0.1:162"
                                 SNMP trap server destination.
      --snmp.retries=1           SNMP number of retries
      --snmp.community="public"  SNMP community
      --snmp.trap-oid-label="oid"
                                 Label where to find the trap OID.
      --snmp.trap-default-oid="1.1.1"
                                 Trap OID to send if none is found in the alert labels
      --snmp.trap-id-template="{{ .Labels.alertname }}"
                                 SNMP ID template, to group several alerts in a single trap.
      --snmp.trap-description-template="\n{{- if (len .Alerts) gt 0 -}}Status: {{ .Severity -}}\n{{ range $key, $value := .Alerts }}\n\n- Alert name: {{ $value.Labels.alertname }}\n{{\"  \"}}Severity: {{ $value.Labels.severity }}\n{{\"  \"}}Summary: {{ $value.Annotations.summary }}\n{{\"  \"}}Description: {{ $value.Annotations.description }}{{- end -}}\n{{- else -}}\nStatus: OK\n{{- end }}"
                                 SNMP description template.
      --log.level="info"         Only log messages with the given severity or above. Valid levels: [debug, info, warn, error, fatal]
      --log.format="logger:stderr"
                                 Set the log target and format. Example: "logger:syslog?appname=bob&local=7" or "logger:stdout?json=true"
      --version                  Show application version.
```

Note the `snmp.trap-id-template` which allows to generate the trap unique ID. Consequently, it is also used to group alerts under a unique trap. By default, a trap per alert name will be sent, but if you are willing to send your alerts per environment instead, you may use the following command line:

```
./snmp_notifier --snmp.trap-id-template="{{ .Labels.environment }}"
```

Any Go template directive may be used in the `snmp.trap-id-template` and `snmp.trap-description-template` options.

## Examples

Here are 2 example traps received with default configuration. It includes 2 firing alerts sharing the same OID, and 1 resolved alert.

Traps include 3 fields:
* a trap unique ID;
* the alert/trap status;
* a description of the alerts.

```
NET-SNMP version 5.6.2.1
 Agent Address: 0.0.0.0
 Agent Hostname: localhost
 Date: 1 - 0 - 0 - 1 - 1 - 1970
 Enterprise OID: .
 Trap Type: Cold Start
 Trap Sub-Type: 0
 Community/Infosec Context: TRAP2, SNMP v2c, community public
 Uptime: 0
 Description: Cold Start
 PDU Attribute/Value Pair Array:
.iso.org.dod.internet.mgmt.mib-2.system.sysUpTime.sysUpTimeInstance = Timeticks: (751844) 2:05:18.44
.iso.org.dod.internet.snmpV2.snmpModules.snmpMIB.snmpMIBObjects.snmpTrap.snmpTrapOID.0 = OID: .iso.org.dod.internet.private.enterprises.123.0.10.1.1.1.5.1
.iso.org.dod.internet.private.enterprises.123.0.10.1.1.1.5.1.1 = STRING: "1.3.6.1.4.1.123.0.10.1.1.1.5.1[ServiceIsDown]"
.iso.org.dod.internet.private.enterprises.123.0.10.1.1.1.5.1.2 = STRING: "critical"
.iso.org.dod.internet.private.enterprises.123.0.10.1.1.1.5.1.3 = STRING: "Status: critical

- Alert name: ServiceIsDown
  Severity: warning
  Summary: A service is down.
  Description: Service my_app on 192.168.1.1:9000 is down

- Alert name: ServiceIsDown
  Severity: critical
  Summary: A service is down.
  Description: Service my_app on 192.168.1.2:9000 is down"
 --------------
 Agent Address: 0.0.0.0
 Agent Hostname: localhost
 Date: 1 - 0 - 0 - 1 - 1 - 1970
 Enterprise OID: .
 Trap Type: Cold Start
 Trap Sub-Type: 0
 Community/Infosec Context: TRAP2, SNMP v2c, community public
 Uptime: 0
 Description: Cold Start
 PDU Attribute/Value Pair Array:
.iso.org.dod.internet.mgmt.mib-2.system.sysUpTime.sysUpTimeInstance = Timeticks: (751844) 2:05:18.44
.iso.org.dod.internet.snmpV2.snmpModules.snmpMIB.snmpMIBObjects.snmpTrap.snmpTrapOID.0 = OID: .iso.org.dod.internet.private.enterprises.123.0.10.1.1.1.1.1
.iso.org.dod.internet.private.enterprises.123.0.10.1.1.1.1.1.1 = STRING: "1.3.6.1.4.1.123.0.10.1.1.1.1.1[TestAlert]"
.iso.org.dod.internet.private.enterprises.123.0.10.1.1.1.1.1.2 = STRING: "info"
.iso.org.dod.internet.private.enterprises.123.0.10.1.1.1.1.1.3 = STRING: "Status: OK"
 --------------
```

## Contributing

Issues, feedback, PR welcome.
