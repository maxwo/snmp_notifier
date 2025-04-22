# SNMP Notifier

[![CircleCI](https://circleci.com/gh/maxwo/snmp_notifier/tree/main.svg?style=svg)](https://circleci.com/gh/maxwo/snmp_notifier/tree/main)
[![Go Report Card](https://goreportcard.com/badge/github.com/maxwo/snmp_notifier)](https://goreportcard.com/report/github.com/maxwo/snmp_notifier)

`snmp_notifier` receives alerts from the Prometheus' Alertmanager and routes them as SNMP traps.

## Overview

The SNMP notifier receives alerts and sends them as SNMP traps to any given SNMP poller.

It has been created to handle older monitoring and alerting systems such as Nagios or Centreon.

Prometheus' Alertmanager sends the alerts to the SNMP notifier on its HTTP API. The SNMP notifier then looks for OID in the given alerts' labels. Each trap is sent with a unique ID, which allows, if the alert is updated or once it is resolved, to send additional traps with updated status and data.

## Install

There are various ways to install the SNMP notifier:

### Helm Chart

The SNMP notifier chart is available via the [Prometheus Community Kubernetes Helm Charts](https://github.com/prometheus-community/helm-charts):

```console
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install snmp-notifier prometheus-community/alertmanager-snmp-notifier --set 'snmpNotifier.snmpDestinations={my-snmp-server:162}'
```

Refer to the [chart values](https://github.com/prometheus-community/helm-charts/blob/main/charts/alertmanager-snmp-notifier/values.yaml) to see the available options.

### Docker Images

Docker images are available on the [Docker Hub](https://hub.docker.com/r/maxwo/snmp-notifier).

### Precompiled binaries

Precompiled binaries are available in the [_release_ section](https://github.com/maxwo/snmp_notifier/releases) of this repository.

### Compiling the binary

Check out the source code and build it manually:

```console
git clone https://github.com/maxwo/snmp_notifier.git
cd snmp_notifier
make build
./snmp_notifier
```

## Running and configuration

### Prometheus' alerts configuration

OID may be added to the alert labels to identify the kind of trap to be sent:

---

A default OID is specified in the SNMP notifier if none is found in the alert. This can be useful if you want all the alerts to share the same OID.

---

```yaml
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
          description: "Service {{ $labels.job }} on {{ $labels.instance }} is down"
          summary: "A service is down."
```

### Alertmanager configuration

The Alertmanager should be configured with the SNMP notifier as alert receiver:

```yaml
receivers:
  - name: "snmp_notifier"
    webhook_configs:
      - send_resolved: true
        url: http://snmp.notifier.service:9464/alerts
```

Note that the `send_resolved` option allows the notifier to update the trap status to normal.

### SNMP notifier configuration

Launch the `snmp_notifier` executable with the help flag to see the available options.

```console
$ ./snmp_notifier --help
usage: snmp_notifier [<flags>]

A tool to relay Prometheus alerts as SNMP traps


Flags:
  -h, --[no-]help                Show context-sensitive help (also try --help-long and --help-man).
      --web.listen-address=:9464 ...  
                                 Addresses on which to expose metrics and web interface. Repeatable for multiple addresses. Examples: `:9100` or `[::1]:9100` for http,
                                 `vsock://:9100` for vsock
      --web.config.file=""       Path to configuration file that can enable TLS or authentication. See:
                                 https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md
      --alert.severity-label="severity"  
                                 Label where to find the alert severity.
      --alert.severities="critical,warning,info"  
                                 The ordered list of alert severities, from more priority to less priority.
      --alert.default-severity="critical"  
                                 The alert severity if none is provided via labels.
      --snmp.version=V2c         SNMP version. V2c and V3 are currently supported.
      --snmp.destination=127.0.0.1:162 ...  
                                 SNMP trap server destination.
      --snmp.retries=1           SNMP number of retries
      --snmp.trap-default-oid="1.3.6.1.4.1.98789"  
                                 Trap OID to send if none is found in the alert labels.
      --snmp.trap-oid-label="oid"  
                                 Label where to find the trap OID.
      --snmp.trap-default-resolved-oid=1.3.6.1.4.1.444.555  
                                 Resolution trap OID to send if none is found in the alert labels. Defaults to the same trap OID as the firing trap.
      --snmp.trap-resolved-oid-label=resolution-oid  
                                 Label where to find the resolution trap OID. Deafults to the same label as the firing OID label.
      --snmp.trap-description-template=description-template.tpl  
                                 SNMP description template.
      --snmp.extra-field-template=4=extra-field-template.tpl ...  
                                 SNMP extra field templates, eg. --snmp.extra-field-templates=4=new-field.template.tpl to add a 4th field to the trap, with the given template file.
                                 You may add several fields using that flag several times.
      --snmp.timeout=5s          SNMP timeout duration
      --snmp.sub-object-default-oid=1.3.6.1.4.1.123.456  
                                 OID to use as the base of the sub-objects of each trap.
      --snmp.community="public"  SNMP community (V2c only). Passing secrets to the command line is not recommended, consider using the SNMP_NOTIFIER_COMMUNITY environment variable
                                 instead. ($SNMP_NOTIFIER_COMMUNITY)
      --[no-]snmp.authentication-enabled  
                                 Enable SNMP authentication (V3 only).
      --snmp.authentication-protocol=MD5  
                                 Protocol for password encryption (V3 only). MD5 and SHA are currently supported.
      --snmp.authentication-username=USERNAME  
                                 SNMP authentication username (V3 only). Passing secrets to the command line is not recommended, consider using the SNMP_NOTIFIER_AUTH_USERNAME
                                 environment variable instead. ($SNMP_NOTIFIER_AUTH_USERNAME)
      --snmp.authentication-password=PASSWORD  
                                 SNMP authentication password (V3 only). Passing secrets to the command line is not recommended, consider using the SNMP_NOTIFIER_AUTH_PASSWORD
                                 environment variable instead. ($SNMP_NOTIFIER_AUTH_PASSWORD)
      --[no-]snmp.private-enabled  
                                 Enable SNMP encryption (V3 only).
      --snmp.private-protocol=DES  
                                 Protocol for SNMP data transmission (V3 only). DES and AES are currently supported.
      --snmp.private-password=SECRET  
                                 SNMP private password (V3 only). Passing secrets to the command line is not recommended, consider using the SNMP_NOTIFIER_PRIV_PASSWORD environment
                                 variable instead. ($SNMP_NOTIFIER_PRIV_PASSWORD)
      --snmp.security-engine-id=SECURITY_ENGINE_ID  
                                 SNMP security engine ID (V3 only).
      --snmp.context-engine-id=CONTEXT_ENGINE_ID  
                                 SNMP context engine ID (V3 only).
      --snmp.context-name=CONTEXT_ENGINE_NAME  
                                 SNMP context name (V3 only).
      --log.level=info           Only log messages with the given severity or above. One of: [debug, info, warn, error]
      --log.format=logfmt        Output format of log messages. One of: [logfmt, json]
      --[no-]version             Show application version.
```

Also, it is recommended to use the following environment variables to set the SNMP secrets:

| Environment variable        | Configuration                                 | Default |
| --------------------------- | --------------------------------------------- | ------- |
| SNMP_NOTIFIER_COMMUNITY     | SNMP community for SNMP v2c                   | public  |
| SNMP_NOTIFIER_AUTH_USERNAME | SNMP authentication username for SNMP v3      |         |
| SNMP_NOTIFIER_AUTH_PASSWORD | SNMP authentication password for SNMP v3      |         |
| SNMP_NOTIFIER_PRIV_PASSWORD | SNMP private (or server) password for SNMP v3 |         |

Any Go template directive may be used in the `snmp.trap-description-template` file.

## Examples

### Simple Usage

Here are 2 example traps received with the default configuration. It includes 2 firing alerts sharing the same OID, and 1 resolved alert.

Traps include 3 fields:

- a trap unique ID;
- the alert/trap status;
- a description of the alerts.

```console
$ snmptrapd -m ALL -m +SNMP-NOTIFIER-MIB -f -Of -Lo -c scripts/snmptrapd.conf
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
.iso.org.dod.internet.mgmt.mib-2.system.sysUpTime.sysUpTimeInstance = Timeticks: (853395100) 98 days, 18:32:31.00
.iso.org.dod.internet.snmpV2.snmpModules.snmpMIB.snmpMIBObjects.snmpTrap.snmpTrapOID.0 = OID: .iso.org.dod.internet.private.enterprises.snmpNotifier.snmpNotifierDefaultTrap
.iso.org.dod.internet.private.enterprises.snmpNotifier.snmpNotifierAlertsObjects.snmpNotifierAlertId = STRING: "1.3.6.1.4.1.98789[environment=production,label=test]"
.iso.org.dod.internet.private.enterprises.snmpNotifier.snmpNotifierAlertsObjects.snmpNotifierAlertSeverity = STRING: "critical"
.iso.org.dod.internet.private.enterprises.snmpNotifier.snmpNotifierAlertsObjects.snmpNotifierAlertDescription = STRING: "2/3 alerts are firing:

Status: critical
- Alert: TestAlert
  Summary: this is the summary
  Description: this is the description on job1

Status: warning
- Alert: TestAlert
  Summary: this is the random summary
  Description: this is the description of alert 1"
 --------------
```

### With extra fields

You may add additional fields thanks to the `--snmp.extra-field-template` arguments.

For instance, the template `{{ len .Alerts }} alerts are firing.` given in the `--snmp.extra-field-template=4=alert-count.tpl` argument will produce:

```console
$ snmptrapd -m ALL -m +SNMP-NOTIFIER-MIB -f -Of -Lo -c scripts/snmptrapd.conf
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
.iso.org.dod.internet.mgmt.mib-2.system.sysUpTime.sysUpTimeInstance = Timeticks: (2665700) 7:24:17.00
.iso.org.dod.internet.snmpV2.snmpModules.snmpMIB.snmpMIBObjects.snmpTrap.snmpTrapOID.0 = OID: .iso.org.dod.internet.private.enterprises.snmpNotifier.snmpNotifierDefaultTrap
.iso.org.dod.internet.private.enterprises.snmpNotifier.snmpNotifierAlertsObjects.snmpNotifierAlertId = STRING: "1.3.6.1.4.1.98789[environment=production,label=test]"
.iso.org.dod.internet.private.enterprises.snmpNotifier.snmpNotifierAlertsObjects.snmpNotifierAlertSeverity = STRING: "critical"
.iso.org.dod.internet.private.enterprises.snmpNotifier.snmpNotifierAlertsObjects.snmpNotifierAlertDescription = STRING: "2/3 alerts are firing:

Status: critical
- Alert: TestAlert
  Summary: this is the summary
  Description: this is the description on job1

Status: warning
- Alert: TestAlert
  Summary: this is the random summary
  Description: this is the description of alert 1"
.iso.org.dod.internet.private.enterprises.snmpNotifier.snmpNotifierAlertsObjects.4 = STRING: "2 alerts are firing."
--------------
````

## Contributing

Issues, feedback, PR welcome.
