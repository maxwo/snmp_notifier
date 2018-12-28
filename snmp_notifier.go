// Copyright 2018 Maxime Wojtczak
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/maxwo/snmp_notifier/alertparser"
	"github.com/maxwo/snmp_notifier/commons"
	"github.com/maxwo/snmp_notifier/httpserver"
	"github.com/maxwo/snmp_notifier/telemetry"
	"github.com/maxwo/snmp_notifier/trapsender"

	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	snmpTrapDescriptionTemplateDefault = `
{{- if (len .Alerts) gt 0 -}}
{{- range $severity, $alerts := (groupAlertsByLabel .Alerts "severity") -}}
Status: {{ $severity }}
{{- range $index, $alert := $alerts }}
- Alert: {{ $alert.Labels.alertname }}
  Summary: {{ $alert.Annotations.summary }}
  Description: {{ $alert.Annotations.description }}
{{ end }}
{{ end }}
{{ else -}}
Status: OK
{{- end -}}`
	snmpTrapIDTemplateDefault = `{{ .Labels.alertname }}`
)

type snmpNotifierConfiguration struct {
	alertParserConfiguration alertparser.AlertParserConfiguration
	trapSenderConfiguration  trapsender.TrapSenderConfiguration
	httpServerConfiguration  httpserver.HTTPServerConfiguration
}

func main() {
	configuration, err := parseConfiguration(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	snmpNotifier, err := createSNMPNotifier(*configuration)
	if err != nil {
		log.Fatal(err)
	}
	telemetry.Init()
	err = snmpNotifier.Configure().ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

func createSNMPNotifier(configuration snmpNotifierConfiguration) (*httpserver.HTTPServer, error) {
	trapSender := trapsender.New(configuration.trapSenderConfiguration)
	alertParser := alertparser.New(configuration.alertParserConfiguration)
	return httpserver.New(configuration.httpServerConfiguration, alertParser, trapSender), nil
}

func parseConfiguration(args []string) (*snmpNotifierConfiguration, error) {
	var (
		application                 = kingpin.New("snmp_notifier", "A tool to relay Prometheus alerts as SNMP traps")
		webListenAddress            = application.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9464").String()
		alertSeverityLabel          = application.Flag("alert.severity-label", "Label where to find the alert severity.").Default("severity").String()
		alertSeverities             = application.Flag("alert.severities", "The ordered list of alert severities, from more prioritary to less prioritary.").Default("critical,warning,info").String()
		alertDefaultSeverity        = application.Flag("alert.default-severity", "The alert severity if none is provided via labels.").Default("critical").String()
		snmpDestination             = application.Flag("snmp.destination", "SNMP trap server destination.").Default("127.0.0.1:162").String()
		snmpRetries                 = application.Flag("snmp.retries", "SNMP number of retries").Default("1").Uint()
		snmpCommunity               = application.Flag("snmp.community", "SNMP community").Default("public").String()
		snmpTrapOidLabel            = application.Flag("snmp.trap-oid-label", "Label where to find the trap OID.").Default("oid").String()
		snmpDefaultOid              = application.Flag("snmp.trap-default-oid", "Trap OID to send if none is found in the alert labels").Default("1.1.1").String()
		snmpTrapIDTemplate          = application.Flag("snmp.trap-id-template", "SNMP ID template, to group several alerts in a single trap.").Default(snmpTrapIDTemplateDefault).String()
		snmpTrapDescriptionTemplate = application.Flag("snmp.trap-description-template", "SNMP description template.").Default(snmpTrapDescriptionTemplateDefault).String()
	)

	log.AddFlags(application)
	application.Version(version.Print("snmp_notifier"))
	application.HelpFlag.Short('h')
	kingpin.MustParse(application.Parse(args))

	idTemplate, err := template.New("id").Parse(*snmpTrapIDTemplate)
	if err != nil {
		return nil, err
	}

	descriptionTemplate, err := template.New("description").Funcs(template.FuncMap{
		"groupAlertsByLabel": commons.GroupAlertsByLabel,
		"groupAlertsByName":  commons.GroupAlertsByName,
	}).Parse(*snmpTrapDescriptionTemplate)
	if err != nil {
		return nil, err
	}

	if !commons.IsOID(*snmpDefaultOid) {
		return nil, fmt.Errorf("Invalid default OID provided: %s", *snmpDefaultOid)
	}

	snmp, err := trapsender.Connect(*snmpDestination, *snmpRetries, *snmpCommunity)
	if err != nil {
		return nil, err
	}

	severities := strings.Split(*alertSeverities, ",")
	alertParserConfiguration := alertparser.AlertParserConfiguration{*idTemplate, *snmpDefaultOid, *snmpTrapOidLabel, *alertDefaultSeverity, severities, *alertSeverityLabel}
	trapSenderConfiguration := trapsender.TrapSenderConfiguration{*snmp, *descriptionTemplate}
	httpServerConfiguration := httpserver.HTTPServerConfiguration{*webListenAddress}
	configuration := snmpNotifierConfiguration{alertParserConfiguration, trapSenderConfiguration, httpServerConfiguration}

	return &configuration, nil
}
