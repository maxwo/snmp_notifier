package configuration

import (
	"fmt"
	"strings"
	"text/template"

	"github.com/maxwo/snmp_notifier/alertparser"
	"github.com/maxwo/snmp_notifier/commons"
	"github.com/maxwo/snmp_notifier/httpserver"
	"github.com/maxwo/snmp_notifier/trapsender"

	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

type SNMPNotifierConfiguration struct {
	AlertParserConfiguration alertparser.AlertParserConfiguration
	TrapSenderConfiguration  trapsender.TrapSenderConfiguration
	HTTPServerConfiguration  httpserver.HTTPServerConfiguration
}

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

func ParseConfiguration(args []string) (*SNMPNotifierConfiguration, error) {
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
		snmpDefaultOid              = application.Flag("snmp.trap-default-oid", "Trap OID to send if none is found in the alert labels").Default("1.3.6.1.4.1.1664.1").String()
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

	severities := strings.Split(*alertSeverities, ",")

	alertParserConfiguration := alertparser.AlertParserConfiguration{
		IDTemplate:      *idTemplate,
		DefaultOID:      *snmpDefaultOid,
		OIDLabel:        *snmpTrapOidLabel,
		DefaultSeverity: *alertDefaultSeverity,
		Severities:      severities,
		SeverityLabel:   *alertSeverityLabel,
	}

	trapSenderConfiguration := trapsender.TrapSenderConfiguration{
		SNMPDestination:     *snmpDestination,
		SNMPRetries:         *snmpRetries,
		SNMPCommunity:       *snmpCommunity,
		DescriptionTemplate: *descriptionTemplate,
	}

	httpServerConfiguration := httpserver.HTTPServerConfiguration{
		WebListenAddress: *webListenAddress,
	}

	configuration := SNMPNotifierConfiguration{
		AlertParserConfiguration: alertParserConfiguration,
		TrapSenderConfiguration:  trapSenderConfiguration,
		HTTPServerConfiguration:  httpServerConfiguration,
	}

	return &configuration, nil
}
