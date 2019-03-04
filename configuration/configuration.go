package configuration

import (
	"fmt"
	"os"
	"path/filepath"
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

// SNMPNotifierConfiguration handles the configuration of the whole application
type SNMPNotifierConfiguration struct {
	AlertParserConfiguration alertparser.Configuration
	TrapSenderConfiguration  trapsender.Configuration
	HTTPServerConfiguration  httpserver.Configuration
}

var (
	snmpDefaultCommunity             = "public"
	snmpCommunityEnvironmentVariable = "SNMP_NOTIFIER_COMMUNITY"
)

// ParseConfiguration parses the command line for configurations
func ParseConfiguration(args []string) (*SNMPNotifierConfiguration, error) {
	var (
		application                 = kingpin.New("snmp_notifier", "A tool to relay Prometheus alerts as SNMP traps")
		webListenAddress            = application.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9464").TCP()
		alertSeverityLabel          = application.Flag("alert.severity-label", "Label where to find the alert severity.").Default("severity").String()
		alertSeverities             = application.Flag("alert.severities", "The ordered list of alert severities, from more prioritary to less prioritary.").Default("critical,warning,info").String()
		alertDefaultSeverity        = application.Flag("alert.default-severity", "The alert severity if none is provided via labels.").Default("critical").String()
		snmpDestination             = application.Flag("snmp.destination", "SNMP trap server destination.").Default("127.0.0.1:162").TCP()
		snmpRetries                 = application.Flag("snmp.retries", "SNMP number of retries").Default("1").Uint()
		snmpTrapOidLabel            = application.Flag("snmp.trap-oid-label", "Label where to find the trap OID.").Default("oid").String()
		snmpDefaultOid              = application.Flag("snmp.trap-default-oid", "Trap OID to send if none is found in the alert labels").Default("1.3.6.1.4.1.1664.1").String()
		snmpTrapDescriptionTemplate = application.Flag("snmp.trap-description-template", "SNMP description template.").Default("description-template.tpl").ExistingFile()
	)

	log.AddFlags(application)
	application.Version(version.Print("snmp_notifier"))
	application.HelpFlag.Short('h')
	kingpin.MustParse(application.Parse(args))

	descriptionTemplate, err := template.New(filepath.Base(*snmpTrapDescriptionTemplate)).Funcs(template.FuncMap{
		"groupAlertsByLabel": commons.GroupAlertsByLabel,
		"groupAlertsByName":  commons.GroupAlertsByName,
	}).ParseFiles(*snmpTrapDescriptionTemplate)
	if err != nil {
		return nil, err
	}

	snmpCommunity := snmpDefaultCommunity
	if len(strings.TrimSpace(os.Getenv(snmpCommunityEnvironmentVariable))) > 0 {
		snmpCommunity = os.Getenv(snmpCommunityEnvironmentVariable)
	}

	if !commons.IsOID(*snmpDefaultOid) {
		return nil, fmt.Errorf("Invalid default OID provided: %s", *snmpDefaultOid)
	}

	severities := strings.Split(*alertSeverities, ",")

	alertParserConfiguration := alertparser.Configuration{
		DefaultOID:      *snmpDefaultOid,
		OIDLabel:        *snmpTrapOidLabel,
		DefaultSeverity: *alertDefaultSeverity,
		Severities:      severities,
		SeverityLabel:   *alertSeverityLabel,
	}

	trapSenderConfiguration := trapsender.Configuration{
		SNMPDestination:     (*snmpDestination).String(),
		SNMPRetries:         *snmpRetries,
		SNMPCommunity:       snmpCommunity,
		DescriptionTemplate: *descriptionTemplate,
	}

	httpServerConfiguration := httpserver.Configuration{
		WebListenAddress: (*webListenAddress).String(),
	}

	configuration := SNMPNotifierConfiguration{
		AlertParserConfiguration: alertParserConfiguration,
		TrapSenderConfiguration:  trapSenderConfiguration,
		HTTPServerConfiguration:  httpServerConfiguration,
	}

	return &configuration, nil
}
