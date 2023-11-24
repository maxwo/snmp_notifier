package configuration

import (
	"fmt"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/go-kit/log"

	"github.com/prometheus/common/promlog"
	promlogflag "github.com/prometheus/common/promlog/flag"

	"github.com/prometheus/exporter-toolkit/web/kingpinflag"

	"github.com/maxwo/snmp_notifier/alertparser"
	"github.com/maxwo/snmp_notifier/commons"
	"github.com/maxwo/snmp_notifier/httpserver"
	"github.com/maxwo/snmp_notifier/trapsender"

	"strconv"

	kingpin "github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/common/version"
)

// SNMPNotifierConfiguration handles the configuration of the whole application
type SNMPNotifierConfiguration struct {
	AlertParserConfiguration alertparser.Configuration
	TrapSenderConfiguration  trapsender.Configuration
	HTTPServerConfiguration  httpserver.Configuration
}

var (
	snmpCommunityEnvironmentVariable    = "SNMP_NOTIFIER_COMMUNITY"
	snmpAuthUsernameEnvironmentVariable = "SNMP_NOTIFIER_AUTH_USERNAME"
	snmpAuthPasswordEnvironmentVariable = "SNMP_NOTIFIER_AUTH_PASSWORD"
	snmpPrivPasswordEnvironmentVariable = "SNMP_NOTIFIER_PRIV_PASSWORD"
)

// ParseConfiguration parses the command line for configurations
func ParseConfiguration(args []string) (*SNMPNotifierConfiguration, log.Logger, error) {
	var (
		application          = kingpin.New("snmp_notifier", "A tool to relay Prometheus alerts as SNMP traps")
		toolKitConfiguration = kingpinflag.AddFlags(application, ":9464")

		alertSeverityLabel   = application.Flag("alert.severity-label", "Label where to find the alert severity.").Default("severity").String()
		alertSeverities      = application.Flag("alert.severities", "The ordered list of alert severities, from more priority to less priority.").Default("critical,warning,info").String()
		alertDefaultSeverity = application.Flag("alert.default-severity", "The alert severity if none is provided via labels.").Default("critical").String()

		snmpVersion                 = application.Flag("snmp.version", "SNMP version. V2c and V3 are currently supported.").Default("V2c").HintOptions("V2c", "V3").Enum("V2c", "V3")
		snmpDestination             = application.Flag("snmp.destination", "SNMP trap server destination.").Default("127.0.0.1:162").TCPList()
		snmpRetries                 = application.Flag("snmp.retries", "SNMP number of retries").Default("1").Uint()
		snmpTrapOidLabel            = application.Flag("snmp.trap-oid-label", "Label where to find the trap OID.").Default("oid").String()
		snmpDefaultOid              = application.Flag("snmp.trap-default-oid", "Trap OID to send if none is found in the alert labels.").Default("1.3.6.1.4.1.98789").String()
		snmpTrapDescriptionTemplate = application.Flag("snmp.trap-description-template", "SNMP description template.").Default("description-template.tpl").ExistingFile()
		snmpExtraFieldTemplate      = application.Flag("snmp.extra-field-template", "SNMP extra field templates, eg. --snmp.extra-field-templates=4=new-field.template.tpl to add a 4th field to the trap, with the given template file. You may add several fields using that flag several times.").PlaceHolder("4=extra-field-template.tpl").StringMap()
		snmpTimeout                 = application.Flag("snmp.timeout", "SNMP timeout duration").Default("5s").Duration()
		snmpSubObjectDefaultOid     = application.Flag("snmp.sub-object-default-oid", "OID to use as the base of the sub-objects of each trap.").PlaceHolder("1.3.6.1.4.1.123.456").String()

		// V2c only
		snmpCommunity = application.Flag("snmp.community", "SNMP community (V2c only). Passing secrets to the command line is not recommended, consider using the SNMP_NOTIFIER_COMMUNITY environment variable instead.").Envar(snmpCommunityEnvironmentVariable).Default("public").String()

		// V3 only
		snmpAuthenticationEnabled  = application.Flag("snmp.authentication-enabled", "Enable SNMP authentication (V3 only).").Default("false").Bool()
		snmpAuthenticationProtocol = application.Flag("snmp.authentication-protocol", "Protocol for password encryption (V3 only). MD5 and SHA are currently supported.").Default("MD5").HintOptions("MD5", "SHA").Enum("MD5", "SHA")
		snmpAuthenticationUsername = application.Flag("snmp.authentication-username", "SNMP authentication username (V3 only). Passing secrets to the command line is not recommended, consider using the SNMP_NOTIFIER_AUTH_USERNAME environment variable instead.").PlaceHolder("USERNAME").Envar(snmpAuthUsernameEnvironmentVariable).String()
		snmpAuthenticationPassword = application.Flag("snmp.authentication-password", "SNMP authentication password (V3 only). Passing secrets to the command line is not recommended, consider using the SNMP_NOTIFIER_AUTH_PASSWORD environment variable instead.").PlaceHolder("PASSWORD").Envar(snmpAuthPasswordEnvironmentVariable).String()
		snmpPrivateEnabled         = application.Flag("snmp.private-enabled", "Enable SNMP encryption (V3 only).").Default("false").Bool()
		snmpPrivateProtocol        = application.Flag("snmp.private-protocol", "Protocol for SNMP data transmission (V3 only). DES and AES are currently supported.").Default("DES").HintOptions("DES", "AES").Enum("DES", "AES")
		snmpPrivatePassword        = application.Flag("snmp.private-password", "SNMP private password (V3 only). Passing secrets to the command line is not recommended, consider using the SNMP_NOTIFIER_PRIV_PASSWORD environment variable instead.").PlaceHolder("SECRET").Envar(snmpPrivPasswordEnvironmentVariable).String()
		snmpSecurityEngineID       = application.Flag("snmp.security-engine-id", "SNMP security engine ID (V3 only).").PlaceHolder("SECURITY_ENGINE_ID").String()
		snmpContextEngineID        = application.Flag("snmp.context-engine-id", "SNMP context engine ID (V3 only).").PlaceHolder("CONTEXT_ENGINE_ID").String()
		snmpContextName            = application.Flag("snmp.context-name", "SNMP context name (V3 only).").PlaceHolder("CONTEXT_ENGINE_NAME").String()
	)

	promlogConfig := promlog.Config{}
	promlogflag.AddFlags(application, &promlogConfig)

	application.Version(version.Print("snmp_notifier"))
	application.HelpFlag.Short('h')
	kingpin.MustParse(application.Parse(args))

	logger := promlog.New(&promlogConfig)

	descriptionTemplate, err := template.New(filepath.Base(*snmpTrapDescriptionTemplate)).Funcs(template.FuncMap{
		"groupAlertsByLabel":  commons.GroupAlertsByLabel,
		"groupAlertsByName":   commons.GroupAlertsByName,
		"groupAlertsByStatus": commons.GroupAlertsByStatus,
	}).ParseFiles(*snmpTrapDescriptionTemplate)
	if err != nil {
		return nil, logger, err
	}

	extraFieldTemplates := make(map[string]template.Template)
	if snmpExtraFieldTemplate != nil {
		for k, v := range *snmpExtraFieldTemplate {
			i, err := strconv.Atoi(k)
			if err != nil || i < 4 {
				return nil, logger, fmt.Errorf("Invalid field ID: %s. Field ID must be a number superior to 3", k)
			}
			currentTemplate, err := template.New(filepath.Base(v)).Funcs(template.FuncMap{
				"groupAlertsByLabel":  commons.GroupAlertsByLabel,
				"groupAlertsByName":   commons.GroupAlertsByName,
				"groupAlertsByStatus": commons.GroupAlertsByStatus,
			}).ParseFiles(v)
			if err != nil {
				return nil, logger, err
			}
			extraFieldTemplates[k] = *currentTemplate
		}
	}

	if !commons.IsOID(*snmpDefaultOid) {
		return nil, logger, fmt.Errorf("Invalid default OID provided: %s", *snmpDefaultOid)
	}

	severities := strings.Split(*alertSeverities, ",")

	alertParserConfiguration := alertparser.Configuration{
		DefaultOID:      *snmpDefaultOid,
		OIDLabel:        *snmpTrapOidLabel,
		DefaultSeverity: *alertDefaultSeverity,
		Severities:      severities,
		SeverityLabel:   *alertSeverityLabel,
	}

	isV2c := *snmpVersion == "V2c"

	snmpDestinations := []string{}
	for _, destination := range *snmpDestination {
		snmpDestinations = append(snmpDestinations, destination.String())
	}

	trapSenderConfiguration := trapsender.Configuration{
		SNMPVersion:         *snmpVersion,
		SNMPDestination:     snmpDestinations,
		SNMPRetries:         *snmpRetries,
		DescriptionTemplate: *descriptionTemplate,
		ExtraFieldTemplates: extraFieldTemplates,
		SNMPTimeout:         *snmpTimeout,
	}

	if isV2c {
		trapSenderConfiguration.SNMPCommunity = *snmpCommunity
	}

	if !isV2c {
		trapSenderConfiguration.SNMPAuthenticationUsername = *snmpAuthenticationUsername
		trapSenderConfiguration.SNMPSecurityEngineID = *snmpSecurityEngineID
		trapSenderConfiguration.SNMPContextEngineID = *snmpContextEngineID
		trapSenderConfiguration.SNMPContextName = *snmpContextName
	}

	if isV2c && (*snmpAuthenticationEnabled || *snmpPrivateEnabled) {
		return nil, logger, fmt.Errorf("SNMP authentication or private only available with SNMP v3")
	}

	if !*snmpAuthenticationEnabled && *snmpPrivateEnabled {
		return nil, logger, fmt.Errorf("SNMP private encryption requires authentication enabled.")
	}

	if *snmpAuthenticationEnabled {
		trapSenderConfiguration.SNMPAuthenticationEnabled = *snmpAuthenticationEnabled
		trapSenderConfiguration.SNMPAuthenticationProtocol = *snmpAuthenticationProtocol
		trapSenderConfiguration.SNMPAuthenticationPassword = *snmpAuthenticationPassword
	}
	if *snmpPrivateEnabled {
		trapSenderConfiguration.SNMPPrivateEnabled = *snmpPrivateEnabled
		trapSenderConfiguration.SNMPPrivateProtocol = *snmpPrivateProtocol
		trapSenderConfiguration.SNMPPrivatePassword = *snmpPrivatePassword
	}

	if *snmpSubObjectDefaultOid != "" {
		trapSenderConfiguration.SNMPSubObjectDefaultOid = *snmpSubObjectDefaultOid
	}

	httpServerConfiguration := httpserver.Configuration{
		ToolKitConfiguration: *toolKitConfiguration,
	}

	configuration := SNMPNotifierConfiguration{
		AlertParserConfiguration: alertParserConfiguration,
		TrapSenderConfiguration:  trapSenderConfiguration,
		HTTPServerConfiguration:  httpServerConfiguration,
	}

	return &configuration, logger, err
}
