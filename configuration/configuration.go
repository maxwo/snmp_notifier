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

package configuration

import (
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"log/slog"

	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/promslog/flag"
	"github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"github.com/shirou/gopsutil/host"

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
func ParseConfiguration(args []string) (*SNMPNotifierConfiguration, *slog.Logger, error) {
	var (
		application          = kingpin.New("snmp_notifier", "A tool to relay Prometheus alerts as SNMP traps")
		toolKitConfiguration = kingpinflag.AddFlags(application, ":9464")

		alertSeverityLabel   = application.Flag("alert.severity-label", "Label where to find the alert severity.").Default("severity").String()
		alertSeverities      = application.Flag("alert.severities", "The ordered list of alert severities, from more priority to less priority.").Default("critical,warning,info").String()
		alertDefaultSeverity = application.Flag("alert.default-severity", "The alert severity if none is provided via labels.").Default("critical").String()

		// SNMP configuration
		snmpVersion     = application.Flag("snmp.version", "SNMP version. V2c and V3 are currently supported.").Default("V2c").HintOptions("V2c", "V3").Enum("V2c", "V3")
		snmpDestination = application.Flag("snmp.destination", "SNMP trap server destination.").Default("127.0.0.1:162").TCPList()
		snmpRetries     = application.Flag("snmp.retries", "SNMP number of retries").Default("1").Uint()
		snmpTimeout     = application.Flag("snmp.timeout", "SNMP timeout duration").Default("5s").Duration()

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
		snmpEngineStartTime        = application.Flag("snmp.engine-start-time", "UNIX timestamp specifying the engine start time in seconds. Defaults to the host boot time.").Default("").String()

		// Trap configurations
		trapDefaultOID            = application.Flag("trap.default-oid", "Default trap OID.").Default("1.3.6.1.4.1.98789.1").String()
		trapOIDLabel              = application.Flag("trap.oid-label", "Label containing a custom trap OID.").Default("oid").String()
		trapResolutionDefaultOID  = application.Flag("trap.resolution-default-oid", "Resolution trap OID, if different from the firing trap OID.").String()
		trapResolutionOIDLabel    = application.Flag("trap.resolution-oid-label", "Label containing a custom resolution trap OID, if different from the firing trap OID.").String()
		trapDefaultObjectsBaseOID = application.Flag("trap.default-objects-base-oid", "Base OID for default trap objects.").Default("1.3.6.1.4.1.98789.2").String()
		trapDescriptionTemplate   = application.Flag("trap.description-template", "Trap description template.").Default("description-template.tpl").ExistingFile()
		trapUserObjectsBaseOID    = application.Flag("trap.user-objects-base-oid", "Base OID for user-defined trap objects.").Default("1.3.6.1.4.1.98789.3").String()
		trapUserObject            = application.Flag("trap.user-object", "User object sub-OID and template, e.g. --trap.user-object=4=new-object.template.tpl to add a sub-object to the trap, with the given template file. You may add several user objects using that flag several times.").PlaceHolder("4=user-object-template.tpl").StringMap()
	)

	promslogConfig := &promslog.Config{}
	flag.AddFlags(application, promslogConfig)

	application.Version(version.Print("snmp_notifier"))
	application.HelpFlag.Short('h')
	kingpin.MustParse(application.Parse(args))

	logger := promslog.New(promslogConfig)
	logger.Info("Starting snmp_notifier", "version", version.Info())
	logger.Info("Build context", "build_context", version.BuildContext())

	descriptionTemplate, err := template.New(filepath.Base(*trapDescriptionTemplate)).Funcs(template.FuncMap{
		"groupAlertsByLabel":  commons.GroupAlertsByLabel,
		"groupAlertsByName":   commons.GroupAlertsByName,
		"groupAlertsByStatus": commons.GroupAlertsByStatus,
	}).ParseFiles(*trapDescriptionTemplate)
	if err != nil {
		return nil, logger, err
	}

	minimumUserObjectSubOID := 0
	if *trapDefaultObjectsBaseOID == *trapUserObjectsBaseOID {
		logger.Warn("using the same OID for default objects and user objects is deprecated, and will be removed in future versions. Please consider using different OID")
		minimumUserObjectSubOID = 4
	}

	userObjectsTemplates := make(map[int]template.Template)
	if trapUserObject != nil {
		for subOid, templatePath := range *trapUserObject {
			oidValue, err := strconv.Atoi(subOid)
			if err != nil || oidValue < minimumUserObjectSubOID {
				return nil, logger, fmt.Errorf("invalid object ID: %s. Object ID must be a number greater or equal to 4", subOid)
			}

			_, defined := userObjectsTemplates[oidValue]
			if defined {
				return nil, logger, fmt.Errorf("invalid object ID: %d defined twice", oidValue)
			}

			currentTemplate, err := template.New(filepath.Base(templatePath)).Funcs(template.FuncMap{
				"groupAlertsByLabel":  commons.GroupAlertsByLabel,
				"groupAlertsByName":   commons.GroupAlertsByName,
				"groupAlertsByStatus": commons.GroupAlertsByStatus,
			}).ParseFiles(templatePath)
			if err != nil {
				return nil, logger, err
			}

			userObjectsTemplates[oidValue] = *currentTemplate
		}
	}

	subOIDs := make([]int, 0, len(userObjectsTemplates))
	for subOID := range userObjectsTemplates {
		subOIDs = append(subOIDs, subOID)
	}
	sort.Ints(subOIDs)

	userObjects := make([]trapsender.UserObject, len(userObjectsTemplates))
	for index, subOID := range subOIDs {
		contentTemplate := userObjectsTemplates[subOID]
		userObject := trapsender.UserObject{
			SubOID:          subOID,
			ContentTemplate: contentTemplate,
		}
		userObjects[index] = userObject
	}

	if !commons.IsOID(*trapDefaultOID) {
		return nil, logger, fmt.Errorf("invalid default trap OID provided: %s", *trapDefaultOID)
	}

	if *trapResolutionDefaultOID != "" && !commons.IsOID(*trapResolutionDefaultOID) {
		return nil, logger, fmt.Errorf("invalid resolution trap OID provided: %s", *trapResolutionDefaultOID)
	} else if *trapResolutionDefaultOID == "" {
		trapResolutionDefaultOID = nil
	}

	if *trapResolutionOIDLabel == "" {
		trapResolutionOIDLabel = nil
	}

	if !commons.IsOID(*trapDefaultObjectsBaseOID) {
		return nil, logger, fmt.Errorf("invalid default objects base OID provided: %s", *trapDefaultObjectsBaseOID)
	}

	if !commons.IsOID(*trapUserObjectsBaseOID) {
		return nil, logger, fmt.Errorf("invalid user objects base OID provided: %s", *trapUserObjectsBaseOID)
	}

	severities := strings.Split(*alertSeverities, ",")

	alertParserConfiguration := alertparser.Configuration{
		TrapDefaultOID:            *trapDefaultOID,
		TrapOIDLabel:              *trapOIDLabel,
		TrapResolutionDefaultOID:  trapResolutionDefaultOID,
		TrapResolutionOIDLabel:    trapResolutionOIDLabel,
		DefaultSeverity:           *alertDefaultSeverity,
		Severities:                severities,
		SeverityLabel:             *alertSeverityLabel,
		TrapDefaultObjectsBaseOID: *trapDefaultObjectsBaseOID,
		TrapUserObjectsBaseOID:    *trapUserObjectsBaseOID,
	}

	isV2c := *snmpVersion == "V2c"

	snmpDestinations := []string{}
	for _, destination := range *snmpDestination {
		snmpDestinations = append(snmpDestinations, destination.String())
	}

	var engineStartTime int
	if *snmpEngineStartTime == "" {
		bootTime, err := host.BootTime()
		if err != nil {
			return nil, logger, fmt.Errorf("unable to get the host boot time: %w", err)
		}
		if bootTime > math.MaxInt {
			bootTime = 0
		}
		engineStartTime = int(bootTime)
	} else {
		engineStartTime, err = strconv.Atoi(*snmpEngineStartTime)
		if err != nil {
			return nil, logger, fmt.Errorf("unable to parse snmp engine start time: %w", err)
		}
	}

	trapSenderConfiguration := trapsender.Configuration{
		SNMPVersion:             *snmpVersion,
		SNMPDestination:         snmpDestinations,
		SNMPRetries:             *snmpRetries,
		DescriptionTemplate:     *descriptionTemplate,
		UserObjects:             userObjects,
		SNMPTimeout:             *snmpTimeout,
		SNMPEngineStartTimeUnix: engineStartTime,
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
		return nil, logger, fmt.Errorf("SNMP private encryption requires authentication enabled")
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
