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
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/maxwo/snmp_notifier/alertparser"
	"github.com/maxwo/snmp_notifier/commons"
	"github.com/maxwo/snmp_notifier/httpserver"
	"github.com/maxwo/snmp_notifier/trapsender"
	"github.com/prometheus/exporter-toolkit/web"

	"github.com/go-test/deep"
)

var falseValue = false
var emptyString = ""
var testListenAddresses = []string{":1234"}

func TestDefaultConfiguration(t *testing.T) {
	expectConfigurationFromCommandLine(t,
		"--web.listen-address=:1234 --trap.description-template=../description-template.tpl",
		SNMPNotifierConfiguration{
			alertparser.Configuration{
				TrapDefaultOID:            "1.3.6.1.4.1.98789.1",
				TrapOIDLabel:              "oid",
				DefaultSeverity:           "critical",
				SeverityLabel:             "severity",
				Severities:                []string{"critical", "warning", "info"},
				TrapDefaultObjectsBaseOID: "1.3.6.1.4.1.98789.2",
				TrapUserObjectsBaseOID:    "1.3.6.1.4.1.98789.3",
			},
			trapsender.Configuration{
				SNMPVersion:     "V2c",
				SNMPDestination: []string{"127.0.0.1:162"},
				SNMPRetries:     1,
				SNMPTimeout:     5 * time.Second,
				SNMPCommunity:   "public",
				UserObjects:     make([]trapsender.UserObject, 0),
			},
			httpserver.Configuration{
				ToolKitConfiguration: web.FlagConfig{
					WebSystemdSocket:   &falseValue,
					WebConfigFile:      &emptyString,
					WebListenAddresses: &testListenAddresses,
				},
			},
		},
		true,
	)
}

func TestSimpleConfiguration(t *testing.T) {
	expectConfigurationFromCommandLine(t,
		"--web.listen-address=:1234 --trap.description-template=../description-template.tpl --snmp.timeout=10s",
		SNMPNotifierConfiguration{
			alertparser.Configuration{
				TrapDefaultOID:            "1.3.6.1.4.1.98789.1",
				TrapOIDLabel:              "oid",
				DefaultSeverity:           "critical",
				SeverityLabel:             "severity",
				Severities:                []string{"critical", "warning", "info"},
				TrapDefaultObjectsBaseOID: "1.3.6.1.4.1.98789.2",
				TrapUserObjectsBaseOID:    "1.3.6.1.4.1.98789.3",
			},
			trapsender.Configuration{
				SNMPVersion:     "V2c",
				SNMPDestination: []string{"127.0.0.1:162"},
				SNMPRetries:     1,
				SNMPTimeout:     10 * time.Second,
				SNMPCommunity:   "public",
				UserObjects:     make([]trapsender.UserObject, 0),
			},
			httpserver.Configuration{
				ToolKitConfiguration: web.FlagConfig{
					WebSystemdSocket:   &falseValue,
					WebConfigFile:      &emptyString,
					WebListenAddresses: &testListenAddresses,
				},
			},
		},
		true,
	)
}

func TestV2Configuration(t *testing.T) {
	expectConfigurationFromCommandLineAndEnvironmentVariables(
		t,
		"--web.listen-address=:1234 --trap.description-template=../description-template.tpl --snmp.destination=127.0.0.2:163 --snmp.retries=4 --trap.default-oid=4.4.4 --trap.oid-label=other-oid --alert.default-severity=warning --alert.severity-label=severity --alert.severities=critical,error,warning,info",
		map[string]string{
			"SNMP_NOTIFIER_COMMUNITY": "private",
		},
		SNMPNotifierConfiguration{
			alertparser.Configuration{
				TrapDefaultOID:            "4.4.4",
				TrapOIDLabel:              "other-oid",
				DefaultSeverity:           "warning",
				SeverityLabel:             "severity",
				Severities:                []string{"critical", "error", "warning", "info"},
				TrapDefaultObjectsBaseOID: "1.3.6.1.4.1.98789.2",
				TrapUserObjectsBaseOID:    "1.3.6.1.4.1.98789.3",
			},
			trapsender.Configuration{
				SNMPVersion:     "V2c",
				SNMPDestination: []string{"127.0.0.2:163"},
				SNMPRetries:     4,
				SNMPTimeout:     5 * time.Second,
				SNMPCommunity:   "private",
				UserObjects:     make([]trapsender.UserObject, 0),
			},
			httpserver.Configuration{
				ToolKitConfiguration: web.FlagConfig{
					WebSystemdSocket:   &falseValue,
					WebConfigFile:      &emptyString,
					WebListenAddresses: &testListenAddresses,
				},
			},
		},
		true,
	)
}

func TestV3Configuration(t *testing.T) {
	expectConfigurationFromCommandLineAndEnvironmentVariables(
		t,
		"--web.listen-address=:1234 --snmp.version=V3 --trap.description-template=../description-template.tpl --snmp.destination=127.0.0.2:163 --snmp.retries=4 --trap.default-oid=4.4.4 --trap.oid-label=other-oid --alert.default-severity=warning --alert.severity-label=severity --alert.severities=critical,error,warning,info --snmp.engine-start-time=1750334785",
		map[string]string{
			"SNMP_NOTIFIER_COMMUNITY": "private",
		},
		SNMPNotifierConfiguration{
			alertparser.Configuration{
				TrapDefaultOID:            "4.4.4",
				TrapOIDLabel:              "other-oid",
				DefaultSeverity:           "warning",
				SeverityLabel:             "severity",
				Severities:                []string{"critical", "error", "warning", "info"},
				TrapDefaultObjectsBaseOID: "1.3.6.1.4.1.98789.2",
				TrapUserObjectsBaseOID:    "1.3.6.1.4.1.98789.3",
			},
			trapsender.Configuration{
				SNMPVersion:             "V3",
				SNMPDestination:         []string{"127.0.0.2:163"},
				SNMPRetries:             4,
				SNMPTimeout:             5 * time.Second,
				UserObjects:             make([]trapsender.UserObject, 0),
				SNMPEngineStartTimeUnix: 1750334785,
			},
			httpserver.Configuration{
				ToolKitConfiguration: web.FlagConfig{
					WebSystemdSocket:   &falseValue,
					WebConfigFile:      &emptyString,
					WebListenAddresses: &testListenAddresses,
				},
			},
		},
		false,
	)
}

func TestV3AuthenticationConfiguration(t *testing.T) {
	expectConfigurationFromCommandLineAndEnvironmentVariables(
		t,
		"--web.listen-address=:1234 --snmp.version=V3 --snmp.authentication-enabled --trap.description-template=../description-template.tpl --snmp.destination=127.0.0.2:163 --snmp.retries=4 --trap.default-oid=4.4.4 --trap.oid-label=other-oid --alert.default-severity=warning --alert.severity-label=severity --alert.severities=critical,error,warning,info",
		map[string]string{
			"SNMP_NOTIFIER_AUTH_USERNAME": "username_v3",
			"SNMP_NOTIFIER_AUTH_PASSWORD": "password_v3",
		},
		SNMPNotifierConfiguration{
			alertparser.Configuration{
				TrapDefaultOID:            "4.4.4",
				TrapOIDLabel:              "other-oid",
				DefaultSeverity:           "warning",
				SeverityLabel:             "severity",
				Severities:                []string{"critical", "error", "warning", "info"},
				TrapDefaultObjectsBaseOID: "1.3.6.1.4.1.98789.2",
				TrapUserObjectsBaseOID:    "1.3.6.1.4.1.98789.3",
			},
			trapsender.Configuration{
				SNMPVersion:                "V3",
				SNMPDestination:            []string{"127.0.0.2:163"},
				SNMPRetries:                4,
				SNMPTimeout:                5 * time.Second,
				SNMPAuthenticationEnabled:  true,
				SNMPAuthenticationProtocol: "MD5",
				SNMPAuthenticationUsername: "username_v3",
				SNMPAuthenticationPassword: "password_v3",
				UserObjects:                make([]trapsender.UserObject, 0),
			},
			httpserver.Configuration{
				ToolKitConfiguration: web.FlagConfig{
					WebSystemdSocket:   &falseValue,
					WebConfigFile:      &emptyString,
					WebListenAddresses: &testListenAddresses,
				},
			},
		},
		true,
	)
}

func TestV3AuthenticationAndPrivateConfiguration(t *testing.T) {
	expectConfigurationFromCommandLineAndEnvironmentVariables(
		t, "--web.listen-address=:1234 --snmp.version=V3 --snmp.private-enabled --snmp.authentication-enabled --trap.description-template=../description-template.tpl --snmp.destination=127.0.0.2:163 --snmp.retries=4 --trap.default-oid=4.4.4 --trap.oid-label=other-oid --alert.default-severity=warning --alert.severity-label=severity --alert.severities=critical,error,warning,info",
		map[string]string{
			"SNMP_NOTIFIER_AUTH_USERNAME": "username_v3",
			"SNMP_NOTIFIER_AUTH_PASSWORD": "password_v3",
			"SNMP_NOTIFIER_PRIV_PASSWORD": "priv_password_v3",
		},
		SNMPNotifierConfiguration{
			alertparser.Configuration{
				TrapDefaultOID:            "4.4.4",
				TrapOIDLabel:              "other-oid",
				DefaultSeverity:           "warning",
				SeverityLabel:             "severity",
				Severities:                []string{"critical", "error", "warning", "info"},
				TrapDefaultObjectsBaseOID: "1.3.6.1.4.1.98789.2",
				TrapUserObjectsBaseOID:    "1.3.6.1.4.1.98789.3",
			},
			trapsender.Configuration{
				SNMPVersion:                "V3",
				SNMPDestination:            []string{"127.0.0.2:163"},
				SNMPRetries:                4,
				SNMPTimeout:                5 * time.Second,
				SNMPPrivateEnabled:         true,
				SNMPPrivateProtocol:        "DES",
				SNMPPrivatePassword:        "priv_password_v3",
				SNMPAuthenticationEnabled:  true,
				SNMPAuthenticationProtocol: "MD5",
				SNMPAuthenticationUsername: "username_v3",
				SNMPAuthenticationPassword: "password_v3",
				UserObjects:                make([]trapsender.UserObject, 0),
			},
			httpserver.Configuration{
				ToolKitConfiguration: web.FlagConfig{
					WebSystemdSocket:   &falseValue,
					WebConfigFile:      &emptyString,
					WebListenAddresses: &testListenAddresses,
				},
			},
		},
		true,
	)
}

func TestConfigurationWithDifferentResolvedTrapOIDConfiguration(t *testing.T) {
	resolutionOID := "1.3.6.1.4.1.123456"
	expectConfigurationFromCommandLine(t,
		"--web.listen-address=:1234 --trap.resolution-default-oid=1.3.6.1.4.1.123456 --trap.description-template=../description-template.tpl",
		SNMPNotifierConfiguration{
			alertparser.Configuration{
				TrapDefaultOID:            "1.3.6.1.4.1.98789.1",
				TrapOIDLabel:              "oid",
				TrapResolutionDefaultOID:  &resolutionOID,
				DefaultSeverity:           "critical",
				SeverityLabel:             "severity",
				Severities:                []string{"critical", "warning", "info"},
				TrapDefaultObjectsBaseOID: "1.3.6.1.4.1.98789.2",
				TrapUserObjectsBaseOID:    "1.3.6.1.4.1.98789.3",
			},
			trapsender.Configuration{
				SNMPVersion:     "V2c",
				SNMPDestination: []string{"127.0.0.1:162"},
				SNMPRetries:     1,
				SNMPTimeout:     5 * time.Second,
				SNMPCommunity:   "public",
				UserObjects:     make([]trapsender.UserObject, 0),
			},
			httpserver.Configuration{
				ToolKitConfiguration: web.FlagConfig{
					WebSystemdSocket:   &falseValue,
					WebConfigFile:      &emptyString,
					WebListenAddresses: &testListenAddresses,
				},
			},
		},
		true,
	)
}

func TestConfigurationWithDifferentResolvedTrapLabelOIDConfiguration(t *testing.T) {
	// resolutionOID := "1.3.6.1.4.1.123456"
	resolutionOIDLabel := "oid-on-resolution"
	expectConfigurationFromCommandLine(t,
		"--web.listen-address=:1234 --trap.resolution-oid-label=oid-on-resolution --trap.description-template=../description-template.tpl",
		SNMPNotifierConfiguration{
			alertparser.Configuration{
				TrapDefaultOID:            "1.3.6.1.4.1.98789.1",
				TrapOIDLabel:              "oid",
				TrapResolutionOIDLabel:    &resolutionOIDLabel,
				DefaultSeverity:           "critical",
				SeverityLabel:             "severity",
				Severities:                []string{"critical", "warning", "info"},
				TrapDefaultObjectsBaseOID: "1.3.6.1.4.1.98789.2",
				TrapUserObjectsBaseOID:    "1.3.6.1.4.1.98789.3",
			},
			trapsender.Configuration{
				SNMPVersion:     "V2c",
				SNMPDestination: []string{"127.0.0.1:162"},
				SNMPRetries:     1,
				SNMPTimeout:     5 * time.Second,
				SNMPCommunity:   "public",
				UserObjects:     make([]trapsender.UserObject, 0),
			},
			httpserver.Configuration{
				ToolKitConfiguration: web.FlagConfig{
					WebSystemdSocket:   &falseValue,
					WebConfigFile:      &emptyString,
					WebListenAddresses: &testListenAddresses,
				},
			},
		},
		true,
	)
}

func TestMalFormedTrapOID(t *testing.T) {
	expectConfigurationFromCommandLineError(
		t,
		"--trap.default-oid=A.1.1.1 --trap.description-template=../description-template.tpl",
	)
}

func TestMalFormedTrapBaseOID(t *testing.T) {
	expectConfigurationFromCommandLineError(
		t,
		"--trap.default-objects-base-oid=A.1.1.1 --trap.description-template=../description-template.tpl",
	)
}

func TestMalFormedResolutionTrapOID(t *testing.T) {
	expectConfigurationFromCommandLineError(
		t,
		"--trap.resolution-default-oid=A.1.1.1 --trap.description-template=../description-template.tpl",
	)
}

func TestMalFormedTrapUserObjectsOID(t *testing.T) {
	expectConfigurationFromCommandLineError(
		t,
		"--trap.user-objects-base-oid=A.1.1.1 --trap.description-template=../description-template.tpl",
	)
}

func TestConfigurationMixingV2AndV3Elements(t *testing.T) {
	expectConfigurationFromCommandLineError(
		t,
		"--web.listen-address=:1234 --snmp.version=V3 --snmp.private-enabled --trap.description-template=../description-template.tpl --snmp.destination=127.0.0.2:163 --snmp.retries=4 --trap.default-oid=4.4.4 --trap.oid-label=other-oid --alert.default-severity=warning --alert.severity-label=severity --alert.severities=critical,error,warning,info",
	)
}

func TestConfigurationMixingV2AndV3AuthenticationAndPrivate(t *testing.T) {
	expectConfigurationFromCommandLineError(
		t,
		"--web.listen-address=:1234 --snmp.version=V2c --snmp.private-enabled --snmp.authentication-enabled --trap.description-template=../description-template.tpl --snmp.destination=127.0.0.2:163 --snmp.retries=4 --trap.default-oid=4.4.4 --trap.oid-label=other-oid --alert.default-severity=warning --alert.severity-label=severity --alert.severities=critical,error,warning,info",
	)
}

func TestConfigurationMixingV2AndV3Authentication(t *testing.T) {
	expectConfigurationFromCommandLineError(
		t,
		"--web.listen-address=:1234 --snmp.version=V2c --snmp.authentication-enabled --trap.description-template=../description-template.tpl --snmp.destination=127.0.0.2:163 --snmp.retries=4 --trap.default-oid=4.4.4 --trap.oid-label=other-oid --alert.default-severity=warning --alert.severity-label=severity --alert.severities=critical,error,warning,info",
	)
}

func TestConfigurationMixingV2AndV3Private(t *testing.T) {
	expectConfigurationFromCommandLineError(
		t,
		"--web.listen-address=:1234 --snmp.version=V2c --snmp.private-enabled --trap.description-template=../description-template.tpl --snmp.destination=127.0.0.2:163 --snmp.retries=4 --trap.default-oid=4.4.4 --trap.oid-label=other-oid --alert.default-severity=warning --alert.severity-label=severity --alert.severities=critical,error,warning,info",
	)
}

func expectConfigurationFromCommandLine(t *testing.T, commandLine string, configuration SNMPNotifierConfiguration, ignoreStartUpTime bool) {
	expectConfigurationFromCommandLineAndEnvironmentVariables(
		t,
		commandLine,
		map[string]string{},
		configuration,
		ignoreStartUpTime,
	)
}

func expectConfigurationFromCommandLineAndEnvironmentVariables(t *testing.T, commandLine string, environmentVariables map[string]string, configuration SNMPNotifierConfiguration, ignoreStartUpTime bool) {
	os.Clearenv()
	for variable, value := range environmentVariables {
		os.Setenv(variable, value)
	}
	elements := strings.Split(commandLine, " ")
	log.Print(elements)
	parsedConfiguration, _, err := ParseConfiguration(elements)

	if err != nil {
		t.Error("error occured and no expected error", "err", err)
	}

	if err == nil {
		descriptionTemplate, err := template.New(filepath.Base("description-template.tpl")).Funcs(template.FuncMap{
			"groupAlertsByLabel": commons.GroupAlertsByLabel,
			"groupAlertsByName":  commons.GroupAlertsByName,
		}).ParseFiles("../description-template.tpl")
		if err != nil {
			t.Fatal("Error while generating default description template")
		}

		configuration.TrapSenderConfiguration.DescriptionTemplate = *descriptionTemplate
		if ignoreStartUpTime {
			parsedConfiguration.TrapSenderConfiguration.SNMPEngineStartTimeUnix = 0 // Reset the SNMPEngineStartTimeUnix to avoid issues with tests
		}

		if diff := deep.Equal(*parsedConfiguration, configuration); diff != nil {
			t.Error(diff)
		}
	}
}

func expectConfigurationFromCommandLineError(t *testing.T, commandLine string) {
	expectConfigurationErrorFromCommandLineAndEnvironmentVariables(
		t,
		commandLine,
		map[string]string{},
	)
}

func expectConfigurationErrorFromCommandLineAndEnvironmentVariables(t *testing.T, commandLine string, environmentVariables map[string]string) {
	os.Clearenv()
	for variable, value := range environmentVariables {
		os.Setenv(variable, value)
	}
	elements := strings.Split(commandLine, " ")
	log.Print(elements)
	_, _, err := ParseConfiguration(elements)
	fmt.Printf("err: %s\n", err)
	if err == nil {
		t.Error("expected error, but none occured")
	}
}
