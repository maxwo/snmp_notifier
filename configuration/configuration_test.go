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

	"github.com/go-test/deep"
)

type Test struct {
	CommandLine          string
	EnvironmentVariables map[string]string
	Configuration        SNMPNotifierConfiguration
	ExpectError          bool
}

var tests = []Test{
	{
		"--web.listen-address=:1234 --snmp.trap-description-template=../description-template.tpl --snmp.timeout=10s",
		map[string]string{},
		SNMPNotifierConfiguration{
			alertparser.Configuration{
				DefaultOID:      "1.3.6.1.4.1.98789.0.1",
				OIDLabel:        "oid",
				DefaultSeverity: "critical",
				SeverityLabel:   "severity",
				Severities:      []string{"critical", "warning", "info"},
			},
			trapsender.Configuration{
				SNMPVersion:         "V2c",
				SNMPDestination:     "127.0.0.1:162",
				SNMPRetries:         1,
				SNMPTimeout:         10 * time.Second,
				SNMPCommunity:       "public",
				ExtraFieldTemplates: make(map[string]template.Template),
			},
			httpserver.Configuration{
				WebListenAddress: ":1234",
			},
		},
		false,
	},
	{
		"--web.listen-address=:1234 --snmp.trap-description-template=../description-template.tpl --snmp.destination=127.0.0.2:163 --snmp.retries=4 --snmp.trap-default-oid=4.4.4 --snmp.trap-oid-label=other-oid --alert.default-severity=warning --alert.severity-label=severity --alert.severities=critical,error,warning,info",
		map[string]string{
			"SNMP_NOTIFIER_COMMUNITY": "private",
		},
		SNMPNotifierConfiguration{
			alertparser.Configuration{
				DefaultOID:      "4.4.4",
				OIDLabel:        "other-oid",
				DefaultSeverity: "warning",
				SeverityLabel:   "severity",
				Severities:      []string{"critical", "error", "warning", "info"},
			},
			trapsender.Configuration{
				SNMPVersion:         "V2c",
				SNMPDestination:     "127.0.0.2:163",
				SNMPRetries:         4,
				SNMPTimeout:         5 * time.Second,
				SNMPCommunity:       "private",
				ExtraFieldTemplates: make(map[string]template.Template),
			},
			httpserver.Configuration{
				WebListenAddress: ":1234",
			},
		},
		false,
	},
	{
		"--web.listen-address=:1234 --snmp.version=V3 --snmp.trap-description-template=../description-template.tpl --snmp.destination=127.0.0.2:163 --snmp.retries=4 --snmp.trap-default-oid=4.4.4 --snmp.trap-oid-label=other-oid --alert.default-severity=warning --alert.severity-label=severity --alert.severities=critical,error,warning,info",
		map[string]string{
			"SNMP_NOTIFIER_COMMUNITY": "private",
		},
		SNMPNotifierConfiguration{
			alertparser.Configuration{
				DefaultOID:      "4.4.4",
				OIDLabel:        "other-oid",
				DefaultSeverity: "warning",
				SeverityLabel:   "severity",
				Severities:      []string{"critical", "error", "warning", "info"},
			},
			trapsender.Configuration{
				SNMPVersion:         "V3",
				SNMPDestination:     "127.0.0.2:163",
				SNMPRetries:         4,
				SNMPTimeout:         5 * time.Second,
				ExtraFieldTemplates: make(map[string]template.Template),
			},
			httpserver.Configuration{
				WebListenAddress: ":1234",
			},
		},
		false,
	},
	{
		"--web.listen-address=:1234 --snmp.version=V3 --snmp.authentication-enabled --snmp.trap-description-template=../description-template.tpl --snmp.destination=127.0.0.2:163 --snmp.retries=4 --snmp.trap-default-oid=4.4.4 --snmp.trap-oid-label=other-oid --alert.default-severity=warning --alert.severity-label=severity --alert.severities=critical,error,warning,info",
		map[string]string{
			"SNMP_NOTIFIER_AUTH_USERNAME": "username_v3",
			"SNMP_NOTIFIER_AUTH_PASSWORD": "password_v3",
		},
		SNMPNotifierConfiguration{
			alertparser.Configuration{
				DefaultOID:      "4.4.4",
				OIDLabel:        "other-oid",
				DefaultSeverity: "warning",
				SeverityLabel:   "severity",
				Severities:      []string{"critical", "error", "warning", "info"},
			},
			trapsender.Configuration{
				SNMPVersion:                "V3",
				SNMPDestination:            "127.0.0.2:163",
				SNMPRetries:                4,
				SNMPTimeout:                5 * time.Second,
				SNMPAuthenticationEnabled:  true,
				SNMPAuthenticationProtocol: "MD5",
				SNMPAuthenticationUsername: "username_v3",
				SNMPAuthenticationPassword: "password_v3",
				ExtraFieldTemplates:        make(map[string]template.Template),
			},
			httpserver.Configuration{
				WebListenAddress: ":1234",
			},
		},
		false,
	},
	{
		"--web.listen-address=:1234 --snmp.version=V3 --snmp.trap-description-template=../description-template.tpl --snmp.destination=127.0.0.2:163 --snmp.retries=4 --snmp.trap-default-oid=4.4.4 --snmp.trap-oid-label=other-oid --alert.default-severity=warning --alert.severity-label=severity --alert.severities=critical,error,warning,info",
		map[string]string{
			"SNMP_NOTIFIER_AUTH_USERNAME": "username_v3",
			"SNMP_NOTIFIER_AUTH_PASSWORD": "password_v3",
		},
		SNMPNotifierConfiguration{
			alertparser.Configuration{
				DefaultOID:      "4.4.4",
				OIDLabel:        "other-oid",
				DefaultSeverity: "warning",
				SeverityLabel:   "severity",
				Severities:      []string{"critical", "error", "warning", "info"},
			},
			trapsender.Configuration{
				SNMPVersion:                "V3",
				SNMPDestination:            "127.0.0.2:163",
				SNMPRetries:                4,
				SNMPTimeout:                5 * time.Second,
				SNMPAuthenticationUsername: "username_v3",
				ExtraFieldTemplates:        make(map[string]template.Template),
			},
			httpserver.Configuration{
				WebListenAddress: ":1234",
			},
		},
		false,
	},
	{
		"--web.listen-address=:1234 --snmp.version=V3 --snmp.private-enabled --snmp.authentication-enabled --snmp.trap-description-template=../description-template.tpl --snmp.destination=127.0.0.2:163 --snmp.retries=4 --snmp.trap-default-oid=4.4.4 --snmp.trap-oid-label=other-oid --alert.default-severity=warning --alert.severity-label=severity --alert.severities=critical,error,warning,info",
		map[string]string{
			"SNMP_NOTIFIER_AUTH_USERNAME": "username_v3",
			"SNMP_NOTIFIER_AUTH_PASSWORD": "password_v3",
			"SNMP_NOTIFIER_PRIV_PASSWORD": "priv_password_v3",
		},
		SNMPNotifierConfiguration{
			alertparser.Configuration{
				DefaultOID:      "4.4.4",
				OIDLabel:        "other-oid",
				DefaultSeverity: "warning",
				SeverityLabel:   "severity",
				Severities:      []string{"critical", "error", "warning", "info"},
			},
			trapsender.Configuration{
				SNMPVersion:                "V3",
				SNMPDestination:            "127.0.0.2:163",
				SNMPRetries:                4,
				SNMPTimeout:                5 * time.Second,
				SNMPPrivateEnabled:         true,
				SNMPPrivateProtocol:        "DES",
				SNMPPrivatePassword:        "priv_password_v3",
				SNMPAuthenticationEnabled:  true,
				SNMPAuthenticationProtocol: "MD5",
				SNMPAuthenticationUsername: "username_v3",
				SNMPAuthenticationPassword: "password_v3",
				ExtraFieldTemplates:        make(map[string]template.Template),
			},
			httpserver.Configuration{
				WebListenAddress: ":1234",
			},
		},
		false,
	},
	{
		"--web.listen-address=:1234 --snmp.version=V2c --snmp.private-enabled --snmp.authentication-enabled --snmp.trap-description-template=../description-template.tpl --snmp.destination=127.0.0.2:163 --snmp.retries=4 --snmp.trap-default-oid=4.4.4 --snmp.trap-oid-label=other-oid --alert.default-severity=warning --alert.severity-label=severity --alert.severities=critical,error,warning,info",
		map[string]string{
			"SNMP_NOTIFIER_AUTH_USERNAME": "username_v3",
			"SNMP_NOTIFIER_AUTH_PASSWORD": "password_v3",
			"SNMP_NOTIFIER_PRIV_PASSWORD": "priv_password_v3",
		},
		SNMPNotifierConfiguration{},
		true,
	},
	{
		"--web.listen-address=:1234 --snmp.version=V3 --snmp.private-enabled --snmp.trap-description-template=../description-template.tpl --snmp.destination=127.0.0.2:163 --snmp.retries=4 --snmp.trap-default-oid=4.4.4 --snmp.trap-oid-label=other-oid --alert.default-severity=warning --alert.severity-label=severity --alert.severities=critical,error,warning,info",
		map[string]string{
			"SNMP_NOTIFIER_AUTH_USERNAME": "username_v3",
			"SNMP_NOTIFIER_AUTH_PASSWORD": "password_v3",
			"SNMP_NOTIFIER_PRIV_PASSWORD": "priv_password_v3",
		},
		SNMPNotifierConfiguration{},
		true,
	},
	{
		"--snmp.trap-default-oid=A.1.1.1 --snmp.trap-description-template=../description-template.tpl",
		map[string]string{},
		SNMPNotifierConfiguration{},
		true,
	},
}

func TestParseConfiguration(t *testing.T) {
	for _, test := range tests {
		os.Clearenv()
		for variable, value := range test.EnvironmentVariables {
			os.Setenv(variable, value)
		}
		elements := strings.Split(test.CommandLine, " ")
		log.Print(elements)
		configuration, _, err := ParseConfiguration(elements)
		log.Print(elements)

		if test.ExpectError && err == nil {
			t.Error("An error was expected")
		}

		if !test.ExpectError && err != nil {
			t.Error("An unexpected error occurred", err)
		}

		if err == nil {
			descriptionTemplate, err := template.New(filepath.Base("description-template.tpl")).Funcs(template.FuncMap{
				"groupAlertsByLabel": commons.GroupAlertsByLabel,
				"groupAlertsByName":  commons.GroupAlertsByName,
			}).ParseFiles("../description-template.tpl")
			if err != nil {
				t.Fatal("Error while generating default description template")
			}

			test.Configuration.TrapSenderConfiguration.DescriptionTemplate = *descriptionTemplate

			if diff := deep.Equal(*configuration, test.Configuration); diff != nil {
				t.Error(diff)
			}
		}
	}
}
