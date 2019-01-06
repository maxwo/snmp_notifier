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
	"strings"
	"testing"
	"text/template"

	"github.com/maxwo/snmp_notifier/alertparser"
	"github.com/maxwo/snmp_notifier/commons"
	"github.com/maxwo/snmp_notifier/httpserver"
	"github.com/maxwo/snmp_notifier/trapsender"

	"github.com/go-test/deep"
)

type Test struct {
	CommandLine                      string
	SNMPCommunityEnvironmentVariable string
	Configuration                    SNMPNotifierConfiguration
	ExpectError                      bool
}

var tests = []Test{
	{
		"--web.listen-address=:1234",
		"",
		SNMPNotifierConfiguration{
			alertparser.Configuration{
				DefaultOID:      "1.3.6.1.4.1.1664.1",
				OIDLabel:        "oid",
				DefaultSeverity: "critical",
				SeverityLabel:   "severity",
				Severities:      []string{"critical", "warning", "info"},
			},
			trapsender.Configuration{
				SNMPDestination: "127.0.0.1:162",
				SNMPRetries:     1,
				SNMPCommunity:   "public",
			},
			httpserver.Configuration{
				WebListenAddress: ":1234",
			},
		},
		false,
	},
	{
		"--web.listen-address=:1234 --snmp.destination=127.0.0.2:163 --snmp.retries=4 --snmp.trap-default-oid=4.4.4 --snmp.trap-oid-label=other-oid --alert.default-severity=warning --alert.severity-label=criticity --alert.severities=critical,error,warning,info",
		"private",
		SNMPNotifierConfiguration{
			alertparser.Configuration{
				DefaultOID:      "4.4.4",
				OIDLabel:        "other-oid",
				DefaultSeverity: "warning",
				SeverityLabel:   "criticity",
				Severities:      []string{"critical", "error", "warning", "info"},
			},
			trapsender.Configuration{
				SNMPDestination: "127.0.0.2:163",
				SNMPRetries:     4,
				SNMPCommunity:   "private",
			},
			httpserver.Configuration{
				WebListenAddress: ":1234",
			},
		},
		false,
	},
	{
		"--snmp.trap-description-template=\"{{.lkdfjskl\"",
		"",
		SNMPNotifierConfiguration{},
		true,
	},
	{
		"--snmp.trap-default-oid=A.1.1.1",
		"",
		SNMPNotifierConfiguration{},
		true,
	},
}

func TestParseConfiguration(t *testing.T) {
	for _, test := range tests {
		os.Clearenv()
		os.Setenv("SNMP_NOTIFIER_COMMUNITY", test.SNMPCommunityEnvironmentVariable)
		elements := strings.Split(test.CommandLine, " ")
		log.Print(elements)
		configuration, err := ParseConfiguration(elements)
		log.Print(elements)

		if test.ExpectError && err == nil {
			t.Error("An error was expected")
		}

		if !test.ExpectError && err != nil {
			t.Error("An unexpected error occurred", err)
		}

		if err == nil {
			descriptionTemplate, err := template.New("description").Funcs(template.FuncMap{
				"groupAlertsByLabel": commons.GroupAlertsByLabel,
				"groupAlertsByName":  commons.GroupAlertsByName,
			}).Parse(snmpTrapDescriptionTemplateDefault)
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
