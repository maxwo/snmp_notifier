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

package httpserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/k-sone/snmpgo"
	"github.com/maxwo/snmp_notifier/alertparser"
	"github.com/maxwo/snmp_notifier/trapsender"

	testutils "github.com/maxwo/snmp_notifier/test"

	"text/template"

	"github.com/prometheus/exporter-toolkit/web"
)

var dummyDescriptionTemplate = `{{ len .Alerts }}/{{ len .DeclaredAlerts }} alerts are firing:
{{ range $key, $value := .Alerts }}Alert name: {{ $value.Labels.alertname }}
Severity: {{ $value.Labels.severity }}
Summary: {{ $value.Annotations.summary }}
Description: {{ $value.Annotations.description }}
{{ end -}}`

type Test struct {
	AlertsFileName      string
	TrapsFileName       string
	SNMPDestinationPort int
	URI                 string
	Verb                string
	ExpectStatus        int
}

var tests = []Test{
	{
		"test_mixed_alerts.json",
		"test_mixed_traps.json",
		1164,
		"/alerts",
		"POST",
		200,
	},
	{
		"test_unprocessable_alerts.json",
		"test_no_trap.json",
		1164,
		"/alerts",
		"POST",
		422,
	},
	{
		"test_mixed_alerts.json",
		"test_no_trap.json",
		1166,
		"/alerts",
		"POST",
		502,
	},
	{
		"test_wrong_oid_alerts.json",
		"test_no_trap.json",
		1164,
		"/alerts",
		"POST",
		400,
	},
	{
		"test_mixed_alerts.json",
		"test_no_trap.json",
		1164,
		"/",
		"GET",
		200,
	},
	{
		"test_mixed_alerts.json",
		"test_no_trap.json",
		1164,
		"/health",
		"GET",
		200,
	},
}

func TestPostAlerts(t *testing.T) {

	server, trapChannel, err := testutils.LaunchTrapReceiver("127.0.0.1:1164")
	if err != nil {
		t.Fatal("msg", "Error while starting SNMP server:", "err", err)
	}
	defer server.Close()

	for _, test := range tests {
		launchSingleTest(t, test, trapChannel)
	}
}

func launchSingleTest(t *testing.T, test Test, trapChannel chan *snmpgo.TrapRequest) {

	httpserver, notifierPort := launchHTTPServer(t, test)

	defer httpserver.Stop()

	t.Log("Testing with file", test.AlertsFileName)
	alertsByteData, err := ioutil.ReadFile(test.AlertsFileName)
	if err != nil {
		t.Fatal("Error while reading alert file:", err)
	}
	alertsReader := bytes.NewReader(alertsByteData)

	url := fmt.Sprintf("http://127.0.0.1:%d%s", notifierPort, test.URI)
	req, err := http.NewRequest(test.Verb, url, alertsReader)
	if err != nil {
		t.Fatal("Error while building request:", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("Error while sending request:", err)
	}
	defer resp.Body.Close()

	t.Log("response Status:", resp.Status)
	t.Log("response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	t.Log("response Body:", string(body))

	if resp.StatusCode != test.ExpectStatus {
		t.Fatal(test.ExpectStatus, "status expected, but got:", resp.StatusCode)
	} else {
		receivedTraps := testutils.ReadTraps(trapChannel)

		log.Print("Traps received:", receivedTraps)

		expectedTrapsByteData, err := ioutil.ReadFile(test.TrapsFileName)
		if err != nil {
			t.Fatal("Error while reading traps file:", err)
		}
		expectedTrapsReader := bytes.NewReader(expectedTrapsByteData)
		expectedTrapsData := []map[string]string{}
		err = json.NewDecoder(expectedTrapsReader).Decode(&expectedTrapsData)
		if err != nil {
			t.Fatal("Error while parsing traps file:", err)
		}

		if len(receivedTraps) != len(expectedTrapsData) {
			t.Fatal(len(expectedTrapsData), "traps expected, but received", receivedTraps)
		}

		for _, expectedTrap := range expectedTrapsData {
			if !testutils.FindTrap(receivedTraps, expectedTrap) {
				t.Fatal("Expected trap not found:", expectedTrap)
			}
		}
	}
}

func launchHTTPServer(t *testing.T, test Test) (*HTTPServer, int) {
	notfierRandomPort := 10000 + rand.Intn(1000)

	snmpDestination := fmt.Sprintf("127.0.0.1:%d", test.SNMPDestinationPort)
	notifierAddress := fmt.Sprintf(":%d", notfierRandomPort)

	alertParserConfiguration := alertparser.Configuration{
		DefaultOID:      "1",
		OIDLabel:        "oid",
		DefaultSeverity: "critical",
		Severities:      strings.Split("critical,warning,info", ","),
		SeverityLabel:   "severity",
	}
	alertParser := alertparser.New(alertParserConfiguration)

	descriptionTemplate, err := template.New("description").Parse(dummyDescriptionTemplate)
	if err != nil {
		t.Fatal("Error while building template")
	}

	var falseValue = false
	var emptyString = ""

	trapSenderConfiguration := trapsender.Configuration{
		SNMPDestination:            []string{snmpDestination},
		SNMPRetries:                1,
		SNMPVersion:                "V2c",
		SNMPTimeout:                5 * time.Second,
		SNMPCommunity:              "public",
		SNMPAuthenticationEnabled:  false,
		SNMPAuthenticationProtocol: "",
		SNMPAuthenticationUsername: "",
		SNMPAuthenticationPassword: "",
		SNMPPrivateEnabled:         false,
		SNMPPrivateProtocol:        "",
		SNMPPrivatePassword:        "",
		SNMPSecurityEngineID:       "",
		SNMPContextEngineID:        "",
		SNMPContextName:            "",
		DescriptionTemplate:        *descriptionTemplate,
		ExtraFieldTemplates:        make(map[string]template.Template),
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	trapSender := trapsender.New(trapSenderConfiguration, logger)

	httpServerConfiguration := Configuration{
		web.FlagConfig{
			WebListenAddresses: &[]string{notifierAddress},
			WebSystemdSocket:   &falseValue,
			WebConfigFile:      &emptyString,
		},
	}
	httpServer := New(httpServerConfiguration, alertParser, trapSender, logger)
	go func() {
		if err := httpServer.Start(); err != nil {
			t.Error("err", err)
		}
	}()
	time.Sleep(200 * time.Millisecond)

	return httpServer, notfierRandomPort
}
