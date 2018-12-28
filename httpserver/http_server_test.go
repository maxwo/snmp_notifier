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
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/maxwo/snmp_notifier/alertparser"
	"github.com/maxwo/snmp_notifier/trapsender"

	testutils "github.com/maxwo/snmp_notifier/test"

	"text/template"
)

var dummyDescriptionTemplate = `{{ range $key, $value := .Alerts }}Alert name: {{ $value.Labels.alertname }}
Severity: {{ $value.Labels.severity }}
Summary: {{ $value.Annotations.summary }}
Description: {{ $value.Annotations.description }}
{{ end -}}`

type Test struct {
	IDTemplate          string
	DescriptionTemplate string
	DefaultOID          string
	OIDLabel            string
	DefaultSeverity     string
	Severities          []string
	SeverityLabel       string
	AlertsFileName      string
	TrapsFileName       string
	SNMPConnectionPort  int
	URI                 string
	Verb                string
	ExpectStatus        int
}

var tests = []Test{
	{
		"{{ .Labels.alertname }}",
		dummyDescriptionTemplate,
		"1.1",
		"oid",
		"critical",
		strings.Split("critical,warning,info", ","),
		"severity",
		"test_mixed_alerts.json",
		"../trapsender/test_mixed_traps.json",
		1164,
		"/alerts",
		"POST",
		200,
	},
	{
		"{{ .Labels.alertname }}",
		dummyDescriptionTemplate,
		"1.1",
		"oid",
		"critical",
		strings.Split("critical,warning,info", ","),
		"severity",
		"test_unprocessable_alerts.json",
		"test_no_trap.json",
		1164,
		"/alerts",
		"POST",
		422,
	},
	{
		"{{ .Labels.alertname }}",
		dummyDescriptionTemplate,
		"1.1",
		"oid",
		"critical",
		strings.Split("critical,warning,info", ","),
		"severity",
		"test_wrong_oid_alerts.json",
		"test_no_trap.json",
		1164,
		"/alerts",
		"POST",
		400,
	},
	{
		"{{ .Labels.alertname }}",
		dummyDescriptionTemplate,
		"1.1",
		"oid",
		"critical",
		strings.Split("critical,warning,info", ","),
		"severity",
		"test_mixed_alerts.json",
		"test_no_trap.json",
		1166,
		"/alerts",
		"POST",
		502,
	},
	{
		"{{ .Labels.alertname }}",
		dummyDescriptionTemplate,
		"1.1",
		"oid",
		"critical",
		strings.Split("critical,warning,info", ","),
		"severity",
		"test_mixed_alerts.json",
		"test_no_trap.json",
		1164,
		"/",
		"GET",
		200,
	},
	{
		"{{ .Labels.alertname }}",
		dummyDescriptionTemplate,
		"1.1",
		"oid",
		"critical",
		strings.Split("critical,warning,info", ","),
		"severity",
		"test_mixed_alerts.json",
		"test_no_trap.json",
		1164,
		"/health",
		"GET",
		200,
	},
}

func TestPostAlerts(t *testing.T) {
	server, channel, err := testutils.LaunchTrapReceiver(1164)
	if err != nil {
		t.Fatal("Error while opening server:", err)
	}
	defer server.Close()

	for _, test := range tests {
		httpserver := launchHTTPServer(t, test)

		t.Log("Testing with file", test.AlertsFileName)
		alertsByteData, err := ioutil.ReadFile(test.AlertsFileName)
		if err != nil {
			t.Fatal("Error while reading alert file:", err)
		}
		alertsReader := bytes.NewReader(alertsByteData)

		url := fmt.Sprintf("http://127.0.0.1:9465%s", test.URI)
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

		httpserver.Close()

		t.Log("response Status:", resp.Status)
		t.Log("response Headers:", resp.Header)
		body, _ := ioutil.ReadAll(resp.Body)
		t.Log("response Body:", string(body))

		if resp.StatusCode != test.ExpectStatus {
			t.Error(test.ExpectStatus, "status expected, but got:", resp.StatusCode)
		} else {
			receivedTraps := testutils.ReadTraps(channel)

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
				t.Error(len(expectedTrapsData), "traps expected, but received", receivedTraps)
			}

			for _, expectedTrap := range expectedTrapsData {
				if !testutils.FindTrap(receivedTraps, expectedTrap) {
					t.Fatal("Expected trap not found:", expectedTrap)
				}
			}
		}
	}
}

func launchHTTPServer(t *testing.T, test Test) *http.Server {
	snmpDestination := fmt.Sprintf("127.0.0.1:%d", test.SNMPConnectionPort)

	idTemplate, err := template.New("id").Parse(test.IDTemplate)
	if err != nil {
		t.Fatal("Error while parsing bucket file:", err)
	}
	alertParserConfiguration := alertparser.AlertParserConfiguration{*idTemplate, test.DefaultOID, test.OIDLabel, test.DefaultSeverity, test.Severities, test.SeverityLabel}
	alertParser := alertparser.New(alertParserConfiguration)

	descriptionTemplate, err := template.New("description").Parse(test.DescriptionTemplate)
	if err != nil {
		t.Fatal("Error while building template")
	}

	trapSenderConfiguration := trapsender.TrapSenderConfiguration{snmpDestination, 1, "public", *descriptionTemplate}
	trapSender := trapsender.New(trapSenderConfiguration)

	httpServerConfiguration := HTTPServerConfiguration{":9465"}
	httpServer := New(httpServerConfiguration, alertParser, trapSender).Configure()
	go func() {
		httpServer.ListenAndServe()
	}()
	time.Sleep(200 * time.Millisecond)

	return httpServer
}
