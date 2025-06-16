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
	"io"
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

func TestAlertNotification(t *testing.T) {
	port, server, trapChannel, err := testutils.LaunchTrapReceiver()
	if err != nil {
		t.Fatal("msg", "Error while starting SNMP server:", "err", err)
	}
	defer server.Close()

	expectHTTPStatus(t, *port, "POST", "/alerts", "test_mixed_alerts.json", 200)
	expectSNMPTraps(t, "test_mixed_traps.json", trapChannel)
}

func TestBadAlertNotification(t *testing.T) {
	port, server, trapChannel, err := testutils.LaunchTrapReceiver()
	if err != nil {
		t.Fatal("msg", "Error while starting SNMP server:", "err", err)
	}
	defer server.Close()

	expectHTTPStatus(t, *port, "POST", "/alerts", "test_unprocessable_alerts.json", 422)
	expectNoSNMPTrap(t, trapChannel)
}

func TestBadSNMPDestination(t *testing.T) {
	expectHTTPStatus(t, 123, "POST", "/alerts", "test_mixed_alerts.json", 502)
}

func TestMalformedOIDLabel(t *testing.T) {
	port, server, trapChannel, err := testutils.LaunchTrapReceiver()
	if err != nil {
		t.Fatal("msg", "Error while starting SNMP server:", "err", err)
	}
	defer server.Close()

	expectHTTPStatus(t, *port, "POST", "/alerts", "test_wrong_oid_alerts.json", 400)
	expectNoSNMPTrap(t, trapChannel)
}

func TestCallRootURI(t *testing.T) {
	port, server, trapChannel, err := testutils.LaunchTrapReceiver()
	if err != nil {
		t.Fatal("msg", "Error while starting SNMP server:", "err", err)
	}
	defer server.Close()

	expectHTTPStatus(t, *port, "GET", "/", "test_mixed_alerts.json", 200)
	expectNoSNMPTrap(t, trapChannel)
}

func TestCallHealthURI(t *testing.T) {
	port, server, trapChannel, err := testutils.LaunchTrapReceiver()
	if err != nil {
		t.Fatal("msg", "Error while starting SNMP server:", "err", err)
	}
	defer server.Close()

	expectHTTPStatus(t, *port, "GET", "/health", "test_mixed_alerts.json", 200)
	expectNoSNMPTrap(t, trapChannel)
}

func expectHTTPStatus(t *testing.T, snmpDestinationPort int32, verb string, uri string, body string, status int) {
	httpserver, notifierPort := launchHTTPServer(t, snmpDestinationPort)
	defer httpserver.Stop()

	t.Log("Testing with file", body)
	alertsByteData, err := os.ReadFile(body)
	if err != nil {
		t.Fatal("Error while reading alert file:", err)
	}
	alertsReader := bytes.NewReader(alertsByteData)

	url := fmt.Sprintf("http://127.0.0.1:%d%s", notifierPort, uri)
	req, err := http.NewRequest(verb, url, alertsReader)
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
	response, _ := io.ReadAll(resp.Body)
	t.Log("response Body:", string(response))

	if resp.StatusCode != status {
		t.Fatal(status, "status expected, but got:", resp.StatusCode)
	}
}

func launchHTTPServer(t *testing.T, port int32) (*HTTPServer, int) {
	notfierRandomPort := 10000 + rand.Intn(10000)

	snmpDestination := fmt.Sprintf("127.0.0.1:%d", port)
	notifierAddress := fmt.Sprintf(":%d", notfierRandomPort)

	alertParserConfiguration := alertparser.Configuration{
		TrapDefaultOID:            "1.2.3",
		TrapOIDLabel:              "oid",
		DefaultSeverity:           "critical",
		Severities:                strings.Split("critical,warning,info", ","),
		SeverityLabel:             "severity",
		TrapDefaultObjectsBaseOID: "1.7.8",
		TrapUserObjectsBaseOID:    "1.7.9",
	}
	alertParser := alertparser.New(alertParserConfiguration, slog.New(slog.NewTextHandler(os.Stdout, nil)))

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
		UserObjects:                make([]trapsender.UserObject, 0),
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

func expectNoSNMPTrap(t *testing.T, trapChannel chan *snmpgo.TrapRequest) {
	receivedTraps := testutils.ReadTraps(trapChannel)

	log.Print("Traps received:", receivedTraps)

	if len(receivedTraps) != 0 {
		t.Fatal("no traps expected, but received", receivedTraps)
	}
}

func expectSNMPTraps(t *testing.T, trapsFileName string, trapChannel chan *snmpgo.TrapRequest) {
	receivedTraps := testutils.ReadTraps(trapChannel)

	log.Print("Traps received:", receivedTraps)

	expectedTrapsByteData, err := os.ReadFile(trapsFileName)
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
