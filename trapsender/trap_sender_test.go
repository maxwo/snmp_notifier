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

package trapsender

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"text/template"

	"github.com/maxwo/snmp_notifier/types"

	"log/slog"

	testutils "github.com/maxwo/snmp_notifier/test"

	"github.com/k-sone/snmpgo"
)

var dummyDescriptionTemplate = `{{ len .Alerts }}/{{ len .DeclaredAlerts }} alerts are firing:
{{ range $key, $value := .Alerts }}Alert name: {{ $value.Labels.alertname }}
Severity: {{ $value.Labels.severity }}
Summary: {{ $value.Annotations.summary }}
Description: {{ $value.Annotations.description }}
{{ end -}}`

var invalidDescriptionTemplate = `{{ range $key, $value := .InvalidAlerts }}{{ end }}`

var userObjectTemplate = `Alert count: {{ len .Alerts }}`

func TestSimpleV2Trap(t *testing.T) {
	port, server, channel, err := testutils.LaunchTrapReceiver()
	if err != nil {
		t.Fatal("Error while opening server:", err)
	}
	defer server.Close()

	expectTraps(t, "test_mixed_bucket.json",
		"test_mixed_traps.json",
		Configuration{
			SNMPDestination:            []string{fmt.Sprintf("127.0.0.1:%d", *port)},
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
			DescriptionTemplate:        *template.Must(template.New("dummyDescriptionTemplate").Parse(dummyDescriptionTemplate)),
			UserObjects:                make([]UserObject, 0),
		}, channel)
}

func TestV2TrapWithUserObject(t *testing.T) {
	port, server, channel, err := testutils.LaunchTrapReceiver()
	if err != nil {
		t.Fatal("Error while opening server:", err)
	}
	defer server.Close()

	expectTraps(t, "test_mixed_bucket_user_objects.json",
		"test_mixed_traps_user_objects.json",
		Configuration{
			SNMPDestination:            []string{fmt.Sprintf("127.0.0.1:%d", *port)},
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
			DescriptionTemplate:        *template.Must(template.New("dummyDescriptionTemplate").Parse(dummyDescriptionTemplate)),
			UserObjects: []UserObject{
				{
					SubOID:          8,
					ContentTemplate: *template.Must(template.New("userObjectTemplate").Parse(userObjectTemplate)),
				},
			},
		}, channel)
}

func TestV2TrapWithCustomOID(t *testing.T) {
	port, server, channel, err := testutils.LaunchTrapReceiver()
	if err != nil {
		t.Fatal("Error while opening server:", err)
	}
	defer server.Close()

	expectTraps(t,
		"test_mixed_bucket.json",
		"test_mixed_traps_custom_base_oid.json",
		Configuration{
			SNMPDestination:            []string{fmt.Sprintf("127.0.0.1:%d", *port)},
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
			DescriptionTemplate:        *template.Must(template.New("dummyDescriptionTemplate").Parse(dummyDescriptionTemplate)),
			UserObjects:                make([]UserObject, 0),
		}, channel)
}

func TestSimpleV3Trap(t *testing.T) {
	port, server, channel, err := testutils.LaunchTrapReceiver()
	if err != nil {
		t.Fatal("Error while opening server:", err)
	}
	defer server.Close()

	expectTraps(t,
		"test_mixed_bucket.json",
		"test_mixed_traps.json",
		Configuration{
			SNMPDestination:            []string{fmt.Sprintf("127.0.0.1:%d", *port)},
			SNMPRetries:                1,
			SNMPVersion:                "V3",
			SNMPTimeout:                5 * time.Second,
			SNMPCommunity:              "",
			SNMPAuthenticationEnabled:  true,
			SNMPAuthenticationProtocol: "SHA",
			SNMPAuthenticationUsername: "v3_username",
			SNMPAuthenticationPassword: "v3_password",
			SNMPPrivateEnabled:         true,
			SNMPPrivateProtocol:        "AES",
			SNMPPrivatePassword:        "v3_private_secret",
			SNMPSecurityEngineID:       "8000000004736e6d70676f",
			SNMPContextEngineID:        "",
			SNMPContextName:            "",
			DescriptionTemplate:        *template.Must(template.New("dummyDescriptionTemplate").Parse(dummyDescriptionTemplate)),
			UserObjects:                make([]UserObject, 0),
		},
		channel)
}

func TestV2TrapWithInvalidDescriptionTemplate(t *testing.T) {
	port, server, _, err := testutils.LaunchTrapReceiver()
	if err != nil {
		t.Fatal("Error while opening server:", err)
	}
	defer server.Close()

	expectErrorOnSending(t,
		"test_mixed_bucket.json",
		Configuration{
			SNMPDestination:            []string{fmt.Sprintf("127.0.0.1:%d", *port)},
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
			DescriptionTemplate:        *template.Must(template.New("invalidDescriptionTemplate").Parse(invalidDescriptionTemplate)),
			UserObjects:                make([]UserObject, 0),
		})
}

func TestV3TrapWithAuthenticationError(t *testing.T) {
	port, server, _, err := testutils.LaunchTrapReceiver()
	if err != nil {
		t.Fatal("Error while opening server:", err)
	}
	defer server.Close()

	expectErrorOnSending(t,
		"test_mixed_bucket.json",
		Configuration{
			SNMPDestination:            []string{fmt.Sprintf("127.0.0.1:%d", *port)},
			SNMPRetries:                1,
			SNMPVersion:                "V3",
			SNMPTimeout:                5 * time.Second,
			SNMPCommunity:              "",
			SNMPAuthenticationEnabled:  true,
			SNMPAuthenticationProtocol: "SHA",
			SNMPAuthenticationUsername: "v3_username",
			SNMPAuthenticationPassword: "v3_password",
			SNMPPrivateEnabled:         true,
			SNMPPrivateProtocol:        "AES",
			SNMPPrivatePassword:        "v3_private_secret",
			SNMPSecurityEngineID:       "",
			SNMPContextEngineID:        "",
			SNMPContextName:            "",
			DescriptionTemplate:        *template.Must(template.New("dummyDescriptionTemplate").Parse(dummyDescriptionTemplate)),
			UserObjects:                make([]UserObject, 0),
		})
}

func expectErrorOnSending(t *testing.T, bucketFileName string, configuration Configuration) {
	bucketByteData, err := os.ReadFile(bucketFileName)
	if err != nil {
		t.Fatal("Error while reading bucket file:", err)
	}
	bucketReader := bytes.NewReader(bucketByteData)
	bucketData := types.AlertBucket{}
	err = json.NewDecoder(bucketReader).Decode(&bucketData)
	if err != nil {
		t.Fatal("Error while parsing bucket file:", err)
	}

	trapSender := New(configuration, slog.New(slog.NewTextHandler(os.Stdout, nil)))

	err = trapSender.SendAlertTraps(bucketData)
	if err == nil {
		t.Error("An error was expected")
	}
}

func expectTraps(t *testing.T, bucketFileName string, trapFileName string, configuration Configuration, channel chan *snmpgo.TrapRequest) {

	bucketByteData, err := os.ReadFile(bucketFileName)
	if err != nil {
		t.Fatal("Error while reading bucket file:", err)
	}
	bucketReader := bytes.NewReader(bucketByteData)
	bucketData := types.AlertBucket{}
	err = json.NewDecoder(bucketReader).Decode(&bucketData)
	if err != nil {
		t.Fatal("Error while parsing bucket file:", err)
	}

	trapSender := New(configuration, slog.New(slog.NewTextHandler(os.Stdout, nil)))

	err = trapSender.SendAlertTraps(bucketData)
	if err != nil {
		t.Error("An unexpected error occurred:", err)
	}

	if err == nil {
		receivedTraps := testutils.ReadTraps(channel)

		log.Print("Traps received:", receivedTraps)

		if len(receivedTraps) != 2 {
			t.Error("2 traps expected, but received", receivedTraps)
		}

		expectedTrapsByteData, err := os.ReadFile(trapFileName)
		if err != nil {
			t.Fatal("Error while reading traps file:", err)
		}
		expectedTrapsReader := bytes.NewReader(expectedTrapsByteData)
		expectedTrapsData := []map[string]string{}
		err = json.NewDecoder(expectedTrapsReader).Decode(&expectedTrapsData)
		if err != nil {
			t.Fatal("Error while parsing traps file:", err)
		}

		for _, expectedTrap := range expectedTrapsData {
			if !testutils.FindTrap(receivedTraps, expectedTrap) {
				t.Fatal("Expected trap not found:", expectedTrap)
			}
		}
	}
}
