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
	"io/ioutil"
	"log"
	"testing"

	"text/template"

	"github.com/maxwo/snmp_notifier/types"

	testutils "github.com/maxwo/snmp_notifier/test"
)

var dummyDescriptionTemplate = `{{ range $key, $value := .Alerts }}Alert name: {{ $value.Labels.alertname }}
Severity: {{ $value.Labels.severity }}
Summary: {{ $value.Annotations.summary }}
Description: {{ $value.Annotations.description }}
{{ end -}}`

var invalidDescriptionTemplate = `{{ range $key, $value := .InvalidAlerts }}{{ end }}`

func TestSend(t *testing.T) {
	var tests = []struct {
		BucketFileName string
		TrapsFileName  string
		Template       string
		Port           uint
		Configuration  *Configuration
		ExpectError    bool
	}{
		{
			"test_mixed_bucket.json",
			"test_mixed_traps.json",
			dummyDescriptionTemplate,
			1163,
			&Configuration{
				"127.0.0.1:1163",
				1,
				"V2c",
				"public",
				false,
				"",
				"",
				"",
				false,
				"",
				"",
				"",
				"",
				"",
				*template.Must(template.New("dummyDescriptionTemplate").Parse(dummyDescriptionTemplate)),
			},
			false,
		},
		{
			"test_mixed_bucket.json",
			"test_mixed_traps.json",
			invalidDescriptionTemplate,
			1163,
			&Configuration{
				"127.0.0.1:1163",
				1,
				"V2c",
				"public",
				false,
				"",
				"",
				"",
				false,
				"",
				"",
				"",
				"",
				"",
				*template.Must(template.New("invalidDescriptionTemplate").Parse(invalidDescriptionTemplate)),
			},
			true,
		},
		{
			"test_mixed_bucket.json",
			"test_mixed_traps.json",
			dummyDescriptionTemplate,
			1166,
			&Configuration{
				"127.0.0.1:1166",
				1,
				"V3",
				"",
				true,
				"SHA",
				"v3_username",
				"v3_password",
				true,
				"AES",
				"v3_private_secret",
				"",
				"",
				"",
				*template.Must(template.New("dummyDescriptionTemplate").Parse(dummyDescriptionTemplate)),
			},
			true,
		},
	}

	server, channel, err := testutils.LaunchTrapReceiver(1163)
	if err != nil {
		t.Fatal("Error while opening server:", err)
	}
	defer server.Close()

	for index, test := range tests {
		t.Log("Launching test ", index)
		bucketByteData, err := ioutil.ReadFile(test.BucketFileName)
		if err != nil {
			t.Fatal("Error while reading bucket file:", err)
		}
		bucketReader := bytes.NewReader(bucketByteData)
		bucketData := types.AlertBucket{}
		err = json.NewDecoder(bucketReader).Decode(&bucketData)
		if err != nil {
			t.Fatal("Error while parsing bucket file:", err)
		}

		trapSender := New(*test.Configuration)

		err = trapSender.SendAlertTraps(bucketData)
		if test.ExpectError && err == nil {
			t.Error("An error was expected")
		}

		if !test.ExpectError && err != nil {
			t.Error("An unexpected error occurred:", err)
		}

		if err == nil {
			receivedTraps := testutils.ReadTraps(channel)

			log.Print("Traps received:", receivedTraps)

			if len(receivedTraps) != 2 {
				t.Error("2 traps expected, but received", receivedTraps)
			}

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

			for _, expectedTrap := range expectedTrapsData {
				if !testutils.FindTrap(receivedTraps, expectedTrap) {
					t.Fatal("Expected trap not found:", expectedTrap)
				}
			}
		}
	}
}
