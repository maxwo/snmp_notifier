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

package alertparser

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"strings"
	"testing"
	"text/template"

	"github.com/maxwo/snmp_notifier/commons"

	"github.com/go-test/deep"
	alertmanagertemplate "github.com/prometheus/alertmanager/template"
)

func TestParse(t *testing.T) {
	var tests = []struct {
		Template        string
		DefaultOid      string
		OidLabel        string
		DefaultSeverity string
		Severities      []string
		SeverityLabel   string
		AlertsFileName  string
		BucketFileName  string
		ExpectError     bool
	}{
		{
			"{{ .Labels.alertname }}",
			"1.1",
			"oid",
			"critical",
			strings.Split("critical,warning,info", ","),
			"severity",
			"test_mixed_alerts.json",
			"test_mixed_bucket.json",
			false,
		},
		{
			"{{ .Labels.alertname }}",
			"1.1",
			"oid",
			"critical",
			strings.Split("critical,warning,info", ","),
			"severity",
			"test_wrong_oid_alerts.json",
			"",
			true,
		},
		{
			"{{ .Labels.alertname }}",
			"1.1",
			"oid",
			"critical",
			strings.Split("critical,warning,info", ","),
			"severity",
			"test_wrong_severity_alerts.json",
			"",
			true,
		},
	}

	for _, test := range tests {
		t.Log("Testing with file", test.AlertsFileName)
		alertsByteData, err := ioutil.ReadFile(test.AlertsFileName)
		if err != nil {
			t.Fatal("Error while reading alert file:", err)
		}
		alertsReader := bytes.NewReader(alertsByteData)
		alertsData := []alertmanagertemplate.Alert{}
		err = json.NewDecoder(alertsReader).Decode(&alertsData)
		if err != nil {
			t.Fatal("Error while parsing alert file:", err)
		}

		template, err := template.New("id").Parse(test.Template)
		if err != nil {
			t.Fatal("Error while parsing bucket file:", err)
		}

		parser := New(*template, test.DefaultOid, test.OidLabel, test.DefaultSeverity, test.Severities, test.SeverityLabel)
		bucket, err := parser.Parse(alertsData)

		if test.ExpectError && err == nil {
			t.Error("An error was expected")
			continue
		}

		if !test.ExpectError && err != nil {
			t.Error("An unexpected error occurred:", err)
			continue
		}

		if err == nil {
			bucketByteData, err := ioutil.ReadFile(test.BucketFileName)
			if err != nil {
				t.Fatal("Error while reading bucket file:", err)
				continue
			}
			bucketReader := bytes.NewReader(bucketByteData)
			bucketData := commons.AlertBucket{}
			err = json.NewDecoder(bucketReader).Decode(&bucketData)
			if err != nil {
				t.Fatal("Error while parsing bucket file:", err)
				continue
			}

			if diff := deep.Equal(bucketData, *bucket); diff != nil {
				t.Error(diff)
			}
		}
	}
}
