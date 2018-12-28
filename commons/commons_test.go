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

package commons

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"

	"text/template"

	"github.com/go-test/deep"

	"github.com/maxwo/snmp_notifier/types"
)

func TestFillTemplate(t *testing.T) {
	var tests = []struct {
		template string
		object   interface{}
		result   string
	}{
		{
			"Hello {{ .Title }}",
			struct {
				Title string
			}{
				"title",
			},
			"Hello title",
		},
	}
	for _, test := range tests {
		template, err := template.New(test.template).Parse(test.template)
		if err != nil {
			t.Error("Unable to compile template", err)
			continue
		}
		if result, _ := FillTemplate(test.object, *template); *result != test.result {
			t.Errorf("FillTemplate of [%s] shoud be [%s], got [%s]", test.template, test.result, *result)
		}
	}
}

func TestGroupAlertsByName(t *testing.T) {
	var tests = []struct {
		AlertsFileName string
		GroupsFileName string
		ExpectError    bool
	}{
		{
			"test_alerts.json",
			"test_groups_alertname.json",
			false,
		},
	}

	for _, test := range tests {
		alertsByteData, err := ioutil.ReadFile(test.AlertsFileName)
		if err != nil {
			t.Fatal("Error while reading alert file", err)
		}
		alertsReader := bytes.NewReader(alertsByteData)
		alertsData := []types.Alert{}
		err = json.NewDecoder(alertsReader).Decode(&alertsData)
		if err != nil {
			t.Fatal("Error while parsing alert file", err)
		}

		groupsByteData, err := ioutil.ReadFile(test.GroupsFileName)
		if err != nil {
			t.Fatal("Error while reading group file", err)
		}
		groupsReader := bytes.NewReader(groupsByteData)
		groupsData := map[string][]types.Alert{}
		err = json.NewDecoder(groupsReader).Decode(&groupsData)
		if err != nil {
			t.Fatal("Error while parsing group file", err)
		}

		groups, err := GroupAlertsByName(alertsData)

		if test.ExpectError && err == nil {
			t.Error("An error was expected")
			continue
		}

		if !test.ExpectError && err != nil {
			t.Error("Unexpected error", err)
			continue
		}

		if err == nil {
			if diff := deep.Equal(groupsData, *groups); diff != nil {
				t.Error(diff)
			}
		}
	}
}

func TestGroupAlertsByLabel(t *testing.T) {
	var tests = []struct {
		AlertsFileName string
		Label          string
		GroupsFileName string
		ExpectError    bool
	}{
		{
			"test_alerts.json",
			"alertname",
			"test_groups_alertname.json",
			false,
		},
	}

	for _, test := range tests {
		alertsByteData, err := ioutil.ReadFile(test.AlertsFileName)
		if err != nil {
			t.Fatal("Error while reading alert file", err)
		}
		alertsReader := bytes.NewReader(alertsByteData)
		alertsData := []types.Alert{}
		err = json.NewDecoder(alertsReader).Decode(&alertsData)
		if err != nil {
			t.Fatal("Error while parsing alert file", err)
		}

		groupsByteData, err := ioutil.ReadFile(test.GroupsFileName)
		if err != nil {
			t.Fatal("Error while reading group file", err)
		}
		groupsReader := bytes.NewReader(groupsByteData)
		groupsData := map[string][]types.Alert{}
		err = json.NewDecoder(groupsReader).Decode(&groupsData)
		if err != nil {
			t.Fatal("Error while parsing group file", err)
		}

		groups, err := GroupAlertsByLabel(alertsData, test.Label)

		if test.ExpectError && err == nil {
			t.Error("An error was expected")
			continue
		}

		if !test.ExpectError && err != nil {
			t.Error("Unexpected error", err)
			continue
		}

		if err == nil {
			if diff := deep.Equal(groupsData, *groups); diff != nil {
				t.Error(diff)
			}
		}
	}
}

func TestGroupAlertsBy(t *testing.T) {
	var tests = []struct {
		AlertsFileName string
		Classifier     types.GetAlertGroupName
		GroupsFileName string
		ExpectError    bool
	}{
		{
			"test_alerts.json",
			func(alert types.Alert) (*string, error) {
				oid := alert.Labels["oid"]
				return &oid, nil
			},
			"test_groups.json",
			false,
		},
		{
			"test_alerts.json",
			func(alert types.Alert) (*string, error) {
				return nil, fmt.Errorf("Ohlala")
			},
			"test_groups.json",
			true,
		},
	}

	for _, test := range tests {
		alertsByteData, err := ioutil.ReadFile(test.AlertsFileName)
		if err != nil {
			t.Fatal("Error while reading alert file", err)
		}
		alertsReader := bytes.NewReader(alertsByteData)
		alertsData := []types.Alert{}
		err = json.NewDecoder(alertsReader).Decode(&alertsData)
		if err != nil {
			t.Fatal("Error while parsing alert file", err)
		}

		groupsByteData, err := ioutil.ReadFile(test.GroupsFileName)
		if err != nil {
			t.Fatal("Error while reading group file", err)
		}
		groupsReader := bytes.NewReader(groupsByteData)
		groupsData := map[string][]types.Alert{}
		err = json.NewDecoder(groupsReader).Decode(&groupsData)
		if err != nil {
			t.Fatal("Error while parsing group file", err)
		}

		groups, err := GroupAlertsBy(alertsData, test.Classifier)

		if test.ExpectError && err == nil {
			t.Error("An error was expected")
			continue
		}

		if !test.ExpectError && err != nil {
			t.Error("Unexpected error", err)
			continue
		}

		if err == nil {
			if diff := deep.Equal(groupsData, *groups); diff != nil {
				t.Error(diff)
			}
		}
	}
}

func TestIsOID(t *testing.T) {
	var oids = map[string]bool{
		"1":                 true,
		"1.1":               true,
		"1.2.3.4.5.6.7.8.9": true,
		"dlfjqklsjf":        false,
		"":                  false,
		"1.":                false,
		"1a":                false,
		"1.a":               false,
		"aaaaa1.1.1":        false,
		"1.1aaaa":           false,
	}
	for oid, result := range oids {
		if IsOID(oid) != result {
			t.Errorf("OID %s shoud be %t", oid, result)
		}
	}
}

func TestIndexOf(t *testing.T) {
	var tests = []struct {
		list   []string
		value  string
		result int
	}{
		{
			[]string{
				"element1",
				"element2",
			},
			"element2",
			1,
		},
		{
			[]string{
				"element1",
				"element2",
			},
			"not_found",
			-1,
		},
	}
	for _, test := range tests {
		if IndexOf(test.value, test.list) != test.result {
			t.Errorf("IndexOf of %s shoud be %d", test.value, test.result)
		}
	}
}
