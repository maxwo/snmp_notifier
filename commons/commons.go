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
	"regexp"

	"text/template"

	"github.com/maxwo/snmp_notifier/types"
)

var oidRegexp = regexp.MustCompile("^[0-9]+((\\.[0-9]+)*)$")

// FillTemplate is a boiler-plate function to fill a template
func FillTemplate(object interface{}, tmpl template.Template) (*string, error) {
	buf := &bytes.Buffer{}
	err := tmpl.Execute(buf, object)
	if err != nil {
		return nil, err
	}
	var result = buf.String()
	return &result, err
}

// GroupAlertsByLabel groups several alerts by a given label. If the label does not exists, then a "<none>" key is created
func GroupAlertsByLabel(alerts []types.Alert, label string) (*map[string][]types.Alert, error) {
	return GroupAlertsBy(alerts, getAlertLabel(label))
}

// GroupAlertsByName groups several alerts by their names
func GroupAlertsByName(alerts []types.Alert) (*map[string][]types.Alert, error) {
	return GroupAlertsBy(alerts, getAlertLabel("alertname"))
}

func getAlertLabel(label string) types.GetAlertGroupName {
	return func(alert types.Alert) (*string, error) {
		value := "<none>"
		if _, found := alert.Labels[label]; found {
			value = alert.Labels[label]
		}
		return &value, nil
	}
}

// GroupAlertsBy groups given alerts according to an ID
func GroupAlertsBy(alerts []types.Alert, groupNameFunction types.GetAlertGroupName) (*map[string][]types.Alert, error) {
	var groups = make(map[string][]types.Alert)
	for _, alert := range alerts {
		groupName, err := groupNameFunction(alert)
		if err != nil {
			return nil, err
		}
		groups[*groupName] = append(groups[*groupName], alert)
	}
	return &groups, nil
}

// IsOID checks if a given string is a valid OID
func IsOID(text string) bool {
	return oidRegexp.MatchString(text)
}

// IndexOf returns the position of a given element in a string slice
func IndexOf(element string, data []string) int {
	for k, v := range data {
		if element == v {
			return k
		}
	}
	return -1
}
