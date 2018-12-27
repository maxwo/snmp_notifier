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

	alertmanagertemplate "github.com/prometheus/alertmanager/template"
)

// AlertBucket mutualizes alerts by Trap IDs
type AlertBucket struct {
	AlertGroups map[string]*AlertGroup
}

// AlertGroup type, with OID and group ID
type AlertGroup struct {
	OID      string
	GroupID  string
	Severity string
	Alerts   []alertmanagertemplate.Alert
}

// GetAlertGroupName allows to retrieve a group name from a given alert
type GetAlertGroupName func(alertmanagertemplate.Alert) (*string, error)

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

// GroupAlertsBy groups given alerts according to an ID
func GroupAlertsBy(alerts []alertmanagertemplate.Alert, groupNameFunction GetAlertGroupName) (*map[string][]alertmanagertemplate.Alert, error) {
	var groups = make(map[string][]alertmanagertemplate.Alert)
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
