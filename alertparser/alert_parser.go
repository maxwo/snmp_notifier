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
	"fmt"
	"strings"

	"github.com/maxwo/snmp_notifier/commons"

	"text/template"

	alertmanagertemplate "github.com/prometheus/alertmanager/template"
)

// AlertParser parses alerts from the Prometheus Alert Manager
type AlertParser struct {
	idTemplate      template.Template
	defaultOID      string
	oidLabel        string
	defaultSeverity string
	severities      []string
	severityLabel   string
}

// New creates an AlertParser instance
func New(idTemplate template.Template, defaultOID string, oidLabel string, defaultSeverity string, severities []string, severityLabel string) AlertParser {
	return AlertParser{idTemplate, defaultOID, oidLabel, defaultSeverity, severities, severityLabel}
}

// Parse parses alerts coming from the Prometheus Alert Manager
func (alertParser AlertParser) Parse(alerts alertmanagertemplate.Alerts) (*commons.AlertBucket, error) {
	var (
		alertGroups = map[string]*commons.AlertGroup{}
	)

	for _, alert := range alerts {
		oid, err := alertParser.getAlertOID(alert)
		if err != nil {
			return nil, err
		}
		groupID, err := generateGroupID(alert, alertParser.idTemplate)
		if err != nil {
			return nil, err
		}
		key := strings.Join([]string{*oid, "[", *groupID, "]"}, "")
		if _, found := alertGroups[key]; !found {
			alertGroups[key] = &commons.AlertGroup{OID: *oid, GroupID: *groupID, Severity: alertParser.getLowestSeverity(), Alerts: []alertmanagertemplate.Alert{}}
		}
		if alert.Status == "firing" {
			err = alertParser.addAlertToGroup(alertGroups[key], alert)
			if err != nil {
				return nil, err
			}
		}
	}

	return &commons.AlertBucket{AlertGroups: alertGroups}, nil
}

func (alertParser AlertParser) addAlertToGroup(alertGroup *commons.AlertGroup, alert alertmanagertemplate.Alert) error {
	var severity = alertParser.defaultSeverity
	if _, found := alert.Labels[alertParser.severityLabel]; found {
		severity = alert.Labels[alertParser.severityLabel]
	}

	var currentGroupSeverityIndex = commons.IndexOf(alertGroup.Severity, alertParser.severities)
	var alertSeverityIndex = commons.IndexOf(severity, alertParser.severities)
	if alertSeverityIndex == -1 {
		return fmt.Errorf("Incorrect severity: %s", severity)
	}
	// Update group severity
	if alertSeverityIndex < currentGroupSeverityIndex {
		alertGroup.Severity = severity
	}
	alertGroup.Alerts = append(alertGroup.Alerts, alert)
	return nil
}

func (alertParser AlertParser) getAlertOID(alert alertmanagertemplate.Alert) (*string, error) {
	var (
		oid = alertParser.defaultOID
	)
	if _, found := alert.Labels[alertParser.oidLabel]; found {
		oid = alert.Labels[alertParser.oidLabel]
		if !commons.IsOID(oid) {
			return nil, fmt.Errorf("Invalid OID provided: \"%s\"", alert.Labels[alertParser.oidLabel])
		}
	}
	return &oid, nil
}

func (alertParser AlertParser) getLowestSeverity() string {
	return alertParser.severities[len(alertParser.severities)-1]
}

func generateGroupID(alert alertmanagertemplate.Alert, idTemplate template.Template) (*string, error) {
	return commons.FillTemplate(alert, idTemplate)
}
