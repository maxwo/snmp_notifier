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
	"github.com/maxwo/snmp_notifier/types"
)

// AlertParser parses alerts from the Prometheus Alert Manager
type AlertParser struct {
	configuration Configuration
}

// Configuration stores configuration of an AlertParser
type Configuration struct {
	DefaultOID      string
	OIDLabel        string
	DefaultSeverity string
	Severities      []string
	SeverityLabel   string
}

// New creates an AlertParser instance
func New(configuration Configuration) AlertParser {
	return AlertParser{configuration}
}

// Parse parses alerts coming from the Prometheus Alert Manager
func (alertParser AlertParser) Parse(alertsData types.AlertsData) (*types.AlertBucket, error) {
	var (
		alertGroups = map[string]*types.AlertGroup{}
		groupID     string
	)
	groupID = generateGroupID(alertsData)
	for _, alert := range alertsData.Alerts {
		oid, err := alertParser.getAlertOID(alert)
		if err != nil {
			return nil, err
		}
		key := strings.Join([]string{*oid, "[", groupID, "]"}, "")
		if _, found := alertGroups[key]; !found {
			alertGroups[key] = &types.AlertGroup{OID: *oid, GroupID: groupID, Severity: alertParser.getLowestSeverity(), Alerts: []types.Alert{}, DeclaredAlerts: []types.Alert{}}
		}
		alertGroups[key].DeclaredAlerts = append(alertGroups[key].DeclaredAlerts, alert)
		if alert.Status == "firing" {
			err = alertParser.addAlertToGroup(alertGroups[key], alert)
			if err != nil {
				return nil, err
			}
		}
	}

	return &types.AlertBucket{AlertGroups: alertGroups}, nil
}

func (alertParser AlertParser) addAlertToGroup(alertGroup *types.AlertGroup, alert types.Alert) error {
	var severity = alertParser.configuration.DefaultSeverity
	if _, found := alert.Labels[alertParser.configuration.SeverityLabel]; found {
		severity = alert.Labels[alertParser.configuration.SeverityLabel]
	}

	var currentGroupSeverityIndex = commons.IndexOf(alertGroup.Severity, alertParser.configuration.Severities)
	var alertSeverityIndex = commons.IndexOf(severity, alertParser.configuration.Severities)
	if alertSeverityIndex == -1 {
		return fmt.Errorf("incorrect severity: %s", severity)
	}
	// Update group severity
	if alertSeverityIndex < currentGroupSeverityIndex {
		alertGroup.Severity = severity
	}
	alertGroup.Alerts = append(alertGroup.Alerts, alert)
	return nil
}

func (alertParser AlertParser) getAlertOID(alert types.Alert) (*string, error) {
	var (
		oid string
	)
	if _, found := alert.Labels[alertParser.configuration.OIDLabel]; found {
		oid = alert.Labels[alertParser.configuration.OIDLabel]
	} else {
		oid = alertParser.configuration.DefaultOID
	}
	if !commons.IsOID(oid) {
		return nil, fmt.Errorf("invalid OID provided: \"%s\"", oid)
	}
	return &oid, nil
}

func (alertParser AlertParser) getLowestSeverity() string {
	return alertParser.configuration.Severities[len(alertParser.configuration.Severities)-1]
}

func generateGroupID(alertsData types.AlertsData) string {
	var (
		pairs []string
	)
	for _, pair := range alertsData.GroupLabels.SortedPairs() {
		pairs = append(pairs, fmt.Sprintf("%s=%s", pair.Name, pair.Value))
	}
	return strings.Join(pairs, ",")
}
