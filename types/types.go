// Copyright 2026 Maxime Wojtczak
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

package types

import (
	alertmanagertemplate "github.com/prometheus/alertmanager/template"
)

// Alert is an alert received from the Alertmanager
type Alert = alertmanagertemplate.Alert

// Alerts is a set of alerts received from the Alertmanager
type Alerts = alertmanagertemplate.Alerts

// AlertsData is the alerts object received from the Alertmanager
type AlertsData = alertmanagertemplate.Data

// AlertBucket mutualizes alerts by Trap IDs
type AlertBucket struct {
	AlertGroups map[string]*AlertGroup
}

// AlertGroup type, with OID and group ID
type AlertGroup struct {
	TrapOID               string
	GroupID               string
	DefaultObjectsBaseOID string
	UserObjectsBaseOID    string
	GroupLabels           map[string]string
	CommonLabels          map[string]string
	CommonAnnotations     map[string]string
	Severity              string
	Alerts                []Alert
	DeclaredAlerts        []Alert
}

// GetAlertGroupName allows to retrieve a group name from a given alert
type GetAlertGroupName func(Alert) (*string, error)
