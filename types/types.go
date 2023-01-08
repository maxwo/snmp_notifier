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
	OID               string
	GroupID           string
	GroupLabels       map[string]string
	CommonLabels      map[string]string
	CommonAnnotations map[string]string
	Severity          string
	Alerts            []Alert
	DeclaredAlerts    []Alert
}

// GetAlertGroupName allows to retrieve a group name from a given alert
type GetAlertGroupName func(Alert) (*string, error)
