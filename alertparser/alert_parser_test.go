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
	"log/slog"
	"os"
	"testing"

	"github.com/maxwo/snmp_notifier/types"

	"github.com/go-test/deep"
)

var resolutionOIDForTest = "2.2"
var resolutionOIDLabelForTest = "resolution-oid"
var wrongResolutionOIDLabelForTest = "severity"

func TestUniqueAlertBuckets(t *testing.T) {
	expectTrapOIDFromUniqueAlertAndConfiguration(t,
		Configuration{
			TrapDefaultOID:            "1.1",
			TrapOIDLabel:              "oid",
			DefaultSeverity:           "critical",
			Severities:                []string{"critical", "warning", "info"},
			SeverityLabel:             "severity",
			TrapDefaultObjectsBaseOID: "4.4.4",
			TrapUserObjectsBaseOID:    "4.4.5",
		},
		"1.1[environment=production,label=test]",
		"1.1")
}

func TestUniqueResolvedAlertBuckets(t *testing.T) {
	expectTrapOIDFromUniqueResolvedAlertAndConfiguration(t,
		Configuration{
			TrapDefaultOID:            "1.1",
			TrapOIDLabel:              "oid",
			DefaultSeverity:           "critical",
			Severities:                []string{"critical", "warning", "info"},
			SeverityLabel:             "severity",
			TrapDefaultObjectsBaseOID: "4.4.4",
			TrapUserObjectsBaseOID:    "4.4.5",
		},
		"1.1[environment=production,label=test]",
		"1.1")
}

func TestUniqueAlertBucketsWithCustomFiringOID(t *testing.T) {
	expectTrapOIDFromUniqueAlertAndConfiguration(t,
		Configuration{
			TrapDefaultOID:            "1.1",
			TrapOIDLabel:              "firing-oid",
			DefaultSeverity:           "critical",
			Severities:                []string{"critical", "warning", "info"},
			SeverityLabel:             "severity",
			TrapDefaultObjectsBaseOID: "4.4.4",
			TrapUserObjectsBaseOID:    "4.4.5",
		},
		"1.2.3[environment=production,label=test]",
		"1.2.3")
}

func TestUniqueResolvedAlertBucketsWithCustomFiringOID(t *testing.T) {
	expectTrapOIDFromUniqueResolvedAlertAndConfiguration(t,
		Configuration{
			TrapDefaultOID:            "1.1",
			TrapOIDLabel:              "firing-oid",
			DefaultSeverity:           "critical",
			Severities:                []string{"critical", "warning", "info"},
			SeverityLabel:             "severity",
			TrapDefaultObjectsBaseOID: "4.4.4",
			TrapUserObjectsBaseOID:    "4.4.5",
		},
		"1.2.3[environment=production,label=test]",
		"1.2.3")
}

func TestUniqueAlertBucketsWithResolutionTrapOID(t *testing.T) {
	expectTrapOIDFromUniqueAlertAndConfiguration(t,
		Configuration{
			TrapDefaultOID:            "1.1",
			TrapOIDLabel:              "oid",
			TrapResolutionDefaultOID:  &resolutionOIDForTest,
			DefaultSeverity:           "critical",
			Severities:                []string{"critical", "warning", "info"},
			SeverityLabel:             "severity",
			TrapDefaultObjectsBaseOID: "4.4.4",
			TrapUserObjectsBaseOID:    "4.4.5",
		},
		"1.1-2.2[environment=production,label=test]",
		"1.1")
}

func TestUniqueResolvedAlertBucketsWithResolutionTrapOID(t *testing.T) {
	expectTrapOIDFromUniqueResolvedAlertAndConfiguration(t,
		Configuration{
			TrapDefaultOID:            "1.1",
			TrapOIDLabel:              "oid",
			TrapResolutionDefaultOID:  &resolutionOIDForTest,
			DefaultSeverity:           "critical",
			Severities:                []string{"critical", "warning", "info"},
			SeverityLabel:             "severity",
			TrapDefaultObjectsBaseOID: "4.4.4",
			TrapUserObjectsBaseOID:    "4.4.5",
		},
		"1.1-2.2[environment=production,label=test]",
		"2.2")
}

// any firing trap custom OID has higher priority than default resolution trap OID
func TestUniqueAlertBucketsWithResolutionTrapOIDAndCustomFiringTrapOID(t *testing.T) {
	expectTrapOIDFromUniqueAlertAndConfiguration(t,
		Configuration{
			TrapDefaultOID:            "1.1",
			TrapOIDLabel:              "firing-oid",
			TrapResolutionDefaultOID:  &resolutionOIDForTest,
			DefaultSeverity:           "critical",
			Severities:                []string{"critical", "warning", "info"},
			SeverityLabel:             "severity",
			TrapDefaultObjectsBaseOID: "4.4.4",
			TrapUserObjectsBaseOID:    "4.4.5",
		},
		"1.2.3[environment=production,label=test]",
		"1.2.3")
}

func TestUniqueResolvedAlertBucketsWithResolutionTrapOIDAndCustomFiringTrapOID(t *testing.T) {
	expectTrapOIDFromUniqueResolvedAlertAndConfiguration(t,
		Configuration{
			TrapDefaultOID:            "1.1",
			TrapOIDLabel:              "firing-oid",
			TrapResolutionDefaultOID:  &resolutionOIDForTest,
			DefaultSeverity:           "critical",
			Severities:                []string{"critical", "warning", "info"},
			SeverityLabel:             "severity",
			TrapDefaultObjectsBaseOID: "4.4.4",
			TrapUserObjectsBaseOID:    "4.4.5",
		},
		"1.2.3[environment=production,label=test]",
		"1.2.3")
}

// any custom resolution OID has higher priority than custom firing trap OID
func TestUniqueAlertBucketsWithResolutionTrapOIDAndCustomFiringAndResolutionTrapOID(t *testing.T) {
	expectTrapOIDFromUniqueAlertAndConfiguration(t,
		Configuration{
			TrapDefaultOID:            "1.1",
			TrapOIDLabel:              "firing-oid",
			TrapResolutionOIDLabel:    &resolutionOIDLabelForTest,
			DefaultSeverity:           "critical",
			Severities:                []string{"critical", "warning", "info"},
			SeverityLabel:             "severity",
			TrapDefaultObjectsBaseOID: "4.4.4",
			TrapUserObjectsBaseOID:    "4.4.5",
		},
		"1.2.3-1.2.4[environment=production,label=test]",
		"1.2.3")
}

func TestUniqueResolvedAlertBucketsWithResolutionTrapOIDAndCustomFiringAndResolutionTrapOID(t *testing.T) {
	expectTrapOIDFromUniqueResolvedAlertAndConfiguration(t,
		Configuration{
			TrapDefaultOID:            "1.1",
			TrapOIDLabel:              "firing-oid",
			TrapResolutionOIDLabel:    &resolutionOIDLabelForTest,
			DefaultSeverity:           "critical",
			Severities:                []string{"critical", "warning", "info"},
			SeverityLabel:             "severity",
			TrapDefaultObjectsBaseOID: "4.4.4",
			TrapUserObjectsBaseOID:    "4.4.5",
		},
		"1.2.3-1.2.4[environment=production,label=test]",
		"1.2.4")
}

func TestMixedAlertBuckets(t *testing.T) {
	alerts := readAlertFile(t, "test_mixed_alerts.json")
	buckets := readBucketsFile(t, "test_mixed_bucket.json")

	expectAlertBuckets(
		t,
		Configuration{
			TrapDefaultOID:            "1.1",
			TrapOIDLabel:              "oid",
			DefaultSeverity:           "critical",
			Severities:                []string{"critical", "warning", "info"},
			SeverityLabel:             "severity",
			TrapDefaultObjectsBaseOID: "4.4.4",
			TrapUserObjectsBaseOID:    "4.4.5",
		},
		alerts,
		buckets,
	)
}

func TestAlertBucketsWithTrapResolutionDefaultOID(t *testing.T) {
	alerts := readAlertFile(t, "test_resolved_alerts.json")
	buckets := readBucketsFile(t, "test_resolved_default_resolved_oid_alerts.json")

	expectAlertBuckets(
		t,
		Configuration{
			TrapDefaultOID:            "1.1",
			TrapOIDLabel:              "oid",
			TrapResolutionDefaultOID:  &resolutionOIDForTest,
			TrapResolutionOIDLabel:    &resolutionOIDLabelForTest,
			DefaultSeverity:           "critical",
			Severities:                []string{"critical", "warning", "info"},
			SeverityLabel:             "severity",
			TrapDefaultObjectsBaseOID: "4.4.4",
			TrapUserObjectsBaseOID:    "4.4.5",
		},
		alerts,
		buckets,
	)
}

func TestAlertBucketsWithFiringAndResolvedAlerts(t *testing.T) {
	alerts := readAlertFile(t, "test_resolved_alerts.json")
	buckets := readBucketsFile(t, "test_resolved_default_firing_oid_alerts.json")

	alerts.Alerts[0].Status = "firing"

	expectAlertBuckets(
		t,
		Configuration{
			TrapDefaultOID:            "1.1",
			TrapOIDLabel:              "oid",
			TrapResolutionDefaultOID:  &resolutionOIDForTest,
			TrapResolutionOIDLabel:    &resolutionOIDLabelForTest,
			DefaultSeverity:           "critical",
			Severities:                []string{"critical", "warning", "info"},
			SeverityLabel:             "severity",
			TrapDefaultObjectsBaseOID: "4.4.4",
			TrapUserObjectsBaseOID:    "4.4.5",
		},
		alerts,
		buckets,
	)
}

func TestAlertBucketsWithResolvedTrapOIDFromLabels(t *testing.T) {
	alerts := readAlertFile(t, "test_resolved_alerts.json")
	buckets := readBucketsFile(t, "test_resolved_oid_from_labels_alerts.json")

	alerts.Alerts[0].Labels["resolution-oid"] = "7.7.7"
	alerts.Alerts[1].Labels["resolution-oid"] = "7.7.7"

	expectAlertBuckets(
		t,
		Configuration{
			TrapDefaultOID:            "1.1",
			TrapOIDLabel:              "oid",
			TrapResolutionDefaultOID:  &resolutionOIDForTest,
			TrapResolutionOIDLabel:    &resolutionOIDLabelForTest,
			DefaultSeverity:           "critical",
			Severities:                []string{"critical", "warning", "info"},
			SeverityLabel:             "severity",
			TrapDefaultObjectsBaseOID: "4.4.4",
			TrapUserObjectsBaseOID:    "4.4.5",
		},
		alerts,
		buckets,
	)
}

func TestAlertBucketsWithFiringAndResolvedTrapOIDFromLabels(t *testing.T) {
	alerts := readAlertFile(t, "test_resolved_alerts.json")
	buckets := readBucketsFile(t, "test_resolved_and_firing_oid_from_labels_alerts.json")

	alerts.Alerts[0].Labels["oid"] = "8.8.8"
	alerts.Alerts[1].Labels["oid"] = "8.8.8"
	alerts.Alerts[0].Labels["resolution-oid"] = "7.7.7"
	alerts.Alerts[1].Labels["resolution-oid"] = "7.7.7"

	expectAlertBuckets(
		t,
		Configuration{
			TrapDefaultOID:            "1.1",
			TrapOIDLabel:              "oid",
			TrapResolutionDefaultOID:  &resolutionOIDForTest,
			TrapResolutionOIDLabel:    &resolutionOIDLabelForTest,
			DefaultSeverity:           "critical",
			Severities:                []string{"critical", "warning", "info"},
			SeverityLabel:             "severity",
			TrapDefaultObjectsBaseOID: "4.4.4",
			TrapUserObjectsBaseOID:    "4.4.5",
		},
		alerts,
		buckets,
	)
}

func TestSeverityLabelValueCheck(t *testing.T) {
	alerts := readAlertFile(t, "test_mixed_alerts.json")

	alerts.Alerts[0].Labels["severity"] = "unknown"

	expectAlertParserError(
		t,
		Configuration{
			TrapDefaultOID:            "1.1",
			TrapOIDLabel:              "oid",
			DefaultSeverity:           "critical",
			Severities:                []string{"critical", "warning", "info"},
			SeverityLabel:             "severity",
			TrapDefaultObjectsBaseOID: "4.4.4",
			TrapUserObjectsBaseOID:    "4.4.5",
		},
		alerts,
	)
}

func TestOIDLabelValueCheck(t *testing.T) {
	alerts := readAlertFile(t, "test_mixed_alerts.json")

	alerts.Alerts[0].Labels["oid"] = "1.a.2.3"

	expectAlertParserError(
		t,
		Configuration{
			TrapDefaultOID:            "1.1",
			TrapOIDLabel:              "oid",
			DefaultSeverity:           "critical",
			Severities:                []string{"critical", "warning", "info"},
			SeverityLabel:             "severity",
			TrapDefaultObjectsBaseOID: "4.4.4",
			TrapUserObjectsBaseOID:    "4.4.5",
		},
		alerts,
	)
}

func TestResolvedOIDLabelValueCheck(t *testing.T) {
	alerts := readAlertFile(t, "test_mixed_alerts.json")

	expectAlertParserError(
		t,
		Configuration{
			TrapDefaultOID:            "1.1",
			TrapOIDLabel:              "oid",
			TrapResolutionOIDLabel:    &wrongResolutionOIDLabelForTest, // tries to use severity as OID
			DefaultSeverity:           "critical",
			Severities:                []string{"critical", "warning", "info"},
			SeverityLabel:             "severity",
			TrapDefaultObjectsBaseOID: "4.4.4",
			TrapUserObjectsBaseOID:    "4.4.5",
		},
		alerts,
	)
}

func expectAlertParserError(t *testing.T, configuration Configuration, alerts types.AlertsData) {
	parser := New(configuration, slog.New(slog.NewTextHandler(os.Stdout, nil)))
	_, err := parser.Parse(alerts)

	if err == nil {
		t.Fatal("An unexpected error occurred:", err)
	}
}

func expectTrapOIDFromUniqueAlertAndConfiguration(t *testing.T, configuration Configuration, groupID string, trapOID string) {
	alerts := readAlertFile(t, "test_unique_alert.json")
	expectTrapOIDAndGroupIDFromAlertAndConfiguration(t, configuration, alerts, groupID, trapOID)
}

func expectTrapOIDFromUniqueResolvedAlertAndConfiguration(t *testing.T, configuration Configuration, groupID string, trapOID string) {
	alerts := readAlertFile(t, "test_unique_alert.json")
	alerts.Alerts[0].Status = "resolved"
	expectTrapOIDAndGroupIDFromAlertAndConfiguration(t, configuration, alerts, groupID, trapOID)
}

func expectTrapOIDAndGroupIDFromAlertAndConfiguration(t *testing.T, configuration Configuration, alerts types.AlertsData, groupID string, trapOID string) {
	buckets := getAlertBuckets(t, configuration, alerts)

	if value, found := buckets.AlertGroups[groupID]; found {
		if value.TrapOID != trapOID {
			t.Error("unexpected trap OID", "trapOID", value.TrapOID)
		}
	} else {
		t.Error("expected group ID not found", "groupID", groupID, "buckets", buckets)
	}
}

func expectAlertBuckets(t *testing.T, configuration Configuration, alerts types.AlertsData, expectedBuckets types.AlertBucket) {
	actualBuckets := getAlertBuckets(t, configuration, alerts)

	if diff := deep.Equal(actualBuckets, expectedBuckets); diff != nil {
		t.Error(diff)
	}
}

func getAlertBuckets(t *testing.T, configuration Configuration, alerts types.AlertsData) types.AlertBucket {
	parser := New(configuration, slog.New(slog.NewTextHandler(os.Stdout, nil)))
	buckets, err := parser.Parse(alerts)

	if err != nil {
		t.Fatal("An error occured")
	}

	return *buckets
}

func readAlertFile(t *testing.T, alertFileName string) types.AlertsData {
	alertsByteData, err := os.ReadFile(alertFileName)
	if err != nil {
		t.Fatal("Error while reading alert file:", err)
	}
	alertsReader := bytes.NewReader(alertsByteData)
	alertsData := types.AlertsData{}
	err = json.NewDecoder(alertsReader).Decode(&alertsData)
	if err != nil {
		t.Fatal("Error while parsing alert file:", err)
	}
	return alertsData
}

func readBucketsFile(t *testing.T, bucketFileName string) types.AlertBucket {
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
	return bucketData
}
