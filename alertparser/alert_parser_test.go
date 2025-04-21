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
	"os"
	"testing"

	"github.com/maxwo/snmp_notifier/types"

	"github.com/go-test/deep"
)

func TestSimpleAlertBuckets(t *testing.T) {
	alerts := readAlertFile(t, "test_mixed_alerts.json")
	buckets := readBucketsFile(t, "test_mixed_bucket.json")

	expectAlertBuckets(
		t,
		Configuration{
			DefaultFiringTrapOID:   "1.1",
			FiringTrapOIDLabel:     "oid",
			DefaultResolvedTrapOID: "1.1",
			ResolvedTrapOIDLabel:   "oid",
			DefaultSeverity:        "critical",
			Severities:             []string{"critical", "warning", "info"},
			SeverityLabel:          "severity",
		},
		alerts,
		buckets,
	)
}

func TestAlertBucketsWithDefaultResolvedTrapOID(t *testing.T) {
	alerts := readAlertFile(t, "test_resolved_alerts.json")
	buckets := readBucketsFile(t, "test_resolved_default_resolved_oid_alerts.json")

	expectAlertBuckets(
		t,
		Configuration{
			DefaultFiringTrapOID:   "1.1",
			FiringTrapOIDLabel:     "oid",
			DefaultResolvedTrapOID: "2.2",
			ResolvedTrapOIDLabel:   "resolution-oid",
			DefaultSeverity:        "critical",
			Severities:             []string{"critical", "warning", "info"},
			SeverityLabel:          "severity",
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
			DefaultFiringTrapOID:   "1.1",
			FiringTrapOIDLabel:     "oid",
			DefaultResolvedTrapOID: "2.2",
			ResolvedTrapOIDLabel:   "resolution-oid",
			DefaultSeverity:        "critical",
			Severities:             []string{"critical", "warning", "info"},
			SeverityLabel:          "severity",
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
			DefaultFiringTrapOID:   "1.1",
			FiringTrapOIDLabel:     "oid",
			DefaultResolvedTrapOID: "2.2",
			ResolvedTrapOIDLabel:   "resolution-oid",
			DefaultSeverity:        "critical",
			Severities:             []string{"critical", "warning", "info"},
			SeverityLabel:          "severity",
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
			DefaultFiringTrapOID:   "1.1",
			FiringTrapOIDLabel:     "oid",
			DefaultResolvedTrapOID: "2.2",
			ResolvedTrapOIDLabel:   "resolution-oid",
			DefaultSeverity:        "critical",
			Severities:             []string{"critical", "warning", "info"},
			SeverityLabel:          "severity",
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
			DefaultFiringTrapOID:   "1.1",
			FiringTrapOIDLabel:     "oid",
			DefaultResolvedTrapOID: "1.1",
			ResolvedTrapOIDLabel:   "oid",
			DefaultSeverity:        "critical",
			Severities:             []string{"critical", "warning", "info"},
			SeverityLabel:          "severity",
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
			DefaultFiringTrapOID:   "1.1",
			FiringTrapOIDLabel:     "oid",
			DefaultResolvedTrapOID: "1.1",
			ResolvedTrapOIDLabel:   "oid",
			DefaultSeverity:        "critical",
			Severities:             []string{"critical", "warning", "info"},
			SeverityLabel:          "severity",
		},
		alerts,
	)
}

func TestResolvedOIDLabelValueCheck(t *testing.T) {
	alerts := readAlertFile(t, "test_mixed_alerts.json")

	expectAlertParserError(
		t,
		Configuration{
			DefaultFiringTrapOID:   "1.1",
			FiringTrapOIDLabel:     "oid",
			DefaultResolvedTrapOID: "1.1",
			ResolvedTrapOIDLabel:   "severity", // tries to use severity as OID
			DefaultSeverity:        "critical",
			Severities:             []string{"critical", "warning", "info"},
			SeverityLabel:          "severity",
		},
		alerts,
	)
}

func expectAlertParserError(t *testing.T, configuration Configuration, alerts types.AlertsData) {
	parser := New(configuration)
	_, err := parser.Parse(alerts)

	if err == nil {
		t.Fatal("An unexpected error occurred:", err)
	}
}

func expectAlertBuckets(t *testing.T, configuration Configuration, alerts types.AlertsData, expectedBuckets types.AlertBucket) {
	parser := New(configuration)
	actualBuckets, err := parser.Parse(alerts)

	if err != nil {
		t.Fatal("An error occured")
	}

	if diff := deep.Equal(*actualBuckets, expectedBuckets); diff != nil {
		t.Error(diff)
	}
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
