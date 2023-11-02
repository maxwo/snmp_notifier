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

package telemetry

import "github.com/prometheus/client_golang/prometheus"

var (
	// RequestTotal counts the number of received HTTP calls
	RequestTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "snmp_notifier_requests_total",
			Help: "Total number of HTTP requests by status code.",
		},
		[]string{"code"},
	)
	// SNMPSentTotal counts the number of SNMP traps sent.
	SNMPTrapTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "snmp_notifier_traps_total",
			Help: "Total number of trap by SNMP destination and outcome.",
		},
		[]string{"destination", "outcome"},
	)
)

// Init starts Prometheus metric counters collection
func Init() {
	prometheus.Register(RequestTotal)
	prometheus.Register(SNMPTrapTotal)
}
