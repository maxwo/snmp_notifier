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
			Help: "Requests processed, by status code.",
		},
		[]string{"code"},
	)
	// SNMPSentTotal counts the number of SNMP traps sent.
	SNMPSentTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "snmp_notifier_trap_sent_total",
			Help: "Traps sent, by SNMP destination.",
		},
		[]string{},
	)
	// SNMPErrorTotal counts the number of SNMP traps in error.
	SNMPErrorTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "snmp_notifier_trap_error_total",
			Help: "Traps send errors, by SNMP destination.",
		},
		[]string{},
	)
)

// Init starts Prometheus metric counters collection
func Init() {
	prometheus.Register(RequestTotal)
	prometheus.Register(SNMPSentTotal)
	prometheus.Register(SNMPErrorTotal)
}
