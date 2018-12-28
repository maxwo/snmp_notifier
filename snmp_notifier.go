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

package main

import (
	"os"

	"github.com/maxwo/snmp_notifier/alertparser"
	"github.com/maxwo/snmp_notifier/configuration"
	"github.com/maxwo/snmp_notifier/httpserver"
	"github.com/maxwo/snmp_notifier/telemetry"
	"github.com/maxwo/snmp_notifier/trapsender"

	"github.com/prometheus/common/log"
)

func main() {
	configuration, err := configuration.ParseConfiguration(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	snmpNotifier, err := createSNMPNotifier(*configuration)
	if err != nil {
		log.Fatal(err)
	}
	telemetry.Init()
	err = snmpNotifier.Configure().ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

func createSNMPNotifier(snmpNotifierConfiguration configuration.SNMPNotifierConfiguration) (*httpserver.HTTPServer, error) {
	trapSender := trapsender.New(snmpNotifierConfiguration.TrapSenderConfiguration)
	alertParser := alertparser.New(snmpNotifierConfiguration.AlertParserConfiguration)
	return httpserver.New(snmpNotifierConfiguration.HTTPServerConfiguration, alertParser, trapSender), nil
}
