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
	"fmt"
	"os"

	"github.com/go-kit/log/level"
	"github.com/prometheus/exporter-toolkit/web"

	"github.com/maxwo/snmp_notifier/alertparser"
	"github.com/maxwo/snmp_notifier/configuration"
	"github.com/maxwo/snmp_notifier/httpserver"
	"github.com/maxwo/snmp_notifier/telemetry"
	"github.com/maxwo/snmp_notifier/trapsender"
)

func main() {
	configuration, logger, err := configuration.ParseConfiguration(os.Args[1:])
	if logger == nil {
		fmt.Fprintln(os.Stderr, "logger is nil")
		os.Exit(1)
	}
	if err != nil {
		level.Error(logger).Log("msg", "unable to parse configuration", "err", err)
		os.Exit(1)
	}

	trapSender := trapsender.New(configuration.TrapSenderConfiguration)
	alertParser := alertparser.New(configuration.AlertParserConfiguration)
	httpServer := httpserver.New(configuration.HTTPServerConfiguration, alertParser, trapSender, logger)

	telemetry.Init()

	if err := web.ListenAndServe(httpServer.Configure(), &configuration.HTTPServerConfiguration.ToolKitConfiguration, logger); err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}
}
