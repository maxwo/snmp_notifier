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

package httpserver

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/prometheus/exporter-toolkit/web"

	"github.com/maxwo/snmp_notifier/alertparser"
	"github.com/maxwo/snmp_notifier/telemetry"
	"github.com/maxwo/snmp_notifier/trapsender"
	"github.com/maxwo/snmp_notifier/types"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/prometheus/common/version"
)

// HTTPServer listens for alerts on /alerts endpoint, and sends them as SNMP traps.
type HTTPServer struct {
	configuration Configuration
	alertParser   alertparser.AlertParser
	trapSender    trapsender.TrapSender
	logger        *slog.Logger
	server        *http.Server
}

// Configuration describes the configuration for serving HTTP requests
type Configuration struct {
	ToolKitConfiguration web.FlagConfig
}

// New creates an HTTPServer instance
func New(configuration Configuration, alertParser alertparser.AlertParser, trapSender trapsender.TrapSender, logger *slog.Logger) *HTTPServer {
	return &HTTPServer{configuration, alertParser, trapSender, logger, nil}
}

// Configure creates and configures the HTTP server
func (httpServer HTTPServer) Start() error {
	mux := http.NewServeMux()
	server := &http.Server{
		Handler: mux,
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
         <head><title>SNMP Notifier</title></head>
         <body>
         <h1>SNMP Notifier</h1>
         <p><a href='/metrics'>SNMP Notifier metrics</a></p>
         <p><a href='/alerts'>SNMP alerts endpoint</a></p>
         <p><a href='/health'>health endpoint</a></p>
         <h2>Build</h2>
         <pre>` + version.Info() + ` ` + version.BuildContext() + `</pre>
         </body>
         </html>`))
	})

	mux.HandleFunc("/alerts", func(w http.ResponseWriter, req *http.Request) {
		httpServer.logger.Info("Handling /alerts webhook request")

		defer req.Body.Close()

		data := types.AlertsData{}
		err := json.NewDecoder(req.Body).Decode(&data)
		if err != nil {
			httpServer.errorHandler(w, http.StatusUnprocessableEntity, err, &data)
			return
		}

		alertBucket, err := httpServer.alertParser.Parse(data)
		if err != nil {
			httpServer.errorHandler(w, http.StatusBadRequest, err, &data)
			return
		}

		err = httpServer.trapSender.SendAlertTraps(*alertBucket)
		if err != nil {
			httpServer.errorHandler(w, http.StatusBadGateway, err, &data)
			return
		}

		telemetry.RequestTotal.WithLabelValues("200").Inc()
	})

	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", healthHandler)

	if err := web.ListenAndServe(server, &httpServer.configuration.ToolKitConfiguration, httpServer.logger); err != nil {
		httpServer.logger.Error("Unable to listen", "err", err.Error())
		return err
	}

	httpServer.server = server

	return nil
}

func (httpServer HTTPServer) Stop() error {
	if httpServer.server != nil {
		httpServer.logger.Error("No server started")
		return httpServer.server.Close()
	}
	return nil
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "Health: OK\n")
}

func (httpServer HTTPServer) errorHandler(w http.ResponseWriter, status int, err error, data *types.AlertsData) {
	w.WriteHeader(status)

	response := struct {
		Error   bool
		Status  int
		Message string
	}{
		true,
		status,
		err.Error(),
	}
	// JSON response
	bytes, _ := json.Marshal(response)
	json := string(bytes[:])
	fmt.Fprint(w, json)

	httpServer.logger.Error("error while handling request", "status", status, "statustext", http.StatusText(status), "err", err, "data", data)
	telemetry.RequestTotal.WithLabelValues(strconv.FormatInt(int64(status), 10)).Inc()
}
