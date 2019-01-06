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
	"net/http"
	"os"
	"strconv"

	"github.com/maxwo/snmp_notifier/alertparser"
	"github.com/maxwo/snmp_notifier/telemetry"
	"github.com/maxwo/snmp_notifier/trapsender"
	"github.com/maxwo/snmp_notifier/types"

	"github.com/gorilla/handlers"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
)

// HTTPServer listens for alerts on /alerts endpoint, and sends them as SNMP traps.
type HTTPServer struct {
	configuration Configuration
	alertParser   alertparser.AlertParser
	trapSender    trapsender.TrapSender
}

// Configuration describes the configuration for serving HTTP requests
type Configuration struct {
	WebListenAddress string
}

// New creates an HTTPServer instance
func New(configuration Configuration, alertParser alertparser.AlertParser, trapSender trapsender.TrapSender) *HTTPServer {
	return &HTTPServer{configuration, alertParser, trapSender}
}

// Configure creates and configures the HTTP server
func (httpServer HTTPServer) Configure() *http.Server {
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    httpServer.configuration.WebListenAddress,
		Handler: handlers.LoggingHandler(os.Stdout, mux),
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
		log.Debugf("Handling /alerts webhook request")
		defer req.Body.Close()

		data := types.AlertsData{}
		err := json.NewDecoder(req.Body).Decode(&data)
		if err != nil {
			errorHandler(w, http.StatusUnprocessableEntity, err, &data)
			return
		}

		alertBucket, err := httpServer.alertParser.Parse(data)
		if err != nil {
			errorHandler(w, http.StatusBadRequest, err, &data)
			return
		}

		err = httpServer.trapSender.SendAlertTraps(*alertBucket)
		if err != nil {
			errorHandler(w, http.StatusBadGateway, err, &data)
			return
		}

		telemetry.RequestTotal.WithLabelValues("200").Inc()
	})

	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", healthHandler)

	log.Infoln("Preparing to listen on: ", httpServer.configuration.WebListenAddress)
	return server
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "Health: OK\n")
}

func errorHandler(w http.ResponseWriter, status int, err error, data *types.AlertsData) {
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

	log.Errorf("%d %s: err=%s data=%+v", status, http.StatusText(status), err, data)
	telemetry.RequestTotal.WithLabelValues(strconv.FormatInt(int64(status), 10)).Inc()
}
