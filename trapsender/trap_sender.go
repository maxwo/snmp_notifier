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

package trapsender

import (
	"errors"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/maxwo/snmp_notifier/commons"
	"github.com/maxwo/snmp_notifier/telemetry"
	"github.com/maxwo/snmp_notifier/types"

	"text/template"

	"github.com/k-sone/snmpgo"
	"github.com/shirou/gopsutil/host"
)

// TrapSender sends traps according to given alerts
type TrapSender struct {
	logger                  *slog.Logger
	configuration           Configuration
	snmpConnectionArguments []snmpgo.SNMPArguments
}

// Configuration describes the configuration for sending traps
type Configuration struct {
	SNMPDestination []string
	SNMPRetries     uint
	SNMPVersion     string
	SNMPTimeout     time.Duration

	SNMPCommunity string

	SNMPAuthenticationEnabled  bool
	SNMPAuthenticationProtocol string
	SNMPAuthenticationUsername string
	SNMPAuthenticationPassword string
	SNMPPrivateEnabled         bool
	SNMPPrivateProtocol        string
	SNMPPrivatePassword        string
	SNMPSecurityEngineID       string
	SNMPContextEngineID        string
	SNMPContextName            string
	SNMPSubObjectDefaultOid    string

	DescriptionTemplate template.Template
	ExtraFields         []ExtraField
}

// ExtraField describes a custom field sent via SNMP
type ExtraField struct {
	SubOid          int
	ContentTemplate template.Template
}

// New creates a new TrapSender
func New(configuration Configuration, logger *slog.Logger) TrapSender {
	snmpConnectionArguments := generationConnectionArguments(configuration)
	return TrapSender{logger, configuration, snmpConnectionArguments}
}

// SendAlertTraps sends a bucket of alerts to the given SNMP connection
func (trapSender TrapSender) SendAlertTraps(alertBucket types.AlertBucket) error {
	traps, err := trapSender.generateTraps(alertBucket)
	if err != nil {
		for _, connection := range trapSender.snmpConnectionArguments {
			telemetry.SNMPTrapTotal.WithLabelValues(connection.Address, "failure").Add(float64(len(traps)))
		}
		return err
	}

	hasError := false

	for _, connection := range trapSender.snmpConnectionArguments {
		if trapSender.sendTraps(connection, traps) != nil {
			hasError = true
		}
	}

	if hasError {
		return errors.New("error while sending one or more traps")
	}
	return nil
}

func (trapSender TrapSender) sendTraps(connectionArguments snmpgo.SNMPArguments, traps []snmpgo.VarBinds) error {
	distinationForMetrics := connectionArguments.Address

	snmp, err := snmpgo.NewSNMP(connectionArguments)
	if err != nil {
		trapSender.logger.Error("error while creating SNMP connection", "err", err.Error())
		telemetry.SNMPTrapTotal.WithLabelValues(distinationForMetrics, "failure").Add(float64(len(traps)))
		return err
	}

	err = snmp.Open()
	if err != nil {
		trapSender.logger.Error("error while opening SNMP connection", "err", err.Error())
		telemetry.SNMPTrapTotal.WithLabelValues(distinationForMetrics, "failure").Add(float64(len(traps)))
		return err
	}

	defer func() {
		snmp.Close()
	}()

	uptime, _ := host.Uptime()
	if uptime > math.MaxInt32 {
		uptime = 0
	}

	hasError := false
	for _, trap := range traps {
		err = snmp.V2TrapWithBootsTime(trap, 0, int(uptime))
		if err != nil {
			telemetry.SNMPTrapTotal.WithLabelValues(distinationForMetrics, "failure").Inc()
			trapSender.logger.Error("error while generating trap", "destination", distinationForMetrics, "err", err.Error())
			hasError = true
		}
		telemetry.SNMPTrapTotal.WithLabelValues(distinationForMetrics, "success").Inc()
	}

	if hasError {
		return errors.New("error while sending one or more traps")
	}
	return nil
}

func (trapSender TrapSender) generateTraps(alertBucket types.AlertBucket) ([]snmpgo.VarBinds, error) {
	var (
		traps []snmpgo.VarBinds
	)
	for _, alertGroup := range alertBucket.AlertGroups {
		varBinds, err := trapSender.generateVarBinds(*alertGroup)
		if err != nil {
			return nil, err
		}

		traps = append(traps, varBinds)
	}
	return traps, nil
}

func (trapSender TrapSender) generateVarBinds(alertGroup types.AlertGroup) (snmpgo.VarBinds, error) {
	var (
		varBinds snmpgo.VarBinds
	)

	trapUniqueID := strings.Join([]string{alertGroup.OID, "[", alertGroup.GroupID, "]"}, "")

	description, err := commons.FillTemplate(alertGroup, trapSender.configuration.DescriptionTemplate)
	if err != nil {
		return nil, err
	}

	baseOid := strings.Join([]string{alertGroup.OID, "2"}, ".")
	trapOid, _ := snmpgo.NewOid(strings.Join([]string{alertGroup.OID, "1"}, "."))
	if trapSender.configuration.SNMPSubObjectDefaultOid != "" {
		baseOid = trapSender.configuration.SNMPSubObjectDefaultOid
		trapOid, _ = snmpgo.NewOid(alertGroup.OID)
	}

	varBinds = addUpTime(varBinds)
	varBinds = append(varBinds, snmpgo.NewVarBind(snmpgo.OidSnmpTrap, trapOid))
	varBinds = addTrapSubObject(varBinds, baseOid, 1, trapUniqueID)
	varBinds = addTrapSubObject(varBinds, baseOid, 2, alertGroup.Severity)
	varBinds = addTrapSubObject(varBinds, baseOid, 3, *description)

	for _, extraField := range trapSender.configuration.ExtraFields {
		value, err := commons.FillTemplate(alertGroup, extraField.ContentTemplate)
		if err != nil {
			return nil, err
		}
		varBinds = addTrapSubObject(varBinds, baseOid, extraField.SubOid, *value)
	}

	return varBinds, nil
}

func addUpTime(varBinds snmpgo.VarBinds) snmpgo.VarBinds {
	uptime, _ := host.Uptime()
	return append(varBinds, snmpgo.NewVarBind(snmpgo.OidSysUpTime, snmpgo.NewTimeTicks(uint32(uptime*100))))
}

func addTrapSubObject(varBinds snmpgo.VarBinds, baseOid string, subOid int, value string) snmpgo.VarBinds {
	oidString := strings.Join([]string{baseOid, strconv.Itoa(subOid)}, ".")
	oid, _ := snmpgo.NewOid(oidString)
	return append(varBinds, snmpgo.NewVarBind(oid, snmpgo.NewOctetString([]byte(strings.TrimSpace(value)))))
}

func generationConnectionArguments(configuration Configuration) []snmpgo.SNMPArguments {
	snmpArguments := []snmpgo.SNMPArguments{}
	for _, destination := range configuration.SNMPDestination {
		snmpArgument := snmpgo.SNMPArguments{
			Address: destination,
			Retries: configuration.SNMPRetries,
			Timeout: configuration.SNMPTimeout,
		}

		if configuration.SNMPVersion == "V2c" {
			snmpArgument.Version = snmpgo.V2c
			snmpArgument.Community = configuration.SNMPCommunity
		}

		if configuration.SNMPVersion == "V3" {
			snmpArgument.Version = snmpgo.V3
			snmpArgument.UserName = configuration.SNMPAuthenticationUsername

			if configuration.SNMPAuthenticationEnabled && configuration.SNMPPrivateEnabled {
				snmpArgument.SecurityLevel = snmpgo.AuthPriv
			} else if configuration.SNMPAuthenticationEnabled {
				snmpArgument.SecurityLevel = snmpgo.AuthNoPriv
			} else {
				snmpArgument.SecurityLevel = snmpgo.NoAuthNoPriv
			}

			if configuration.SNMPPrivateEnabled {
				snmpArgument.PrivProtocol = snmpgo.PrivProtocol(configuration.SNMPPrivateProtocol)
				snmpArgument.PrivPassword = configuration.SNMPPrivatePassword
			}

			if configuration.SNMPAuthenticationEnabled {
				snmpArgument.AuthProtocol = snmpgo.AuthProtocol(configuration.SNMPAuthenticationProtocol)
				snmpArgument.AuthPassword = configuration.SNMPAuthenticationPassword
			}

			snmpArgument.SecurityEngineId = configuration.SNMPSecurityEngineID
			snmpArgument.ContextEngineId = configuration.SNMPContextEngineID
			snmpArgument.ContextName = configuration.SNMPContextName
		}

		snmpArguments = append(snmpArguments, snmpArgument)
	}

	return snmpArguments
}
