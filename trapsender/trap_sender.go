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
	configuration Configuration
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

	DescriptionTemplate template.Template
	ExtraFieldTemplates map[string]template.Template
}

// New creates a new TrapSender
func New(configuration Configuration) TrapSender {
	return TrapSender{configuration}
}

// SendAlertTraps sends a bucket of alerts to the given SNMP connection
func (trapSender TrapSender) SendAlertTraps(alertBucket types.AlertBucket) error {
	traps, err := trapSender.generateTraps(alertBucket)
	if err != nil {
		return err
	}
	connections, err := trapSender.connect()
	if err != nil {
		return err
	}
	defer func() {
		for _, connection := range connections {
			connection.Close()
		}
	}()

	for _, connection := range connections {
		for _, trap := range traps {
			err = connection.V2Trap(trap)
			if err != nil {
				telemetry.SNMPErrorTotal.WithLabelValues().Inc()
				return err
			}
			telemetry.SNMPSentTotal.WithLabelValues().Inc()
		}
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

	trapOid, _ := snmpgo.NewOid(strings.Join([]string{alertGroup.OID, "1"}, "."))
	varBinds = addUpTime(varBinds)
	varBinds = append(varBinds, snmpgo.NewVarBind(snmpgo.OidSnmpTrap, trapOid))
	varBinds = addTrapSubObject(varBinds, alertGroup.OID, "1", trapUniqueID)
	varBinds = addTrapSubObject(varBinds, alertGroup.OID, "2", alertGroup.Severity)
	varBinds = addTrapSubObject(varBinds, alertGroup.OID, "3", *description)
	for subOid, template := range trapSender.configuration.ExtraFieldTemplates {
		value, err := commons.FillTemplate(alertGroup, template)
		if err != nil {
			return nil, err
		}
		varBinds = addTrapSubObject(varBinds, alertGroup.OID, subOid, *value)
	}

	return varBinds, nil
}

func addUpTime(varBinds snmpgo.VarBinds) snmpgo.VarBinds {
	uptime, _ := host.Uptime()
	return append(varBinds, snmpgo.NewVarBind(snmpgo.OidSysUpTime, snmpgo.NewTimeTicks(uint32(uptime*100))))
}

func addTrapSubObject(varBinds snmpgo.VarBinds, alertOid string, subOid string, value string) snmpgo.VarBinds {
	oidString := strings.Join([]string{alertOid, "2", subOid}, ".")
	oid, _ := snmpgo.NewOid(oidString)
	return append(varBinds, snmpgo.NewVarBind(oid, snmpgo.NewOctetString([]byte(strings.TrimSpace(value)))))
}

func (trapSender TrapSender) connect() ([]*snmpgo.SNMP, error) {
	snmpArguments := []snmpgo.SNMPArguments{}
	for _, destination := range trapSender.configuration.SNMPDestination {
		snmpArgument := snmpgo.SNMPArguments{
			Address: destination,
			Retries: trapSender.configuration.SNMPRetries,
			Timeout: trapSender.configuration.SNMPTimeout,
		}

		if trapSender.configuration.SNMPVersion == "V2c" {
			snmpArgument.Version = snmpgo.V2c
			snmpArgument.Community = trapSender.configuration.SNMPCommunity
		}

		if trapSender.configuration.SNMPVersion == "V3" {
			snmpArgument.Version = snmpgo.V3
			snmpArgument.UserName = trapSender.configuration.SNMPAuthenticationUsername

			if trapSender.configuration.SNMPAuthenticationEnabled && trapSender.configuration.SNMPPrivateEnabled {
				snmpArgument.SecurityLevel = snmpgo.AuthPriv
			} else if trapSender.configuration.SNMPAuthenticationEnabled {
				snmpArgument.SecurityLevel = snmpgo.AuthNoPriv
			} else {
				snmpArgument.SecurityLevel = snmpgo.NoAuthNoPriv
			}

			if trapSender.configuration.SNMPPrivateEnabled {
				snmpArgument.PrivProtocol = snmpgo.PrivProtocol(trapSender.configuration.SNMPPrivateProtocol)
				snmpArgument.PrivPassword = trapSender.configuration.SNMPPrivatePassword
			}

			if trapSender.configuration.SNMPAuthenticationEnabled {
				snmpArgument.AuthProtocol = snmpgo.AuthProtocol(trapSender.configuration.SNMPAuthenticationProtocol)
				snmpArgument.AuthPassword = trapSender.configuration.SNMPAuthenticationPassword
			}

			snmpArgument.SecurityEngineId = trapSender.configuration.SNMPSecurityEngineID
			snmpArgument.ContextEngineId = trapSender.configuration.SNMPContextEngineID
			snmpArgument.ContextName = trapSender.configuration.SNMPContextName
		}

		snmpArguments = append(snmpArguments, snmpArgument)
	}

	snmps := []*snmpgo.SNMP{}
	for _, snmpArgument := range snmpArguments {
		snmp, err := snmpgo.NewSNMP(snmpArgument)
		if err != nil {
			return nil, err
		}

		err = snmp.Open()
		if err != nil {
			return nil, err
		}

		snmps = append(snmps, snmp)
	}

	return snmps, nil
}
