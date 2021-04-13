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
	SNMPDestination string
	SNMPRetries     uint
	SNMPVersion     string

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
	connection, err := trapSender.connect()
	if err != nil {
		return err
	}
	defer connection.Close()
	for _, trap := range traps {
		err = connection.V2Trap(trap)
		if err != nil {
			telemetry.SNMPErrorTotal.WithLabelValues().Inc()
			return err
		}
		telemetry.SNMPSentTotal.WithLabelValues().Inc()
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

	trapOid, _ := snmpgo.NewOid(alertGroup.OID)
	varBinds = addUpTime(varBinds)
	varBinds = append(varBinds, snmpgo.NewVarBind(snmpgo.OidSnmpTrap, trapOid))
	varBinds = addStringSubOid(varBinds, alertGroup.OID, "1", trapUniqueID)
	varBinds = addStringSubOid(varBinds, alertGroup.OID, "2", alertGroup.Severity)
	varBinds = addStringSubOid(varBinds, alertGroup.OID, "3", *description)
	for subOid, template := range trapSender.configuration.ExtraFieldTemplates {
		value, err := commons.FillTemplate(alertGroup, template)
		if err != nil {
			return nil, err
		}
		varBinds = addStringSubOid(varBinds, alertGroup.OID, subOid, *value)
	}

	return varBinds, nil
}

func addUpTime(varBinds snmpgo.VarBinds) snmpgo.VarBinds {
	uptime, _ := host.Uptime()
	return append(varBinds, snmpgo.NewVarBind(snmpgo.OidSysUpTime, snmpgo.NewTimeTicks(uint32(uptime*100))))
}

func addStringSubOid(varBinds snmpgo.VarBinds, alertOid string, subOid string, value string) snmpgo.VarBinds {
	oidString := strings.Join([]string{alertOid, subOid}, ".")
	oid, _ := snmpgo.NewOid(oidString)
	return append(varBinds, snmpgo.NewVarBind(oid, snmpgo.NewOctetString([]byte(strings.TrimSpace(value)))))
}

func (trapSender TrapSender) connect() (*snmpgo.SNMP, error) {
	snmpArguments := snmpgo.SNMPArguments{
		Address: trapSender.configuration.SNMPDestination,
		Retries: trapSender.configuration.SNMPRetries,
	}

	if trapSender.configuration.SNMPVersion == "V2c" {
		snmpArguments.Version = snmpgo.V2c
		snmpArguments.Community = trapSender.configuration.SNMPCommunity
	}

	if trapSender.configuration.SNMPVersion == "V3" {
		snmpArguments.Version = snmpgo.V3
		snmpArguments.UserName = trapSender.configuration.SNMPAuthenticationUsername

		if trapSender.configuration.SNMPAuthenticationEnabled && trapSender.configuration.SNMPPrivateEnabled {
			snmpArguments.SecurityLevel = snmpgo.AuthPriv
		} else if trapSender.configuration.SNMPAuthenticationEnabled {
			snmpArguments.SecurityLevel = snmpgo.AuthNoPriv
		} else {
			snmpArguments.SecurityLevel = snmpgo.NoAuthNoPriv
		}

		if trapSender.configuration.SNMPPrivateEnabled {
			snmpArguments.PrivProtocol = snmpgo.PrivProtocol(trapSender.configuration.SNMPPrivateProtocol)
			snmpArguments.PrivPassword = trapSender.configuration.SNMPPrivatePassword
		}

		if trapSender.configuration.SNMPAuthenticationEnabled {
			snmpArguments.AuthProtocol = snmpgo.AuthProtocol(trapSender.configuration.SNMPAuthenticationProtocol)
			snmpArguments.AuthPassword = trapSender.configuration.SNMPAuthenticationPassword
		}

		snmpArguments.SecurityEngineId = trapSender.configuration.SNMPSecurityEngineID
		snmpArguments.ContextEngineId = trapSender.configuration.SNMPContextEngineID
		snmpArguments.ContextName = trapSender.configuration.SNMPContextName
	}

	snmp, err := snmpgo.NewSNMP(snmpArguments)
	if err != nil {
		return nil, err
	}
	err = snmp.Open()
	if err != nil {
		return nil, err
	}
	return snmp, nil
}
