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

	"text/template"

	"github.com/k-sone/snmpgo"
	"github.com/prometheus/common/log"
	"github.com/shirou/gopsutil/host"
)

// TrapSender sends traps according to given alerts
type TrapSender struct {
	snmpConnection  snmpgo.SNMP
	contentTemplate template.Template
}

// New creates a new TrapSender
func New(snmpConnection snmpgo.SNMP, contentTemplate template.Template) TrapSender {
	return TrapSender{snmpConnection, contentTemplate}
}

// SendAlertTraps sends a bucket of alerts to the given SNMP connection
func (trapSender TrapSender) SendAlertTraps(alertBucket commons.AlertBucket) error {
	traps, err := trapSender.generateTraps(alertBucket)
	if err != nil {
		return err
	}
	for _, trap := range traps {
		err = trapSender.snmpConnection.V2Trap(trap)
		if err != nil {
			telemetry.SNMPErrorTotal.WithLabelValues().Inc()
			return err
		}
		telemetry.SNMPSentTotal.WithLabelValues().Inc()
	}
	return nil
}

func (trapSender TrapSender) generateTraps(alertBucket commons.AlertBucket) ([]snmpgo.VarBinds, error) {
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

func (trapSender TrapSender) generateVarBinds(alertGroup commons.AlertGroup) (snmpgo.VarBinds, error) {
	var (
		varBinds snmpgo.VarBinds
	)

	trapUniqueID := strings.Join([]string{alertGroup.OID, "[", alertGroup.GroupID, "]"}, "")

	descriptions, err := commons.FillTemplate(alertGroup, trapSender.contentTemplate)
	if err != nil {
		return nil, err
	}

	trapOid, _ := snmpgo.NewOid(alertGroup.OID)
	varBinds = addUpTime(varBinds)
	varBinds = append(varBinds, snmpgo.NewVarBind(snmpgo.OidSnmpTrap, trapOid))
	varBinds = addStringSubOid(varBinds, alertGroup.OID, "1", trapUniqueID)
	varBinds = addStringSubOid(varBinds, alertGroup.OID, "2", alertGroup.Severity)
	varBinds = addStringSubOid(varBinds, alertGroup.OID, "3", *descriptions)

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

// Connect initiates a connection to a SNMP destination sever
func Connect(snmpDestination string, snmpRetries uint, snmpCommunity string) (*snmpgo.SNMP, error) {
	snmp, err := snmpgo.NewSNMP(snmpgo.SNMPArguments{
		Version:   snmpgo.V2c,
		Address:   snmpDestination,
		Retries:   snmpRetries,
		Community: snmpCommunity,
	})
	if err != nil {
		log.Error(err)
		return nil, err
	}
	err = snmp.Open()
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return snmp, nil
}
