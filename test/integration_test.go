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

package test

import (
	"fmt"
	"testing"

	sigar "github.com/cloudfoundry/gosigar"
	"github.com/k-sone/snmpgo"
)

func TestReadV2Traps(t *testing.T) {

	server, channel, err := LaunchTrapReceiver("127.0.0.1:1162")
	if err != nil {
		t.Fatal("Error while opening server", err)
	}
	defer server.Close()

	sendTrapV2(t, 1162, "first trap")
	sendTrapV3(t, 1162, "second trap")

	traps := ReadTraps(channel)

	if !FindTrap(traps, map[string]string{"1.1.1.3": "first trap"}) {
		t.Error("Cannot find first trap")
	}
	if !FindTrap(traps, map[string]string{"1.1.1.3": "second trap"}) {
		t.Error("Cannot find second trap")
	}
}

func TestFindTrap(t *testing.T) {

	server, channel, err := LaunchTrapReceiver("127.0.0.1:1162")
	if err != nil {
		t.Fatal("Error while opening server", err)
	}
	defer server.Close()

	sendTrapV2(t, 1162, "first trap")
	sendTrapV2(t, 1162, "second trap")

	traps := ReadTraps(channel)

	if !FindTrap(traps, map[string]string{"1.1.1.3": "first trap", "1.1.1.4": "this is a constant"}) {
		t.Error("Findable trap found")
	}
	if FindTrap(traps, map[string]string{"1.1.1.3": "third non-existing trap", "1.1.1.4": "this is a constant"}) {
		t.Error("Unfindable trap found")
	}
}

func sendTrapV2(t *testing.T, port int32, text string) {
	var (
		varBinds snmpgo.VarBinds
	)

	uptime := sigar.Uptime{}
	uptime.Get()
	trapOid, _ := snmpgo.NewOid("1.1.1")
	textOid, _ := snmpgo.NewOid("1.1.1.3")
	constantOid, _ := snmpgo.NewOid("1.1.1.4")
	varBinds = append(varBinds, snmpgo.NewVarBind(snmpgo.OidSysUpTime, snmpgo.NewTimeTicks(uint32(uptime.Length*100))))
	varBinds = append(varBinds, snmpgo.NewVarBind(snmpgo.OidSnmpTrap, trapOid))
	varBinds = append(varBinds, snmpgo.NewVarBind(textOid, snmpgo.NewOctetString([]byte(text))))
	varBinds = append(varBinds, snmpgo.NewVarBind(constantOid, snmpgo.NewOctetString([]byte("this is a constant"))))

	snmp, err := snmpgo.NewSNMP(snmpgo.SNMPArguments{
		Version:   snmpgo.V2c,
		Address:   fmt.Sprintf("127.0.0.1:%d", port),
		Retries:   1,
		Community: "public",
	})
	if err != nil {
		t.Fatal("Error while creating SNMP connection", err)
	}
	err = snmp.Open()
	if err != nil {
		t.Fatal("Error while opening SNMP connection", err)
	}
	defer snmp.Close()

	err = snmp.V2Trap(varBinds)
	if err != nil {
		t.Fatal("Error while sending trap", err)
	}
}

func sendTrapV3(t *testing.T, port int32, text string) {
	var (
		varBinds snmpgo.VarBinds
	)

	uptime := sigar.Uptime{}
	uptime.Get()
	trapOid, _ := snmpgo.NewOid("1.1.1")
	textOid, _ := snmpgo.NewOid("1.1.1.3")
	constantOid, _ := snmpgo.NewOid("1.1.1.4")
	varBinds = append(varBinds, snmpgo.NewVarBind(snmpgo.OidSysUpTime, snmpgo.NewTimeTicks(uint32(uptime.Length*100))))
	varBinds = append(varBinds, snmpgo.NewVarBind(snmpgo.OidSnmpTrap, trapOid))
	varBinds = append(varBinds, snmpgo.NewVarBind(textOid, snmpgo.NewOctetString([]byte(text))))
	varBinds = append(varBinds, snmpgo.NewVarBind(constantOid, snmpgo.NewOctetString([]byte("this is a constant"))))

	snmp, err := snmpgo.NewSNMP(snmpgo.SNMPArguments{
		Version:          snmpgo.V3,
		Address:          fmt.Sprintf("127.0.0.1:%d", port),
		Retries:          1,
		SecurityLevel:    snmpgo.AuthPriv,
		UserName:         "v3_username",
		AuthPassword:     "v3_password",
		AuthProtocol:     snmpgo.AuthProtocol("SHA"),
		PrivPassword:     "v3_private_secret",
		PrivProtocol:     snmpgo.PrivProtocol("AES"),
		SecurityEngineId: "8000000004736e6d70676f",
	})
	if err != nil {
		t.Fatal("Error while creating SNMP connection", err)
	}
	err = snmp.Open()
	if err != nil {
		t.Fatal("Error while opening SNMP connection", err)
	}
	defer snmp.Close()

	err = snmp.V2Trap(varBinds)
	if err != nil {
		t.Fatal("Error while sending trap", err)
	}
}
