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
	"log"
	"time"

	"github.com/k-sone/snmpgo"
)

type testTrapListener struct {
	traps chan *snmpgo.TrapRequest
}

func (trapListener *testTrapListener) OnTRAP(trap *snmpgo.TrapRequest) {
	log.Print("trap received in listener: ", trap)
	trapListener.traps <- trap
}

// LaunchTrapReceiver provides a SNMP server for testing purposes
func LaunchTrapReceiver(port int32) (*snmpgo.TrapServer, chan *snmpgo.TrapRequest, error) {
	trapServer, err := snmpgo.NewTrapServer(snmpgo.ServerArguments{
		LocalAddr: fmt.Sprintf("127.0.0.1:%d", port),
	})
	if err != nil {
		return nil, nil, err
	}
	err = trapServer.AddSecurity(&snmpgo.SecurityEntry{
		Version:   snmpgo.V2c,
		Community: "public",
	})
	if err != nil {
		return nil, nil, err
	}
	traps := make(chan *snmpgo.TrapRequest)
	go launchSNMPServer(trapServer, traps)
	time.Sleep(200 * time.Millisecond)
	return trapServer, traps, nil
}

func launchSNMPServer(trapServer *snmpgo.TrapServer, traps chan *snmpgo.TrapRequest) {
	log.Print("Serving SNMP server...")
	err := trapServer.Serve(&testTrapListener{traps})
	if err != nil {
		log.Fatal(err)
	}
}

// ReadTraps reads all available traps sent to server
func ReadTraps(trapChannel chan *snmpgo.TrapRequest) []snmpgo.TrapRequest {
	var (
		trapsReceived []snmpgo.TrapRequest
		end           bool
	)
	for !end {
		select {
		case trap := <-trapChannel:
			trapsReceived = append(trapsReceived, *trap)
		case <-time.After(200 * time.Millisecond):
			end = true
		}
	}
	return trapsReceived
}

// FindTrap search a trap matching the given variables
func FindTrap(trapsReceived []snmpgo.TrapRequest, variables map[string]string) bool {
	var (
		found bool
	)
	for _, trap := range trapsReceived {
		doCurrentMatch := true
		for oid, value := range variables {
			oidPrefix, _ := snmpgo.NewOid(oid)
			varBind := trap.Pdu.VarBinds().MatchOid(oidPrefix)
			if varBind == nil || varBind.Variable.String() != value {
				doCurrentMatch = false
			}
		}
		found = found || doCurrentMatch
	}
	return found
}
