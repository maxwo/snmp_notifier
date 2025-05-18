# Copyright 2018 Maxime Wojtczak
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

default: precheck style unused build test

include Makefile.common

STATICCHECK_IGNORE =

DOCKER_IMAGE_NAME  := snmp-notifier

ifdef DEBUG
	bindata_flags = -debug
endif

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
mkfile_dir := $(dir $(mkfile_path))

install-docker:
	apt-get update
	apt-get install --yes ca-certificates curl gnupg
	mkdir -p /etc/apt/keyrings
	curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
	echo "deb [arch=$(shell dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian buster stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
	apt-get update
	apt-get install --yes docker-ce-cli

listen:
	snmptrapd -m ALL -m +SNMP-NOTIFIER-MIB -M +$(mkfile_dir)/mibs/ -f -Of -Lo -c scripts/local/snmptrapd.conf

install-github-release:
	apt-get update
	apt-get install --yes bzip2
	mkdir -v -p ${HOME}/bin
	curl -L 'https://github.com/github-release/github-release/releases/download/v0.7.2/linux-amd64-github-release.tar.bz2' | tar xvjf - --strip-components 3 -C ${HOME}/bin

k8s-install: k8s-snmp-server-install k8s-snmp-notifier-install

k8s-helm-update:
	helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
	helm repo update

k8s-prometheus-install: k8s-helm-update
	helm install prometheus prometheus-community/kube-prometheus-stack

k8s-snmp-server-install:
	kubectl create configmap snmp-notifier-mib --from-file=mibs/SNMP-NOTIFIER-MIB.my
	kubectl apply -f scripts/kubernetes/snmp-server.yaml

k8s-snmp-notifier-install: k8s-prometheus-install
	kubectl apply -f scripts/kubernetes/secrets.yaml
	helm install snmp-notifier prometheus-community/alertmanager-snmp-notifier --values scripts/kubernetes/chart-values.yaml
	kubectl apply -f scripts/kubernetes/alertmanager-webhook-configuration.yaml

k8s-cleanup:
	kubectl delete -f scripts/kubernetes/alertmanager-webhook-configuration.yaml
	helm uninstall snmp-notifier || true
	kubectl delete -f scripts/kubernetes/secrets.yaml || true
	helm uninstall prometheus || true
	kubectl delete -f scripts/kubernetes/snmp-server.yaml || true
	kubectl delete configmap snmp-notifier-mib || true
