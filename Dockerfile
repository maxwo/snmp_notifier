ARG ARCH="amd64"
ARG OS="linux"

FROM debian AS builder

ARG ARCH="amd64"
ARG OS="linux"

RUN mkdir -p /rootdir/etc/snmp_notifier
COPY .build/${OS}-${ARCH}/snmp_notifier /rootdir/bin/snmp_notifier
COPY description-template.tpl  /rootdir/etc/snmp_notifier/description-template.tpl
COPY LICENSE NOTICE /rootdir/

FROM quay.io/prometheus/busybox-${OS}-${ARCH}:latest
LABEL maintainer="Maxime Wojtczak <maxime.pub@icloud.com>"

COPY --from=builder rootdir /

EXPOSE      9464
ENTRYPOINT  [ "/bin/snmp_notifier" ]
CMD ["--snmp.trap-description-template=/etc/snmp_notifier/description-template.tpl"]
