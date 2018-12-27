FROM        quay.io/prometheus/busybox:latest
LABEL       maintainer="Maxime Wojtczak <maxime.wojtczak@zenika.com>"

COPY snmp_notifier  /bin/snmp_notifier

EXPOSE      9464
ENTRYPOINT  [ "/bin/snmp_notifier" ]
