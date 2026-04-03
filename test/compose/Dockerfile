FROM alpine

RUN apk add --update net-snmp

COPY snmpd.conf /etc/snmp

EXPOSE 161/UDP

CMD ["snmpd", "-f", "-c /etc/snnmp/snmpd.conf"]