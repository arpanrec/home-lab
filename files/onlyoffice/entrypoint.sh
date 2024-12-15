#!/bin/sh
sudo update-ca-certificates

sudo apt update && sudo apt install -y jq

JSON_BIN=/var/www/${COMPANY_NAME}/documentserver/npm/json
${JSON_BIN} -f /etc/onlyoffice/documentserver/default.json -I \
    -e 'this.services.CoAuthoring.requestDefaults.agentOptions={}'
ca_content=$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' /usr/local/share/ca-certificates/ownca.crt)
${JSON_BIN} -f /etc/onlyoffice/documentserver/default.json -I \
    -e 'this.services.CoAuthoring.requestDefaults.agentOptions.ca="'"${ca_content}"'"'

db_cert_content=$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' /db-cert.pem)
db_privkey_content=$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' /db-privkey.pem)
db_ca_content=$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' /db-chain.pem)

${JSON_BIN} -f /etc/onlyoffice/documentserver/default.json -I \
    -e 'this.services.CoAuthoring.sql.pgPoolExtraOptions.ssl={}'

${JSON_BIN} -f /etc/onlyoffice/documentserver/default.json -I \
    -e 'this.services.CoAuthoring.sql.pgPoolExtraOptions.ssl.rejectUnauthorized=false'

${JSON_BIN} -f /etc/onlyoffice/documentserver/default.json -I \
    -e 'this.services.CoAuthoring.sql.pgPoolExtraOptions.ssl.cert="'"${db_cert_content}"'"'

${JSON_BIN} -f /etc/onlyoffice/documentserver/default.json -I \
    -e 'this.services.CoAuthoring.sql.pgPoolExtraOptions.ssl.key="'"${db_privkey_content}"'"'

${JSON_BIN} -f /etc/onlyoffice/documentserver/default.json -I \
    -e 'this.services.CoAuthoring.sql.pgPoolExtraOptions.ssl.ca="'"${db_ca_content}"'"'

${JSON_BIN} -f /etc/onlyoffice/documentserver/default.json -I \
    -e 'this.services.CoAuthoring.sql.type="'"${DB_TYPE}"'"'

${JSON_BIN} -f /etc/onlyoffice/documentserver/default.json -I \
    -e 'this.services.CoAuthoring.sql.dbHost="'"${DB_HOST}"'"'

${JSON_BIN} -f /etc/onlyoffice/documentserver/default.json -I \
    -e 'this.services.CoAuthoring.sql.dbPort="'"${DB_PORT}"'"'

${JSON_BIN} -f /etc/onlyoffice/documentserver/default.json -I \
    -e 'this.services.CoAuthoring.sql.dbName="'"${DB_NAME}"'"'

${JSON_BIN} -f /etc/onlyoffice/documentserver/default.json -I \
    -e 'this.services.CoAuthoring.sql.dbUser="'"${DB_USER}"'"'

${JSON_BIN} -f /etc/onlyoffice/documentserver/default.json -I \
    -e 'this.services.CoAuthoring.sql.dbPass="'"${DB_PASS}"'"'
# sed -i '/^ALLOW_CONFIG_MUTATIONS/d' /etc/supervisor/conf.d/ds-converter.conf
# sed -i '/^ALLOW_CONFIG_MUTATIONS/d' /etc/supervisor/conf.d/ds-docservice.conf

# echo "ALLOW_CONFIG_MUTATIONS=true" >>/etc/supervisor/conf.d/ds-converter.conf
# echo "ALLOW_CONFIG_MUTATIONS=true" >>/etc/supervisor/conf.d/ds-docservice.conf

# environment=NODE_ENV=production-linux,NODE_CONFIG_DIR=/etc/onlyoffice/documentserver,NODE_DISABLE_COLORS=1,APPLICATION_NAME=onlyoffice
# environment=NODE_ENV=production-linux,NODE_CONFIG_DIR=/etc/onlyoffice/documentserver,NODE_DISABLE_COLORS=1,APPLICATION_NAME=onlyoffice,ALLOW_CONFIG_MUTATIONS=true

current_env=$(grep -oP 'environment=\K.*' /etc/supervisor/conf.d/ds-docservice.conf)
new_env="${current_env},ALLOW_CONFIG_MUTATIONS=true"
sed -i "s|environment=${current_env}|environment=${new_env}|" /etc/supervisor/conf.d/ds-docservice.conf

current_env=$(grep -oP 'environment=\K.*' /etc/supervisor/conf.d/ds-converter.conf)
new_env="${current_env},ALLOW_CONFIG_MUTATIONS=true"
sed -i "s|environment=${current_env}|environment=${new_env}|" /etc/supervisor/conf.d/ds-converter.conf

/app/ds/run-document-server.sh
