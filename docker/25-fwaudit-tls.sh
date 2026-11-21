#!/bin/sh
# Gera, uma vez, os certificados HTTPS do painel (executado pelo entrypoint do nginx).
#
#   - Uma CA local ("FW Audit Local CA", 10 anos) e um certificado de servidor (825 dias) assinado por ela.
#   - Importe ca.crt uma única vez nos navegadores/computadores que acessam o painel: as renovações do
#     certificado do servidor continuam confiáveis, pois são assinadas pela mesma CA.
#   - O certificado cobre localhost, o hostname do container, TLS_HOSTNAMES e TLS_IPS (separados por vírgula).
#     Se esses nomes mudarem, o certificado do servidor é refeito sozinho (a CA continua a mesma).
#   - Renova o certificado do servidor quando faltam menos de 30 dias para vencer.
#   - Certificado próprio: coloque server.crt e server.key no volume e este script não mexe neles
#     (só gerencia arquivos que ele mesmo criou, marcados com .fwaudit-generated).
set -eu

DIR="${TLS_DIR:-/etc/nginx/certs}"
LEAF_DAYS="${TLS_CERT_DAYS:-825}"
RENEW_BEFORE_DAYS=30
CA_RENEW_BEFORE_DAYS=90
MARK=".fwaudit-generated"

log() { echo "[tls] $*"; }

mkdir -p "$DIR"
cd "$DIR"

if [ -f server.crt ] && [ -f server.key ] && [ ! -f "$MARK" ]; then
  log "Usando o certificado fornecido em $DIR/server.crt (não será alterado)."
  exit 0
fi

# ---- nomes e IPs do certificado (somente caracteres seguros: vão para um arquivo de configuração)
HOST_NAME="$(hostname 2>/dev/null || true)"
DNS_NAMES=""
for n in localhost "$HOST_NAME" $(printf '%s' "${TLS_HOSTNAMES:-}" | tr ',;' '  '); do
  case "$n" in
    ''|*[!A-Za-z0-9._-]*) continue ;;
  esac
  case " $DNS_NAMES " in *" $n "*) continue ;; esac
  DNS_NAMES="$DNS_NAMES $n"
done
IP_ADDRS=""
for ip in 127.0.0.1 $(printf '%s' "${TLS_IPS:-}" | tr ',;' '  '); do
  case "$ip" in
    ''|*[!0-9A-Fa-f:.]*) continue ;;
  esac
  case " $IP_ADDRS " in *" $ip "*) continue ;; esac
  IP_ADDRS="$IP_ADDRS $ip"
done
SAN_SIGNATURE="DNS:$DNS_NAMES IP:$IP_ADDRS"

# ---- precisa gerar algo?
need_ca=false
need_leaf=false
if [ ! -f ca.crt ] || [ ! -f ca.key ]; then
  need_ca=true
elif ! openssl x509 -checkend $((CA_RENEW_BEFORE_DAYS * 86400)) -noout -in ca.crt >/dev/null 2>&1; then
  need_ca=true
fi
if $need_ca || [ ! -f server.crt ] || [ ! -f server.key ]; then
  need_leaf=true
elif ! openssl x509 -checkend $((RENEW_BEFORE_DAYS * 86400)) -noout -in server.crt >/dev/null 2>&1; then
  need_leaf=true
elif [ "$(cat san.txt 2>/dev/null || true)" != "$SAN_SIGNATURE" ]; then
  need_leaf=true
fi

if ! $need_ca && ! $need_leaf; then
  log "Certificados em dia ($(openssl x509 -in server.crt -noout -enddate | cut -d= -f2))."
  exit 0
fi

umask 077

if $need_ca; then
  log "Gerando a CA local do FW Audit (10 anos)."
  cat > ca.cnf <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = FW Audit Local CA
O = FW Audit
[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
  openssl ecparam -genkey -name prime256v1 -noout -out ca.key
  openssl req -x509 -new -key ca.key -sha256 -days 3650 -config ca.cnf -out ca.crt
  rm -f ca.cnf ca.srl
fi

log "Gerando o certificado do servidor (${LEAF_DAYS} dias) para:${DNS_NAMES} |${IP_ADDRS}"
FIRST_NAME="$(printf '%s' "$DNS_NAMES $IP_ADDRS" | awk '{print $1}')"
cat > server.cnf <<EOF
[req]
distinguished_name = dn
prompt = no
[dn]
CN = ${FIRST_NAME:-localhost}
O = FW Audit
EOF
{
  echo "basicConstraints = critical, CA:FALSE"
  echo "keyUsage = critical, digitalSignature"
  echo "extendedKeyUsage = serverAuth"
  echo "subjectKeyIdentifier = hash"
  echo "authorityKeyIdentifier = keyid,issuer"
  echo "subjectAltName = @alt"
  echo "[alt]"
  i=0
  for n in $DNS_NAMES; do i=$((i + 1)); echo "DNS.$i = $n"; done
  i=0
  for ip in $IP_ADDRS; do i=$((i + 1)); echo "IP.$i = $ip"; done
} > server.ext

openssl ecparam -genkey -name prime256v1 -noout -out server.key.new
openssl req -new -key server.key.new -config server.cnf -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt.new -days "$LEAF_DAYS" -sha256 -extfile server.ext >/dev/null 2>&1
mv server.key.new server.key
mv server.crt.new server.crt
rm -f server.csr server.cnf server.ext
printf '%s' "$SAN_SIGNATURE" > san.txt
chmod 600 ca.key server.key
chmod 644 ca.crt server.crt san.txt
touch "$MARK"

log "Certificado pronto. Importe ca.crt nos computadores que acessam o painel (baixe em /fwaudit-ca.crt)."
log "Impressão digital da CA: $(openssl x509 -in ca.crt -noout -fingerprint -sha256 | cut -d= -f2)"
