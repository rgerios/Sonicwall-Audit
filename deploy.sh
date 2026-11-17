#!/usr/bin/env bash
# Deploy do FW Audit em Ubuntu Server (Docker Compose).
#
# Uso, dentro da pasta do projeto:
#   ./deploy.sh            instala o que faltar, cria o .env e sobe os containers
#   ./deploy.sh --update   faz git pull antes de reconstruir e subir
#
# Pode ser executado quantas vezes for preciso: não recria o .env nem apaga dados.

set -euo pipefail

cd "$(dirname "$0")"

UPDATE=false
for arg in "$@"; do
  case "$arg" in
    --update) UPDATE=true ;;
    -h|--help)
      sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Opção desconhecida: $arg (use --help)" >&2
      exit 1
      ;;
  esac
done

info()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[aviso]\033[0m %s\n' "$*"; }
fail()  { printf '\033[1;31m[erro]\033[0m %s\n' "$*" >&2; exit 1; }

[ -f docker-compose.yml ] || fail "docker-compose.yml não encontrado. Execute o script dentro da pasta do projeto."

if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  command -v sudo >/dev/null 2>&1 || fail "Este script precisa de sudo (ou execute como root)."
  SUDO="sudo"
fi

# ---------------------------------------------------------------------------
# 1. Docker
# ---------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  info "Instalando o Docker Engine"
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    [ "${ID:-}" = "ubuntu" ] || warn "Sistema detectado: ${PRETTY_NAME:-desconhecido}. O script foi feito para Ubuntu."
  fi
  $SUDO apt-get update -y
  $SUDO apt-get install -y ca-certificates curl gnupg
  $SUDO install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | $SUDO gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
  $SUDO chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
  $SUDO apt-get update -y
  $SUDO apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  $SUDO systemctl enable --now docker
  if [ -n "$SUDO" ]; then
    $SUDO usermod -aG docker "$USER" || true
    warn "Usuário $USER adicionado ao grupo docker (vale a partir do próximo login)."
  fi
else
  info "Docker já instalado: $(docker --version)"
fi

# Usa sudo para o docker enquanto o usuário ainda não tem acesso ao socket
if docker info >/dev/null 2>&1; then
  DOCKER="docker"
else
  DOCKER="$SUDO docker"
  $DOCKER info >/dev/null 2>&1 || fail "O serviço do Docker não está respondendo (tente: sudo systemctl start docker)."
fi

$DOCKER compose version >/dev/null 2>&1 || fail "Plugin 'docker compose' ausente. Instale o pacote docker-compose-plugin."

# ---------------------------------------------------------------------------
# 2. Código
# ---------------------------------------------------------------------------
if $UPDATE; then
  info "Atualizando o código (git pull)"
  git pull --ff-only
fi

# ---------------------------------------------------------------------------
# 3. Arquivo .env
# ---------------------------------------------------------------------------
random_secret() {
  # Apenas letras e números: a senha do banco entra em uma URL de conexão
  LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1" || true
}

CREATED_ENV=false
if [ ! -f .env ]; then
  info "Criando o arquivo .env"
  ADMIN_USER_DEFAULT="admin"
  ADMIN_USER="$ADMIN_USER_DEFAULT"
  ADMIN_PASS=""

  if [ -t 0 ]; then
    read -r -p "Usuário administrador [${ADMIN_USER_DEFAULT}]: " input_user
    ADMIN_USER="${input_user:-$ADMIN_USER_DEFAULT}"
    while true; do
      read -r -s -p "Senha do administrador (mín. 10 caracteres, Enter para gerar uma): " input_pass
      echo
      if [ -z "$input_pass" ]; then
        break
      fi
      if [ "${#input_pass}" -lt 10 ]; then
        warn "A senha precisa ter pelo menos 10 caracteres."
        continue
      fi
      case "$input_pass" in
        *[\'\"\$\`\\\ ]*|*'#'*)
          warn "Evite aspas, espaço, \$, crase, barra invertida e # (o .env não os aceita sem escape)."
          continue
          ;;
      esac
      ADMIN_PASS="$input_pass"
      break
    done
  fi

  GENERATED_PASS=false
  if [ -z "$ADMIN_PASS" ]; then
    ADMIN_PASS="$(random_secret 20)"
    GENERATED_PASS=true
  fi

  TZ_VALUE="$(cat /etc/timezone 2>/dev/null || true)"
  [ -n "$TZ_VALUE" ] && [ "$TZ_VALUE" != "Etc/UTC" ] || TZ_VALUE="America/Sao_Paulo"

  umask 077
  cat > .env <<EOF
# Gerado por deploy.sh em $(date '+%Y-%m-%d %H:%M'). Não versione este arquivo.
POSTGRES_USER=fwaudit
POSTGRES_DB=fwaudit
POSTGRES_PASSWORD=$(random_secret 32)

# Usado apenas na primeira subida, para criar o administrador inicial.
FWAUDIT_ADMIN_USER=${ADMIN_USER}
FWAUDIT_ADMIN_PASS=${ADMIN_PASS}

TZ=${TZ_VALUE}
FRONTEND_PORT=8080
SONICWALL_UDP_PORT=5514
FORTIGATE_UDP_PORT=5515

# Chave opcional do Gemini para a aba "Análise com IA" (também configurável pela interface).
GEMINI_API_KEY=

# Janela recente em memória por firewall e teto opcional de linhas no banco (0 = sem teto).
SYSLOG_MEMORY_WINDOW=50000
SYSLOG_MAX_ROWS_PER_SITE=0
EOF
  chmod 600 .env
  CREATED_ENV=true
else
  info "Arquivo .env já existe: mantido como está"
fi

# Lê as portas efetivas do .env (sem executar o arquivo)
env_value() {
  local value
  value="$(grep -E "^$1=" .env 2>/dev/null | tail -n 1 | cut -d= -f2- | tr -d '"' || true)"
  printf '%s' "${value:-$2}"
}
FRONTEND_PORT="$(env_value FRONTEND_PORT 8080)"
SONICWALL_UDP_PORT="$(env_value SONICWALL_UDP_PORT 5514)"
FORTIGATE_UDP_PORT="$(env_value FORTIGATE_UDP_PORT 5515)"

# ---------------------------------------------------------------------------
# 4. Firewall do Ubuntu (somente se o UFW estiver ativo)
# ---------------------------------------------------------------------------
if command -v ufw >/dev/null 2>&1 && $SUDO ufw status 2>/dev/null | grep -q "Status: active"; then
  info "Liberando portas no UFW"
  $SUDO ufw allow "${FRONTEND_PORT}/tcp" comment "FW Audit Web UI" >/dev/null
  $SUDO ufw allow "${SONICWALL_UDP_PORT}/udp" comment "FW Audit SonicWall Syslog" >/dev/null
  $SUDO ufw allow "${FORTIGATE_UDP_PORT}/udp" comment "FW Audit FortiGate Syslog" >/dev/null
  echo "Portas liberadas: ${FRONTEND_PORT}/tcp, ${SONICWALL_UDP_PORT}/udp, ${FORTIGATE_UDP_PORT}/udp"
else
  info "UFW inativo ou ausente: nenhuma regra de firewall alterada"
fi

# ---------------------------------------------------------------------------
# 5. Build e subida
# ---------------------------------------------------------------------------
info "Construindo as imagens e subindo os containers (pode levar alguns minutos)"
$DOCKER compose up -d --build

info "Aguardando os serviços ficarem saudáveis"
SERVICES="db backend-sonicwall backend-fortigate frontend"
DEADLINE=$(( $(date +%s) + 240 ))
ALL_HEALTHY=false
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  ALL_HEALTHY=true
  for svc in $SERVICES; do
    cid="$($DOCKER compose ps -q "$svc" 2>/dev/null || true)"
    status="ausente"
    if [ -n "$cid" ]; then
      status="$($DOCKER inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || echo "desconhecido")"
    fi
    if [ "$status" != "healthy" ]; then
      ALL_HEALTHY=false
    fi
  done
  $ALL_HEALTHY && break
  sleep 5
done

$DOCKER compose ps

if ! $ALL_HEALTHY; then
  warn "Nem todos os serviços ficaram saudáveis em 4 minutos. Últimas linhas de log:"
  $DOCKER compose logs --tail 40 backend-sonicwall backend-fortigate frontend || true
  fail "Deploy incompleto. Corrija o problema acima e execute ./deploy.sh novamente."
fi

# ---------------------------------------------------------------------------
# 6. Resumo
# ---------------------------------------------------------------------------
SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
SERVER_IP="${SERVER_IP:-IP_DO_SERVIDOR}"

info "FW Audit no ar"
echo "  Painel:            http://${SERVER_IP}:${FRONTEND_PORT}"
echo "  Syslog SonicWall:  ${SERVER_IP} porta UDP ${SONICWALL_UDP_PORT}"
echo "  Syslog FortiGate:  ${SERVER_IP} porta UDP ${FORTIGATE_UDP_PORT}"
if $CREATED_ENV; then
  echo "  Usuário:           ${ADMIN_USER}"
  if $GENERATED_PASS; then
    echo "  Senha gerada:      ${ADMIN_PASS}"
    echo "  (anote agora; ela também está em .env, e pode ser trocada pelo painel)"
  else
    echo "  Senha:             a que você digitou"
  fi
fi
echo
echo "  Atualizar depois:  ./deploy.sh --update"
echo "  Ver logs:          ${DOCKER} compose logs -f"
echo "  Backup do banco:   ${DOCKER} exec -t fwaudit-db pg_dump -U fwaudit fwaudit > backup-\$(date +%F).sql"
echo
warn "O painel usa HTTP sem criptografia: mantenha o acesso restrito à rede interna ou VPN."
