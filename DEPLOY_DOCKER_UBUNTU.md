# Deploy do FW Audit no Ubuntu Server com Docker (4 Containers)

Esta arquitetura separa o **FW Audit** em quatro containers independentes na mesma rede privada Docker (`fwaudit_net`):

1. **`fwaudit-db` (`postgres:16-alpine`)**: Banco de dados PostgreSQL compartilhado com isolamento lógico por coluna `vendor` (`sonicwall` / `fortigate`), login único e configurações de IA compartilhadas (volume `fwaudit_pgdata`).
2. **`fwaudit-backend-sonicwall` (`FW_VENDOR=sonicwall`)**: API SonicOS, parser `.exp`, IA e receptor UDP Syslog dedicado na porta **`5514/udp`**.
3. **`fwaudit-backend-fortigate` (`FW_VENDOR=fortigate`)**: API REST FortiOS v2 (Bearer Token + VDOM), CLI FortiOS, IA e receptor UDP Syslog dedicado na porta **`5515/udp`**.
4. **`fwaudit-frontend` (`Dockerfile.frontend`)**: Nginx servindo o painel React unificado (**Azul Pastel** para SonicWall e **Vermelho Pastel** para FortiGate) e roteando `/api/auth/*`, `/api/sonicwall/*` e `/api/fortigate/*`.

---

## 1. Pré-requisitos no Ubuntu Server

Instale o Docker Engine e o plugin `docker compose`:

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
```

*(Saia e entre novamente no SSH para aplicar o grupo `docker`.)*

---

## 2. Configuração e Subida

No diretório do projeto no servidor Ubuntu:

```bash
cp .env.docker.example .env
nano .env   # Defina uma senha forte em POSTGRES_PASSWORD
```

Suba os 4 containers em segundo plano:

```bash
docker compose up -d --build
```

Verifique o status e a saúde dos containers:

```bash
docker compose ps
docker compose logs -f backend-sonicwall backend-fortigate
```

Acesse no navegador:

```text
http://IP_DO_SERVIDOR_UBUNTU:8080
```

Na primeira abertura, crie seu usuário e senha únicos pela tela inicial (ou defina `FWAUDIT_ADMIN_USER` / `FWAUDIT_ADMIN_PASS` no `.env`).

---

## 3. Regras de Firewall no Ubuntu (UFW)

Libere a porta web e as duas portas UDP dedicadas para receber syslogs dos firewalls SonicWall e FortiGate:

```bash
sudo ufw allow 8080/tcp comment "FW Audit Web UI"
sudo ufw allow 5514/udp comment "FW Audit SonicWall Syslog UDP"
sudo ufw allow 5515/udp comment "FW Audit FortiGate Syslog UDP"
sudo ufw reload
```

> **Dica**: Dentro do FW Audit (aba *Localidades & Linux*), inicie o socket UDP em `5514` no ambiente SonicWall e em `5515` no ambiente FortiGate, apontando os respectivos firewalls (ou o `rsyslog`) para o IP do servidor Ubuntu.

---

## 4. Manutenção Independente por Container

- **Reconstruir apenas o frontend**:
  ```bash
  docker compose up -d --build --no-deps frontend
  ```
- **Reconstruir apenas o backend FortiGate (sem parar SonicWall ou PostgreSQL)**:
  ```bash
  docker compose up -d --build --no-deps backend-fortigate
  ```
- **Reconstruir apenas o backend SonicWall**:
  ```bash
  docker compose up -d --build --no-deps backend-sonicwall
  ```
- **Backup completo do banco PostgreSQL**:
  ```bash
  docker exec -t fwaudit-db pg_dump -U fwaudit fwaudit > backup-fwaudit-$(date +%F).sql
  ```
- **Restaurar backup**:
  ```bash
  cat backup-fwaudit-AAAA-MM-DD.sql | docker exec -i fwaudit-db psql -U fwaudit -d fwaudit
  ```
