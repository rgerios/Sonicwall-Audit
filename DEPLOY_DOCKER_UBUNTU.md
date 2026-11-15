# Deploy do SonicAudit no Ubuntu Server com Docker (3 Containers)

Esta arquitetura separa o **SonicAudit** em três containers independentes na mesma rede privada Docker (`sonicaudit_net`):

1. **`sonicaudit-db` (`postgres:16-alpine`)**: Banco de dados PostgreSQL local persistente (volume `sonicaudit_pgdata`).
2. **`sonicaudit-backend` (`Dockerfile.backend`)**: API Node.js/Express, autenticação, sincronização SonicOS, IA e receptor UDP de Syslogs (`5514/udp`).
3. **`sonicaudit-frontend` (`Dockerfile.frontend`)**: Nginx servindo o frontend React compilado e fazendo proxy de `/api/` para o container `backend`.

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

Suba os 3 containers em segundo plano:

```bash
docker compose up -d --build
```

Verifique o status e a saúde dos containers:

```bash
docker compose ps
docker compose logs -f backend
```

Acesse no navegador:

```text
http://IP_DO_SERVIDOR_UBUNTU:8080
```

Na primeira abertura, crie seu usuário e senha administrativos pela tela inicial (ou defina `SONICAUDIT_ADMIN_USER` / `SONICAUDIT_ADMIN_PASS` no `.env`).

---

## 3. Regras de Firewall no Ubuntu (UFW)

Libere a porta web e a porta UDP para receber os syslogs dos SonicWalls:

```bash
sudo ufw allow 8080/tcp comment "SonicAudit Web UI"
sudo ufw allow 5514/udp comment "SonicAudit Syslog UDP"
sudo ufw reload
```

> **Dica**: Se alterar `FRONTEND_PORT=80` no `.env` (para acessar sem `:8080`), libere `80/tcp` no UFW. No SonicAudit (aba *Conexão & Linux*), ao iniciar o servidor Syslog UDP dentro do container, informe porta **5514** e bind `0.0.0.0`.

---

## 4. Manutenção Independente por Container

- **Reconstruir apenas o frontend** (sem reiniciar o banco):
  ```bash
  docker compose up -d --build --no-deps frontend
  ```
- **Reconstruir apenas o backend** (sem perder conexões do banco):
  ```bash
  docker compose up -d --build --no-deps backend
  ```
- **Backup completo do banco PostgreSQL**:
  ```bash
  docker exec -t sonicaudit-db pg_dump -U sonicaudit sonicaudit > backup-sonicaudit-$(date +%F).sql
  ```
- **Restaurar backup**:
  ```bash
  cat backup-sonicaudit-AAAA-MM-DD.sql | docker exec -i sonicaudit-db psql -U sonicaudit -d sonicaudit
  ```
