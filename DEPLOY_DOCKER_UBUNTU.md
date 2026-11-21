# Deploy do FW Audit no Ubuntu Server com Docker (4 Containers)

Esta arquitetura separa o **FW Audit** em quatro containers independentes na mesma rede privada Docker (`fwaudit_net`):

1. **`fwaudit-db` (`postgres:16-alpine`)**: Banco de dados PostgreSQL compartilhado com isolamento lógico por coluna `vendor` (`sonicwall` / `fortigate`), login único e configurações de IA compartilhadas (volume `fwaudit_pgdata`).
2. **`fwaudit-backend-sonicwall` (`FW_VENDOR=sonicwall`)**: API SonicOS, parser `.exp`, IA e receptor UDP Syslog dedicado na porta **`5514/udp`**.
3. **`fwaudit-backend-fortigate` (`FW_VENDOR=fortigate`)**: API REST FortiOS v2 (Bearer Token + VDOM), CLI FortiOS, IA e receptor UDP Syslog dedicado na porta **`5515/udp`**.
4. **`fwaudit-frontend` (`Dockerfile.frontend`)**: Nginx servindo o painel React unificado (**Azul Pastel** para SonicWall e **Vermelho Pastel** para FortiGate) e roteando `/api/auth/*`, `/api/sonicwall/*` e `/api/fortigate/*`.

---

## Caminho rápido: script de deploy

Dentro da pasta do projeto, no servidor Ubuntu:

```bash
./deploy.sh
```

O script instala o Docker se faltar, cria o `.env` com senhas geradas (pergunta o usuário e a senha do administrador), libera as portas no UFW quando ele está ativo, constrói e sobe os containers e espera todos ficarem saudáveis. Para atualizar depois: `./deploy.sh --update`.

As seções abaixo descrevem os mesmos passos feitos à mão.

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
nano .env   # Crie o arquivo com POSTGRES_PASSWORD (senha forte, só letras e números), FWAUDIT_ADMIN_USER e FWAUDIT_ADMIN_PASS
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
https://IP_DO_SERVIDOR_UBUNTU:8443
```

Na primeira abertura, crie seu usuário e senha únicos pela tela inicial (ou defina `FWAUDIT_ADMIN_USER` / `FWAUDIT_ADMIN_PASS` no `.env`).

---

## 3. Regras de Firewall no Ubuntu (UFW)

Libere a porta web e as duas portas UDP dedicadas para receber syslogs dos firewalls SonicWall e FortiGate:

```bash
sudo ufw allow 8443/tcp comment "FW Audit Web UI HTTPS"
sudo ufw allow 8080/tcp comment "FW Audit Web UI (redireciona para HTTPS)"
sudo ufw allow 5514/udp comment "FW Audit SonicWall Syslog UDP"
sudo ufw allow 5515/udp comment "FW Audit FortiGate Syslog UDP"
sudo ufw reload
```

> **Dica**: os receptores UDP sobem sozinhos (`5514` no SonicWall, `5515` no FortiGate) e voltam após reiniciar os containers. Aponte os firewalls (ou o `rsyslog`) para o IP do servidor Ubuntu. Com mais de um firewall cadastrado, cada log é atribuído pelo número de série ou pelo IP de origem; logs de origem não cadastrada são descartados e listados na aba *Localidades & Linux*.
>
> **Armazenamento**: todo o histórico de syslog fica no PostgreSQL, limitado apenas pela retenção em dias de cada firewall. Acompanhe o tamanho do banco na mesma aba; `SYSLOG_MAX_ROWS_PER_SITE` define um teto opcional de linhas por firewall. A senha do administrador precisa ter no mínimo 10 caracteres.

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

---

## Disco mecânico (HDD) e muitos logs

O FW Audit guarda todo o histórico de syslogs no PostgreSQL. Em disco mecânico, uma tabela com milhões de
linhas fica lenta se o sistema recontar tudo toda hora. A versão atual evita isso:

- **Contadores incrementais.** Totais por ação/severidade e por hora são mantidos no próprio banco
  (tabelas `syslog_counters` e `syslog_hourly`), atualizados a cada ingestão e a cada limpeza. A partida e a
  limpeza de retenção **não varrem mais a tabela inteira**.
- **Cálculo inicial uma única vez.** Na primeira subida após atualizar, cada firewall tem seus contadores
  calculados em segundo plano (uma varredura completa, uma só vez, e uma por vez no banco). O log mostra
  `Calculando os contadores de syslog...` e depois `...prontos em Ns`. Enquanto isso a tela usa a janela
  recente; os números exatos aparecem quando terminar. Em HDD com muitos GB isso pode levar vários minutos.
- **Servidor abre a porta na hora.** `/api/health` responde logo (`ready:false` até concluir a carga) e a API
  responde 503 durante a carga, então o Docker não marca o container como `unhealthy`.
- **Limpeza de retenção em lotes** de 10 mil linhas, com pausa entre lotes, em segundo plano.
- **PostgreSQL ajustado para HDD** no `docker-compose.yml` (`synchronous_commit=off`, checkpoints espaçados,
  WAL comprimido). `synchronous_commit=off` faz o COMMIT não esperar o disco: numa queda de energia perdem-se,
  no máximo, ~0,6 s de logs recém-chegados, sem corromper o banco.

Ajustes que ajudam ainda mais (no `.env`):

```text
# Menos eventos na memória = partida e análises mais leves (padrão com PostgreSQL: 50000)
SYSLOG_MEMORY_WINDOW=20000
# Teto de linhas por firewall (0 = sem teto) e a retenção em dias, definida por firewall na tela de conexão
SYSLOG_MAX_ROWS_PER_SITE=0
# Memória do PostgreSQL (ajuste conforme a RAM do servidor)
PG_SHARED_BUFFERS=512MB
PG_EFFECTIVE_CACHE_SIZE=2GB
```

Se puder, mova o volume do banco (`fwaudit_pgdata`) para um SSD: é o ganho mais direto. Consultas acima de
5 s ficam registradas no log do PostgreSQL (`docker compose logs db`).

### Busca na tela de Syslogs

- A contagem de correspondências para em **10.000** (a tela mostra `10.000+`): contar milhões de linhas só para
  exibir um número custa uma leitura enorme em disco mecânico. Restrinja o período ou os filtros para ver o resto.
- Cada busca tem um **tempo limite** (padrão 20 s, `SYSLOG_SEARCH_TIMEOUT_MS` no `.env`). Se estourar, a tela avisa
  em vez de travar o banco.
- Os filtros de IP e de dispositivo usam o índice de texto antes de conferir o campo exato, e filtros comuns
  percorrem o índice de tempo e param ao juntar a página.
- O índice `idx_syslogs_vendor_site_ingested` (149 MB por 2 milhões de linhas, sem nenhuma consulta que o use) foi
  removido, e a tabela de syslogs ganhou um autovacuum mais frequente.

---

## HTTPS (certificado local)

O painel é servido **somente em HTTPS**. A porta HTTP (`8080`) apenas redireciona para o HTTPS (`8443`).

- **O certificado é gerado sozinho** no primeiro start do container `fwaudit-frontend` e guardado no volume `fwaudit_certs`.
  Ele é assinado por uma **CA local** ("FW Audit Local CA", 10 anos); o certificado do servidor vale 825 dias e é
  renovado automaticamente 30 dias antes de vencer.
- **O certificado cobre** `localhost`, o hostname do servidor e os IPs em `TLS_HOSTNAMES` e `TLS_IPS` (no `.env`,
  separados por vírgula; o `deploy.sh` preenche com o IP do servidor). Se o IP ou o nome mudar, edite o `.env` e rode
  `docker compose up -d`: o certificado do servidor é refeito e a CA continua a mesma.
- **TLS 1.2 e 1.3**, HTTP/2, e o cookie de sessão sai com o atributo `Secure`.

### Fazer o navegador confiar (uma única vez)

Sem isso, o navegador mostra "conexão não é particular" (o acesso funciona, é só o aviso). Importe a **CA**, não o
certificado do servidor: assim as renovações continuam confiáveis.

1. Baixe a CA: `http://IP_DO_SERVIDOR:8080/fwaudit-ca.crt` (também em `https://IP_DO_SERVIDOR:8443/fwaudit-ca.crt`).
2. Confira a impressão digital (SHA-256) com a mostrada ao final do `deploy.sh` ou com:
   ```bash
   docker compose exec -T frontend openssl x509 -in /etc/nginx/certs/ca.crt -noout -fingerprint -sha256
   ```
3. Instale como **Autoridade de Certificação Raiz Confiável**:
   - **Windows:** duplo clique no arquivo > Instalar certificado > Computador local > "Autoridades de Certificação Raiz Confiáveis".
   - **macOS:** abra no Acesso às Chaves, dê duplo clique no certificado e em "Confiança" escolha "Sempre Confiar".
   - **Linux (Chrome/Firefox):** importe em Configurações > Certificados > Autoridades (Firefox usa o próprio repositório).

> Importe a CA apenas nos computadores dos administradores. Quem tiver a chave da CA (volume `fwaudit_certs`) consegue
> emitir certificados aceitos por esses computadores; proteja o acesso ao servidor.

### Usar o seu próprio certificado

Coloque `server.crt` (com a cadeia, se houver) e `server.key` no volume e reinicie o frontend. O script não altera
arquivos que ele não criou:

```bash
docker cp meu.crt fwaudit-frontend:/etc/nginx/certs/server.crt
docker cp minha.key fwaudit-frontend:/etc/nginx/certs/server.key
docker compose restart frontend
```

Para voltar ao certificado automático, apague `server.crt`, `server.key` e `.fwaudit-generated` desse volume e reinicie.

### Portas padrão (443 e 80)

No `.env`: `FRONTEND_HTTPS_PORT=443` e `FRONTEND_PORT=80`, depois `docker compose up -d`. Libere as portas no firewall do servidor.

### Observações

- Não ativei o **HSTS** de propósito: com certificado local ele impediria o navegador de permitir a exceção.
- Se o painel ficar atrás de outro proxy/balanceador com TLS, ele deve enviar `X-Forwarded-Proto: https` para o cookie sair como `Secure`.
- `/api/health` e `/healthz` respondem na porta HTTP para monitoramento.
