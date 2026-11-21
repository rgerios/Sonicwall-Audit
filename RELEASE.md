# Fluxo HML → PRD

| Ambiente | Branch | Pasta no servidor | Painel | Syslog UDP (SonicWall / FortiGate) |
|---|---|---|---|---|
| **PRD** (produção) | `main` | `~/Sonicwall-Audit` | `https://IP` (443) | 5514 / 5515 |
| **HML** (homologação) | `hml` | `~/Sonicwall-Audit-hml` | `https://IP:8443` | 5614 / 5615 |

Cada ambiente tem containers (`fwaudit-*` e `fwaudit-hml-*`), volumes, rede, banco e certificados **próprios**.
HML e PRD podem rodar no mesmo servidor sem se atrapalhar. Os dados de um nunca aparecem no outro.

## Regra

**Toda mudança nova entra primeiro em `hml`. Só depois de validada é promovida a `main`.** Ninguém sobe código direto na `main`.

## Fluxo de uma mudança

```bash
# 1) desenvolver a partir de hml
git checkout hml && git pull
git checkout -b feat/minha-mudanca
# ... código, testes (npm test, npx tsc --noEmit) ...
git checkout hml && git merge --no-ff feat/minha-mudanca && git push origin hml

# 2) publicar em HML (no servidor, pasta ~/Sonicwall-Audit-hml)
./deploy.sh hml --update

# 3) homologar em https://IP:8443 (apontar um firewall de teste para as portas UDP 5614/5615)

# 4) aprovado? promover a PRD
git checkout main && git pull
git merge --ff-only hml          # main passa a ser exatamente o que foi homologado
git tag -a vAAAA.MM.DD -m "release"   # opcional, facilita rollback
git push origin main --tags

# 5) publicar em PRD (no servidor, pasta ~/Sonicwall-Audit)
./deploy.sh --update
```

`--ff-only` garante que o que vai para PRD é **idêntico** ao que foi homologado (se falhar, `main` recebeu algo que
não passou por HML: traga `main` para dentro de `hml`, homologue de novo e promova).

## Correção urgente em produção (hotfix)

Corrija em `hml`, homologue rápido e promova como acima. Se for inviável, faça na `main` e **traga de volta**:
`git checkout hml && git merge main && git push origin hml`, para as branches não divergirem.

## Rollback

```bash
git checkout main && git revert <commit>   # ou: git reset --hard <tag anterior> no servidor + ./deploy.sh
./deploy.sh --update
```

Antes de mudanças que mexam no banco, faça backup: `docker exec -t fwaudit-db pg_dump -U fwaudit fwaudit > backup-$(date +%F).sql`.

## Primeira instalação do HML no servidor

```bash
git clone -b hml git@github.com:rgerios/Sonicwall-Audit.git ~/Sonicwall-Audit-hml
cd ~/Sonicwall-Audit-hml && ./deploy.sh hml
```

O `deploy.sh` recusa rodar se a pasta estiver na branch errada (HML exige `hml`, PRD exige `main`).
O HML nasce com banco vazio e usuário próprio. Libere as portas 8443/tcp e 5614-5615/udp se houver firewall (o script faz isso no UFW).

## Recomendado no GitHub

Em *Settings → Branches*, proteger `main` (exigir pull request e impedir push direto) para fazer valer a regra acima.
