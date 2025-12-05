# SecureShare CLI - Comandos

## Autenticação

```bash
python3 -m cli.main auth login
```
Login com username e password. Cria sessão ativa.

```bash
python3 -m cli.main auth logout
```
Termina a sessão ativa.

```bash
python3 -m cli.main auth activate
```
Ativa conta nova com OTP e define password. Gera par de chaves.

---

## Utilizador Atual
# Alterar password
python3 -m cli.main user update-password

# Atualizar email e/ou nome
python3 -m cli.main user update-info --email novo@email.com --name "Novo Nome"

```bash
python3 -m cli.main user me
```
Mostra informação do utilizador atual (ID, username, email, etc.).

---

## Gestão de Utilizadores (Admin/SO)

# Apagar user com confirmação
python3 -m cli.main users delete user3

# Apagar sem confirmação
python3 -m cli.main users delete user3 --force

```bash
python3 -m cli.main users list
```
Lista todos os utilizadores (requer Admin ou Security Officer).

```bash
python3 -m cli.main users create
```
Cria um novo utilizador (requer Admin).
jao@barreira.pt
goncalo@barreira.pt
margarida@barreira.pt

```bash
python3 -m cli.main users role
```
Lista e seleciona um RBAC Token (role) ativo.

```bash
python3 -m cli.main users clearance
```
Lista e seleciona uma clearance MLS ativa.

```bash
python3 -m cli.main users assign-role <USERNAME> --role <ROLE>

python3 -m cli.main users assign-role user1 --role SECURITY_OFFICER

python3 -m cli.main users assign-role user2 --role TRUSTED_OFFICER
```
Atribui um role a um utilizador (requer Admin ou SO).
Roles: ADMINISTRATOR, SECURITY_OFFICER, TRUSTED_OFFICER, AUDITOR, STANDARD_USER

```bash
python3 -m cli.main users assign-clearance <USERNAME> --level <LEVEL> --dept <DEPT>

python3 -m cli.main users assign-clearance user2 --level SECRET --dept Engineering --dept HR
python3 -m cli.main users assign-clearance user3 --level CONFIDENTIAL --dept HR 
python3 -m cli.main users assign-clearance user3 --level SECRET --dept Engineering  
```
Atribui clearance MLS a um utilizador (requer SO).
Níveis: TOP_SECRET, SECRET, CONFIDENTIAL, UNCLASSIFIED

---

## Transferências

```bash
python3 -m cli.main transfers upload <FILEPATH> --to <USER_ID> --level <LEVEL> --dept <DEPT>
```
Upload E2EE de um ficheiro para destinatário(s) específico(s).

```bash
python3 -m cli.main transfers upload <FILEPATH> --public
```
Upload público com link + chave no fragmento.

```bash
python3 -m cli.main transfers download <TRANSFER_ID> [--output <PATH>]
```
Download E2EE de um ficheiro. Requer clearance adequada.

```bash
python3 -m cli.main transfers list
```
Lista transferências onde és remetente ou destinatário.

```bash
python3 -m cli.main transfers delete <TRANSFER_ID> [--force]
```
Apaga uma transferência (apenas owner).

---

## Departamentos (Admin)

```bash
python3 -m cli.main departments list
```
Lista todos os departamentos.

```bash
python3 -m cli.main departments create <NAME>

python3 -m cli.main departments create "Engineering"
```

Cria um novo departamento (requer Admin).

```bash
python3 -m cli.main departments delete <ID> [--force]
```
Apaga um departamento (requer Admin).
