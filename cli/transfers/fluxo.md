# SecureShare – Módulo de Transferências (CLI)

## Visão Geral

O módulo de Transferências do **SecureShare CLI** implementa um sistema de partilha segura de ficheiros com **End-to-End Encryption (E2EE)**. Este documento descreve toda a arquitetura, fluxos criptográficos e garantias de segurança do sistema.

### Objetivo

Permitir transferência segura de ficheiros entre utilizadores, garantindo que o servidor **nunca** consegue aceder a:
- Conteúdo do ficheiro original
- File Key de cifragem
- Private key do utilizador

---

## 🏗️ Arquitetura do Módulo
```
cli/
  transfers/
    commands.py     ← Comandos: upload, download, list, delete
  core/
    crypto.py       ← AES-GCM, RSA-OAEP, PBKDF2, vault decrypt
    api.py          ← Chamadas REST ao backend
    session.py      ← Gestão do access token
    config.py       ← Configurações (~/.secureshare)
```

**Stack Tecnológica:**
- **Typer** – Framework de comandos CLI
- **cryptography** – Biblioteca criptográfica Python

---

## 🔐 Fundamentos Criptográficos

### AES-256-GCM
**Uso:** Cifragem de ficheiros

**Propriedades:**
- Confidencialidade dos dados
- Integridade através de authentication tag
- Nonce aleatório único por operação

### RSA-4096 (OAEP + SHA-256)
**Uso:** Cifragem da File Key para cada destinatário

**Características:**
- Padding OAEP com SHA-256
- Chaves de 4096 bits
- Permite partilha segura da File Key sem canal seguro prévio

### Vault (Private Key Cifrada)
**Localização:** `~/.secureshare/vault.json`

**Proteção:**
- **PBKDF2-HMAC-SHA256** com 480.000 iterações
- **AES-256-GCM** para cifrar a private key
- Private key **nunca** sai em claro do cliente
- Servidor armazena apenas o vault cifrado

---

## 📤 Upload – Fluxo Completo

### Comando
```bash
secureshare transfers upload <ficheiro> --to alice --to bob
```

### Passos Internos

#### 1. Leitura do Ficheiro
```python
file_bytes = Path(filepath).read_bytes()
```

#### 2. Geração da File Key
```python
file_key = os.urandom(32)  # AES-256 → 32 bytes
```

#### 3. Cifragem do Ficheiro
```python
nonce = os.urandom(12)
ciphertext = AESGCM(file_key).encrypt(nonce, file_bytes, None)
```

#### 4. Obtenção das Public Keys dos Destinatários
```http
GET /users/<username>/key
```

**Resposta:**
```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----..."
}
```

#### 5. Cifragem da File Key (por Destinatário)
```python
encrypted_key_for_user = RSA_encrypt(public_key_user, file_key)
```

#### 6. Envio ao Servidor
```http
POST /transfers
```

**Payload:**
```json
{
  "filename": "segredo.pdf",
  "cipher": "AES-256-GCM",
  "nonce": "BASE64_NONCE",
  "encrypted_file": "BASE64_CIPHERTEXT",
  "encrypted_keys": {
    "alice": "BASE64_RSA_CIPHERTEXT",
    "bob": "BASE64_RSA_CIPHERTEXT"
  }
}
```

### Resultado

O servidor recebe apenas dados cifrados. Não tem acesso a:
- Conteúdo do ficheiro
- File Key
- Qualquer informação que permita descifragem

---

## 📥 Download – Fluxo Completo

### Comando
```bash
secureshare transfers download <id> [-o output]
```

### Passos Internos

#### 1. Obter Metadata da Transferência
```http
GET /transfers/<id>
```

**Resposta:**
```json
{
  "filename": "segredo.pdf",
  "cipher": "AES-256-GCM",
  "nonce": "BASE64_NONCE",
  "encrypted_file_key": "BASE64_RSA_CIPHERTEXT"
}
```

#### 2. Obter Ficheiro Cifrado
```http
GET /download/<id>
```

**Resposta:** Bytes do ficheiro cifrado

#### 3. Desbloquear Vault
```python
PBKDF2(password, salt_vault) → derived_key
AES-GCM.decrypt(ciphertext_vault) → private_key_pem
```

#### 4. Carregar Private Key RSA
```python
private_key = load_pem_private_key(private_pem)
```

#### 5. Desencriptar File Key
```python
file_key = private_key.decrypt(encrypted_file_key, OAEP(...))
```

#### 6. Desencriptar Ficheiro
```python
plaintext = AESGCM(file_key).decrypt(nonce, encrypted_file)
```

#### 7. Guardar Ficheiro Localmente
Ficheiro descifrado é guardado no sistema de ficheiros local.

### Garantia Crítica

O servidor **nunca** tem acesso a:
- Password do utilizador
- Private key
- File key
- Conteúdo do ficheiro em claro

---

## 🛠️ Comandos Disponíveis

### 📤 Upload
```bash
secureshare transfers upload <ficheiro> --to <username>
```
Carrega e cifra um ficheiro para um ou mais destinatários.

### 📥 Download
```bash
secureshare transfers download <id> [-o output]
```
Descarrega e descifra um ficheiro recebido.

### 📜 Listar Transferências
```bash
secureshare transfers list
```

**Informação exibida:**
- ID da transferência
- Nome do ficheiro
- Data de criação
- Data de expiração
- Classificação MLS (quando implementado)

### 🗑️ Apagar Transferência
```bash
secureshare transfers delete <id> [--force]
```
Remove uma transferência do servidor.

---

## 🔒 Garantias de Segurança

### End-to-End Encryption (E2EE)

✅ **Ficheiros são cifrados antes de sair da máquina do cliente**  
✅ **Servidor recebe apenas dados cifrados**  
✅ **Private Key nunca sai do cliente**  
✅ **Vault protegido por PBKDF2 (480k iterações) + AES-GCM**  
✅ **File Key cifrada individualmente com RSA para cada destinatário**  
✅ **Download exige private key + password do vault**

### O Que o Servidor NÃO Consegue Fazer

❌ Abrir o vault do utilizador  
❌ Recuperar a File Key  
❌ Desencriptar ficheiros  
❌ Aceder ao conteúdo em claro  

### Cumprimento de E2EE Real

O sistema implementa **E2EE verdadeiro**:
- Zero-knowledge do lado do servidor
- Chaves criptográficas controladas exclusivamente pelo cliente
- Impossibilidade matemática de o servidor aceder aos dados

---

## 🔗 Integração com Backend

### APIs Utilizadas

| Endpoint | Método | Descrição |
|----------|--------|-----------|
| `/users/<username>/key` | GET | Obter public key de um utilizador |
| `/transfers` | POST | Upload de ficheiro cifrado |
| `/transfers/<id>` | GET | Obter metadata da transferência |
| `/download/<id>` | GET | Descarregar ficheiro cifrado |
| `/transfers` | GET | Listar transferências |
| `/transfers/<id>` | DELETE | Apagar transferência |

### Autenticação

Todas as chamadas usam **Bearer Token** (JWT) obtido durante o login e gerido por `session.py`.

---

## 📋 Resumo do Fluxo E2EE
```
┌─────────────┐                    ┌──────────────┐                    ┌─────────────┐
│   Cliente   │                    │   Servidor   │                    │ Destinatário│
│   (Alice)   │                    │  (Backend)   │                    │    (Bob)    │
└──────┬──────┘                    └──────┬───────┘                    └──────┬──────┘
       │                                   │                                   │
       │ 1. Gera File Key (AES-256)        │                                   │
       │ 2. Cifra ficheiro                 │                                   │
       │ 3. Obtém public key de Bob ──────>│                                   │
       │                            <───────│ Public Key de Bob                │
       │ 4. Cifra File Key com RSA         │                                   │
       │ 5. Envia dados cifrados ─────────>│                                   │
       │                                   │ (armazena tudo cifrado)           │
       │                                   │                                   │
       │                                   │<──────────────────────────────────│ Download
       │                                   │ Metadata + ficheiro cifrado ─────>│
       │                                   │                                   │
       │                                   │                    6. Descifra File Key
       │                                   │                    7. Descifra ficheiro
       │                                   │                                   │
```

---

## 🎯 Conclusão

O módulo de Transferências do **SecureShare CLI** implementa um sistema robusto de E2EE que garante:

- **Confidencialidade total** dos ficheiros partilhados
- **Controlo exclusivo** das chaves pelo utilizador
- **Zero-knowledge** do servidor sobre o conteúdo
- **Segurança criptográfica** baseada em padrões da indústria (AES-256, RSA-4096)

Este design assegura que mesmo em caso de comprometimento do servidor, os dados dos utilizadores permanecem protegidos.