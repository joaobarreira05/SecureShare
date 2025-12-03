# SecureShare CLI – Módulo de Autenticação (Auth & Vault)

Este documento descreve a estrutura e comportamento da **CLI** do SecureShare
relacionada com autenticação e gestão de chaves/vault.

> ⚠️ Nota: Nesta fase inicial, a CLI funciona **sem backend**.
> A estrutura foi desenhada para ser fácil ligar às APIs assim que existirem.

---

## Estrutura de Pastas da CLI

```text
cli/
├── main.py                 # Entry point da CLI (comando principal)
├── __init__.py
├── core/
│   ├── __init__.py
│   ├── config.py           # Configuração global da CLI (URLs, paths)
│   ├── session.py          # Gestão de sessão (token JWT local)
│   └── crypto.py           # Funções criptográficas (RSA, KDF, AES-GCM)
└── auth/
    ├── __init__.py
    └── commands.py         # Comandos de autenticação (login, me, logout, activate)


User: secureshare auth login
CLI:
  - pergunta username
  - pergunta password
  - valida inputs
  - gera token fake (ex.: "fake-token-for-<username>")
  - chama save_token(token)
  - mostra "Login efetuado com sucesso"
