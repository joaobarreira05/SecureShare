#!/bin/bash
# ===================================================================
# SecureShare CLI - Test Script (Backend Integration)
# ===================================================================
# Pré-requisitos:
#   1. Backend a correr em http://localhost:8000
#   2. Admin já criado no sistema (via init_db ou .env)
#   3. Ficheiro de teste: echo "test content" > /tmp/testfile.txt
# ===================================================================

# set -e  # Comentado para ver todos os testes

# Função para correr CLI
cli() {
    PYTHONPATH=. .venv/bin/python3 -m cli.main "$@"
}

echo "=========================================="
echo "🔧 Setup"
echo "=========================================="
echo "test content" > /tmp/testfile.txt
echo "secret document" > /tmp/secret.txt

# ===================================================================
# 1. AUTH - Login/Logout
# ===================================================================
echo ""
echo "=========================================="
echo "1. AUTH TESTS"
echo "=========================================="

echo "--- 1.1 Login como Admin (DEVE SUCEDER) ---"
cli auth login
# Vai pedir username/password interativamente

echo "--- 1.2 Logout ---"
cli auth logout

echo "--- 1.3 Tentativa sem sessão (DEVE FALHAR) ---"
cli users create || echo "✅ Falhou como esperado (sem sessão)"

# Login novamente para continuar testes
echo "--- Login Admin novamente ---"
cli auth login

# ===================================================================
# 2. DEPARTMENTS (Admin Only)
# ===================================================================
echo ""
echo "=========================================="
echo "2. DEPARTMENTS TESTS (Admin Only)"
echo "=========================================="

echo "--- 2.1 Criar departamentos ---"
cli departments create "Finance"
cli departments create "HR"
cli departments create "Engineering"

echo "--- 2.2 Listar departamentos ---"
cli departments list

echo "--- 2.3 Apagar um departamento ---"
cli departments delete 1 --force || echo "⚠️ Pode falhar se ID não existe"

echo "--- 2.4 Listar após delete ---"
cli departments list

# ===================================================================
# 3. USERS (Admin/SO)
# ===================================================================
echo ""
echo "=========================================="
echo "3. USERS TESTS"
echo "=========================================="

echo "--- 3.1 Criar utilizador regular ---"
# Interativo: vai pedir username, otp, email, full_name
cli users create
# Sugestão: user1, temppass123, user1@test.com, User One

echo "--- 3.2 Criar outro utilizador ---"
cli users create
# Sugestão: user2, temppass456, user2@test.com, User Two

echo "--- 3.3 Atribuir role SECURITY_OFFICER a user1 ---"
# Primeiro, user1 precisa ativar a conta e ter vault
# Assumindo que já está ativado:
cli users assign-role user1 --role SECURITY_OFFICER || echo "⚠️ Pode falhar se user não ativou"

# ===================================================================
# 4. MLS & RBAC TOKENS (Como user ativado)
# ===================================================================
echo ""
echo "=========================================="
echo "4. MLS & RBAC TOKENS"
echo "=========================================="

echo "--- 4.1 [Admin] Logout ---"
cli auth logout

echo "--- 4.2 [User1] Login ---"
# Ativar primeiro se necessário: cli auth activate
cli auth login
# username: user1, password: <a password definida na ativação>

echo "--- 4.3 Listar clearances MLS ---"
cli users clearance || echo "⚠️ Sem clearances (SO precisa atribuir)"

echo "--- 4.4 Listar roles RBAC ---"
cli users role || echo "⚠️ Sem roles"

# ===================================================================
# 5. TRANSFERS - Upload/Download
# ===================================================================
echo ""
echo "=========================================="
echo "5. TRANSFERS TESTS"
echo "=========================================="

echo "--- 5.1 Upload ficheiro privado (para user2) ---"
cli transfers upload /tmp/testfile.txt --to user2 --level UNCLASSIFIED

echo "--- 5.2 Upload com nível SECRET (pode falhar sem clearance) ---"
cli transfers upload /tmp/secret.txt --to user2 --level SECRET --dept Engineering || echo "⚠️ MLS Check falhou (esperado sem clearance)"

echo "--- 5.3 Upload público ---"
cli transfers upload /tmp/testfile.txt --public
# Vai mostrar link com #key

echo "--- 5.4 Listar transferências ---"
cli transfers list

echo "--- 5.5 Download (como destinatário) ---"
# Logout e login como user2
cli auth logout
cli auth login
# username: user2

# Obter ID da lista e fazer download
# cli transfers download <TRANSFER_ID> --output /tmp/downloaded.txt

echo "--- 5.6 Download público (qualquer user com link) ---"
# cli transfers download "http://localhost:8000/transfers/download/<ID>#<KEY>" --output /tmp/public_download.txt

echo "--- 5.7 Delete transferência (como owner) ---"
# cli transfers delete <TRANSFER_ID> --force

# ===================================================================
# 6. MLS VIOLATION TESTS
# ===================================================================
echo ""
echo "=========================================="
echo "6. MLS VIOLATION TESTS"
echo "=========================================="

echo "--- 6.1 [User com SECRET clearance] Upload CONFIDENTIAL (Write Down - DEVE FALHAR) ---"
# Se user tem clearance SECRET, não pode criar ficheiros CONFIDENTIAL (No Write Down)
# $CLI transfers upload /tmp/testfile.txt --to user2 --level CONFIDENTIAL
# Esperado: "Erro MLS: Não podes fazer upload com nível CONFIDENTIAL"

echo "--- 6.2 [User com SECRET clearance] Upload TOP_SECRET (Write Up - OK) ---"
# $CLI transfers upload /tmp/testfile.txt --to user2 --level TOP_SECRET --dept Engineering

echo "--- 6.3 [User sem dept Finance] Upload para Finance (DEVE FALHAR) ---"
# $CLI transfers upload /tmp/testfile.txt --to user2 --level SECRET --dept Finance
# Esperado: "Erro MLS: Não tens acesso aos departamentos: Finance"

# ===================================================================
# 7. RBAC PERMISSION TESTS
# ===================================================================
echo ""
echo "=========================================="
echo "7. RBAC PERMISSION TESTS"
echo "=========================================="

echo "--- 7.1 [User regular] Tentar assign-role (DEVE FALHAR) ---"
$CLI users assign-role user2 --role AUDITOR || echo "✅ Falhou como esperado (não é Admin/SO)"

echo "--- 7.2 [Security Officer] Assign role ---"
# Precisa ter role SO ativo primeiro:
# $CLI users role (select SO role)
# $CLI users assign-role user2 --role TRUSTED_OFFICER

echo "--- 7.3 [User regular] Criar departamento (DEVE FALHAR) ---"
$CLI departments create "NewDept" || echo "✅ Falhou como esperado (só Admin)"

# ===================================================================
# CLEANUP
# ===================================================================
echo ""
echo "=========================================="
echo "🧹 Cleanup"
echo "=========================================="
rm -f /tmp/testfile.txt /tmp/secret.txt /tmp/downloaded.txt /tmp/public_download.txt
$CLI auth logout || true

echo ""
echo "=========================================="
echo "✅ Testes concluídos!"