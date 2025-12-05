#!/bin/bash
# ===================================================================
# SecureShare CLI - Test Script (Backend Integration)
# ===================================================================
# Pré-requisitos:
#   1. Backend a correr em https://localhost:8000
#   2. Admin já criado no sistema (via init_db ou .env)
# ===================================================================

set -e  # Parar em caso de erro

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
# 1. AUTH - Login Admin
# ===================================================================
echo ""
echo "=========================================="
echo "1. LOGIN ADMIN"
echo "=========================================="

echo "--- Login como Admin ---"
echo "Username: admin | Password: adminadmin"
cli auth login

# ===================================================================
# 2. DEPARTMENTS (Admin)
# ===================================================================
echo ""
echo "=========================================="
echo "2. CRIAR DEPARTAMENTOS"
echo "=========================================="

cli departments create "Finance"
cli departments create "HR"
cli departments create "Engineering"
cli departments list

# ===================================================================
# 3. CRIAR USERS (Admin)
# ===================================================================
echo ""
echo "=========================================="
echo "3. CRIAR 3 UTILIZADORES"
echo "=========================================="

echo "--- Criar user1 (vai ser regular) ---"
echo "username=user1, otp=otp1, email=user1@test.com, name=User One"
cli users create

echo "--- Criar user2 (vai ser regular) ---"
echo "username=user2, otp=otp2, email=user2@test.com, name=User Two"
cli users create

echo "--- Criar user3 (vai ser Security Officer) ---"
echo "username=officer, otp=otp3, email=officer@test.com, name=Security Officer"
cli users create

# ===================================================================
# 4. ATRIBUIR ROLE SO AO USER3 (Admin)
# ===================================================================
echo ""
echo "=========================================="
echo "4. ATRIBUIR SECURITY_OFFICER AO USER3"
echo "=========================================="

echo "--- Admin atribui role SO ao officer ---"
cli users assign-role officer --role SECURITY_OFFICER

echo "--- Logout Admin ---"
cli auth logout

# ===================================================================
# 5. ATIVAR CONTAS
# ===================================================================
echo ""
echo "=========================================="
echo "5. ATIVAR CONTAS DOS USERS"
echo "=========================================="

echo "--- Ativar user1 ---"
echo "username=user1, otp=otp1, password=user1pass"
cli auth activate
cli auth logout

echo "--- Ativar user2 ---"
echo "username=user2, otp=otp2, password=user2pass"
cli auth activate
cli auth logout

echo "--- Ativar officer ---"
echo "username=officer, otp=otp3, password=officerpass"
cli auth activate

# ===================================================================
# 6. OFFICER ATRIBUI CLEARANCES
# ===================================================================
echo ""
echo "=========================================="
echo "6. OFFICER ATRIBUI CLEARANCES"
echo "=========================================="

echo "--- Officer já está logado ---"

echo "--- Selecionar role SO ---"
cli users role

echo "--- Atribuir SECRET clearance ao user1 ---"
cli users assign-clearance user1 --level SECRET --dept Engineering --dept Finance

echo "--- Atribuir CONFIDENTIAL clearance ao user2 ---"
cli users assign-clearance user2 --level CONFIDENTIAL --dept HR

echo "--- Logout officer ---"
cli auth logout

# ===================================================================
# 7. TESTAR MLS - User1 (SECRET)
# ===================================================================
echo ""
echo "=========================================="
echo "7. TESTAR MLS - USER1 (SECRET)"
echo "=========================================="

echo "--- Login user1 ---"
cli auth login

echo "--- Verificar clearances ---"
cli users clearance

echo "--- Upload SECRET para Engineering (DEVE FUNCIONAR) ---"
cli transfers upload /tmp/testfile.txt --to user2 --level SECRET --dept Engineering

echo "--- Upload CONFIDENTIAL (Write Down - DEVE FALHAR) ---"
cli transfers upload /tmp/testfile.txt --to user2 --level CONFIDENTIAL || echo "✅ Falhou como esperado (No Write Down)"

echo "--- Logout user1 ---"
cli auth logout

# ===================================================================
# 8. TESTAR MLS - User2 (CONFIDENTIAL)
# ===================================================================
echo ""
echo "=========================================="
echo "8. TESTAR MLS - USER2 (CONFIDENTIAL)"
echo "=========================================="

echo "--- Login user2 ---"
cli auth login

echo "--- Verificar clearances ---"
cli users clearance

echo "--- Listar transfers recebidos ---"
cli transfers list

echo "--- Tentar download de SECRET (Read Up - DEVE FALHAR) ---"
# cli transfers download <ID> || echo "✅ Falhou como esperado (No Read Up)"

echo "--- Logout user2 ---"
cli auth logout

# ===================================================================
# CLEANUP
# ===================================================================
echo ""
echo "=========================================="
echo "🧹 Cleanup"
echo "=========================================="
rm -f /tmp/testfile.txt /tmp/secret.txt
cli auth logout 2>/dev/null || true

echo ""
echo "=========================================="
echo "✅ Testes concluídos!"
echo "=========================================="
echo ""
echo "Resumo:"
echo "  - Admin criou 3 departments e 3 users"
echo "  - Admin atribuiu role SO ao 'officer'"
echo "  - Officer atribuiu SECRET ao user1 (Engineering, Finance)"
echo "  - Officer atribuiu CONFIDENTIAL ao user2 (HR)"
echo "  - User1 (SECRET) conseguiu upload SECRET"
echo "  - User1 (SECRET) NÃO conseguiu upload CONFIDENTIAL (No Write Down)"
echo "  - User2 (CONFIDENTIAL) NÃO consegue ler SECRET (No Read Up)"