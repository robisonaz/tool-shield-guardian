# SecVersions Backend API

## Guia de Instalação

### 1. Pré-requisitos
- Node.js 18+
- PostgreSQL 14+

### 2. Configurar o Banco de Dados

```bash
# Criar o banco
createdb secversions

# Executar o schema
psql -d secversions -f database/schema.sql

# Criar o primeiro usuário admin
psql -d secversions -c "
  INSERT INTO users (email, password_hash, full_name) 
  VALUES ('admin@exemplo.com', '\$2a\$10\$...hash...', 'Admin');
"
# Use o script abaixo para gerar o hash:
# node -e "const bcrypt=require('bcryptjs'); bcrypt.hash('sua-senha', 10).then(console.log)"
```

### 3. Configurar o Backend

```bash
cd backend-api
cp .env.example .env
# Edite .env com suas credenciais de banco
npm install
npm run dev
```

### 4. Configurar o Frontend

Crie/edite o arquivo `.env.local` na raiz do projeto:

```
VITE_API_URL=http://localhost:3010/api
```

```bash
npm install
npm run dev
```

### 5. Estrutura da API

| Endpoint | Método | Auth | Descrição |
|---|---|---|---|
| `/api/auth/login` | POST | - | Login local (email/senha) |
| `/api/auth/refresh` | POST | - | Renovar token JWT |
| `/api/auth/me` | GET | JWT | Dados do usuário logado |
| `/api/auth/logout` | POST | - | Invalidar refresh token |
| `/api/providers/public` | GET | - | Listar provedores OIDC ativos |
| `/api/providers` | GET/POST | Admin | Gerenciar provedores |
| `/api/providers/:id` | PUT/DELETE | Admin | Editar/remover provedor |
| `/api/oidc/callback` | POST | - | Callback OIDC (Keycloak) |
| `/api/tools/nvd-lookup` | POST | JWT | Buscar CVEs no NVD |
| `/api/tools/version-detect` | POST | JWT | Detectar versão por URL |

### 6. Criar Usuário Admin

```bash
cd backend-api
node -e "
const bcrypt = require('bcryptjs');
bcrypt.hash('sua-senha', 10).then(hash => {
  console.log('Execute no psql:');
  console.log(\`INSERT INTO users (email, password_hash, full_name) VALUES ('admin@exemplo.com', '\${hash}', 'Admin');\`);
  console.log(\`INSERT INTO user_roles (user_id, role) SELECT id, 'admin' FROM users WHERE email = 'admin@exemplo.com';\`);
});
"
```
