# Painel de Reservas — autenticação isolada por projeto Vercel

## Segurança implementada

- O HTML não contém URL do Supabase, chaves, tabela ou lista de e-mails.
- O login é validado pelo Supabase Auth no servidor da Vercel.
- Depois do login, a Vercel verifica se o e-mail está em `AUTHORIZED_EMAILS`.
- A sessão do painel é própria desta implantação e fica em cookie `HttpOnly`, `SameSite=Strict`.
- Estar conectado em outro painel ou outro projeto não libera este sistema.
- Todas as consultas, inclusões, alterações, exclusões e uploads passam pela função `/api/backend`.
- A chave `SUPABASE_SERVICE_ROLE_KEY` nunca é enviada ao navegador.

## Variáveis na Vercel

Em **Project → Settings → Environment Variables**, cadastre:

- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `SUPABASE_SERVICE_ROLE_KEY`
- `AUTHORIZED_EMAILS`
- `APP_SESSION_SECRET`
- `COMPANY_NAME`
- `RESERVAS_TABLE`
- `REPORTS_BUCKET`

Use uma implantação Vercel diferente para cada empresa. Em cada projeto, altere principalmente:

- `AUTHORIZED_EMAILS`
- `COMPANY_NAME`
- `RESERVAS_TABLE`
- `APP_SESSION_SECRET`

O segredo de sessão deve ser diferente em cada projeto.

## Cadastro de usuários

O e-mail precisa cumprir duas condições:

1. existir no **Supabase Authentication → Users**;
2. estar listado em `AUTHORIZED_EMAILS` naquele projeto da Vercel.

Assim, um usuário pode existir no Auth geral, mas entrar somente nos projetos em que foi explicitamente autorizado.

## Publicação

1. Envie toda esta pasta para um repositório ou importe-a na Vercel.
2. Cadastre as variáveis de ambiente.
3. Faça um novo deploy após alterar variáveis.
4. Abra o domínio do projeto e entre com e-mail e senha do Supabase Auth.

## Atenção

A `SUPABASE_SERVICE_ROLE_KEY` ignora RLS. Ela está protegida no servidor, mas deve ser usada exclusivamente nas funções da Vercel. Nunca coloque essa chave em HTML, JavaScript público ou repositório público.
