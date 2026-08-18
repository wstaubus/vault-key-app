# Cofre — login com Google + Google Drive

App de credenciais (nome, senha, link, imagem, descritivo, data de atualização) com:
- Login oficial com a Conta Google
- Dados salvos como um JSON no **Google Drive do próprio usuário** (arquivo `cofre-vault.json`, criado numa pasta comum do Drive, não numa área oculta)
- Criptografia AES-256 no navegador com senha mestra — mesmo alguém com acesso ao Drive não lê as senhas sem essa senha mestra

Isso só funciona publicado num domínio de verdade (https), porque o login do Google bloqueia rodar dentro de iframes/sandboxes. Siga o passo a passo abaixo — leva uns 10 minutos.

## 1. Criar as credenciais no Google Cloud

1. Acesse https://console.cloud.google.com e crie um projeto novo (ou use um existente).
2. No menu, vá em **APIs e serviços → Biblioteca**, procure **Google Drive API** e clique em **Ativar**.
3. Vá em **APIs e serviços → Tela de consentimento OAuth**:
   - Tipo de usuário: **Externo**
   - Preencha nome do app, e-mail de suporte e e-mail de contato
   - Em "Escopos", não precisa adicionar nada manualmente
   - Em "Usuários de teste" (enquanto o app não é publicado), adicione o(s) e-mail(s) do Google que vão usar o app
4. Vá em **APIs e serviços → Credenciais → Criar credenciais → ID do cliente OAuth**:
   - Tipo de aplicativo: **Aplicativo da Web**
   - Em **Origens JavaScript autorizadas**, adicione a URL onde você vai publicar (ex: `https://seu-app.vercel.app`)
   - Em **URIs de redirecionamento autorizados**, adicione **a mesma URL, exatamente igual** (ex: `https://seu-app.vercel.app/`) — este é o passo essencial: é para essa URL que o Google devolve o usuário depois do login, e o login usa redirecionamento de página inteira (não popup), então nada fica sujeito a bloqueador de pop-up do navegador
   - Salve e copie o **Client ID** gerado (termina em `.apps.googleusercontent.com`)

## 2. Configurar o projeto

Abra `config.js` e cole o Client ID:

```js
GOOGLE_CLIENT_ID: "SEU_CLIENT_ID_AQUI.apps.googleusercontent.com",
```

## 3. Publicar

Este é um site estático (sem build) — três formas simples:

**Vercel**
```
npm i -g vercel
cd cofre-app
vercel
```

**Netlify**
- Arraste a pasta `cofre-app` para https://app.netlify.com/drop

**GitHub Pages**
- Suba a pasta para um repositório e ative Pages nas configurações do repo

Depois de publicar, **volte no passo 1** e confirme que a URL final está em "Origens JavaScript autorizadas" — sem isso o login trava com erro `redirect_uri_mismatch` / `origin_mismatch`.

## 4. Usar

1. Abra a URL publicada
2. Clique em "Entrar com Google" e autorize o acesso ao Drive
3. Na primeira vez, crie uma senha mestra — ela protege o conteúdo dentro do arquivo salvo no Drive
4. Pronto: cada credencial salva atualiza automaticamente o arquivo `cofre-vault.json` no Drive do usuário

## Limitações a saber

- O escopo usado (`drive.file`) só dá ao app acesso a **arquivos que ele mesmo criou** — não ao resto do Drive do usuário. É a opção mais segura para esse tipo de app.
- O login é feito por **redirecionamento de página inteira**, não por popup — assim nenhum bloqueador de pop-up do navegador interfere. A sessão fica salva no navegador (aba atual) e dura cerca de 1h; ao expirar, basta clicar em "Entrar com o Google" de novo.
- Para publicar oficialmente (sem a tela de aviso "app não verificado"), depois é preciso passar pela verificação do Google — opcional, só necessário se for distribuir para muita gente.
