
// ============================================================
// CONFIGURAÇÃO — preencha antes de publicar
// ============================================================
// 1. Crie um projeto em https://console.cloud.google.com
// 2. Ative a "Google Drive API"
// 3. Configure a tela de consentimento OAuth (External)
// 4. Crie uma credencial "ID do cliente OAuth 2.0" do tipo
//    "Aplicativo da Web"
// 5. Em "Origens JavaScript autorizadas", adicione a URL onde
//    você vai publicar (ex: https://seu-app.vercel.app)
// 6. Em "URIs de redirecionamento autorizados", adicione a
//    MESMA URL, exatamente igual (esse é o passo que faz o
//    login funcionar sem popup — veja o README.md)
// 7. Cole o Client ID gerado abaixo.
// ============================================================

const CONFIG = {
  GOOGLE_CLIENT_ID: "72017923244-vgi8ld2vak89r62uufppf3q8un7m2c57.apps.googleusercontent.com",
  DRIVE_FILE_NAME: "cofre-vault.json",
  // openid+profile+email para mostrar nome/foto, drive.file para
  // o app só poder ler/escrever arquivos que ele mesmo criou
  SCOPES: "openid email profile https://www.googleapis.com/auth/drive.file"
};

