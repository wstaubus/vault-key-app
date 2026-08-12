// ============================================================
// CONFIGURAÇÃO — preencha antes de publicar
// ============================================================
// 1. Crie um projeto em https://console.cloud.google.com
// 2. Ative a "Google Drive API"
// 3. Configure a tela de consentimento OAuth (External)
// 4. Crie uma credencial "ID do cliente OAuth 2.0" do tipo
//    "Aplicativo da Web"
// 5. Em "Origens JavaScript autorizadas" adicione a URL onde
//    você vai publicar este site (ex: https://seu-app.vercel.app)
//    e, se quiser testar localmente, http://localhost:5500
// 6. Cole o Client ID gerado abaixo.
// Veja o README.md para o passo a passo completo com prints.
// ============================================================

const CONFIG = {
  GOOGLE_CLIENT_ID: "COLE_SEU_CLIENT_ID_AQUI.apps.googleusercontent.com",
  DRIVE_FILE_NAME: "cofre-vault.json",
  DRIVE_SCOPE: "https://www.googleapis.com/auth/drive.file"
};
