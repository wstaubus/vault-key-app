// ============================================================
// Chave Mestra — sua única chave para tudo
// Login com Google + armazenamento no Google Drive
// ============================================================
const $ = id => document.getElementById(id);
const enc = new TextEncoder(), dec = new TextDecoder();
function b64(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function unb64(str){ return Uint8Array.from(atob(str), c=>c.charCodeAt(0)); }
function toast(msg){ const t=$('toast'); t.textContent=msg; t.classList.add('show'); setTimeout(()=>t.classList.remove('show'),2200); }
function fmtDate(iso){ return new Date(iso).toLocaleDateString('pt-BR',{day:'2-digit',month:'2-digit',year:'numeric'}); }
function escapeHtml(s){ return (s||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

// ---------- categorias ----------
const CATEGORIES = [
  { id:'financas', label:'Finanças', desc:'Bancos, cartões de crédito, investimentos e carteiras digitais.' },
  { id:'trabalho', label:'Trabalho', desc:'E-mails corporativos, ferramentas de gerenciamento e acessos da empresa.' },
  { id:'social', label:'Social', desc:'Redes sociais, aplicativos de mensagem e fóruns.' },
  { id:'essenciais', label:'Essenciais', desc:'E-mails pessoais, contas do governo e serviços de saúde.' },
  { id:'entretenimento', label:'Entretenimento', desc:'Streaming de vídeo, música, jogos e assinaturas de mídia.' },
  { id:'compras', label:'Compras', desc:'Lojas virtuais, aplicativos de entrega e sites de e-commerce.' },
  { id:'outros', label:'Outros', desc:'O que não se encaixa nas categorias acima.' }
];
function catLabel(id){ return (CATEGORIES.find(c => c.id === id) || CATEGORIES[CATEGORIES.length-1]).label; }
function populateCategorySelects(){
  $('fCategoria').innerHTML = CATEGORIES.map(c => `<option value="${c.id}">${c.label}</option>`).join('');
  $('categoryFilter').innerHTML = `<option value="">Todas as categorias</option>` + CATEGORIES.map(c => `<option value="${c.id}">${c.label}</option>`).join('');
}

// ---------- crypto ----------
async function deriveKey(password, saltB64){
  const salt = unb64(saltB64);
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:150000, hash:'SHA-256'}, baseKey, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}
async function encryptJSON(key, obj){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, enc.encode(JSON.stringify(obj)));
  return { iv:b64(iv), ct:b64(ct) };
}
async function decryptJSON(key, ivB64, ctB64){
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(ivB64)}, key, unb64(ctB64));
  return JSON.parse(dec.decode(pt));
}

// ---------- state ----------
let accessToken = null;
let googleUser = null;
let vaultKey = null;
let entries = [];
let driveFileId = null;
let editingId = null;
let pendingImage = '';

// ============================================================
// GOOGLE SIGN-IN — fluxo por redirecionamento (sem popup)
// ============================================================
// O navegador é levado para a tela de login do Google e volta
// para esta mesma URL com o token na fragment (#) do endereço.
// Como é uma navegação normal de página, bloqueadores de popup
// não têm efeito nenhum sobre esse fluxo.

const OAUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const USERINFO_ENDPOINT = 'https://www.googleapis.com/oauth2/v3/userinfo';
const SESSION_KEY = 'cofre_gauth_session';
const STATE_KEY = 'cofre_oauth_state';

function currentRedirectUri(){
  return window.location.origin + window.location.pathname;
}

function startGoogleLogin(){
  if(!CONFIG.GOOGLE_CLIENT_ID || CONFIG.GOOGLE_CLIENT_ID.includes('COLE_SEU_CLIENT_ID')){
    showLoginError('O app ainda não foi configurado: falta colar o Client ID do Google em config.js.');
    return;
  }
  const state = crypto.randomUUID();
  sessionStorage.setItem(STATE_KEY, state);
  const params = new URLSearchParams({
    client_id: CONFIG.GOOGLE_CLIENT_ID,
    redirect_uri: currentRedirectUri(),
    response_type: 'token',
    scope: CONFIG.SCOPES,
    include_granted_scopes: 'true',
    state,
    prompt: 'select_account'
  });
  // navegação de página inteira — não é popup, não é bloqueável
  window.location.href = `${OAUTH_ENDPOINT}?${params.toString()}`;
}

function parseAuthRedirect(){
  if(!window.location.hash) return null;
  const hash = new URLSearchParams(window.location.hash.slice(1));
  const result = {
    access_token: hash.get('access_token'),
    expires_in: hash.get('expires_in'),
    error: hash.get('error'),
    state: hash.get('state')
  };
  // limpa o hash da URL para não deixar o token visível/reutilizável
  history.replaceState(null, '', window.location.pathname + window.location.search);
  return (result.access_token || result.error) ? result : null;
}

async function restoreSession(){
  try{
    const raw = sessionStorage.getItem(SESSION_KEY);
    if(!raw) return false;
    const session = JSON.parse(raw);
    if(!session.access_token || Date.now() >= session.expires_at) return false;
    accessToken = session.access_token;
    googleUser = session.user;
    await afterAuth();
    return true;
  }catch(e){
    return false;
  }
}

async function handleRedirectReturn(){
  const result = parseAuthRedirect();
  if(!result) return false;

  if(result.error){
    showLoginError(mapAuthError(result.error));
    return true;
  }
  const expectedState = sessionStorage.getItem(STATE_KEY);
  if(!result.state || result.state !== expectedState){
    showLoginError('Não foi possível validar o retorno do Google. Tente entrar novamente.');
    return true;
  }
  sessionStorage.removeItem(STATE_KEY);
  accessToken = result.access_token;

  try{
    const r = await fetch(USERINFO_ENDPOINT, { headers:{ Authorization:`Bearer ${accessToken}` } });
    if(!r.ok) throw new Error('userinfo failed');
    const info = await r.json();
    googleUser = { name: info.name, email: info.email, picture: info.picture };
    const expiresAt = Date.now() + (Number(result.expires_in || 3600) * 1000);
    sessionStorage.setItem(SESSION_KEY, JSON.stringify({ access_token: accessToken, user: googleUser, expires_at: expiresAt }));
    await afterAuth();
  }catch(e){
    showLoginError('Login feito, mas não foi possível confirmar sua conta Google. Tente novamente.');
    showRetry(startGoogleLogin);
  }
  return true;
}

function mapAuthError(type){
  switch(type){
    case 'access_denied':
      return 'É necessário autorizar o acesso ao Google Drive para usar o cofre.';
    case 'invalid_request':
    case 'invalid_client':
      return 'O app não está configurado corretamente (Client ID ou URL de redirecionamento). Confira o config.js.';
    case 'redirect_uri_mismatch':
      return 'A URL deste site não está autorizada no Google Cloud. Adicione-a em "URIs de redirecionamento autorizados".';
    default:
      return 'Não foi possível conectar com sua conta Google. Tente novamente.';
  }
}
function showLoginError(msg){
  $('lockErr').textContent = msg;
  setSync('', '');
}
function showRetry(fn){
  const btn = $('retryBtn');
  btn.style.display = 'inline-block';
  btn.onclick = () => { btn.style.display = 'none'; $('lockErr').textContent=''; fn(); };
}

$('googleLoginBtn').onclick = startGoogleLogin;

populateCategorySelects();

// ao carregar a página: primeiro trata volta do redirecionamento,
// senão tenta retomar sessão já autorizada nesta aba
(async () => {
  const handled = await handleRedirectReturn();
  if(!handled) await restoreSession();
})();

// ============================================================
// GOOGLE DRIVE
// ============================================================
const DRIVE_API = 'https://www.googleapis.com/drive/v3';
const DRIVE_UPLOAD_API = 'https://www.googleapis.com/upload/drive/v3';

async function driveFetch(url, options={}){
  let r;
  try{
    r = await fetch(url, options);
  }catch(networkErr){
    throw new Error('Sem conexão com a internet. Verifique sua rede e tente novamente.');
  }
  if(r.status === 401){
    accessToken = null;
    sessionStorage.removeItem(SESSION_KEY);
    throw new Error('SESSION_EXPIRED');
  }
  if(!r.ok){
    throw new Error('O Google Drive não respondeu como esperado. Tente novamente em instantes.');
  }
  return r;
}

async function driveFindFile(){
  const q = encodeURIComponent(`name='${CONFIG.DRIVE_FILE_NAME}' and trashed=false`);
  const r = await driveFetch(`${DRIVE_API}/files?q=${q}&fields=files(id,name,modifiedTime)`, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  const data = await r.json();
  return (data.files && data.files[0]) || null;
}
async function driveReadFile(fileId){
  const r = await driveFetch(`${DRIVE_API}/files/${fileId}?alt=media`, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  return r.json();
}
async function driveCreateFile(content){
  const boundary = 'cofre_boundary';
  const metadata = { name: CONFIG.DRIVE_FILE_NAME, mimeType: 'application/json' };
  const body =
    `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n` +
    `--${boundary}\r\nContent-Type: application/json\r\n\r\n${JSON.stringify(content)}\r\n--${boundary}--`;
  const r = await driveFetch(`${DRIVE_UPLOAD_API}/files?uploadType=multipart&fields=id`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': `multipart/related; boundary=${boundary}` },
    body
  });
  const data = await r.json();
  return data.id;
}
async function driveUpdateFile(fileId, content){
  await driveFetch(`${DRIVE_UPLOAD_API}/files/${fileId}?uploadType=media`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(content)
  });
}

// ============================================================
// AUTH FLOW
// ============================================================
async function afterAuth(){
  $('userChip').innerHTML = `<img src="${googleUser?.picture||''}"><span>${googleUser?.email||'Conta Google'}</span>`;
  $('lockErr').textContent = '';
  setSync('Procurando cofre no Google Drive...', 'saving');

  try{
    const existing = await driveFindFile();
    if(existing){
      driveFileId = existing.id;
      const remote = await driveReadFile(driveFileId);
      showMasterPasswordGate(remote, false);
    } else {
      showMasterPasswordGate(null, true);
    }
    setSync('');
  }catch(e){
    setSync('', '');
    if(e.message === 'SESSION_EXPIRED'){
      showLoginError('Sua sessão do Google expirou. Clique em Entrar novamente.');
      $('gsiStep').style.display = 'block';
      $('pwStep').style.display = 'none';
    } else {
      showLoginError(e.message || 'Não foi possível acessar o Google Drive.');
      showRetry(afterAuth);
    }
  }
}

function showMasterPasswordGate(remote, isNew){
  $('gsiStep').style.display = 'none';
  $('pwStep').style.display = 'block';
  $('pwStepTitle').textContent = isNew ? 'Crie uma senha mestra' : 'Digite sua senha mestra';
  $('pwStepSub').textContent = isNew
    ? 'Vamos criar um cofre novo no seu Drive, protegido por essa senha (ela nunca sai do seu navegador).'
    : 'Encontramos um cofre no seu Drive. Digite a senha para abri-lo.';
  $('pwConfirmField').style.display = isNew ? 'block' : 'none';
  $('pwSubmitBtn').onclick = () => isNew ? createVault() : openVault(remote);
}

async function createVault(){
  const pw = $('pwInput').value, conf = $('pwConfirmInput').value;
  $('lockErr').textContent = '';
  if(pw.length < 6){ $('lockErr').textContent = 'Use ao menos 6 caracteres.'; return; }
  if(pw !== conf){ $('lockErr').textContent = 'As senhas não coincidem.'; return; }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltB64 = b64(salt);
  vaultKey = await deriveKey(pw, saltB64);
  const verifier = await encryptJSON(vaultKey, {check:'ok'});
  entries = [];
  const dataPart = await encryptJSON(vaultKey, entries);

  const remoteObj = { salt:saltB64, verifierIv:verifier.iv, verifierCt:verifier.ct, dataIv:dataPart.iv, dataCt:dataPart.ct };
  setSync('Criando cofre no Google Drive...', 'saving');
  try{
    driveFileId = await driveCreateFile(remoteObj);
    setSync('Sincronizado com o Google Drive');
    enterApp();
  }catch(e){
    setSync('', '');
    showLoginError(e.message === 'SESSION_EXPIRED' ? 'Sua sessão do Google expirou. Faça login novamente.' : (e.message || 'Não foi possível criar o cofre no Google Drive.'));
    showRetry(createVault);
  }
}

async function openVault(remote){
  const pw = $('pwInput').value;
  $('lockErr').textContent = '';
  try{
    vaultKey = await deriveKey(pw, remote.salt);
    await decryptJSON(vaultKey, remote.verifierIv, remote.verifierCt);
    entries = await decryptJSON(vaultKey, remote.dataIv, remote.dataCt);
    setSync('Sincronizado com o Google Drive');
    enterApp();
  }catch(e){
    $('lockErr').textContent = 'Senha incorreta.';
  }
}

function enterApp(){
  $('lockWrap').style.display = 'none';
  $('app').classList.add('active');
  $('pwInput').value=''; $('pwConfirmInput').value='';
  render();
}

$('signOutBtn').onclick = () => {
  sessionStorage.removeItem(SESSION_KEY);
  accessToken = null; googleUser = null; vaultKey = null; entries = []; driveFileId = null;
  $('app').classList.remove('active');
  $('lockWrap').style.display = 'flex';
  $('gsiStep').style.display = 'block';
  $('pwStep').style.display = 'none';
};

function setSync(msg, cls){
  const el = $('syncStatus');
  el.textContent = msg;
  el.className = 'sync-status' + (cls ? ' '+cls : '');
}

// ============================================================
// PERSIST TO DRIVE
// ============================================================
let saveTimer = null;
async function persistVault(){
  setSync('Salvando no Google Drive...', 'saving');
  try{
    const dataPart = await encryptJSON(vaultKey, entries);
    // re-read current meta (salt/verifier) so we only overwrite data fields
    const current = await driveReadFile(driveFileId);
    const merged = { ...current, dataIv: dataPart.iv, dataCt: dataPart.ct };
    await driveUpdateFile(driveFileId, merged);
    setSync('Sincronizado com o Google Drive');
  }catch(e){
    if(e.message === 'SESSION_EXPIRED'){
      setSync('Sessão expirada — faça login novamente para continuar salvando', 'err');
      toast('Sua sessão do Google expirou');
    } else {
      setSync('Falha ao salvar no Drive — verifique sua internet', 'err');
      toast('Não foi possível salvar no Google Drive');
    }
  }
}

// ============================================================
// RENDER / CRUD (same vault UI as before)
// ============================================================
function render(){
  const q = $('searchInput').value.trim().toLowerCase();
  const cat = $('categoryFilter').value;
  const list = entries.filter(e => e.nome.toLowerCase().includes(q) && (!cat || e.categoria === cat));
  const grid = $('grid');
  grid.innerHTML = '';
  $('emptyState').style.display = list.length ? 'none' : 'block';
  list.sort((a,b) => new Date(b.atualizadoEm) - new Date(a.atualizadoEm));

  for(const e of list){
    const card = document.createElement('div');
    card.className = 'card-item';
    const initial = (e.nome||'?').trim().charAt(0).toUpperCase();
    const catId = e.categoria || 'outros';
    card.innerHTML = `
      <div class="card-top">
        ${e.imagem ? `<img class="card-img" src="${e.imagem}">` : `<div class="card-img placeholder">${initial}</div>`}
        <div class="card-titles">
          <p class="name">${escapeHtml(e.nome)}</p>
          ${e.link ? `<a href="${escapeHtml(e.link)}" target="_blank" rel="noopener">${escapeHtml(e.link)}</a>` : ''}
        </div>
      </div>
      <span class="cat-badge cat-${catId}">${catLabel(catId)}</span>
      ${e.login ? `<p class="card-login">👤 ${escapeHtml(e.login)}</p>` : ''}
      ${e.descritivo ? `<p class="card-desc">${escapeHtml(e.descritivo)}</p>` : ''}
      <div class="pw-row">
        <span class="pw-text" data-pw="${escapeHtml(e.senha)}" data-visible="false">••••••••••</span>
        <button class="icon-btn btn-toggle" title="Mostrar/ocultar">👁</button>
        <button class="icon-btn btn-copy" title="Copiar senha">⧉</button>
      </div>
      <div class="card-foot">
        <span class="stamp">Atualizado ${fmtDate(e.atualizadoEm)}</span>
        <div class="card-menu">
          <button class="icon-btn btn-edit" title="Editar">✎</button>
          <button class="icon-btn btn-del" title="Excluir">🗑</button>
        </div>
      </div>`;
    card.querySelector('.btn-toggle').onclick = () => {
      const span = card.querySelector('.pw-text');
      const visible = span.dataset.visible === 'true';
      span.textContent = visible ? '••••••••••' : span.dataset.pw;
      span.dataset.visible = String(!visible);
    };
    card.querySelector('.btn-copy').onclick = async () => {
      try{ await navigator.clipboard.writeText(e.senha); toast('Senha copiada'); }catch(err){ toast('Não foi possível copiar'); }
    };
    card.querySelector('.btn-edit').onclick = () => openModal(e);
    card.querySelector('.btn-del').onclick = async () => {
      if(!confirm(`Excluir "${e.nome}"?`)) return;
      entries = entries.filter(x => x.id !== e.id);
      await persistVault();
      render();
      toast('Excluído');
    };
    grid.appendChild(card);
  }
}
$('searchInput').oninput = render;
$('categoryFilter').onchange = render;

function openModal(entry){
  editingId = entry ? entry.id : null;
  $('modalTitle').textContent = entry ? 'Editar credencial' : 'Nova credencial';
  $('fName').value = entry?.nome || '';
  $('fCategoria').value = entry?.categoria || 'outros';
  $('fLogin').value = entry?.login || '';
  $('fSenha').value = entry?.senha || '';
  $('fLink').value = entry?.link || '';
  $('fDesc').value = entry?.descritivo || '';
  pendingImage = entry?.imagem || '';
  $('imgPreview').src = pendingImage || 'data:image/svg+xml,%3Csvg xmlns="http://www.w3.org/2000/svg" width="56" height="56"%3E%3Crect width="56" height="56" fill="%23242220"/%3E%3C/svg%3E';
  $('imgInput').value = '';
  $('overlay').classList.add('active');
}
$('btnNew').onclick = () => openModal(null);
$('btnCancel').onclick = () => $('overlay').classList.remove('active');
$('overlay').onclick = (e) => { if(e.target.id === 'overlay') $('overlay').classList.remove('active'); };

$('imgInput').onchange = (e) => {
  const file = e.target.files[0];
  if(!file) return;
  const reader = new FileReader();
  reader.onload = (ev) => {
    const img = new Image();
    img.onload = () => {
      const size = 160;
      const canvas = document.createElement('canvas');
      canvas.width = size; canvas.height = size;
      const ctx = canvas.getContext('2d');
      const scale = Math.max(size/img.width, size/img.height);
      const w = img.width*scale, h = img.height*scale;
      ctx.drawImage(img, (size-w)/2, (size-h)/2, w, h);
      pendingImage = canvas.toDataURL('image/jpeg', 0.75);
      $('imgPreview').src = pendingImage;
    };
    img.src = ev.target.result;
  };
  reader.readAsDataURL(file);
};

$('btnSave').onclick = async () => {
  const nome = $('fName').value.trim();
  if(!nome){ toast('Dê um nome para a credencial'); return; }
  const now = new Date().toISOString();
  if(editingId){
    const e = entries.find(x => x.id === editingId);
    Object.assign(e, { nome, categoria:$('fCategoria').value, login:$('fLogin').value.trim(), senha:$('fSenha').value, link:$('fLink').value.trim(), descritivo:$('fDesc').value.trim(), imagem:pendingImage, atualizadoEm:now });
  } else {
    entries.push({ id:crypto.randomUUID(), nome, categoria:$('fCategoria').value, login:$('fLogin').value.trim(), senha:$('fSenha').value, link:$('fLink').value.trim(), descritivo:$('fDesc').value.trim(), imagem:pendingImage, criadoEm:now, atualizadoEm:now });
  }
  await persistVault();
  $('overlay').classList.remove('active');
  render();
  toast('Salvo no Google Drive');
};
