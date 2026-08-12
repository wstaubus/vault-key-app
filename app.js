// ============================================================
// Cofre — login com Google + armazenamento no Google Drive
// ============================================================
const $ = id => document.getElementById(id);
const enc = new TextEncoder(), dec = new TextDecoder();
function b64(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function unb64(str){ return Uint8Array.from(atob(str), c=>c.charCodeAt(0)); }
function toast(msg){ const t=$('toast'); t.textContent=msg; t.classList.add('show'); setTimeout(()=>t.classList.remove('show'),2200); }
function fmtDate(iso){ return new Date(iso).toLocaleDateString('pt-BR',{day:'2-digit',month:'2-digit',year:'numeric'}); }
function escapeHtml(s){ return (s||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

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
let tokenClient = null;

// ============================================================
// GOOGLE SIGN-IN (Identity Services)
// ============================================================
window.onGsiLoad = function(){
  google.accounts.id.initialize({
    client_id: CONFIG.GOOGLE_CLIENT_ID,
    callback: handleCredentialResponse
  });
  google.accounts.id.renderButton($('gsiButtonWrap'), { theme:'filled_black', size:'large', shape:'pill', text:'signin_with' });

  tokenClient = google.accounts.oauth2.initTokenClient({
    client_id: CONFIG.GOOGLE_CLIENT_ID,
    scope: CONFIG.DRIVE_SCOPE,
    callback: async (resp) => {
      if(resp.error){ $('lockErr').textContent = 'Falha ao autorizar o Google Drive.'; return; }
      accessToken = resp.access_token;
      await afterAuth();
    }
  });
};

function handleCredentialResponse(response){
  // decode the JWT just to show name/photo — the real Drive access
  // comes from the separate token client below.
  const payload = JSON.parse(atob(response.credential.split('.')[1]));
  googleUser = { name: payload.name, email: payload.email, picture: payload.picture };
  // now request the Drive access token
  tokenClient.requestAccessToken({ prompt: '' });
}

// ============================================================
// GOOGLE DRIVE
// ============================================================
const DRIVE_API = 'https://www.googleapis.com/drive/v3';
const DRIVE_UPLOAD_API = 'https://www.googleapis.com/upload/drive/v3';

async function driveFindFile(){
  const q = encodeURIComponent(`name='${CONFIG.DRIVE_FILE_NAME}' and trashed=false`);
  const r = await fetch(`${DRIVE_API}/files?q=${q}&fields=files(id,name,modifiedTime)`, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  const data = await r.json();
  return (data.files && data.files[0]) || null;
}
async function driveReadFile(fileId){
  const r = await fetch(`${DRIVE_API}/files/${fileId}?alt=media`, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  if(!r.ok) throw new Error('drive read failed');
  return r.json();
}
async function driveCreateFile(content){
  const boundary = 'cofre_boundary';
  const metadata = { name: CONFIG.DRIVE_FILE_NAME, mimeType: 'application/json' };
  const body =
    `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n` +
    `--${boundary}\r\nContent-Type: application/json\r\n\r\n${JSON.stringify(content)}\r\n--${boundary}--`;
  const r = await fetch(`${DRIVE_UPLOAD_API}/files?uploadType=multipart&fields=id`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': `multipart/related; boundary=${boundary}` },
    body
  });
  const data = await r.json();
  return data.id;
}
async function driveUpdateFile(fileId, content){
  await fetch(`${DRIVE_UPLOAD_API}/files/${fileId}?uploadType=media`, {
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

  const existing = await driveFindFile();
  if(existing){
    driveFileId = existing.id;
    const remote = await driveReadFile(driveFileId);
    // remote = { salt, verifierIv, verifierCt, dataIv, dataCt }
    showMasterPasswordGate(remote, false);
  } else {
    showMasterPasswordGate(null, true);
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
  driveFileId = await driveCreateFile(remoteObj);
  setSync('Sincronizado com o Google Drive');
  enterApp();
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
  google.accounts.id.disableAutoSelect();
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
    setSync('Falha ao salvar no Drive — tentando de novo', 'err');
  }
}

// ============================================================
// RENDER / CRUD (same vault UI as before)
// ============================================================
function render(){
  const q = $('searchInput').value.trim().toLowerCase();
  const list = entries.filter(e => e.nome.toLowerCase().includes(q));
  const grid = $('grid');
  grid.innerHTML = '';
  $('emptyState').style.display = list.length ? 'none' : 'block';
  list.sort((a,b) => new Date(b.atualizadoEm) - new Date(a.atualizadoEm));

  for(const e of list){
    const card = document.createElement('div');
    card.className = 'card-item';
    const initial = (e.nome||'?').trim().charAt(0).toUpperCase();
    card.innerHTML = `
      <div class="card-top">
        ${e.imagem ? `<img class="card-img" src="${e.imagem}">` : `<div class="card-img placeholder">${initial}</div>`}
        <div class="card-titles">
          <p class="name">${escapeHtml(e.nome)}</p>
          ${e.link ? `<a href="${escapeHtml(e.link)}" target="_blank" rel="noopener">${escapeHtml(e.link)}</a>` : ''}
        </div>
      </div>
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

function openModal(entry){
  editingId = entry ? entry.id : null;
  $('modalTitle').textContent = entry ? 'Editar credencial' : 'Nova credencial';
  $('fName').value = entry?.nome || '';
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
    Object.assign(e, { nome, senha:$('fSenha').value, link:$('fLink').value.trim(), descritivo:$('fDesc').value.trim(), imagem:pendingImage, atualizadoEm:now });
  } else {
    entries.push({ id:crypto.randomUUID(), nome, senha:$('fSenha').value, link:$('fLink').value.trim(), descritivo:$('fDesc').value.trim(), imagem:pendingImage, criadoEm:now, atualizadoEm:now });
  }
  await persistVault();
  $('overlay').classList.remove('active');
  render();
  toast('Salvo no Google Drive');
};
