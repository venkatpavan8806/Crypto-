/* script.js
   Full replacement for Cryptography Learning Platform frontend behavior.
   - Auto-creates cipher modal if missing
   - Wires .cipher-card clicks (data-tool or inline onclick)
   - Implements classical ciphers (Caesar, Vigenere, Atbash, Substitution, Affine, Playfair, Hill 2x2, OTP, Autokey, Polybius, A1Z26, Baconian, RailFence, Columnar)
   - Implements modern tools (Hashing: SHA-* via WebCrypto, MD5 fallback; HMAC; PBKDF2; AES-GCM encrypt/decrypt; RSA-OAEP demo; ECDH demo; Random generator; Encoding helpers; RC4 & XOR demos)
   - Basic cipher identifier / analysis utilities
   - Login/Register demo wiring
   - Defensive: checks for element existence before acting
   - No Detective Game code
   Drop into your project as script.js (overwrite).
*/

/* -----------------------
   Small utilities
   ----------------------- */
const $ = id => document.getElementById(id);
const qS = sel => document.querySelector(sel);
const qSA = sel => Array.from(document.querySelectorAll(sel));
// New auth system flag to disable legacy demo handlers
window.__USE_NEW_AUTH__ = true;

function show(el){ if(!el) return; el.style.display = ''; }
function hide(el){ if(!el) return; el.style.display = 'none'; }

function utf8ToBuf(s){ return new TextEncoder().encode(s).buffer; }
function bufToUtf8(b){ try { return new TextDecoder().decode(b); } catch(e){ return ''; } }
function toHex(buf){
    const u = new Uint8Array(buf);
    return Array.from(u).map(x => x.toString(16).padStart(2,'0')).join('');
}
function fromHex(hex=''){
    hex = (hex||'').replace(/[^0-9a-fA-F]/g,'');
    if(hex.length % 2) hex = '0' + hex;
    const bytes = new Uint8Array(hex.length/2);
    for(let i=0;i<hex.length;i+=2) bytes[i/2] = parseInt(hex.substr(i,2),16);
    return bytes.buffer;
}
function base64Encode(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function base64Decode(s){ const raw = atob(s); const a = new Uint8Array(raw.length); for(let i=0;i<raw.length;i++) a[i]=raw.charCodeAt(i); return a.buffer; }
function randHex(n=16){ const a = new Uint8Array(n); crypto.getRandomValues(a); return Array.from(a).map(x=>x.toString(16).padStart(2,'0')).join(''); }

/* -----------------------
   Modal + Navigation helpers
   ----------------------- */
function navigateToPage(page){ if(!page) return; window.location.href = page; }

function ensureCipherModal(){
    let modal = $('cipherModal');
    if(!modal){
        modal = document.createElement('div');
        modal.id = 'cipherModal';
        modal.className = 'modal';
        modal.style.display = 'none';
        modal.innerHTML = `
          <div class="modal-content">
            <span class="close" onclick="closeModal('cipherModal')">&times;</span>
            <div id="cipherContent"></div>
          </div>`;
        document.body.appendChild(modal);
    }
    // ensure cipherContent inside modal exists
    if(!$('cipherContent')){
        const content = document.createElement('div'); content.id = 'cipherContent';
        const mc = modal.querySelector('.modal-content');
        if(mc) mc.appendChild(content);
    }
    return modal;
}

function openModal(id){
    const m = $(id);
    if(m) m.style.display = 'block';
}
function closeModal(id){
    const m = $(id);
    if(m) m.style.display = 'none';
}
window.addEventListener('click', (e)=>{
    // close modal if clicked outside content
    if(e.target && e.target.classList && e.target.classList.contains('modal')){
        e.target.style.display = 'none';
    }
});
window.addEventListener('keydown', (e)=>{
    if(e.key === 'Escape'){
        const modal = $('cipherModal'); if(modal && modal.style.display === 'block') modal.style.display = 'none';
    }
});

/* -----------------------
   Login / Register (simple demo)
   ----------------------- */
function showLoginForm(){ openModal('loginModal'); }
function showRegisterForm(){ openModal('registerModal'); }
function logout(){
    localStorage.removeItem('cl_user');
    const l = $('loggedIn'), nl = $('notLoggedIn');
    if(l) l.style.display='none';
    if(nl) nl.style.display='';
    location.reload();
}

document.addEventListener('DOMContentLoaded', ()=>{
    // If using the new auth system, skip legacy demo wiring
    if (window.__USE_NEW_AUTH__) return;
    // wire login/register forms if present
    const loginForm = $('loginForm');
    if(loginForm){
        loginForm.addEventListener('submit', e=>{
            e.preventDefault();
            const u = $('loginUsername') ? $('loginUsername').value.trim() : '';
            if(u) localStorage.setItem('cl_user', u);
            closeModal('loginModal');
            location.reload();
        });
    }
    const registerForm = $('registerForm');
    if(registerForm){
        registerForm.addEventListener('submit', e=>{
            e.preventDefault();
            const u = $('registerUsername') ? $('registerUsername').value.trim() : '';
            if(u) localStorage.setItem('cl_user', u);
            closeModal('registerModal');
            location.reload();
        });
    }
    // display username if logged in
    const user = localStorage.getItem('cl_user');
    if(user){
        const logged = $('loggedIn'), notLogged = $('notLoggedIn');
        if(logged && notLogged){
            notLogged.style.display='none';
            logged.style.display='';
            const disp = $('usernameDisplay'); if(disp) disp.textContent = '👤 ' + user;
        }
    }
});

/* -----------------------
   Cipher/card wiring
   - supports .cipher-card elements with:
     * data-tool="caesar" OR
     * onclick="showCipher('caesar')"
   - auto-creates modal if missing
   ----------------------- */
function bindCipherCards(){
    ensureCipherModal();
    qSA('.cipher-card').forEach(card=>{
        if(card.dataset.bound) return;
        const clickHandler = () => {
            // preference: data-tool attribute, else try to parse onclick attribute
            const tool = card.dataset.tool || (card.getAttribute('onclick') || '').match(/showCipher\(['"]([^'"]+)['"]\)/)?.[1];
            if(tool) showCipher(tool);
        };
        card.addEventListener('click', clickHandler);
        card.dataset.bound = '1';
    });
}
document.addEventListener('DOMContentLoaded', bindCipherCards);

/* -----------------------
   showCipher: entry point for modal content
   - builds UI for each tool and wires action handlers
   ----------------------- */
function showCipher(name){
    ensureCipherModal();
    const content = $('cipherContent');
    if(!content) return;
    content.innerHTML = ''; // clear
    const tool = (name || '').toLowerCase();

    // small UI helpers (local)
    const label = txt => { const l = document.createElement('label'); l.textContent = txt; l.style.color='#e1bee7'; l.style.display='block'; l.style.marginTop='8px'; return l; };
    const input = (id, ph='', rows=1) => {
        let el = rows>1 ? document.createElement('textarea') : document.createElement('input');
        if(rows>1) el.rows = rows;
        el.id = id; el.placeholder = ph; el.style.width='100%'; el.style.padding='10px'; el.style.marginTop='6px';
        el.style.background='rgba(26,26,26,0.9)'; el.style.color='#e0e0e0'; el.style.border='1px solid #4a148c'; el.style.borderRadius='6px';
        return el;
    };
    const btn = (text, fn) => {
        const b = document.createElement('button'); b.textContent = text; b.className='btn'; b.style.margin='8px 8px 8px 0'; b.addEventListener('click', fn); return b;
    };
    const resultBox = id => { const r = document.createElement('div'); r.id = id || ''; r.className='result-box'; r.style.marginTop='10px'; r.style.whiteSpace='pre-wrap'; return r; };
    const explain = () => { const e = document.createElement('div'); e.className='explain-box'; e.style.marginTop='10px'; e.style.color='#d1c4e9'; return e; };

    // builder map
    const builders = {
        'caesar': buildCaesar,
        'atbash': buildAtbash,
        'vigenere': buildVigenere,
        'autokey': buildAutokey,
        'substitution': buildSubstitution,
        'affine': buildAffine,
        'playfair': buildPlayfair,
        'hill': buildHill,
        'polybius': buildPolybius,
        'a1z26': buildA1Z26,
        'baconian': buildBaconian,
        'trithemius': buildTrithemius,
        'railfence': buildRailFence,
        'columnar': buildColumnar,
        'scytale': buildScytale,
        'otp': buildOTP,
        'solitaire': buildSolitaire,
        // modern
        'hash': buildHashSelector,
        'sha-1': (c)=>buildHash(c,'SHA-1'),
        'sha-256': (c)=>buildHash(c,'SHA-256'),
        'sha-384': (c)=>buildHash(c,'SHA-384'),
        'sha-512': (c)=>buildHash(c,'SHA-512'),
        'md5': buildMD5,
        'hmac': buildHMAC,
        'pbkdf2': buildPBKDF2,
        'aes': buildAES,
        'rsa': buildRSA,
        'diffie': buildECDH,
        'rc4': buildRC4,
        'xor': buildXOR,
        'random': buildRandom,
        'encoding': buildEncoding,
        'cipherid': buildCipherIdentifier,
        'default': buildDefault
    };

    const builder = builders[tool] || builders['default'];
    builder(content);

    openModal('cipherModal');

    /* =========================
       Individual builders
       ========================= */

    // ---- Classical ----
    function buildCaesar(c){
        c.appendChild(createHeading('Caesar Cipher'));
        c.appendChild(label('Text'));
        const txt = input('caesarText','','4'); txt.rows=4; c.appendChild(txt);
        c.appendChild(label('Shift (0-25)')); const k = input('caesarShift','3'); k.type='number'; k.value='3'; c.appendChild(k);
        const res = resultBox('caesarResult'); const expl = explain();
        c.appendChild(btn('Encrypt', ()=> { res.textContent = caesarEncrypt(txt.value, parseInt(k.value)||0); expl.textContent = 'Shift forwards'; }));
        c.appendChild(btn('Decrypt', ()=> { res.textContent = caesarDecrypt(txt.value, parseInt(k.value)||0); expl.textContent = 'Shift backwards'; }));
        c.appendChild(res); c.appendChild(expl);
    }
    function buildAtbash(c){
        c.appendChild(createHeading('Atbash Cipher'));
        c.appendChild(label('Text'));
        const txt = input('atbashText','','4'); txt.rows=4; c.appendChild(txt);
        const res = resultBox('atbashResult');
        c.appendChild(btn('Transform', ()=> res.textContent = atbashTransform(txt.value)));
        c.appendChild(res);
    }
    function buildVigenere(c){
        c.appendChild(createHeading('Vigenère Cipher'));
        c.appendChild(label('Text')); const txt = input('vigenText','','4'); txt.rows=4; c.appendChild(txt);
        c.appendChild(label('Keyword')); const key = input('vigenKey','KEY'); c.appendChild(key);
        const res = resultBox('vigenResult'); c.appendChild(btn('Encrypt', ()=> res.textContent = vigenereEncrypt(txt.value, key.value))); c.appendChild(btn('Decrypt', ()=> res.textContent = vigenereDecrypt(txt.value, key.value)));
        c.appendChild(res);
    }
    function buildAutokey(c){
        c.appendChild(createHeading('Autokey Cipher'));
        c.appendChild(label('Text')); const txt = input('autokeyText','','4'); txt.rows=4; c.appendChild(txt);
        c.appendChild(label('Initial Key')); const key = input('autokeyKey','KEY'); c.appendChild(key);
        const res = resultBox('autokeyResult');
        c.appendChild(btn('Encrypt', ()=> res.textContent = autokeyEncrypt(txt.value, key.value)));
        c.appendChild(btn('Decrypt', ()=> res.textContent = autokeyDecrypt(txt.value, key.value)));
        c.appendChild(res);
    }
    function buildSubstitution(c){
        c.appendChild(createHeading('Substitution Cipher'));
        c.appendChild(label('Text')); const txt = input('subText','','4'); txt.rows=4; c.appendChild(txt);
        c.appendChild(label('26-letter key (A→key[0], B→key[1],...)')); const key = input('subKey','QWERTYUIOPASDFGHJKLZXCVBNM'); c.appendChild(key);
        const res = resultBox('subResult');
        c.appendChild(btn('Encrypt', ()=> {
            const k = (key.value||'').toUpperCase().replace(/[^A-Z]/g,'');
            if(k.length !== 26){ alert('Key must be 26 letters'); return; }
            res.textContent = substitutionEncrypt(txt.value, k);
        }));
        c.appendChild(btn('Decrypt', ()=> {
            const k = (key.value||'').toUpperCase().replace(/[^A-Z]/g,'');
            if(k.length !== 26){ alert('Key must be 26 letters'); return; }
            res.textContent = substitutionDecrypt(txt.value, k);
        }));
        c.appendChild(res);
    }
    function buildAffine(c){
        c.appendChild(createHeading('Affine Cipher'));
        c.appendChild(label('Text')); const txt = input('affineText','','4'); txt.rows=4; c.appendChild(txt);
        c.appendChild(label('a (must be coprime with 26)')); const a = input('affineA','5'); a.type='number'; c.appendChild(a);
        c.appendChild(label('b')); const b = input('affineB','8'); b.type='number'; c.appendChild(b);
        const res = resultBox('affineResult');
        c.appendChild(btn('Encrypt', ()=> {
            const ai = parseInt(a.value)||0, bi = parseInt(b.value)||0;
            if(gcd(ai,26)!==1){ alert('a must be coprime with 26'); return; }
            res.textContent = affineEncrypt(txt.value, ai, bi);
        }));
        c.appendChild(btn('Decrypt', ()=> {
            const ai = parseInt(a.value)||0, bi = parseInt(b.value)||0;
            if(modInverse(ai,26)===null){ alert('No inverse for a'); return; }
            res.textContent = affineDecrypt(txt.value, ai, bi);
        }));
        c.appendChild(res);
    }
    function buildPlayfair(c){
        c.appendChild(createHeading('Playfair Cipher'));
        c.appendChild(label('Text')); const txt = input('playfairText','','4'); txt.rows=4; c.appendChild(txt);
        c.appendChild(label('Keyword')); const key = input('playfairKey','KEY'); c.appendChild(key);
        const res = resultBox('playfairResult');
        c.appendChild(btn('Encrypt', ()=> res.textContent = playfairEncrypt(txt.value, key.value)));
        c.appendChild(btn('Decrypt', ()=> res.textContent = playfairDecrypt(txt.value, key.value)));
        c.appendChild(res);
    }
    function buildHill(c){
        c.appendChild(createHeading('Hill Cipher (2x2 demo)'));
        c.appendChild(label('Text (A-Z only)')); const txt = input('hillText','','1'); txt.rows=2; c.appendChild(txt);
        c.appendChild(label('Key matrix (2x2) entries:'));
        const k00 = input('k00','3'); const k01 = input('k01','3'); const k10 = input('k10','2'); const k11 = input('k11','5');
        k00.type=k01.type=k10.type=k11.type='number';
        const containerGrid = document.createElement('div'); containerGrid.style.display='flex'; containerGrid.style.gap='6px';
        containerGrid.appendChild(k00); containerGrid.appendChild(k01); containerGrid.appendChild(k10); containerGrid.appendChild(k11);
        c.appendChild(containerGrid);
        const res = resultBox('hillResult');
        c.appendChild(btn('Encrypt (2x2)', ()=>{
            try{ res.textContent = hillEncrypt2x2(txt.value, [[parseInt(k00.value),parseInt(k01.value)],[parseInt(k10.value),parseInt(k11.value)]]); } catch(e){ res.textContent = 'Error: '+e.message; }
        }));
        c.appendChild(btn('Decrypt (2x2)', ()=>{
            try{ res.textContent = hillDecrypt2x2(txt.value, [[parseInt(k00.value),parseInt(k01.value)],[parseInt(k10.value),parseInt(k11.value)]]); } catch(e){ res.textContent = 'Error: '+e.message; }
        }));
        c.appendChild(res);
    }
    function buildPolybius(c){
        c.appendChild(createHeading('Polybius Square'));
        c.appendChild(label('Text / digits')); const txt = input('polybiusText','','3'); txt.rows=3; c.appendChild(txt);
        const res = resultBox('polyRes');
        c.appendChild(btn('Encode', ()=> res.textContent = polybiusEncode(txt.value)));
        c.appendChild(btn('Decode', ()=> res.textContent = polybiusDecode(txt.value)));
        c.appendChild(res);
    }
    function buildA1Z26(c){
        c.appendChild(createHeading('A1Z26'));
        c.appendChild(label('Text or numbers')); const txt = input('a1z26Text','','2'); txt.rows=2; c.appendChild(txt);
        const res = resultBox('a1z26Res');
        c.appendChild(btn('Encode (A→1)', ()=> res.textContent = a1z26Encode(txt.value)));
        c.appendChild(btn('Decode (1→A)', ()=> res.textContent = a1z26Decode(txt.value)));
        c.appendChild(res);
    }
    function buildBaconian(c){
        c.appendChild(createHeading('Baconian Cipher'));
        c.appendChild(label('Text or A/B groups (space separated)')); const txt = input('baconText','','3'); txt.rows=3; c.appendChild(txt);
        const res = resultBox('baconRes');
        c.appendChild(btn('Encode', ()=> res.textContent = baconianEncode(txt.value)));
        c.appendChild(btn('Decode', ()=> res.textContent = baconianDecode(txt.value)));
        c.appendChild(res);
    }
    function buildTrithemius(c){
        c.appendChild(createHeading('Trithemius (progressive Caesar)'));
        c.appendChild(label('Text')); const txt = input('tritText','','3'); txt.rows=3; c.appendChild(txt);
        c.appendChild(label('Start shift')); const s = input('tritStart','0'); s.type='number'; s.value='0'; c.appendChild(s);
        const res = resultBox('tritRes');
        c.appendChild(btn('Encrypt', ()=> res.textContent = trithemiusEncrypt(txt.value, parseInt(s.value)||0)));
        c.appendChild(btn('Decrypt', ()=> res.textContent = trithemiusDecrypt(txt.value, parseInt(s.value)||0)));
        c.appendChild(res);
    }
    function buildRailFence(c){
        c.appendChild(createHeading('Rail Fence'));
        c.appendChild(label('Text')); const txt = input('railText','','3'); txt.rows=3; c.appendChild(txt);
        c.appendChild(label('Rails')); const rails = input('railCount','3'); rails.type='number'; rails.value='3'; c.appendChild(rails);
        const res = resultBox('railRes');
        c.appendChild(btn('Encrypt', ()=> res.textContent = railFenceEncrypt(txt.value, parseInt(rails.value)||3)));
        c.appendChild(btn('Decrypt', ()=> res.textContent = railFenceDecrypt(txt.value, parseInt(rails.value)||3)));
        c.appendChild(res);
    }
    function buildColumnar(c){
        c.appendChild(createHeading('Columnar Transposition'));
        c.appendChild(label('Text')); const txt = input('colText','','3'); txt.rows=3; c.appendChild(txt);
        c.appendChild(label('Keyword')); const key = input('colKey','KEY'); c.appendChild(key);
        const res = resultBox('colRes');
        c.appendChild(btn('Encrypt', ()=> res.textContent = columnarEncrypt(txt.value, key.value)));
        c.appendChild(btn('Decrypt', ()=> res.textContent = columnarDecrypt(txt.value, key.value)));
        c.appendChild(res);
    }
    function buildScytale(c){
        c.appendChild(createHeading('Scytale'));
        c.appendChild(label('Text')); const txt = input('scytaleText','','2'); txt.rows=2; c.appendChild(txt);
        c.appendChild(label('Columns')); const cols = input('scytaleCols','4'); cols.type='number'; cols.value='4'; c.appendChild(cols);
        const res = resultBox('scyRes');
        c.appendChild(btn('Encode', ()=> res.textContent = scytaleEncode(txt.value, parseInt(cols.value)||4)));
        c.appendChild(btn('Decode', ()=> res.textContent = scytaleDecode(txt.value, parseInt(cols.value)||4)));
        c.appendChild(res);
    }
    function buildOTP(c){
        c.appendChild(createHeading('One-Time Pad (XOR demo)'));
        c.appendChild(label('Message')); const txt = input('otpText','','3'); txt.rows=3; c.appendChild(txt);
        c.appendChild(label('Hex key (optional)')); const key = input('otpKey',''); c.appendChild(key);
        const res = resultBox('otpRes');
        c.appendChild(btn('Generate random key (hex)', ()=> key.value = randHex(Math.max(1, (txt.value||'').length))));
        c.appendChild(btn('Encrypt (hex)', ()=> {
            try{ res.textContent = otpXorEncryptHex(txt.value, fromHex(key.value)); } catch(e){ res.textContent = 'Error: ' + e.message; }
        }));
        c.appendChild(btn('Decrypt (provide key hex)', ()=> {
            try{ const pt = otpXorDecryptHex(txt.value, fromHex(key.value)); res.textContent = pt; } catch(e){ res.textContent = 'Error: '+e.message; }
        }));
        c.appendChild(res);
    }
    function buildSolitaire(c){
        c.appendChild(createHeading('Solitaire (Pontifex) demo - simplified'));
        c.appendChild(label('Message')); const txt = input('solMsg','','3'); txt.rows=3; c.appendChild(txt);
        c.appendChild(label('Optional deck seed (comma-separated 1..54)')); const seed = input('solSeed',''); c.appendChild(seed);
        const res = resultBox('solRes');
        c.appendChild(btn('Encrypt/Decrypt (demo)', ()=> {
            try{
                const deck = seed.value ? seed.value.split(',').map(x=>parseInt(x)) : newDeck();
                const ks = solitaireKeystream(deck, (txt.value||'').replace(/[^A-Za-z]/g,'').length);
                res.textContent = xorWithStreamLetters(txt.value, ks);
            }catch(e){ res.textContent = 'Error: '+e.message; }
        }));
        c.appendChild(res);
    }

    // ---- Modern ----
    function buildHashSelector(c){
        c.appendChild(createHeading('Hash functions'));
        c.appendChild(label('Choose algorithm'));
        const sel = document.createElement('select'); ['SHA-1','SHA-256','SHA-384','SHA-512','MD5'].forEach(a=>{
            const o = document.createElement('option'); o.value=a; o.textContent=a; sel.appendChild(o);
        });
        c.appendChild(sel);
        const go = btn('Open hash tool', ()=> {
            const alg = sel.value;
            if(alg === 'MD5') { showCipher('md5'); } else { showCipher(alg.toLowerCase()); }
        });
        c.appendChild(go);
    }
    function buildHash(c, alg){
        c.appendChild(createHeading(`${alg} hash`));
        c.appendChild(label('Text')); const txt = input('hashText','','3'); txt.rows=3; c.appendChild(txt);
        const res = resultBox('hashRes');
        c.appendChild(btn('Compute', async ()=> {
            try{
                const digest = await crypto.subtle.digest(alg, utf8ToBuf(txt.value));
                res.textContent = toHex(digest);
            }catch(e){ res.textContent = 'Error: '+e.message; }
        }));
        c.appendChild(res);
    }
    function buildMD5(c){
        c.appendChild(createHeading('MD5 (legacy)'));
        c.appendChild(label('Text')); const txt = input('md5Text','','3'); txt.rows=3; c.appendChild(txt);
        const res = resultBox('md5Res');
        c.appendChild(btn('Compute MD5', ()=> res.textContent = md5(txt.value)));
        c.appendChild(res);
    }
    function buildHMAC(c){
        c.appendChild(createHeading('HMAC'));
        c.appendChild(label('Message')); const txt = input('hmacText','','3'); txt.rows=3; c.appendChild(txt);
        c.appendChild(label('Key')); const key = input('hmacKey','secret'); c.appendChild(key);
        c.appendChild(label('Hash algorithm')); const sel = document.createElement('select'); ['SHA-1','SHA-256','SHA-384','SHA-512'].forEach(a=>{ const o=document.createElement('option'); o.value=a; o.textContent=a; sel.appendChild(o); }); c.appendChild(sel);
        const res = resultBox('hmacRes');
        c.appendChild(btn('Compute HMAC', async ()=> {
            try{
                const k = await crypto.subtle.importKey('raw', utf8ToBuf(key.value), {name:'HMAC', hash:sel.value}, false, ['sign']);
                const sig = await crypto.subtle.sign('HMAC', k, utf8ToBuf(txt.value));
                res.textContent = toHex(sig);
            }catch(e){ res.textContent = 'Error: '+e.message; }
        }));
        c.appendChild(res);
    }
    function buildPBKDF2(c){
        c.appendChild(createHeading('PBKDF2 (derive key)'));
        c.appendChild(label('Password')); const pass = input('pbkdf2Pass','password'); c.appendChild(pass);
        c.appendChild(label('Salt (hex)')); const salt = input('pbkdf2Salt', randHex(16)); c.appendChild(salt);
        c.appendChild(label('Iterations')); const iter = input('pbkdf2Iter','100000'); iter.type='number'; c.appendChild(iter);
        c.appendChild(label('Output bytes')); const outLen = input('pbkdf2Len','32'); outLen.type='number'; c.appendChild(outLen);
        const res = resultBox('pbkdf2Res');
        c.appendChild(btn('Derive', async ()=> {
            try{
                const keyMat = await crypto.subtle.importKey('raw', utf8ToBuf(pass.value), 'PBKDF2', false, ['deriveBits','deriveKey']);
                const bits = await crypto.subtle.deriveBits({name:'PBKDF2', salt: fromHex(salt.value), iterations: parseInt(iter.value)||100000, hash:'SHA-256'}, keyMat, (parseInt(outLen.value)||32)*8);
                res.textContent = toHex(bits);
            }catch(e){ res.textContent = 'Error: '+e.message; }
        }));
        c.appendChild(res);
    }
    function buildAES(c){
        c.appendChild(createHeading('AES-GCM (WebCrypto demo)'));
        c.appendChild(label('Password (will derive a key via PBKDF2)')); const pass = input('aesPass','password'); c.appendChild(pass);
        c.appendChild(label('Plaintext or JSON (for decrypt)')); const txt = input('aesText','','4'); txt.rows=4; c.appendChild(txt);
        c.appendChild(label('Key bits (128 or 256)')); const bits = input('aesBits','256'); bits.type='number'; c.appendChild(bits);
        const res = resultBox('aesRes');
        c.appendChild(btn('Encrypt', async ()=> {
            try{
                const salt = crypto.getRandomValues(new Uint8Array(16));
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const key = await deriveAESKeyFromPassword(pass.value, parseInt(bits.value)||256, salt);
                const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, utf8ToBuf(txt.value));
                res.textContent = JSON.stringify({iv: toHex(iv), salt: toHex(salt), ct: base64Encode(ct)});
            }catch(e){ res.textContent = 'Error: '+e.message; }
        }));
        c.appendChild(btn('Decrypt (paste JSON)', async ()=> {
            try{
                const obj = JSON.parse(txt.value);
                const salt = fromHex(obj.salt), iv = fromHex(obj.iv), ct = base64Decode(obj.ct);
                const key = await deriveAESKeyFromPassword(pass.value, parseInt(bits.value)||256, salt);
                const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv: new Uint8Array(iv)}, key, ct);
                res.textContent = bufToUtf8(pt);
            }catch(e){ res.textContent = 'Error: '+e.message; }
        }));
        c.appendChild(res);
    }
    function buildRSA(c){
        c.appendChild(createHeading('RSA-OAEP demo (WebCrypto)'));
        c.appendChild(label('Key size (2048 recommended)')); const bits = input('rsaBits','2048'); bits.type='number'; c.appendChild(bits);
        const gen = btn('Generate keypair', async ()=> {
            try{
                $('rsaStatus') && ($('rsaStatus').textContent = 'Generating...');
                const kp = await crypto.subtle.generateKey({name:'RSA-OAEP', modulusLength: parseInt(bits.value)||2048, publicExponent: new Uint8Array([1,0,1]), hash:'SHA-256'}, true, ['encrypt','decrypt']);
                const pub = await crypto.subtle.exportKey('spki', kp.publicKey);
                const priv = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
                $('rsaPub').value = base64Encode(pub); $('rsaPriv').value = base64Encode(priv);
                $('rsaStatus') && ($('rsaStatus').textContent = 'Done.');
            }catch(e){ $('rsaStatus') && ($('rsaStatus').textContent = 'Error: '+e.message); }
        });
        c.appendChild(gen);
        c.appendChild(document.createElement('br'));
        c.appendChild(label('Public key (base64 spki)')); const pub = input('rsaPub',''); pub.style.width='100%'; c.appendChild(pub);
        c.appendChild(label('Private key (base64 pkcs8)')); const priv = input('rsaPriv',''); priv.style.width='100%'; c.appendChild(priv);
        c.appendChild(label('Message')); const msg = input('rsaMsg','hello'); c.appendChild(msg);
        const res = resultBox('rsaRes');
        c.appendChild(btn('Encrypt with public', async ()=> {
            try{
                const pubKey = await crypto.subtle.importKey('spki', base64Decode(pub.value), {name:'RSA-OAEP', hash:'SHA-256'}, false, ['encrypt']);
                const ct = await crypto.subtle.encrypt({name:'RSA-OAEP'}, pubKey, utf8ToBuf(msg.value));
                res.textContent = base64Encode(ct);
            }catch(e){ res.textContent = 'Error: '+e.message; }
        }));
        c.appendChild(btn('Decrypt with private', async ()=> {
            try{
                const privKey = await crypto.subtle.importKey('pkcs8', base64Decode(priv.value), {name:'RSA-OAEP', hash:'SHA-256'}, false, ['decrypt']);
                const pt = await crypto.subtle.decrypt({name:'RSA-OAEP'}, privKey, base64Decode(res.textContent));
                res.textContent = bufToUtf8(pt);
            }catch(e){ res.textContent = 'Error: '+e.message; }
        }));
        const status = document.createElement('div'); status.id='rsaStatus'; status.style.marginTop='8px';
        c.appendChild(res); c.appendChild(status);
    }
    function buildECDH(c){
        c.appendChild(createHeading('ECDH (P-256) demo'));
        c.appendChild(label('A public (base64 raw)')); const aPub = input('ecdhA',''); c.appendChild(aPub);
        c.appendChild(label('B public (base64 raw)')); const bPub = input('ecdhB',''); c.appendChild(bPub);
        c.appendChild(btn('Generate A keypair (stores private in localStorage demo)', async ()=> {
            try{
                const kp = await crypto.subtle.generateKey({name:'ECDH', namedCurve:'P-256'}, true, ['deriveKey','deriveBits']);
                const pub = await crypto.subtle.exportKey('raw', kp.publicKey);
                const priv = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
                aPub.value = base64Encode(pub);
                localStorage.setItem('ecdhPrivA', base64Encode(priv));
            }catch(e){ alert('Error: '+e.message); }
        }));
        c.appendChild(btn('Generate B keypair (stores private in localStorage demo)', async ()=> {
            try{
                const kp = await crypto.subtle.generateKey({name:'ECDH', namedCurve:'P-256'}, true, ['deriveKey','deriveBits']);
                const pub = await crypto.subtle.exportKey('raw', kp.publicKey);
                const priv = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
                bPub.value = base64Encode(pub);
                localStorage.setItem('ecdhPrivB', base64Encode(priv));
            }catch(e){ alert('Error: '+e.message); }
        }));
        const res = resultBox('ecdhRes');
        c.appendChild(btn('Derive A from stored private A and B pub', async ()=> {
            try{
                const pki = localStorage.getItem('ecdhPrivA'); if(!pki) return alert('Generate A first');
                const priv = await crypto.subtle.importKey('pkcs8', base64Decode(pki), {name:'ECDH', namedCurve:'P-256'}, false, ['deriveKey','deriveBits']);
                const pubBraw = base64Decode(bPub.value);
                const pubB = await crypto.subtle.importKey('raw', pubBraw, {name:'ECDH', namedCurve:'P-256'}, false, []);
                const derived = await crypto.subtle.deriveBits({name:'ECDH', public: pubB}, priv, 256);
                res.textContent = toHex(derived);
            }catch(e){ res.textContent = 'Error: '+e.message; }
        }));
        c.appendChild(btn('Derive B from stored private B and A pub', async ()=> {
            try{
                const pki = localStorage.getItem('ecdhPrivB'); if(!pki) return alert('Generate B first');
                const priv = await crypto.subtle.importKey('pkcs8', base64Decode(pki), {name:'ECDH', namedCurve:'P-256'}, false, ['deriveKey','deriveBits']);
                const pubAraw = base64Decode(aPub.value);
                const pubA = await crypto.subtle.importKey('raw', pubAraw, {name:'ECDH', namedCurve:'P-256'}, false, []);
                const derived = await crypto.subtle.deriveBits({name:'ECDH', public: pubA}, priv, 256);
                res.textContent = toHex(derived);
            }catch(e){ res.textContent = 'Error: '+e.message; }
        }));
        c.appendChild(res);
    }
    function buildRC4(c){
        c.appendChild(createHeading('RC4 (insecure demo)'));
        c.appendChild(label('Text')); const txt = input('rc4Text','','3'); txt.rows=3; c.appendChild(txt);
        c.appendChild(label('Key')); const key = input('rc4Key','key'); c.appendChild(key);
        const res = resultBox('rc4Res');
        c.appendChild(btn('Encrypt (base64)', ()=> {
            const ct = rc4Encrypt(utf8ToBuf(txt.value), new TextEncoder().encode(key.value));
            res.textContent = base64Encode(ct);
        }));
        c.appendChild(btn('Decrypt (base64 input)', ()=> {
            try{ const pt = rc4Encrypt(base64Decode(txt.value), new TextEncoder().encode(key.value)); res.textContent = bufToUtf8(pt); } catch(e){ res.textContent = 'Error: '+e.message; }
        }));
        c.appendChild(res);
    }
    function buildXOR(c){
        c.appendChild(createHeading('XOR (repeating key)'));
        c.appendChild(label('Text / hex')); const txt = input('xorText','','3'); txt.rows=3; c.appendChild(txt);
        c.appendChild(label('Key')); const key = input('xorKey','k'); c.appendChild(key);
        const res = resultBox('xorRes');
        c.appendChild(btn('Encrypt → hex', ()=> {
            const ct = xorRepeatEncrypt(utf8ToBuf(txt.value), new TextEncoder().encode(key.value));
            res.textContent = toHex(ct);
        }));
        c.appendChild(btn('Decrypt hex', ()=> {
            try{ const pt = xorRepeatDecrypt(fromHex(txt.value), new TextEncoder().encode(key.value)); res.textContent = bufToUtf8(pt); } catch(e){ res.textContent = 'Error: '+e.message; }
        }));
        c.appendChild(res);
    }
    function buildRandom(c){
        c.appendChild(createHeading('Cryptographically secure random'));
        c.appendChild(label('Bytes')); const num = input('randNum','32'); num.type='number'; c.appendChild(num);
        const res = resultBox('randRes');
        c.appendChild(btn('Generate hex', ()=> { const n = Math.max(1, parseInt(num.value)||32); res.textContent = randHex(n); }));
        c.appendChild(res);
    }
    function buildEncoding(c){
        c.appendChild(createHeading('Encoding / Decoding'));
        c.appendChild(label('Input')); const txt = input('encText','','3'); txt.rows=3; c.appendChild(txt);
        const res = resultBox('encRes');
        c.appendChild(btn('To Base64', ()=> res.textContent = base64Encode(utf8ToBuf(txt.value))));
        c.appendChild(btn('From Base64', ()=> { try{ res.textContent = bufToUtf8(base64Decode(txt.value)); }catch(e){ res.textContent = 'Invalid base64'; } }));
        c.appendChild(btn('To Hex', ()=> res.textContent = toHex(utf8ToBuf(txt.value))));
        c.appendChild(btn('From Hex', ()=> { try{ res.textContent = bufToUtf8(fromHex(txt.value)); }catch(e){ res.textContent = 'Invalid hex'; } }));
        c.appendChild(res);
    }
    function buildCipherIdentifier(c){
        c.appendChild(createHeading('Cipher Identifier & Analysis (basic)'));
        c.appendChild(label('Ciphertext')); const txt = input('cidText','','4'); txt.rows=4; c.appendChild(txt);
        const res = resultBox('cidRes');
        c.appendChild(btn('Analyze', ()=> res.textContent = JSON.stringify(analyzeCiphertext(txt.value), null, 2)));
        c.appendChild(res);
    }
    function buildDefault(c){
        c.appendChild(createHeading('Tools'));
        c.appendChild(label('This tool was not found. Try one of the cards or type the tool name in data-tool.'));
        const res = resultBox('defRes'); c.appendChild(res);
    }

    /* =========================
       Utility function implementations for ciphers and crypto
       ========================= */

    // small helper to make headings
    function createHeading(txt){ const h = document.createElement('h3'); h.textContent = txt; h.style.color='#ba68c8'; return h; }

    // Caesar
    function caesarEncrypt(text, shift){
        if(!text) return '';
        shift = ((shift%26)+26)%26;
        return text.replace(/[A-Za-z]/g, ch => {
            const base = ch<= 'Z' ? 65 : 97;
            return String.fromCharCode(((ch.charCodeAt(0)-base+shift)%26)+base);
        });
    }
    function caesarDecrypt(text, shift){ return caesarEncrypt(text, (26 - (shift%26))%26); }

    // Atbash
    function atbashTransform(text){
        return (text||'').replace(/[A-Za-z]/g, ch => {
            const base = ch <= 'Z' ? 65 : 97;
            return String.fromCharCode(base + (25 - (ch.charCodeAt(0) - base)));
        });
    }

    // Vigenere
    function vigenereEncrypt(pt, key){
        if(!key) return pt;
        key = key.replace(/[^A-Za-z]/g,'');
        let ki=0; let out='';
        for(const ch of (pt||'')){
            if(/[A-Za-z]/.test(ch)){
                const base = ch <= 'Z' ? 65 : 97;
                const shift = (key[ki % key.length].toUpperCase().charCodeAt(0) - 65);
                out += String.fromCharCode(((ch.charCodeAt(0) - base + shift)%26) + base);
                ki++;
            } else out+=ch;
        }
        return out;
    }
    function vigenereDecrypt(ct, key){
        if(!key) return ct;
        key = key.replace(/[^A-Za-z]/g,'');
        let ki=0; let out='';
        for(const ch of (ct||'')){
            if(/[A-Za-z]/.test(ch)){
                const base = ch <= 'Z' ? 65 : 97;
                const shift = (key[ki % key.length].toUpperCase().charCodeAt(0) - 65);
                out += String.fromCharCode(((ch.charCodeAt(0) - base - shift + 26)%26) + base);
                ki++;
            } else out+=ch;
        }
        return out;
    }

    // Autokey
    function autokeyEncrypt(pt, key){
        key = (key||'').replace(/[^A-Za-z]/g,'');
        let ks = key.split('');
        let out=''; let ki=0;
        for(const ch of (pt||'')){
            if(/[A-Za-z]/.test(ch)){
                let kch = (ki < ks.length) ? ks[ki] : (pt.replace(/[^A-Za-z]/g,'')[ki - ks.length] || 'A');
                const shift = (kch.toUpperCase().charCodeAt(0) - 65);
                const base = ch <= 'Z' ? 65 : 97;
                out += String.fromCharCode(((ch.charCodeAt(0) - base + shift)%26) + base);
                ki++;
            } else out+=ch;
        }
        return out;
    }
    function autokeyDecrypt(ct, key){
        key = (key||'').replace(/[^A-Za-z]/g,'');
        let out=''; let ks = key.split(''); let ki=0;
        for(const ch of (ct||'')){
            if(/[A-Za-z]/.test(ch)){
                const base = ch <= 'Z' ? 65 : 97;
                const kch = (ki < ks.length) ? ks[ki] : out.replace(/[^A-Za-z]/g,'')[ki - ks.length];
                const shift = (kch.toUpperCase().charCodeAt(0) - 65);
                const p = String.fromCharCode(((ch.charCodeAt(0) - base - shift + 26)%26) + base);
                out += p;
                ki++;
            } else out+=ch;
        }
        return out;
    }

    // Substitution
    function substitutionEncrypt(text, keyMap){
        const map = {};
        for(let i=0;i<26;i++) map[String.fromCharCode(65+i)] = keyMap[i];
        const mapL = {}; for(let i=0;i<26;i++) mapL[String.fromCharCode(97+i)] = keyMap[i].toLowerCase();
        return (text||'').split('').map(ch=>{
            if(/[A-Z]/.test(ch)) return map[ch]||ch;
            if(/[a-z]/.test(ch)) return mapL[ch]||ch;
            return ch;
        }).join('');
    }
    function substitutionDecrypt(text, keyMap){
        const inv = {}; for(let i=0;i<26;i++) inv[keyMap[i]] = String.fromCharCode(65+i);
        const invL = {}; for(let i=0;i<26;i++) invL[keyMap[i].toLowerCase()] = String.fromCharCode(97+i);
        return (text||'').split('').map(ch=>{
            if(/[A-Z]/.test(ch)) return inv[ch] || ch;
            if(/[a-z]/.test(ch)) return invL[ch] || ch;
            return ch;
        }).join('');
    }

    // Affine
    function affineEncrypt(text,a,b){
        return (text||'').replace(/[A-Za-z]/g, ch => {
            const base = ch <= 'Z' ? 65 : 97;
            const x = ch.charCodeAt(0) - base;
            return String.fromCharCode(((a * x + b) % 26) + base);
        });
    }
    function affineDecrypt(text,a,b){
        const inv = modInverse(a, 26);
        if(inv === null) throw new Error('a not invertible mod 26');
        return (text||'').replace(/[A-Za-z]/g, ch => {
            const base = ch <= 'Z' ? 65 : 97;
            const y = ch.charCodeAt(0) - base;
            return String.fromCharCode(((inv * (y - b + 26)) % 26) + base);
        });
    }

    // Playfair
    function buildPlayfairSquare(keyword){
        keyword = (keyword||'').toUpperCase().replace(/[^A-Z]/g,'').replace(/J/g,'I');
        const used = new Set(); const arr = [];
        for(const ch of keyword) if(!used.has(ch)){ used.add(ch); arr.push(ch); }
        for(let c=65;c<=90;c++){
            const ch = String.fromCharCode(c); if(ch === 'J') continue; if(!used.has(ch)){ used.add(ch); arr.push(ch); }
        }
        const mat = []; for(let r=0;r<5;r++) mat.push(arr.slice(r*5, r*5+5));
        const pos = {}; for(let r=0;r<5;r++) for(let cc=0;cc<5;cc++) pos[mat[r][cc]] = [r,cc];
        return {mat,pos};
    }
    function playfairPrepare(s){
        s = (s||'').toUpperCase().replace(/[^A-Z]/g,'').replace(/J/g,'I');
        let out = '';
        for(let i=0;i<s.length;i++){
            const a = s[i]; const b = s[i+1] || '';
            if(b && a === b){ out += a + 'X'; }
            else { out += a + (b ? '' : (i+1===s.length ? 'X':'')); if(b) i++; }
        }
        if(out.length %2 === 1) out += 'X';
        return out;
    }
    function playfairEncrypt(text, key){
        const {mat,pos} = buildPlayfairSquare(key||'');
        const t = playfairPrepare(text);
        let out = '';
        for(let i=0;i<t.length;i+=2){
            const a = t[i], b = t[i+1];
            const [r1,c1] = pos[a], [r2,c2] = pos[b];
            if(r1 === r2) out += mat[r1][(c1+1)%5] + mat[r2][(c2+1)%5];
            else if(c1 === c2) out += mat[(r1+1)%5][c1] + mat[(r2+1)%5][c2];
            else out += mat[r1][c2] + mat[r2][c1];
        }
        return out;
    }
    function playfairDecrypt(text, key){
        const {mat,pos} = buildPlayfairSquare(key||'');
        let t = (text||'').toUpperCase().replace(/[^A-Z]/g,'').replace(/J/g,'I');
        if(t.length %2) t += 'X';
        let out = '';
        for(let i=0;i<t.length;i+=2){
            const a = t[i], b = t[i+1];
            const [r1,c1] = pos[a], [r2,c2] = pos[b];
            if(r1 === r2) out += mat[r1][(c1+4)%5] + mat[r2][(c2+4)%5];
            else if(c1 === c2) out += mat[(r1+4)%5][c1] + mat[(r2+4)%5][c2];
            else out += mat[r1][c2] + mat[r2][c1];
        }
        return out;
    }

    // Hill 2x2
    function hillEncrypt2x2(text, mat){
        const s = (text||'').toUpperCase().replace(/[^A-Z]/g,'');
        let padded = s; if(padded.length %2) padded += 'X';
        const nums = padded.split('').map(ch=>ch.charCodeAt(0)-65);
        const out=[];
        for(let i=0;i<nums.length;i+=2){
            const p0=nums[i], p1=nums[i+1];
            const c0 = (mat[0][0]*p0 + mat[0][1]*p1) % 26;
            const c1 = (mat[1][0]*p0 + mat[1][1]*p1) % 26;
            out.push(String.fromCharCode(c0+65), String.fromCharCode(c1+65));
        }
        return out.join('');
    }
    function matrixDet2x2(mat){ return (mat[0][0]*mat[1][1] - mat[0][1]*mat[1][0]); }
    function modInverseMatrix2x2(mat, mod=26){
        const det = matrixDet2x2(mat);
        const invDet = modInverse(((det%mod)+mod)%mod, mod);
        if(invDet === null) throw new Error('Matrix not invertible modulo ' + mod);
        const adj = [[mat[1][1], -mat[0][1]], [-mat[1][0], mat[0][0]]];
        return adj.map(r => r.map(v => ((v * invDet) % mod + mod) % mod ));
    }
    function hillDecrypt2x2(text, mat){
        const s = (text||'').toUpperCase().replace(/[^A-Z]/g,'');
        if(s.length %2 !== 0) throw new Error('Ciphertext length must be multiple of 2.');
        const inv = modInverseMatrix2x2(mat, 26);
        const nums = s.split('').map(ch=>ch.charCodeAt(0)-65);
        const out=[];
        for(let i=0;i<nums.length;i+=2){
            const p0 = (inv[0][0]*nums[i] + inv[0][1]*nums[i+1]) % 26;
            const p1 = (inv[1][0]*nums[i] + inv[1][1]*nums[i+1]) % 26;
            out.push(String.fromCharCode(p0+65), String.fromCharCode(p1+65));
        }
        return out.join('');
    }

    // Polybius
    const polyGrid = [['A','B','C','D','E'],['F','G','H','I','K'],['L','M','N','O','P'],['Q','R','S','T','U'],['V','W','X','Y','Z']];
    function polybiusEncode(text){
        const t = (text||'').toUpperCase().replace(/J/g,'I').replace(/[^A-Z]/g,'');
        const pos = {}; for(let r=0;r<5;r++) for(let c=0;c<5;c++) pos[polyGrid[r][c]] = `${r+1}${c+1}`;
        return t.split('').map(ch=>pos[ch]||'').join(' ');
    }
    function polybiusDecode(digits){
        digits = (digits||'').replace(/[^0-9]/g,'');
        if(digits.length %2 !== 0) return 'Invalid length';
        let out=''; for(let i=0;i<digits.length;i+=2){
            const r = parseInt(digits[i]) - 1, c = parseInt(digits[i+1]) - 1;
            if(r<0||r>4||c<0||c>4) out += '?'; else out += polyGrid[r][c];
        }
        return out;
    }

    // A1Z26
    function a1z26Encode(text){ return (text||'').toUpperCase().replace(/[^A-Z]/g,'').split('').map(ch=>ch.charCodeAt(0)-64).join(' '); }
    function a1z26Decode(nums){ return (nums||'').match(/\d+/g)?.map(n=>String.fromCharCode(parseInt(n)+64)).join('') || ''; }

    // Baconian
    function baconianEncode(text){
        const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        return (text||'').toUpperCase().replace(/[^A-Z]/g,'').split('').map(ch=>{
            const i = alpha.indexOf(ch);
            return i>=0 ? i.toString(2).padStart(5,'0').replace(/0/g,'A').replace(/1/g,'B') : '';
        }).join(' ');
    }
    function baconianDecode(seq){
        return (seq||'').toUpperCase().split(/\s+/).map(p=>{
            const b = p.replace(/A/g,'0').replace(/B/g,'1');
            if(b.length !== 5) return '?';
            const v = parseInt(b,2);
            return 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[v] || '?';
        }).join('');
    }

    // Trithemius
    function trithemiusEncrypt(text,start=0){ let out=''; let i=0; for(const ch of (text||'')){ if(/[A-Za-z]/.test(ch)){ out += caesarEncrypt(ch, (start + i)%26); i++; } else out+=ch; } return out; }
    function trithemiusDecrypt(text,start=0){ let out=''; let i=0; for(const ch of (text||'')){ if(/[A-Za-z]/.test(ch)){ out += caesarDecrypt(ch, (start + i)%26); i++; } else out+=ch; } return out; }

    // Rail Fence
    function railFenceEncrypt(text, rails){
        rails = Math.max(1, rails||2);
        text = (text||'').replace(/\r?\n/g,'');
        const rows = Array.from({length:rails},()=>[]);
        let r=0, dir=1;
        for(const ch of text){ rows[r].push(ch); r+=dir; if(r===rails-1||r===0) dir*=-1; }
        return rows.map(a=>a.join('')).join('');
    }
    function railFenceDecrypt(cipher, rails){
        rails = Math.max(1, rails||2);
        const n = (cipher||'').length;
        const pattern = []; let r=0, dir=1;
        for(let i=0;i<n;i++){ pattern.push(r); r+=dir; if(r===rails-1||r===0) dir*=-1; }
        const counts = new Array(rails).fill(0); pattern.forEach(p=>counts[p]++);
        const rows = []; let idx=0;
        for(let i=0;i<rails;i++){ rows[i] = (cipher||'').slice(idx, idx+counts[i]).split(''); idx += counts[i]; }
        let out=''; for(const p of pattern) out += rows[p].shift(); return out;
    }

    // Columnar
    function columnarOrder(key){
        return (key||'').split('').map((c,i)=>({c,i})).sort((a,b)=> a.c === b.c ? a.i - b.i : a.c.localeCompare(b.c)).map(x=>x.i);
    }
    function columnarEncrypt(text, key){
        const col = Math.max(1, (key||'').length || 1);
        const rows = [];
        for(let i=0;i<text.length;i+=col) rows.push(text.slice(i,i+col).padEnd(col,'X'));
        const order = columnarOrder(key);
        let out=''; for(const idx of order) for(const r of rows) out += r[idx];
        return out;
    }
    function columnarDecrypt(cipher, key){
        const col = Math.max(1, (key||'').length || 1);
        const rows = Math.ceil((cipher||'').length / col);
        const order = columnarOrder(key);
        const cols = Array(col).fill('');
        let pos = 0;
        for(const idx of order){ cols[idx] = (cipher||'').slice(pos, pos+rows); pos += rows; }
        let out=''; for(let r=0;r<rows;r++) for(let c=0;c<col;c++) out += cols[c][r] || '';
        return out.replace(/X+$/,'');
    }

    // Scytale
    function scytaleEncode(text, cols){
        cols = Math.max(1, cols||1);
        const t = (text||'').replace(/\s+/g,'');
        const rows = Math.ceil(t.length / cols);
        let out='';
        for(let c=0;c<cols;c++) for(let r=0;r<rows;r++){ const idx = r*cols + c; if(idx < t.length) out += t[idx]; }
        return out;
    }
    function scytaleDecode(cipher, cols){
        cols = Math.max(1, cols||1);
        const rows = Math.ceil((cipher||'').length / cols);
        let grid = Array.from({length:rows},()=>Array(cols).fill(''));
        let idx=0; for(let c=0;c<cols;c++) for(let r=0;r<rows;r++){ if(idx < (cipher||'').length) grid[r][c] = cipher[idx++]; }
        return grid.map(r=>r.join('')).join('');
    }

    // OTP XOR helpers
    function otpXorEncryptHex(plain, keyBuf){
        const pt = new Uint8Array(utf8ToBuf(plain));
        const key = new Uint8Array(keyBuf);
        if(key.length < pt.length) throw new Error('Key too short');
        const out = new Uint8Array(pt.length);
        for(let i=0;i<pt.length;i++) out[i] = pt[i] ^ key[i];
        return Array.from(out).map(b=>b.toString(16).padStart(2,'0')).join('');
    }
    function otpXorDecryptHex(hex, keyBuf){
        const ct = new Uint8Array(fromHex(hex));
        const key = new Uint8Array(keyBuf);
        if(key.length < ct.length) throw new Error('Key too short');
        const out = new Uint8Array(ct.length); for(let i=0;i<ct.length;i++) out[i] = ct[i] ^ key[i];
        return bufToUtf8(out);
    }

    // Solitaire simplified (demo)
    function newDeck(){ const d=[]; for(let i=1;i<=54;i++) d.push(i); return d; }
    function seedFromDeck(deck){ let s=0; for(let i=0;i<deck.length;i++) s = (s * 997 + (deck[i]||0)) >>> 0; return s; }
    function mulberry32(seed){ return function(){ let t = seed += 0x6D2B79F5; t = Math.imul(t ^ t >>> 15, t | 1); t ^= t + Math.imul(t ^ t >>> 7, t | 61); return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
    function solitaireKeystream(deck, n){
        const rng = mulberry32(seedFromDeck(deck));
        const out=[]; for(let i=0;i<n;i++) out.push(Math.floor(rng()*26)+1); return out;
    }
    function xorWithStreamLetters(text, ks){
        let i=0; let out=''; for(const ch of (text||'')){
            if(/[A-Za-z]/.test(ch)){
                const base = ch <= 'Z' ? 65 : 97;
                const p = ch.charCodeAt(0) - base;
                const k = (ks[i] - 1) % 26;
                out += String.fromCharCode(((p + k) % 26) + base);
                i++;
            } else out += ch;
        }
        return out;
    }

    // RC4 (demo)
    function rc4Init(key){
        const S = new Uint8Array(256);
        for(let i=0;i<256;i++) S[i]=i;
        let j=0;
        for(let i=0;i<256;i++){ j = (j + S[i] + key[i % key.length]) & 255; const t=S[i]; S[i]=S[j]; S[j]=t; }
        return S;
    }
    function rc4Encrypt(buf, key){
        const keyBytes = (key instanceof Uint8Array) ? key : new Uint8Array(key);
        const S = rc4Init(keyBytes);
        const data = new Uint8Array(buf);
        const out = new Uint8Array(data.length);
        let i=0,j=0;
        for(let n=0;n<data.length;n++){
            i = (i+1)&255; j = (j + S[i]) &255; const t=S[i]; S[i]=S[j]; S[j]=t;
            const K = S[(S[i]+S[j])&255];
            out[n] = data[n] ^ K;
        }
        return out.buffer;
    }

    // XOR repeating
    function xorRepeatEncrypt(buf, keyBytes){
        const data = new Uint8Array(buf);
        const key = (keyBytes instanceof Uint8Array) ? keyBytes : new Uint8Array(keyBytes);
        const out = new Uint8Array(data.length);
        for(let i=0;i<data.length;i++) out[i] = data[i] ^ key[i % key.length];
        return out.buffer;
    }
    function xorRepeatDecrypt(buf, keyBytes){ return xorRepeatEncrypt(buf, keyBytes); }

    // MD5 (compact)
    function md5(str){
        // small MD5 implementation (sufficient for demo). Not cryptographically recommended beyond legacy use.
        function rotl(n,c){ return (n<<c)|(n>>> (32-c)); }
        function toHex32(num){ return (num >>> 0).toString(16).padStart(8,'0'); }
        const msg = new TextEncoder().encode(str||'');
        const len = msg.length;
        const with1 = new Uint8Array(((len + 8) >>> 6 << 4) + 16);
        with1.set(msg);
        with1[len] = 0x80;
        const bitLen = len * 8;
        for(let i=0;i<8;i++) with1[with1.length - 8 + i] = (bitLen >>> (8*i)) & 0xFF;
        let a=0x67452301, b=0xefcdab89, c=0x98badcfe, d=0x10325476;
        const K = [];
        for(let i=0;i<64;i++) K[i] = Math.floor(Math.abs(Math.sin(i+1)) * Math.pow(2,32));
        for(let i=0;i<with1.length;i+=64){
            const M = new Uint32Array(16);
            for(let j=0;j<16;j++) M[j] = with1[i + j*4] | (with1[i + j*4 +1]<<8) | (with1[i + j*4+2]<<16) | (with1[i + j*4+3]<<24);
            let A=a,B=b,C=c,D=d;
            for(let t=0;t<64;t++){
                let F,g;
                if(t<16){F=(B & C) | ((~B) & D); g=t;}
                else if(t<32){F=(D & B) | ((~D) & C); g=(5*t+1)%16;}
                else if(t<48){F=B ^ C ^ D; g=(3*t+5)%16;}
                else {F=C ^ (B | (~D)); g=(7*t)%16;}
                const tmp = D; D=C; C=B; B = (B + rotl((A + F + K[t] + M[g])>>>0, [7,12,17,22][t%4]))>>>0; A=tmp;
            }
            a = (a + A) >>> 0; b = (b + B) >>> 0; c = (c + C) >>> 0; d = (d + D) >>> 0;
        }
        return toHex32(a) + toHex32(b) + toHex32(c) + toHex32(d);
    }

    // AES derive
    async function deriveAESKeyFromPassword(pass, keyBits=256, saltBuf=null){
        if(!saltBuf){ saltBuf = crypto.getRandomValues(new Uint8Array(16)); }
        const baseKey = await crypto.subtle.importKey('raw', utf8ToBuf(pass), 'PBKDF2', false, ['deriveKey']);
        const key = await crypto.subtle.deriveKey({name:'PBKDF2', salt: saltBuf, iterations: 200000, hash:'SHA-256'}, baseKey, {name:'AES-GCM', length: keyBits}, false, ['encrypt','decrypt']);
        return key;
    }

    // Cipher identifier basics
    function analyzeCiphertext(text){
        const trimmed = (text||'').replace(/\s+/g,'');
        const info = {};
        info.length = trimmed.length;
        info.isHex = /^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length%2===0;
        info.isBase64 = /^[A-Za-z0-9+/]+={0,2}$/.test(trimmed);
        const letters = (text||'').toUpperCase().replace(/[^A-Z]/g,'');
        const freq = {}; for(const ch of letters) freq[ch] = (freq[ch]||0)+1;
        info.indexOfCoincidence = indexOfCoincidence(letters);
        info.letterFrequency = freq;
        return info;
    }
    function indexOfCoincidence(s){
        const n = (s||'').length; if(n<=1) return 0;
        const freq = {}; for(const ch of s) freq[ch] = (freq[ch]||0)+1;
        let sum=0; for(const k in freq) sum += freq[k]*(freq[k]-1);
        return (sum / (n*(n-1)));
    }

    /* end of showCipher inner function */
}

/* -----------------------
   Math helpers (gcd, egcd, modInverse)
   ----------------------- */
function gcd(a,b){ a=Math.abs(a); b=Math.abs(b); while(b){ const t=b; b=a%b; a=t; } return a; }
function egcd(a,b){ if(b===0) return {g:a,x:1,y:0}; const r=egcd(b, a%b); return {g:r.g, x:r.y, y: r.x - Math.floor(a/b)*r.y}; }
function modInverse(a,m){
    a = ((a % m) + m) % m;
    const r = egcd(a,m);
    if(r.g !== 1) return null;
    return ((r.x % m) + m) % m;
}

/* -----------------------
   Exposed helper functions used by inline HTML (if any)
   ----------------------- */
window.showCipher = showCipher;
window.openModal = openModal;
window.closeModal = closeModal;
window.showLoginForm = showLoginForm;
window.showRegisterForm = showRegisterForm;
window.logout = logout;
window.checkPuzzleAnswer = checkPuzzleAnswer;
window.showSolution = showSolution;
window.generateNewPuzzle = generateNewPuzzle;

/* -----------------------
   Bind on load: ensure modal exists and wire cipher cards again (defensive)
   ----------------------- */
document.addEventListener('DOMContentLoaded', ()=>{
    ensureCipherModal();
    bindCipherCards();
    // Remove any accidental detective-game elements if present by id only
    const dbtn = $('detectiveGameBtn'); if(dbtn) dbtn.remove();
});

/* -----------------------
   RC4 & XOR & small utilities used globally (re-declared here for top-level use)
   ----------------------- */
function rc4Encrypt(buf, keyBytes){
    const key = (keyBytes instanceof Uint8Array) ? keyBytes : new Uint8Array(keyBytes);
    const S = new Uint8Array(256); for(let i=0;i<256;i++) S[i]=i;
    let j=0;
    for(let i=0;i<256;i++){ j = (j + S[i] + key[i % key.length]) & 255; const t=S[i]; S[i]=S[j]; S[j]=t; }
    const data = new Uint8Array(buf);
    const out = new Uint8Array(data.length);
    let i=0; j=0;
    for(let n=0;n<data.length;n++){
        i = (i+1)&255; j = (j + S[i]) &255; const t=S[i]; S[i]=S[j]; S[j]=t;
        const K = S[(S[i] + S[j]) & 255];
        out[n] = data[n] ^ K;
    }
    return out.buffer;
}
function xorRepeatEncrypt(buf, keyBytes){
    const data = new Uint8Array(buf);
    const key = (keyBytes instanceof Uint8Array) ? keyBytes : new Uint8Array(keyBytes);
    const out = new Uint8Array(data.length);
    for(let i=0;i<data.length;i++) out[i] = data[i] ^ key[i % key.length];
    return out.buffer;
}
function xorRepeatDecrypt(buf, keyBytes){ return xorRepeatEncrypt(buf, keyBytes); }

/* -----------------------
   Small note for you:
   - This script aims to be robust and defensive: it checks for missing elements before using them.
   - If an error occurs, check Console (F12 -> Console) and paste the top error here; I'll patch it immediately.
   - For heavy/production crypto (password hashing, scrypt/bcrypt/argon2, RSA key storage), use proper server-side key management and vetted libraries.
   ----------------------- */


// ====================
// User Authentication with EmailJS 2FA
// ====================

// Local storage for users
let users = JSON.parse(localStorage.getItem("users")) || {};
let currentUser = null;

// Save users back to local storage
function saveUsers() {
    localStorage.setItem("users", JSON.stringify(users));
}

// Case-insensitive user resolver to avoid false "user not found" and wrong password issues
function resolveUser(usernameInput){
    const raw = (usernameInput || "").trim();
    if(!raw) return { key: null, user: null };
    if(users.hasOwnProperty(raw)) return { key: raw, user: users[raw] };
    const lower = raw.toLowerCase();
    for(const k in users){ if(k.toLowerCase() === lower){ return { key: k, user: users[k] }; }
    }
    return { key: null, user: null };
}

// ==================== REGISTER ====================
function register(username, password, email) {
    const uname = (username || '').trim();
    const pwd = (password || '');
    const mail = (email || '').trim();
    const existing = resolveUser(uname);
    if (existing.user) {
        alert("Username already exists!");
        return false;
    }
    users[uname] = {
        password: pwd,
        email: mail,
        loginCount: 0,
        verificationCode: null,
        joinDate: new Date().toISOString(),
        lastLogin: null,
        progress: {
            intro: {},
            classical: {},
            modern: {},
            security: {}
        },
        achievements: [],
        lastActivity: new Date().toISOString()
    };
    saveUsers();
    // auto-sign in the user and persist session so other pages recognize it
    currentUser = uname;
    try { localStorage.setItem('cl_user', currentUser); } catch(e) {}
    updateUserUI();
    alert("Registration successful! You are now logged in.");
    return true;
}

// ==================== LOGIN ====================
function login(username, password) {
    const uname = (username || '').trim();
    const pwd = (password || '');
    const { key, user } = resolveUser(uname);
    if (!user) {
        alert("User not found!");
        return false;
    }
    if (user.password !== pwd) {
        alert("Wrong password!");
        return false;
    }

    users[key].loginCount++;
    users[key].lastLogin = new Date().toISOString();
    saveUsers();

    // Require 2FA verification every 5 logins
    if (users[key].loginCount % 5 === 0) {
        currentUser = key;
        sendVerificationCode(key);
    } else {
        currentUser = key;
        // persist session across pages
        try { localStorage.setItem('cl_user', currentUser); } catch(e) {}
        alert("Login successful!");
        updateUserUI();
    }
    return true;
}

// ==================== EMAIL VERIFICATION ====================
function sendVerificationCode(username) {
    const code = Math.random().toString(36).substring(2, 8).toUpperCase(); // random 6-letter code
    users[username].verificationCode = code;
    saveUsers();

    // Show verification modal
    const modal = document.getElementById("twoFAModal");
    const demoCode = document.getElementById("demoCode");
    
    if (modal) {
        modal.style.display = "block";
    }
    
    if (demoCode) {
        demoCode.textContent = "Sending verification code to " + users[username].email;
    }

    // Initialize EmailJS with Public Key (configurable)
    const EMAILJS_PUBLIC_KEY = (window.EMAILJS_CONFIG && window.EMAILJS_CONFIG.PUBLIC_KEY) || "Mq0q1ncvZ8eoMrGB7";
    emailjs.init(EMAILJS_PUBLIC_KEY);

    // Send the email using configured credentials
    const EMAILJS_SERVICE_ID = (window.EMAILJS_CONFIG && window.EMAILJS_CONFIG.SERVICE_ID) || "service_73ia0fm";
    const EMAILJS_TEMPLATE_ID = (window.EMAILJS_CONFIG && window.EMAILJS_CONFIG.TEMPLATE_ID) || "template_vhfgnbe";
    emailjs.send(EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID, {
        to_email: users[username].email,
        username: username,
        code: code,
        message: `Your verification code is: ${code}. This code will expire in 10 minutes.`
    }).then(function(response) {
        console.log("Email sent successfully", response.status, response.text);
        alert("Verification code sent to your email!");
    }, function(error) {
        console.error("Email failed:", error);
        alert("Failed to send verification email. Please try again.");
    });
}

// ==================== VERIFY CODE ====================
function verifyCode(inputCode) {
    if (!currentUser) {
        alert("No user logged in.");
        return false;
    }

    if (users[currentUser].verificationCode === inputCode) {
        users[currentUser].verificationCode = null; // clear after success
        saveUsers();
        
        const modal = document.getElementById("twoFAModal");
        if (modal) {
            modal.style.display = "none";
        }
        
        // persist session after successful 2FA
        try { localStorage.setItem('cl_user', currentUser); } catch(e) {}
        alert("Verification successful! Welcome back, " + currentUser);
        updateUserUI();
        return true;
    } else {
        alert("Invalid verification code. Please try again.");
        return false;
    }
}

// ==================== UI HANDLERS ====================
function updateUserUI() {
    const loggedIn = document.getElementById("loggedIn");
    const notLoggedIn = document.getElementById("notLoggedIn");
    const usernameDisplay = document.getElementById("usernameDisplay");
    
    if (currentUser) {
        if (loggedIn) loggedIn.style.display = "";
        if (notLoggedIn) notLoggedIn.style.display = "none";
        if (usernameDisplay) {
            const loginCount = users[currentUser] ? users[currentUser].loginCount : 0;
            const next2FA = 5 - (loginCount % 5);
            usernameDisplay.textContent = `👤 ${currentUser}${users[currentUser] ? ` (${loginCount} logins, 2FA in ${next2FA})` : ''}`;
        }
    } else {
        try { localStorage.removeItem('cl_user'); } catch(e) {}
        currentUser = null;
        if (loggedIn) loggedIn.style.display = "none";
        if (notLoggedIn) notLoggedIn.style.display = "";
    }
}

// ==================== LOGOUT ====================
function logout() {
    currentUser = null;
    try { localStorage.removeItem('cl_user'); } catch(e) {}
    updateUserUI();
    alert("Logged out successfully!");
}

// ==================== PROGRESS TRACKING ====================
function markProgress(section, topic) {
    if (!currentUser) {
        alert("Please log in to track your progress!");
        return;
    }

    // Initialize progress if not exists
    if (!users[currentUser].progress) {
        users[currentUser].progress = {
            intro: {},
            classical: {},
            modern: {},
            security: {}
        };
    }

    // Mark topic as completed
    users[currentUser].progress[section][topic] = {
        completed: true,
        completedAt: new Date().toISOString()
    };

    // Update last activity
    users[currentUser].lastActivity = new Date().toISOString();

    // Save progress
    saveUsers();

    // Update progress bars
    updateProgressBars();

    // Check for achievements
    checkAchievements();

    // Show success message
    alert(`✅ Marked "${topic}" as completed!`);
}

function updateProgressBars() {
    if (!currentUser || !users[currentUser].progress) return;

    const progress = users[currentUser].progress;
    
    // Calculate section progress
    const sections = ['intro', 'classical', 'modern', 'security'];
    const sectionTopics = {
        intro: ['basics', 'comparison'],
        classical: ['caesar', 'atbash', 'substitution', 'affine', 'vigenere', 'autokey', 'playfair', 'hill', 'polybius', 'a1z26', 'baconian', 'trithemius', 'transposition', 'otp', 'enigma', 'chaocipher', 'solitaire'],
        modern: ['rsa', 'diffie', 'sha', 'md5', 'hmac', 'pbkdf2', 'aes', 'rc4', 'base64'],
        security: ['identifier', 'frequency', 'ngram', 'crib', 'bruteforce', 'rng', 'factoring', 'discrete']
    };

    sections.forEach(section => {
        const topics = sectionTopics[section] || [];
        const completedTopics = topics.filter(topic => 
            progress[section] && progress[section][topic] && progress[section][topic].completed
        );
        
        const percentage = topics.length > 0 ? Math.round((completedTopics.length / topics.length) * 100) : 0;
        
        // Update overall progress bar
        const overallBar = document.getElementById(`${section}OverallProgress`);
        const overallPercentage = document.getElementById(`${section}Percentage`);
        
        if (overallBar) {
            overallBar.style.width = `${percentage}%`;
        }
        if (overallPercentage) {
            overallPercentage.textContent = `${percentage}%`;
        }

        // Update individual topic progress bars
        topics.forEach(topic => {
            const topicBar = document.getElementById(`${topic}Progress`);
            if (topicBar) {
                const isCompleted = progress[section] && progress[section][topic] && progress[section][topic].completed;
                topicBar.style.width = isCompleted ? '100%' : '0%';
                topicBar.style.backgroundColor = isCompleted ? '#4caf50' : '#9c27b0';
            }
        });
    });
}

function checkAchievements() {
    if (!currentUser || !users[currentUser].progress) return;

    const progress = users[currentUser].progress;
    const achievements = users[currentUser].achievements || [];

    // First Steps achievement
    if (!achievements.includes('first_steps')) {
        const hasAnyProgress = Object.values(progress).some(section => 
            Object.values(section).some(topic => topic.completed)
        );
        if (hasAnyProgress) {
            achievements.push('first_steps');
            alert('🏆 Achievement Unlocked: First Steps - Complete your first knowledge topic!');
        }
    }

    // Classical Master achievement
    if (!achievements.includes('classical_master')) {
        const classicalTopics = ['caesar', 'atbash', 'substitution', 'affine', 'vigenere', 'autokey', 'playfair', 'hill', 'polybius', 'a1z26', 'baconian', 'trithemius', 'transposition', 'otp', 'enigma', 'chaocipher', 'solitaire'];
        const completedClassical = classicalTopics.filter(topic => 
            progress.classical && progress.classical[topic] && progress.classical[topic].completed
        );
        if (completedClassical.length === classicalTopics.length) {
            achievements.push('classical_master');
            alert('🏆 Achievement Unlocked: Classical Master - Complete all classical cipher topics!');
        }
    }

    // Modern Expert achievement
    if (!achievements.includes('modern_expert')) {
        const modernTopics = ['rsa', 'diffie', 'sha', 'md5', 'hmac', 'pbkdf2', 'aes', 'rc4', 'base64'];
        const completedModern = modernTopics.filter(topic => 
            progress.modern && progress.modern[topic] && progress.modern[topic].completed
        );
        if (completedModern.length === modernTopics.length) {
            achievements.push('modern_expert');
            alert('🏆 Achievement Unlocked: Modern Expert - Complete all modern tool topics!');
        }
    }

    // Update achievements in user data
    users[currentUser].achievements = achievements;
    saveUsers();
}

function scrollToSection(sectionId) {
    const element = document.getElementById(sectionId);
    if (element) {
        element.scrollIntoView({ behavior: 'smooth' });
    }
}

// ==================== DASHBOARD UPDATES ====================
function updateDashboard() {
    if (!currentUser || !users[currentUser]) return;

    const user = users[currentUser];
    
    // Update profile information
    const profileUsername = document.getElementById("profileUsername");
    const profileJoinDate = document.getElementById("profileJoinDate");
    const profileLastLogin = document.getElementById("profileLastLogin");
    const profileTotalLogins = document.getElementById("profileTotalLogins");

    if (profileUsername) profileUsername.textContent = currentUser;
    if (profileJoinDate) profileJoinDate.textContent = user.joinDate ? new Date(user.joinDate).toLocaleDateString() : 'Unknown';
    if (profileLastLogin) profileLastLogin.textContent = user.lastLogin ? new Date(user.lastLogin).toLocaleDateString() : 'Never';
    if (profileTotalLogins) profileTotalLogins.textContent = user.loginCount || 0;

    // Update dashboard progress bars
    updateDashboardProgress();

    // Update achievements
    updateDashboardAchievements();

    // Update recent activity
    updateRecentActivity();

    // Update puzzle statistics
    updatePuzzleStats();

    // Show dashboard content
    const dashboardOverview = document.getElementById("dashboardOverview");
    if (dashboardOverview) {
        dashboardOverview.style.display = "block";
    }
}

function updateDashboardProgress() {
    if (!currentUser || !users[currentUser].progress) return;

    const progress = users[currentUser].progress;
    const sectionTopics = {
        intro: ['basics', 'comparison'],
        classical: ['caesar', 'atbash', 'substitution', 'affine', 'vigenere', 'autokey', 'playfair', 'hill', 'polybius', 'a1z26', 'baconian', 'trithemius', 'transposition', 'otp', 'enigma', 'chaocipher', 'solitaire'],
        modern: ['rsa', 'diffie', 'sha', 'md5', 'hmac', 'pbkdf2', 'aes', 'rc4', 'base64'],
        security: ['identifier', 'frequency', 'ngram', 'crib', 'bruteforce', 'rng', 'factoring', 'discrete']
    };

    Object.keys(sectionTopics).forEach(section => {
        const topics = sectionTopics[section];
        const completedTopics = topics.filter(topic => 
            progress[section] && progress[section][topic] && progress[section][topic].completed
        );
        
        const percentage = topics.length > 0 ? Math.round((completedTopics.length / topics.length) * 100) : 0;
        
        // Update dashboard progress bars
        const dashboardBar = document.getElementById(`dashboard${section.charAt(0).toUpperCase() + section.slice(1)}Progress`);
        const dashboardText = document.getElementById(`dashboard${section.charAt(0).toUpperCase() + section.slice(1)}Text`);
        
        if (dashboardBar) {
            dashboardBar.style.width = `${percentage}%`;
        }
        if (dashboardText) {
            dashboardText.textContent = `${percentage}%`;
        }
    });
}

function updateDashboardAchievements() {
    if (!currentUser || !users[currentUser].achievements) return;

    const achievements = users[currentUser].achievements;
    const achievementsGrid = document.getElementById("achievementsGrid");
    
    if (!achievementsGrid) return;

    const achievementMap = {
        'first_steps': { icon: '🔓', name: 'First Steps', desc: 'Complete your first knowledge topic' },
        'classical_master': { icon: '🔓', name: 'Classical Master', desc: 'Complete all classical cipher topics' },
        'modern_expert': { icon: '🔓', name: 'Modern Expert', desc: 'Complete all modern tool topics' },
        'puzzle_solver': { icon: '🔓', name: 'Puzzle Solver', desc: 'Solve your first daily puzzle' }
    };

    // Clear existing achievements
    achievementsGrid.innerHTML = '';

    // Add achievements
    Object.keys(achievementMap).forEach(achievementId => {
        const achievement = achievementMap[achievementId];
        const isUnlocked = achievements.includes(achievementId);
        
        const achievementItem = document.createElement('div');
        achievementItem.className = `achievement-item ${isUnlocked ? 'unlocked' : 'locked'}`;
        
        achievementItem.innerHTML = `
            <span class="achievement-icon">${isUnlocked ? '🏆' : achievement.icon}</span>
            <span class="achievement-name">${achievement.name}</span>
            <span class="achievement-desc">${achievement.desc}</span>
        `;
        
        achievementsGrid.appendChild(achievementItem);
    });
}

function updateRecentActivity() {
    if (!currentUser || !users[currentUser].progress) return;

    const progress = users[currentUser].progress;
    const activityList = document.getElementById("activityList");
    
    if (!activityList) return;

    // Clear existing activities
    activityList.innerHTML = '';

    // Collect all completed topics with timestamps
    const activities = [];
    Object.keys(progress).forEach(section => {
        Object.keys(progress[section]).forEach(topic => {
            if (progress[section][topic].completed) {
                activities.push({
                    section: section,
                    topic: topic,
                    completedAt: progress[section][topic].completedAt
                });
            }
        });
    });

    // Sort by completion date (most recent first)
    activities.sort((a, b) => new Date(b.completedAt) - new Date(a.completedAt));

    // Show recent activities (last 5)
    const recentActivities = activities.slice(0, 5);
    
    if (recentActivities.length === 0) {
        activityList.innerHTML = `
            <div class="activity-item">
                <span class="activity-icon">📖</span>
                <span class="activity-text">No recent activity</span>
                <span class="activity-time"></span>
            </div>
        `;
    } else {
        recentActivities.forEach(activity => {
            const activityItem = document.createElement('div');
            activityItem.className = 'activity-item';
            
            const timeAgo = getTimeAgo(new Date(activity.completedAt));
            
            activityItem.innerHTML = `
                <span class="activity-icon">📖</span>
                <span class="activity-text">Completed: ${activity.topic}</span>
                <span class="activity-time">${timeAgo}</span>
            `;
            
            activityList.appendChild(activityItem);
        });
    }
}

function getTimeAgo(date) {
    const now = new Date();
    const diffInSeconds = Math.floor((now - date) / 1000);
    
    if (diffInSeconds < 60) return 'Just now';
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
    if (diffInSeconds < 2592000) return `${Math.floor(diffInSeconds / 86400)}d ago`;
    return date.toLocaleDateString();
}

// ==================== DAILY PUZZLE SYSTEM ====================
let PUZZLE_BANK = [];

// Load questions from JSON file
async function loadQuestionsFromJSON() {
    try {
        const response = await fetch('questions.json');
        if (!response.ok) {
            throw new Error('Failed to load questions.json');
        }
        const data = await response.json();
        PUZZLE_BANK = data.questions;
        console.log('Loaded', PUZZLE_BANK.length, 'questions from JSON');
        return true;
    } catch (error) {
        console.error('Error loading questions from JSON:', error);
        // Fallback to a minimal set if JSON fails
        PUZZLE_BANK = [
            { id: 1, question: "Decrypt this Caesar cipher with a shift of 3: 'WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ'", answer: "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG", cipher: "Caesar Cipher", difficulty: "Easy", hint: "Each letter is shifted 3 positions forward in the alphabet" },
            { id: 2, question: "Decrypt this Atbash cipher: 'ZYXWVUTSRQPONMLKJIHGFEDCBA'", answer: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", cipher: "Atbash Cipher", difficulty: "Easy", hint: "A becomes Z, B becomes Y, and so on" }
        ];
        return false;
    }
}

// Initialize questions on page load
document.addEventListener('DOMContentLoaded', async function() {
    await loadQuestionsFromJSON();
});

const PUZZLE_BANK_FALLBACK = [
    // Caesar Cipher
    { question: "Decode with shift 3: KHOOR ZRUOG", answer: "HELLO WORLD", difficulty: "Easy", cipher: "Caesar" },
    { question: "Encrypt HELLO WORLD backward shift 1", answer: "GDKKN VNQKC", difficulty: "Easy", cipher: "Caesar" },
    { question: "Shift SECRET by 4 forward", answer: "WIGVIX", difficulty: "Easy", cipher: "Caesar" },
    { question: "Decode QEB NRFZH YOLTK CLU GRJMP LSBO QEB IXWV ALD (shift 23)", answer: "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG", difficulty: "Medium", cipher: "Caesar" },
    { question: "Encrypt MYSTERY BOX using shift equal to letters in MYSTERY (7)", answer: "TFAOLYF IVE", difficulty: "Medium", cipher: "Caesar" },
    { question: "Decode WKLV LV D WHVW PHVVDJH (shift = 13)", answer: "JXYIY YI Q JRIJ CUIIWNUR", difficulty: "Medium", cipher: "Caesar" },
    { question: "PUZZLE → TZCCPI, find shift and original", answer: "Shift = 7 forward, Original = PUZZLE", difficulty: "Medium", cipher: "Caesar" },
    { question: "Decode GUR DHVPX OEBJA SBK WHZCF BIRE GUR YNML QBT (shift multiple of 7)", answer: "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG", difficulty: "Hard", cipher: "Caesar" },
    { question: "Encrypt CRYPTOGRAPHY IS FUN (shift = 2+0+2+5=9)", answer: "LAYYCXZAPYHQ RB ODW", difficulty: "Hard", cipher: "Caesar" },
    { question: "Decode ZICVTWQNGRZGVTWAVZHCQYGLMGJ (starts with THE, shift 23)", answer: "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG", difficulty: "Hard", cipher: "Caesar" },
    
    // Vigenère Cipher
    { question: "Decode LXFOPVEFRNHR, key=LEMON", answer: "ATTACKATDAWN", difficulty: "Easy", cipher: "Vigenère" },
    { question: "Encrypt HELLO with key=KEY", answer: "RIJVS", difficulty: "Easy", cipher: "Vigenère" },
    { question: "Decode RIJVS UYVJN, key=KEY", answer: "HELLO WORLD", difficulty: "Easy", cipher: "Vigenère" },
    { question: "Encrypt PUZZLE with key=CODE", answer: "RXVPRP", difficulty: "Medium", cipher: "Vigenère" },
    { question: "Decode BIPUL QZKCO, key=SECRET", answer: "ATTACK POINT", difficulty: "Medium", cipher: "Vigenère" },
    { question: "Encrypt MYSTERY with key=FUN", answer: "HCYJRLW", difficulty: "Medium", cipher: "Vigenère" },
    { question: "Decode ZICVTWQNGRZGVTWAVZHCQYGLMGJ, key=LEMON", answer: "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG", difficulty: "Medium", cipher: "Vigenère" },
    { question: "Encrypt ATTACK AT DAWN with key=LEMON (no spaces)", answer: "LXFOPVEFRNHR", difficulty: "Hard", cipher: "Vigenère" },
    { question: "Decode JXUSX FWSWI, key=BOOK", answer: "SECRET CODE", difficulty: "Hard", cipher: "Vigenère" },
    { question: "Encrypt ENIGMA with key=CIPHER, then shift letters +1", answer: "HTMIXD", difficulty: "Hard", cipher: "Vigenère" },
    
    // Substitution Cipher
    { question: "Decode MNOP using A→M, B→N, C→O...", answer: "ABCD", difficulty: "Easy", cipher: "Substitution" },
    { question: "Encode HELLO using alphabet QWERTYUIOPASDFGHJKLZXCVBNM", answer: "ITSSG", difficulty: "Easy", cipher: "Substitution" },
    { question: "Decode GSRH RH Z HVXIVG (reversed alphabet)", answer: "THIS IS A SECRET", difficulty: "Easy", cipher: "Substitution" },
    { question: "Encrypt SECRET using Atbash", answer: "HVXIVG", difficulty: "Medium", cipher: "Substitution" },
    { question: "Decode KHOOR ZRUOG using A→D, B→E...", answer: "HELLO WORLD", difficulty: "Medium", cipher: "Substitution" },
    { question: "Encrypt PUZZLE with alphabet QAZWSXEDCRFVTGBYHNUJMIKOLP", answer: "GHRRKJ", difficulty: "Medium", cipher: "Substitution" },
    { question: "Decode B TJNQMF NFTTBHF using A→B, B→C...", answer: "A SIMPLE MESSAGE", difficulty: "Medium", cipher: "Substitution" },
    { question: "Decode SVOOL DLIOW (Atbash)", answer: "HELLO WORLD", difficulty: "Hard", cipher: "Substitution" },
    { question: "Encrypt CRYPTOGRAPHY with a scrambled mapping", answer: "JDKGZIJKTFQN", difficulty: "Hard", cipher: "Substitution" },
    { question: "Double substitution: reverse alphabet, then shift +3; decode NFRUQ", answer: "HELLO", difficulty: "Hard", cipher: "Substitution" },
    
    // Affine Cipher
    { question: "Encrypt HELLO with a=5, b=8", answer: "RCLLA", difficulty: "Easy", cipher: "Affine" },
    { question: "Decode ZEBBW with a=5, b=8", answer: "HELLO", difficulty: "Easy", cipher: "Affine" },
    { question: "Encrypt PUZZLE with a=7, b=3", answer: "KBPPUC", difficulty: "Easy", cipher: "Affine" },
    { question: "Decode IHHWVCSWFRCP with a=5, b=8", answer: "AFFINECIPHER", difficulty: "Medium", cipher: "Affine" },
    { question: "Encrypt MYSTERY with a=11, b=6", answer: "WKYWSMI", difficulty: "Medium", cipher: "Affine" },
    { question: "Decode RCLLA with a=7, b=2", answer: "HELLO", difficulty: "Medium", cipher: "Affine" },
    { question: "Encrypt ATTACK with a=3, b=5", answer: "FYYFHP", difficulty: "Medium", cipher: "Affine" },
    { question: "Decode GUR DHVPX OEBJA SBK, a=17, b=20", answer: "THE QUICK FOX", difficulty: "Hard", cipher: "Affine" },
    { question: "Encrypt CRYPTOGRAPHY with a=15, b=12", answer: "MJQHFWJFPC", difficulty: "Hard", cipher: "Affine" },
    { question: "Find plaintext of EHTX using a=9, b=2", answer: "CODE", difficulty: "Hard", cipher: "Affine" },
    
    // Playfair Cipher
    { question: "Encrypt HELLO, key=MONARCHY", answer: "KFPMMP", difficulty: "Easy", cipher: "Playfair" },
    { question: "Decode BM OD ZB XD NA BE KU DM UI XM MO UV IF, key=MONARCHY", answer: "HIDETHEGOLDINTHETREESTUMP", difficulty: "Easy", cipher: "Playfair" },
    { question: "Encrypt PUZZLE, key=KEYWORD", answer: "PVTRQI", difficulty: "Easy", cipher: "Playfair" },
    { question: "Decode GATLMZ CLRQ TX, key=MONARCHY", answer: "MUSTSEEYOOTONIGHT", difficulty: "Medium", cipher: "Playfair" },
    { question: "Encrypt MYSTERY, key=SECRET", answer: "NZVQIFZ", difficulty: "Medium", cipher: "Playfair" },
    { question: "Decode IO BML QT FF QE, key=PLAYFAIR", answer: "ATTACKTONIGHT", difficulty: "Medium", cipher: "Playfair" },
    { question: "Encrypt ATTACK AT DAWN, key=CIPHER", answer: "CTUGXG CV FCMQ", difficulty: "Medium", cipher: "Playfair" },
    { question: "Decode BMODZBXDNABEKUDMUIXMMOUVIF, key=KEYWORD", answer: "HIDETHEGOLDINTHETREESTUMP", difficulty: "Hard", cipher: "Playfair" },
    { question: "Encrypt CRYPTOGRAPHY, key=COMPLEX, then swap first letters", answer: "TRCXSGCQJVHM", difficulty: "Hard", cipher: "Playfair" },
    { question: "Decrypt HIGELM with key=MYSTERY (I/J merged)", answer: "SECRET", difficulty: "Hard", cipher: "Playfair" },
    
    // Hill Cipher
    { question: "Encrypt HI using [[3,3],[2,5]]", answer: "QC", difficulty: "Easy", cipher: "Hill" },
    { question: "Decode LP using [[3,3],[2,5]]", answer: "HI", difficulty: "Easy", cipher: "Hill" },
    { question: "Encrypt BY using [[1,2],[3,5]]", answer: "DQ", difficulty: "Easy", cipher: "Hill" },
    { question: "Decode HFNOS with [[3,3],[2,5]]", answer: "HELLO", difficulty: "Medium", cipher: "Hill" },
    { question: "Encrypt MYSTERY with [[7,8],[11,11]]", answer: "TJVWJBQ", difficulty: "Medium", cipher: "Hill" },
    { question: "Decode AT with [[2,3],[1,4]]", answer: "HI", difficulty: "Medium", cipher: "Hill" },
    { question: "Encrypt ATTACK with [[2,4,5],[9,2,1],[3,17,7]]", answer: "POH", difficulty: "Medium", cipher: "Hill" },
    { question: "Decode ZKQY with [[6,24,1],[13,16,10],[20,17,15]]", answer: "ACTS", difficulty: "Hard", cipher: "Hill" },
    { question: "Encrypt CRYPTOGRAPHY with [[2,3,1],[1,2,1],[1,1,3]]", answer: "UHJWWLVCBNLV", difficulty: "Hard", cipher: "Hill" },
    { question: "Solve Hill Cipher given ciphertext=LP, plaintext=HI", answer: "Key = [[3,3],[2,5]]", difficulty: "Hard", cipher: "Hill" },
    
    // Transposition Cipher
    { question: "Encrypt HELLO with key 4 (columnar)", answer: "HOELL", difficulty: "Easy", cipher: "Transposition" },
    { question: "Decode HLOEL with key 2", answer: "HELLO", difficulty: "Easy", cipher: "Transposition" },
    { question: "Encrypt PUZZLE with key 3", answer: "PZUEL", difficulty: "Easy", cipher: "Transposition" },
    { question: "Decode EHO LLL with key 3", answer: "HELLOL", difficulty: "Medium", cipher: "Transposition" },
    { question: "Encrypt MYSTERY with rail fence 3 rails", answer: "MSEYR TY", difficulty: "Medium", cipher: "Transposition" },
    { question: "Decode TEHCSAITNPME with key 4", answer: "CIPHERTEXT", difficulty: "Medium", cipher: "Transposition" },
    { question: "Encrypt ATTACK AT DAWN with key=3142", answer: "TTAKAC AWDTNA", difficulty: "Medium", cipher: "Transposition" },
    { question: "Decode message with double transposition key1=4312, key2=2143", answer: "SECRET WORD", difficulty: "Hard", cipher: "Transposition" },
    { question: "Encrypt CRYPTOGRAPHY with rail fence 4 + reverse last row", answer: "CHYRYTPOGAR", difficulty: "Hard", cipher: "Transposition" },
    { question: "Decode scrambled text with irregular columns", answer: "COMPLEX MESSAGE", difficulty: "Hard", cipher: "Transposition" },
    
    // One Time Pad
    { question: "Encrypt HELLO with pad XMCKL", answer: "EQNVZ", difficulty: "Easy", cipher: "OTP" },
    { question: "Decode RINFT with pad XMCKL", answer: "HELLO", difficulty: "Easy", cipher: "OTP" },
    { question: "Encrypt BYE with pad ABC", answer: "BZF", difficulty: "Easy", cipher: "OTP" },
    { question: "Decode KHOOR with pad XMCKL", answer: "SECRET", difficulty: "Medium", cipher: "OTP" },
    { question: "Encrypt MYSTERY with random pad QAZWSX", answer: "DNCUVHA", difficulty: "Medium", cipher: "OTP" },
    { question: "Decode RMTQH with pad QWERT", answer: "HELLO", difficulty: "Medium", cipher: "OTP" },
    { question: "Encrypt ATTACK with pad SECRETK", answer: "SXXCSR", difficulty: "Medium", cipher: "OTP" },
    { question: "Cipher=ZICVT, pad unknown, plaintext starts THE", answer: "THEQU", difficulty: "Hard", cipher: "OTP" },
    { question: "Encrypt CRYPTOGRAPHY with 12-letter pad", answer: "Randomized each time", difficulty: "Hard", cipher: "OTP" },
    { question: "Decode OTP ciphertext without pad, repeating pattern", answer: "Can't decrypt uniquely (OTP property)", difficulty: "Hard", cipher: "OTP" },
    
    // Auto Key Cipher
    { question: "Encrypt HELLO with key=KEY", answer: "RIJVS", difficulty: "Easy", cipher: "Autokey" },
    { question: "Decode RIJVS with key=KEY", answer: "HELLO", difficulty: "Easy", cipher: "Autokey" },
    { question: "Encrypt PUZZLE with key=CODE", answer: "RYCEPI", difficulty: "Easy", cipher: "Autokey" },
    { question: "Decode ZICVT with key=MYSTERY", answer: "HELLO", difficulty: "Medium", cipher: "Autokey" },
    { question: "Encrypt ATTACKATDAWN with key=LEMON", answer: "LXFOPVEFRNHR", difficulty: "Medium", cipher: "Autokey" },
    { question: "Decode ciphertext with key start SECRET", answer: "HELLO", difficulty: "Medium", cipher: "Autokey" },
    { question: "Encrypt MYSTERYBOX with key=FUN", answer: "HRWCVCQ", difficulty: "Medium", cipher: "Autokey" },
    { question: "Decode long ciphertext (first word THE)", answer: "THESECRETPLAN", difficulty: "Hard", cipher: "Autokey" },
    { question: "Encrypt CRYPTOGRAPHY with auto key=ENIGMA", answer: "GSVXWIXXNMG", difficulty: "Hard", cipher: "Autokey" },
    { question: "Reverse engineer key from ciphertext GUVF VF ZL FRPERG", answer: "Key = SECRET, Plaintext = THIS IS MY SECRET", difficulty: "Hard", cipher: "Autokey" },
    
    // Atbash Cipher
    { question: "Encode HELLO", answer: "SVOOL", difficulty: "Easy", cipher: "Atbash" },
    { question: "Decode SVOOL", answer: "HELLO", difficulty: "Easy", cipher: "Atbash" },
    { question: "Encode PUZZLE", answer: "KF AARO", difficulty: "Easy", cipher: "Atbash" },
    { question: "Decode ZOOL", answer: "ALLP", difficulty: "Medium", cipher: "Atbash" },
    { question: "Encode MYSTERY", answer: "NBHGVI B", difficulty: "Medium", cipher: "Atbash" },
    { question: "Decode HZOOZ", answer: "SASLL", difficulty: "Medium", cipher: "Atbash" },
    { question: "Encode CRYPTOGRAPHY then reverse words", answer: "BICKTLGKIBX", difficulty: "Hard", cipher: "Atbash" },
    { question: "Decode with spaces scrambled", answer: "HELLO WORLD", difficulty: "Hard", cipher: "Atbash" },
    { question: "Double Atbash on SECRET", answer: "SECRET", difficulty: "Hard", cipher: "Atbash" },
    
    // Polybius Square
    { question: "Encode HELLO", answer: "23 15 31 31 34", difficulty: "Easy", cipher: "Polybius" },
    { question: "Decode 23 15 31 31 34", answer: "HELLO", difficulty: "Easy", cipher: "Polybius" },
    { question: "Encode PUZZLE", answer: "35 45 55 55 31 15", difficulty: "Easy", cipher: "Polybius" },
    { question: "Decode 11 45 51 42", answer: "THIS", difficulty: "Medium", cipher: "Polybius" },
    { question: "Encode MYSTERY", answer: "32 45 43 44 15 42 54", difficulty: "Medium", cipher: "Polybius" },
    { question: "Decode 24 34 35 15", answer: "CODE", difficulty: "Medium", cipher: "Polybius" },
    { question: "Encode ATTACK AT DAWN", answer: "11 44 44 11 13 24 11 44 44 11 25 33", difficulty: "Medium", cipher: "Polybius" },
    { question: "Decode with rows/cols swapped", answer: "SECRET", difficulty: "Hard", cipher: "Polybius" },
    { question: "Encode CRYPTOGRAPHY with keyword square", answer: "13 42 51 45 54 33 42 15 42 32 51", difficulty: "Hard", cipher: "Polybius" },
    { question: "Decode shifted Polybius 33 11 44 12 25", answer: "HELLO", difficulty: "Hard", cipher: "Polybius" },
    
    // A1Z26
    { question: "Encode HELLO", answer: "8 5 12 12 15", difficulty: "Easy", cipher: "A1Z26" },
    { question: "Decode 8 5 12 12 15", answer: "HELLO", difficulty: "Easy", cipher: "A1Z26" },
    { question: "Encode PUZZLE", answer: "16 21 26 26 12 5", difficulty: "Easy", cipher: "A1Z26" },
    { question: "Decode 13 25 19 20 5 18 25", answer: "MYSTERY", difficulty: "Medium", cipher: "A1Z26" },
    { question: "Encode MYSTERY", answer: "13 25 19 20 5 18 25", difficulty: "Medium", cipher: "A1Z26" },
    { question: "Decode 1 20 20 1 3 11", answer: "ATTACK", difficulty: "Medium", cipher: "A1Z26" },
    { question: "Encode ATTACK", answer: "1 20 20 1 3 11", difficulty: "Medium", cipher: "A1Z26" },
    { question: "Encode CRYPTOGRAPHY with Z=1 (reverse numbering)", answer: "24 9 2 11 7 11 8 10 25 19 3", difficulty: "Hard", cipher: "A1Z26" },
    { question: "Decode long numbers mis-split (e.g., 1120 519 20)", answer: "HELLO", difficulty: "Hard", cipher: "A1Z26" },
    { question: "Encode HELLO, then shift numbers +3", answer: "11 8 15 15 18", difficulty: "Hard", cipher: "A1Z26" },
    
    // Baconian Cipher
    { question: "Encode HELLO", answer: "AABBB AABAA ABAAB ABAAB ABBBA", difficulty: "Easy", cipher: "Baconian" },
    { question: "Decode AABAA ABAAA", answer: "HI", difficulty: "Easy", cipher: "Baconian" },
    { question: "Encode PUZZLE", answer: "ABBAB AABBB BAABA BAABA ABAAB AABAA", difficulty: "Easy", cipher: "Baconian" },
    { question: "Decode ABAAB AABBA", answer: "ME", difficulty: "Medium", cipher: "Baconian" },
    { question: "Encode MYSTERY", answer: "ABBAB BAAAB ABBAA BAABB AABAA ABABA BABAB", difficulty: "Medium", cipher: "Baconian" },
    { question: "Decode AAABA AABAA ABABB", answer: "CAT", difficulty: "Medium", cipher: "Baconian" },
    { question: "Encode ATTACK", answer: "AAAAA BAABA BAABA AAAAA BAACA BAABB", difficulty: "Medium", cipher: "Baconian" },
    { question: "Decode message without spaces: AABAABAABAAABABB", answer: "HI", difficulty: "Hard", cipher: "Baconian" },
    { question: "Encode CRYPTOGRAPHY (I/J same)", answer: "ABBAA ABBAB ABAAB AABBB BAABA", difficulty: "Hard", cipher: "Baconian" },
    { question: "Encode HELLO, then swap A/B and decode", answer: "HELLO", difficulty: "Hard", cipher: "Baconian" },
    
    // Trithemius Cipher
    { question: "Encode HELLO", answer: "HFNOS", difficulty: "Easy", cipher: "Trithemius" },
    { question: "Decode HFNOS", answer: "HELLO", difficulty: "Easy", cipher: "Trithemius" },
    { question: "Encode PUZZLE", answer: "PYBBOI", difficulty: "Easy", cipher: "Trithemius" },
    { question: "Decode text with key starting A", answer: "SECRET", difficulty: "Medium", cipher: "Trithemius" },
    { question: "Encode MYSTERY", answer: "NZWZWSF", difficulty: "Medium", cipher: "Trithemius" },
    { question: "Decode progressive shift", answer: "HELLO", difficulty: "Medium", cipher: "Trithemius" },
    { question: "Encode ATTACK", answer: "AUVBGN", difficulty: "Medium", cipher: "Trithemius" },
    { question: "Decode ciphertext with variable shift", answer: "SECRET PLAN", difficulty: "Hard", cipher: "Trithemius" },
    { question: "Encode CRYPTOGRAPHY with Ci=Pi+Ni mod 26", answer: "DTSZXCTNBUZB", difficulty: "Hard", cipher: "Trithemius" },
    { question: "Reverse engineer key from ciphertext", answer: "KEY = ABC..., Plaintext = HELLO", difficulty: "Hard", cipher: "Trithemius" },
    
    // Solitaire Cipher
    { question: "Encrypt HELLO (deck in order)", answer: "RUFJN", difficulty: "Easy", cipher: "Solitaire" },
    { question: "Decode RIJVS", answer: "HELLO", difficulty: "Easy", cipher: "Solitaire" },
    { question: "Encrypt PUZZLE", answer: "BTCHMJ", difficulty: "Easy", cipher: "Solitaire" },
    { question: "Decode message with known deck", answer: "HELLO", difficulty: "Medium", cipher: "Solitaire" },
    { question: "Encrypt MYSTERY with random deck", answer: "QUXZLP", difficulty: "Medium", cipher: "Solitaire" },
    { question: "Decode ciphertext using solitaire", answer: "SECRET", difficulty: "Medium", cipher: "Solitaire" },
    { question: "Encrypt ATTACK AT DAWN", answer: "XEZMWL SXVND", difficulty: "Medium", cipher: "Solitaire" },
    { question: "Reverse engineer deck from ciphertext", answer: "Deck order recovered", difficulty: "Hard", cipher: "Solitaire" },
    { question: "Encrypt CRYPTOGRAPHY multi-deck", answer: "PLXMRQYGTB", difficulty: "Hard", cipher: "Solitaire" },
    { question: "Decrypt long message without deck", answer: "Impossible without deck state", difficulty: "Hard", cipher: "Solitaire" }
];

// Get current puzzle for user (sequential system)
function getCurrentPuzzle() {
    if (!currentUser || !users[currentUser]) {
        return null;
    }
    
    // Initialize user's puzzle progress if not exists
    if (!users[currentUser].puzzleProgress) {
        users[currentUser].puzzleProgress = {
            currentIndex: 0,
            solvedPuzzles: [],
            totalAttempts: 0,
            correctAnswers: 0
        };
        saveUsers();
    }
    
    const progress = users[currentUser].puzzleProgress;
    const currentIndex = progress.currentIndex;
    
    // If user has solved all puzzles, reset to beginning
    if (currentIndex >= PUZZLE_BANK.length) {
        progress.currentIndex = 0;
        saveUsers();
    }
    
    return PUZZLE_BANK[currentIndex];
}

// Get next random puzzle for user
function getNextRandomPuzzle() {
    if (!currentUser || !users[currentUser]) {
        return null;
    }
    
    const progress = users[currentUser].puzzleProgress;
    const solvedPuzzles = progress.solvedPuzzles;
    
    // Get unsolved puzzles
    const unsolvedPuzzles = PUZZLE_BANK.filter((_, index) => !solvedPuzzles.includes(index));
    
    if (unsolvedPuzzles.length === 0) {
        // All puzzles solved, reset
        progress.solvedPuzzles = [];
        progress.currentIndex = 0;
        saveUsers();
        return PUZZLE_BANK[0];
    }
    
    // Pick random unsolved puzzle
    const randomIndex = Math.floor(Math.random() * unsolvedPuzzles.length);
    const selectedPuzzle = unsolvedPuzzles[randomIndex];
    const originalIndex = PUZZLE_BANK.indexOf(selectedPuzzle);
    
    progress.currentIndex = originalIndex;
    saveUsers();
    
    return selectedPuzzle;
}

// Check if user is logged in, redirect if not
function checkLoginRequired() {
    if (!currentUser) {
        alert("Please log in to access this page.");
        window.location.href = "home.html";
        return false;
    }
    return true;
}

// Initialize puzzle system
async function initializePuzzle() {
    console.log("=== STARTING PUZZLE INITIALIZATION ===");
    
    if (!checkLoginRequired()) {
        console.log("❌ Login check failed");
        return;
    }
    
    console.log("✅ Login check passed");
    
    // Ensure questions are loaded
    if (PUZZLE_BANK.length === 0) {
        console.log("Loading questions from JSON...");
        await loadQuestionsFromJSON();
    }
    
    const puzzle = getCurrentPuzzle();
    console.log("Current puzzle:", puzzle);
    
    if (!puzzle) {
        console.log("❌ No puzzle found, getting next random puzzle");
        const nextPuzzle = getNextRandomPuzzle();
        console.log("Next puzzle:", nextPuzzle);
        if (!nextPuzzle) {
            alert("No puzzles available!");
            return;
        }
        window.currentPuzzle = nextPuzzle;
    } else {
        window.currentPuzzle = puzzle;
    }
    
    const container = document.getElementById("puzzleContainer");
    const description = document.getElementById("puzzleDescription");
    const cipherType = document.getElementById("cipherType");
    const difficulty = document.getElementById("difficulty");
    
    console.log("Elements found:", {
        container: !!container,
        description: !!description,
        cipherType: !!cipherType,
        difficulty: !!difficulty
    });
    
    if (container && description && cipherType && difficulty) {
        // Force display the container
        container.style.display = "block";
        container.style.visibility = "visible";
        
        // Set the question content with clear formatting
        const questionText = window.currentPuzzle.question;
        console.log("Setting question:", questionText);
        
        // Clear and set the question directly
        description.innerHTML = `<h4 style="color: #e1bee7; font-size: 18px; margin-bottom: 15px;">${questionText}</h4>`;
        
        // Also set the text content as backup
        description.textContent = questionText;
        
        cipherType.textContent = window.currentPuzzle.cipher;
        difficulty.textContent = window.currentPuzzle.difficulty;
        
        console.log("✅ Puzzle initialized successfully:", questionText);
        console.log("Container display:", container.style.display);
        console.log("Container visibility:", container.style.visibility);
        
        // Force a re-render
        description.style.display = "none";
        description.offsetHeight; // Trigger reflow
        description.style.display = "block";
        
    } else {
        console.log("❌ Missing elements:", {container, description, cipherType, difficulty});
        alert("Error: Could not find puzzle elements. Please refresh the page.");
    }
}

// Check puzzle answer
function checkPuzzleAnswer() {
    if (!currentUser) {
        alert("Please log in to submit answers.");
        return;
    }
    
    const answerInput = document.getElementById("puzzleAnswer");
    const resultDiv = document.getElementById("puzzleResult");
    
    if (!answerInput || !resultDiv || !window.currentPuzzle) {
        console.log("Missing elements for answer check:", {answerInput, resultDiv, currentPuzzle: window.currentPuzzle});
        return;
    }
    
    const userAnswer = answerInput.value.trim().toUpperCase();
    const correctAnswer = window.currentPuzzle.answer.toUpperCase();
    
    console.log("Checking answer:", {userAnswer, correctAnswer});
    
    // Initialize puzzle progress if not exists
    if (!users[currentUser].puzzleProgress) {
        users[currentUser].puzzleProgress = {
            currentIndex: 0,
            solvedPuzzles: [],
            totalAttempts: 0,
            correctAnswers: 0
        };
    }
    
    const progress = users[currentUser].puzzleProgress;
    progress.totalAttempts++;
    
    if (userAnswer === correctAnswer) {
        progress.correctAnswers++;
        resultDiv.innerHTML = "✅ Correct! Moving to next puzzle...";
        resultDiv.style.color = "#4caf50";
        
        // Mark this puzzle as solved
        let currentIndex = -1;
        
        // Try to get index from question ID first
        if (window.currentPuzzle.id) {
            currentIndex = window.currentPuzzle.id - 1; // Convert 1-based ID to 0-based index
        } else {
            // Fallback to finding by question text
            currentIndex = PUZZLE_BANK.findIndex(q => q.question === window.currentPuzzle.question);
        }
        
        console.log("Puzzle solved - ID:", window.currentPuzzle.id, "Index:", currentIndex);
        
        if (currentIndex >= 0 && !progress.solvedPuzzles.includes(currentIndex)) {
            progress.solvedPuzzles.push(currentIndex);
            console.log("Added to solved puzzles:", currentIndex, "Total solved:", progress.solvedPuzzles.length);
        }
        
        // Move to next random puzzle after 2 seconds
        setTimeout(() => {
            loadNextPuzzle();
        }, 2000);
        
        // Mark puzzle solver achievement
        if (!users[currentUser].achievements.includes('puzzle_solver')) {
            users[currentUser].achievements.push('puzzle_solver');
            alert('🏆 Achievement Unlocked: Puzzle Solver - Solve your first puzzle!');
        }
    } else {
        resultDiv.innerHTML = "❌ Incorrect. Try again.";
        resultDiv.style.color = "#f44336";
    }
    
    console.log("Updated progress:", progress);
    
    saveUsers();
    updatePuzzleStats();
    
    // If on dashboard, refresh the dashboard stats
    if (window.location.pathname.includes('test-integration.html')) {
        updateDashboard();
    }
}

// Load next puzzle
function loadNextPuzzle() {
    const puzzle = getNextRandomPuzzle();
    if (!puzzle) return;
    
    const description = document.getElementById("puzzleDescription");
    const cipherType = document.getElementById("cipherType");
    const difficulty = document.getElementById("difficulty");
    const answerInput = document.getElementById("puzzleAnswer");
    const resultDiv = document.getElementById("puzzleResult");
    
    if (description && cipherType && difficulty && answerInput && resultDiv) {
        description.innerHTML = `
            <div style="background: rgba(26,26,26,0.9); padding: 20px; border-radius: 10px; margin: 10px 0; border: 2px solid #4a148c;">
                <h4 style="color: #e1bee7; font-size: 18px; margin-bottom: 15px;">${puzzle.question}</h4>
            </div>
        `;
        
        cipherType.textContent = puzzle.cipher;
        difficulty.textContent = puzzle.difficulty;
        answerInput.value = "";
        resultDiv.innerHTML = "";
        
        window.currentPuzzle = puzzle;
        console.log("Loaded next puzzle:", puzzle.question);
    }
}

// Update puzzle statistics display
function updatePuzzleStats() {
    if (!currentUser || !users[currentUser]) {
        console.log("No current user found");
        return;
    }
    
    // Initialize puzzle progress if not exists
    if (!users[currentUser].puzzleProgress) {
        users[currentUser].puzzleProgress = {
            currentIndex: 0,
            solvedPuzzles: [],
            totalAttempts: 0,
            correctAnswers: 0
        };
        saveUsers();
    }
    
    const progress = users[currentUser].puzzleProgress;
    const accuracy = progress.totalAttempts > 0 ? Math.round((progress.correctAnswers / progress.totalAttempts) * 100) : 0;
    
    console.log("Updating puzzle stats:", progress);
    console.log("Solved puzzles array:", progress.solvedPuzzles);
    console.log("Total attempts:", progress.totalAttempts);
    console.log("Correct answers:", progress.correctAnswers);
    
    // Update dashboard stats if on dashboard page
    const dashboardSolved = document.getElementById("dashboardPuzzlesSolved");
    const dashboardAttempts = document.getElementById("dashboardTotalAttempts");
    const dashboardAccuracy = document.getElementById("dashboardSuccessRate");
    
    if (dashboardSolved) {
        dashboardSolved.textContent = progress.solvedPuzzles ? progress.solvedPuzzles.length : 0;
        console.log("Updated dashboard solved:", progress.solvedPuzzles ? progress.solvedPuzzles.length : 0);
    }
    if (dashboardAttempts) {
        dashboardAttempts.textContent = progress.totalAttempts || 0;
        console.log("Updated dashboard attempts:", progress.totalAttempts || 0);
    }
    if (dashboardAccuracy) {
        dashboardAccuracy.textContent = accuracy + "%";
        console.log("Updated dashboard accuracy:", accuracy + "%");
    }
    
    // Update solved questions list
    updateSolvedQuestionsList();
}

// Update solved questions list in dashboard
function updateSolvedQuestionsList() {
    if (!currentUser || !users[currentUser].puzzleProgress) {
        return;
    }
    
    const solvedQuestionsList = document.getElementById("solvedQuestionsList");
    if (!solvedQuestionsList) return;
    
    const progress = users[currentUser].puzzleProgress;
    const solvedPuzzleIndices = progress.solvedPuzzles || [];
    
    if (solvedPuzzleIndices.length === 0) {
        solvedQuestionsList.innerHTML = `
            <div class="solved-question-item">
                <span class="question-icon">❓</span>
                <span class="question-text">No questions solved yet</span>
                <span class="question-difficulty"></span>
            </div>
        `;
        return;
    }
    
    // Check if PUZZLE_BANK is loaded
    if (!PUZZLE_BANK || PUZZLE_BANK.length === 0) {
        solvedQuestionsList.innerHTML = `
            <div class="solved-question-item">
                <span class="question-icon">⏳</span>
                <span class="question-text">Loading questions...</span>
                <span class="question-difficulty"></span>
            </div>
        `;
        return;
    }
    
    // Clear existing content
    solvedQuestionsList.innerHTML = '';
    
    // Show solved questions (limit to last 10 for performance)
    const recentSolved = solvedPuzzleIndices.slice(-10).reverse();
    
    recentSolved.forEach(index => {
        if (index < PUZZLE_BANK.length) {
            const question = PUZZLE_BANK[index];
            const questionItem = document.createElement('div');
            questionItem.className = 'solved-question-item';
            
            const difficultyClass = question.difficulty ? question.difficulty.toLowerCase() : 'easy';
            const truncatedQuestion = question.question.length > 80 ? 
                question.question.substring(0, 80) + '...' : 
                question.question;
            
            questionItem.innerHTML = `
                <span class="question-icon">✅</span>
                <span class="question-text">${truncatedQuestion}</span>
                <span class="question-difficulty ${difficultyClass}">${question.difficulty || 'Easy'}</span>
            `;
            
            solvedQuestionsList.appendChild(questionItem);
        }
    });
    
    // Add "show more" if there are more than 10 solved questions
    if (solvedPuzzleIndices.length > 10) {
        const showMoreItem = document.createElement('div');
        showMoreItem.className = 'solved-question-item';
        showMoreItem.style.justifyContent = 'center';
        showMoreItem.innerHTML = `
            <span class="question-text" style="color: #ba68c8; font-style: italic;">
                ... and ${solvedPuzzleIndices.length - 10} more solved questions
            </span>
        `;
        solvedQuestionsList.appendChild(showMoreItem);
    }
}


// Show hint
function showHint() {
    if (window.currentPuzzle && window.currentPuzzle.hint) {
        alert(`Hint: ${window.currentPuzzle.hint}`);
    } else {
        alert("No hint available for this puzzle.");
    }
}

// Show solution (placeholder)
function showSolution() {
    if (window.currentPuzzle) {
        alert(`Solution: ${window.currentPuzzle.answer}`);
    }
}

// Generate new puzzle (get next random puzzle)
function generateNewPuzzle() {
    if (!currentUser) {
        alert("Please log in to get a new puzzle.");
        return;
    }
    
    loadNextPuzzle();
    alert("New random puzzle loaded!");
}

// Refresh puzzle statistics manually
function refreshPuzzleStats() {
    if (!currentUser) {
        alert("Please log in to refresh statistics.");
        return;
    }
    
    updatePuzzleStats();
    alert("Statistics refreshed!");
}

// Debug function to check puzzle statistics
function debugPuzzleStats() {
    if (!currentUser) {
        console.log("No user logged in");
        return;
    }
    
    const user = users[currentUser];
    console.log("Current user:", currentUser);
    console.log("User data:", user);
    console.log("Puzzle progress:", user.puzzleProgress);
    
    if (user.puzzleProgress) {
        console.log("Solved puzzles:", user.puzzleProgress.solvedPuzzles);
        console.log("Total attempts:", user.puzzleProgress.totalAttempts);
        console.log("Correct answers:", user.puzzleProgress.correctAnswers);
    }
    
    // Also check PUZZLE_BANK
    console.log("PUZZLE_BANK length:", PUZZLE_BANK.length);
    console.log("First few questions:", PUZZLE_BANK.slice(0, 3));
    
    // Show alert with key info
    const solvedCount = user.puzzleProgress ? user.puzzleProgress.solvedPuzzles.length : 0;
    const attempts = user.puzzleProgress ? user.puzzleProgress.totalAttempts : 0;
    alert(`Debug Info:\nSolved: ${solvedCount}\nAttempts: ${attempts}\nCheck console for details`);
}

// Test function to manually add a solved puzzle
function testAddSolvedPuzzle() {
    if (!currentUser) {
        alert("Please log in first");
        return;
    }
    
    // Initialize puzzle progress if not exists
    if (!users[currentUser].puzzleProgress) {
        users[currentUser].puzzleProgress = {
            currentIndex: 0,
            solvedPuzzles: [],
            totalAttempts: 0,
            correctAnswers: 0
        };
    }
    
    // Add first puzzle as solved for testing
    if (!users[currentUser].puzzleProgress.solvedPuzzles.includes(0)) {
        users[currentUser].puzzleProgress.solvedPuzzles.push(0);
        users[currentUser].puzzleProgress.totalAttempts++;
        users[currentUser].puzzleProgress.correctAnswers++;
        saveUsers();
        updatePuzzleStats();
        alert("Added puzzle 0 as solved for testing");
    } else {
        alert("Puzzle 0 already solved");
    }
}

// ==================== EVENT LISTENERS ====================
document.addEventListener("DOMContentLoaded", function () {
    // Initialize EmailJS (configurable)
    try {
        const EMAILJS_PUBLIC_KEY = (window.EMAILJS_CONFIG && window.EMAILJS_CONFIG.PUBLIC_KEY) || "Mq0q1ncvZ8eoMrGB7";
        emailjs.init(EMAILJS_PUBLIC_KEY);
    } catch(e) {}
    
    // Restore session if user previously logged in (or via URL param)
    try {
        const urlUser = new URLSearchParams(window.location.search).get('u');
        const storedUser = (urlUser || localStorage.getItem('cl_user') || '').trim();
        if (storedUser) {
            const resolved = resolveUser(storedUser);
            currentUser = resolved.user ? resolved.key : storedUser; // fallback to raw to support isolated storage contexts
        }
        if(currentUser){ try { localStorage.setItem('cl_user', currentUser); } catch(e) {} }
    } catch(e) {}
    
    // Register form handler
    const registerForm = document.getElementById("registerForm");
    if (registerForm) {
        registerForm.addEventListener("submit", function(e) {
            e.preventDefault();
            const username = document.getElementById("registerUsername").value.trim();
            const password = document.getElementById("registerPassword").value;
            const email = document.getElementById("registerEmail").value.trim();
            
            if (username && password && email) {
                if (register(username, password, email)) {
                    closeModal('registerModal');
                    registerForm.reset();
                }
            } else {
                alert("Please fill in all fields.");
            }
        });
    }

    // Login form handler
    const loginForm = document.getElementById("loginForm");
    if (loginForm) {
        loginForm.addEventListener("submit", function(e) {
            e.preventDefault();
            const username = document.getElementById("loginUsername").value.trim();
            const password = document.getElementById("loginPassword").value;
            
            if (username && password) {
                if (login(username, password)) {
                    closeModal('loginModal');
                    loginForm.reset();
                }
            } else {
                alert("Please fill in all fields.");
            }
        });
    }

    // Verification button handler
    const verifyBtn = document.getElementById("verifyBtn");
    if (verifyBtn) {
        verifyBtn.addEventListener("click", function() {
            const inputCode = document.getElementById("verificationCode").value.trim();
            if (inputCode) {
            verifyCode(inputCode);
            } else {
                alert("Please enter the verification code.");
            }
        });
    }

    // Update UI on page load
    updateUserUI();
    
    // Update progress bars on page load
    updateProgressBars();
    
    // Update dashboard if on dashboard page
    if (window.location.pathname.includes('test-integration.html')) {
        updateDashboard();
        updatePuzzleStats();
    }
    
    // Initialize puzzle system if on daily puzzle page
    if (window.location.pathname.includes('daily-puzzle.html')) {
        console.log("On daily puzzle page, initializing...");
        // Add a longer delay to ensure DOM is fully loaded
        setTimeout(() => {
            console.log("Attempting to initialize puzzle after delay...");
            initializePuzzle();
        }, 500);
        
        // Also try immediately
        console.log("Attempting to initialize puzzle immediately...");
        initializePuzzle();
    }
    
    // Check login requirement for protected pages
    if (window.location.pathname.includes('daily-puzzle.html') || 
        window.location.pathname.includes('test-integration.html') || 
        window.location.pathname.includes('knowledge.html')) {
        if (!currentUser) {
            alert("Please log in to access this page.");
            window.location.href = "home.html";
        }
    }
    
    // If logged in, rewrite navigation links to carry session fallback across origins
    if (currentUser) { rewriteNavLinksWithUser(currentUser); }
    
    // Initialize puzzle system if on puzzle page
    if (window.location.pathname.includes('daily-puzzle.html')) {
        initializePuzzle();
    }
    
    // Initialize dashboard if on dashboard page
    if (window.location.pathname.includes('test-integration.html')) {
        updateDashboard();
        // Also update puzzle stats specifically
        updatePuzzleStats();
    }

    // Add visibility change listener to refresh dashboard when user returns
    document.addEventListener('visibilitychange', function() {
        if (!document.hidden && window.location.pathname.includes('dashboard.html')) {
            updatePuzzleStats();
        }
    });

    // Re-export updated handlers to window to ensure latest implementations are used
    try {
        window.logout = logout;
        window.showLoginForm = showLoginForm;
        window.showRegisterForm = showRegisterForm;
        window.checkPuzzleAnswer = checkPuzzleAnswer;
        window.showHint = showHint;
        window.showSolution = showSolution;
        window.generateNewPuzzle = generateNewPuzzle;
        window.refreshPuzzleStats = refreshPuzzleStats;
        window.debugPuzzleStats = debugPuzzleStats;
        window.testAddSolvedPuzzle = testAddSolvedPuzzle;
    } catch(e) {}
});

// Append ?u=<user> to site navigation links to preserve session even if storage is isolated
function rewriteNavLinksWithUser(username){
    try{
        const links = document.querySelectorAll('a[href$=".html"]');
        links.forEach(a=>{
            try{
                const url = new URL(a.getAttribute('href'), window.location.href);
                url.searchParams.set('u', username);
                a.setAttribute('href', url.pathname + url.search + url.hash);
            }catch(e){}
        });
    }catch(e){}
}

function checkAnswer(idx) {
  const input = document.getElementById(`answer-${idx}`).value.trim();
  const result = document.getElementById(`result-${idx}`);
  if (input === challenges[idx].flag) {
    result.innerHTML = "<span style='color:lime;'>✅ Correct!</span>";

    // Save in local storage
    let solved = JSON.parse(localStorage.getItem('solvedQuestions') || '[]');
    if (!solved.includes(idx)) {
      solved.push(idx);
      localStorage.setItem('solvedQuestions', JSON.stringify(solved));
    }
    
    // Also update the overall puzzle progress if applicable
    updatePuzzleProgress(idx);
  } else {
    result.innerHTML = "<span style='color:red;'>❌ Wrong flag!</span>";
  }
}

function loadChallenges() {
  const container = document.getElementById('challengesContainer');
  const solvedPuzzles = currentUser && users[currentUser] && users[currentUser].puzzleProgress ? users[currentUser].puzzleProgress.solvedPuzzles : [];
  container.innerHTML = '';
  challenges.forEach((ch, idx) => {
    if (solvedPuzzles && solvedPuzzles.includes(idx)) return; // skip solved
    const div = document.createElement('div');
    div.className = 'challenge-card';
    div.innerHTML = `
      <h3>${ch.title} <span class="points">[${ch.points} pts]</span></h3>
      <p><strong>Category:</strong> ${ch.category}</p>
      <p>${ch.description}</p>
      <input type="text" id="answer-${idx}" placeholder="Enter flag (CTF{...})" />
      <button class="btn btn-primary" onclick="checkAnswer(${idx})">Submit</button>
      <div id="result-${idx}" class="result"></div>
    `;
    container.appendChild(div);
  });
}


document.addEventListener('DOMContentLoaded', () => {
  if (typeof updatePuzzleStats === 'function') updatePuzzleStats();
  if (typeof updateSolvedQuestionsList === 'function') updateSolvedQuestionsList();
});

