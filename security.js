const enc=new TextEncoder();
export const json=(d,s=200,h={})=>new Response(JSON.stringify(d),{status:s,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...h}});
export const fail=(m,s=400)=>json({ok:false,error:m},s);
export const id=(n=18)=>{let a=new Uint8Array(n);crypto.getRandomValues(a);return [...a].map(x=>x.toString(16).padStart(2,'0')).join('')};
export async function hash(v){let b=await crypto.subtle.digest('SHA-256',enc.encode(v));return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('')}
export async function pwHash(p,s){let k=await crypto.subtle.importKey('raw',enc.encode(p),'PBKDF2',false,['deriveBits']);let b=await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:enc.encode(s),iterations:310000},k,256);return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('')}
export async function pwVerify(p,s,h){let a=await pwHash(p,s);if(a.length!==h.length)return false;let d=0;for(let i=0;i<a.length;i++)d|=a.charCodeAt(i)^h.charCodeAt(i);return d===0}
export const clean=(v,n=2000)=>typeof v==='string'?v.trim().slice(0,n):'';
export const phoneOK=v=>/^((\+98|0098|0)?9\d{9})$/.test(v.replace(/[\s-]/g,''));
export async function body(req,max=200000){let t=await req.text();if(t.length>max)throw Error('حجم اطلاعات ارسالی بیش از حد مجاز است.');return JSON.parse(t||'{}')}
export function cookie(req,n){let x=(req.headers.get('Cookie')||'').split(';').map(s=>s.trim()).find(s=>s.startsWith(n+'='));return x?decodeURIComponent(x.slice(n.length+1)):''}
export const setCookie=(v,age)=>`miad_session=${encodeURIComponent(v)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;
export const clearCookie=()=>`miad_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
export const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function cors(env){return {'access-control-allow-origin':env.APP_ORIGIN||'*','access-control-allow-credentials':'true','access-control-allow-methods':'GET,POST,PUT,PATCH,DELETE,OPTIONS','access-control-allow-headers':'Content-Type,X-CSRF-Token','vary':'Origin','x-content-type-options':'nosniff','referrer-policy':'strict-origin-when-cross-origin','x-frame-options':'DENY','content-security-policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"}}
export function validSignature(s){if(typeof s!=='string'||!s.startsWith('data:image/png;base64,')||s.length>120000)return false;try{let b=atob(s.split(',')[1]);return b.length>150&&b.length<80000&&b.slice(0,8)==='\x89PNG\r\n\x1a\n'}catch{return false}}
