const crypto=require('node:crypto');
const owner='hillkoff-korea',repo='korea-fire-safety';
const cookies=h=>Object.fromEntries((h||'').split(';').map(x=>x.trim().split('=').map(decodeURIComponent)).filter(x=>x.length===2));
function session(h){let s=cookies(h).fire_session;if(!s||!process.env.SESSION_SECRET)throw Error('Not logged in');let b=Buffer.from(s,'base64url'),k=crypto.createHash('sha256').update(process.env.SESSION_SECRET).digest(),d=crypto.createDecipheriv('aes-256-gcm',k,b.subarray(0,12));d.setAuthTag(b.subarray(12,28));let v=JSON.parse(Buffer.concat([d.update(b.subarray(28)),d.final()]).toString());if(Date.now()>v.exp)throw Error('Expired');return v.token}
exports.handler=async e=>{try{
 const token=session(e.headers.cookie);const path=e.queryStringParameters?.path;
 if(!path||!(/^(cms-data\.js|index\.html)$/.test(path)||/^assets\/[a-zA-Z0-9._/-]+\.(png|jpg|jpeg|webp|gif)$/.test(path)&&!path.includes('..')))return {statusCode:400,body:'Invalid path'};
 if(!['GET','PUT'].includes(e.httpMethod)||e.httpMethod==='PUT'&&path==='index.html')return {statusCode:405,body:'Not allowed'};
 let body;if(e.httpMethod==='PUT'){body=JSON.parse(e.body||'{}');if(!body.content||!body.message||body.branch!=='main')return {statusCode:400,body:'Invalid update'};body=JSON.stringify(body)}
 const r=await fetch(`https://api.github.com/repos/${owner}/${repo}/contents/${path}`,{method:e.httpMethod,headers:{Authorization:`Bearer ${token}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'fire-safety-admin',...(body?{'Content-Type':'application/json'}:{})},body});
 return {statusCode:r.status,headers:{'Content-Type':'application/json','Cache-Control':'no-store'},body:await r.text()};
 }catch(err){return {statusCode:401,body:JSON.stringify({message:err.message})}}
};
