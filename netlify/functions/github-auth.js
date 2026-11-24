const crypto = require('node:crypto');
const owner='hillkoff-korea',repo='korea-fire-safety';
const cookie=(name,val,maxAge)=>`${name}=${encodeURIComponent(val)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
const redirect=(url,cookieValue)=>({statusCode:302,headers:{Location:url,'Set-Cookie':cookieValue,'Cache-Control':'no-store'},body:''});
const key=()=>crypto.createHash('sha256').update(process.env.SESSION_SECRET||'').digest();
const seal=s=>{let iv=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',key(),iv),v=Buffer.concat([c.update(s,'utf8'),c.final()]);return Buffer.concat([iv,c.getAuthTag(),v]).toString('base64url')};
const parse=(h)=>Object.fromEntries((h||'').split(';').map(x=>x.trim().split('=').map(decodeURIComponent)).filter(x=>x.length===2));
exports.handler=async event=>{
 const base='https://kfiresafety.co.kr', mode=event.queryStringParameters?.mode||'start';
 if(!process.env.GITHUB_CLIENT_ID||!process.env.GITHUB_CLIENT_SECRET||!process.env.SESSION_SECRET)return {statusCode:500,body:'OAuth environment variables not configured'};
 if(mode==='logout')return redirect('/admin.html',cookie('fire_session','',0));
 if(mode==='start'){
  const state=crypto.randomBytes(24).toString('hex');
  const url=new URL('https://github.com/login/oauth/authorize');url.searchParams.set('client_id',process.env.GITHUB_CLIENT_ID);url.searchParams.set('redirect_uri',base+'/.netlify/functions/github-auth?mode=callback');url.searchParams.set('scope','repo');url.searchParams.set('state',state);
  return redirect(url.toString(),cookie('fire_oauth_state',state,600));
 }
 if(mode==='callback'){
  const q=event.queryStringParameters||{},cookies=parse(event.headers.cookie);
  if(!q.code||!q.state||!cookies.fire_oauth_state||q.state!==cookies.fire_oauth_state)return {statusCode:403,body:'OAuth state mismatch'};
  const r=await fetch('https://github.com/login/oauth/access_token',{method:'POST',headers:{Accept:'application/json','Content-Type':'application/json'},body:JSON.stringify({client_id:process.env.GITHUB_CLIENT_ID,client_secret:process.env.GITHUB_CLIENT_SECRET,code:q.code,redirect_uri:base+'/.netlify/functions/github-auth?mode=callback'})});
  const j=await r.json();if(!j.access_token)return {statusCode:401,body:'GitHub authentication failed'};
  const check=await fetch(`https://api.github.com/repos/${owner}/${repo}`,{headers:{Authorization:`Bearer ${j.access_token}`,Accept:'application/vnd.github+json','User-Agent':'fire-safety-admin'}});
  const info=await check.json();if(!check.ok||!info.permissions?.push)return {statusCode:403,body:'GitHub repository write permission required'};
  return redirect('/admin.html',cookie('fire_session',seal(JSON.stringify({token:j.access_token,exp:Date.now()+7*86400000})),7*86400));
 }
 return {statusCode:404,body:'Not found'};
};
