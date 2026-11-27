const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { createHash, createHmac, timingSafeEqual } = require('node:crypto');
const keys = [
 'SI PUDIERA ELEGIRTE OTRA VEZ_animado.mp4',
 '1-TUS PRIMEROS DÍAS COMO MAMÁ.mp4',
 '2- LA GRAN NOTICIA.mp4',
 '3- ANTES DE MI LLEGADA.mp4',
 '4- MIS PRIMEROS DÍAS JUNTO A TI.mp4',
 '5- SIGO AQUI.mp4',
 '6- MOMENTOS.mp4'
];
const digest = s => createHash('sha256').update(s).digest();
const equal = (a,b) => timingSafeEqual(digest(a),digest(b));
const sign = (expiry, secret) => createHmac('sha256',secret).update('netflix-session:'+expiry).digest('hex');
function authorized(req, secret) {
 const match = /(?:^|;\s*)netflix_session=(\d+)\.([a-f0-9]{64})(?:;|$)/.exec(req.headers.cookie || '');
 return !!match && Number(match[1]) > Date.now() && equal(match[2],sign(match[1],secret));
}
module.exports = async (req,res) => {
 res.setHeader('Cache-Control','no-store');
 if(req.method !== 'POST') return res.status(405).json({error:'Method not allowed'});
 const e = process.env;
 if(!e.NETFLIX_ACCESS_PASSWORD || !e.R2_ACCOUNT_ID || !e.R2_ACCESS_KEY_ID || !e.R2_SECRET_ACCESS_KEY || !e.R2_BUCKET_NAME) return res.status(503).json({error:'Configuration missing'});
 const {id,password,action} = req.body || {};
 const secret = e.NETFLIX_ACCESS_PASSWORD;
 if(action === 'login') {
  if(typeof password !== 'string' || password.length > 512 || !equal(password,secret)) return res.status(401).json({error:'Unauthorized'});
  const expiry = String(Date.now()+86400000);
  res.setHeader('Set-Cookie',`netflix_session=${expiry}.${sign(expiry,secret)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`);
  return res.status(200).json({ok:true});
 }
 if(!authorized(req,secret)) return res.status(401).json({error:'Unauthorized'});
 if(action === 'session') return res.status(200).json({ok:true});
 if(typeof id !== 'string' || !/^[0-6]$/.test(id)) return res.status(400).json({error:'Invalid video'});
 try {
 const client = new S3Client({region:'auto',endpoint:`https://${e.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,credentials:{accessKeyId:e.R2_ACCESS_KEY_ID,secretAccessKey:e.R2_SECRET_ACCESS_KEY},forcePathStyle:true,requestChecksumCalculation:'WHEN_REQUIRED',responseChecksumValidation:'WHEN_REQUIRED'});
 const url = await getSignedUrl(client,new GetObjectCommand({Bucket:e.R2_BUCKET_NAME,Key:keys[Number(id)]}),{expiresIn:3600});
 return res.status(200).json({url});
 } catch(err) { return res.status(500).json({error:'Signing failed'}); }
};
