// Deliberately vulnerable, bounded local-lab baseline. Never use in production.
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns/promises';

export function makePreviewClient(policy = {hosts:{}}, {
  resolveAll = host => dns.lookup(host,{all:true,verbatim:true}), ca,
} = {}) {
  async function fetchPreview(raw, {signal} = {}) {
    const url = new URL(raw);
    if (!['http:','https:'].includes(url.protocol)) throw new Error('scheme denied');
    const rule = policy.hosts[url.hostname];
    const port = Number(url.port || (url.protocol==='https:' ? 443 : 80));
    if (!rule || !rule.ports.includes(port)) throw new Error('host/port denied');
    const answers = await resolveAll(url.hostname);
    // BUG: checks only the first answer, then drops the checked connection identity.
    if (!answers[0] || !rule.addresses.some(x=>x.address===answers[0].address && x.family===answers[0].family)) {
      throw new Error('address denied');
    }
    return request(url,signal,0);
  }
  function request(url,signal,depth) {
    if(depth>=16) return Promise.reject(new Error('lab safety redirect ceiling'));
    return new Promise((resolve,reject)=>{
      const transport = url.protocol==='https:' ? https : http;
      const req = transport.request({protocol:url.protocol, hostname:url.hostname,
        port:Number(url.port || (url.protocol==='https:' ? 443 : 80)),
        path:url.pathname+url.search, method:'GET', agent:false, ca,
        rejectUnauthorized:true, servername:url.hostname,
        headers:{Host:url.host}, signal,
        lookup(host,options,callback) {
          // BUG: performs another resolution after the policy check.
          resolveAll(host).then(values=>{
            if(!values.length) return callback(new Error('empty DNS'));
            if(options.all) callback(null,values);
            else callback(null,values[0].address,values[0].family);
          },callback);
        },
      },res=>{
        if([301,302,303,307,308].includes(res.statusCode) && res.headers.location) {
          // BUG: follows a new authority without repeating policy checks.
          res.destroy();
          request(new URL(res.headers.location,url),signal,depth+1).then(resolve,reject);
          return;
        }
        const chunks=[];let count=0;
        res.on('data',chunk=>{
          count+=chunk.length;
          // Hard ceiling only to keep the intentionally vulnerable baseline bounded.
          if(count>8*1024*1024) req.destroy(new Error('lab safety body ceiling'));
          else chunks.push(chunk);
        });
        res.on('aborted',()=>reject(new Error('response aborted')));
        res.on('error',reject);
        res.on('end',()=>resolve({url:url.href,status:res.statusCode,body:Buffer.concat(chunks)}));
      });
      req.setTimeout(500,()=>req.destroy(new Error('hop timeout')));
      req.on('error',reject);req.end();
    });
  }
  return {fetchPreview};
}
