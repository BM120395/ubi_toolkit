#!/usr/bin/env python3
from __future__ import annotations
from typing import List, Dict, Tuple, Set
_GF={}; _GEN={}
def bits(data,o):
 for x in data:
  for i in (range(8) if o=='lsb' else range(7,-1,-1)): yield (x>>i)&1
def pack(q,bo='forward',po='msb'):
 q=list(q)
 while len(q)%8:q.append(0)
 out=[]
 for i in range(0,len(q),8):
  z=q[i:i+8]; z=z[::-1] if po=='lsb' else z; v=0
  for x in z:v=(v<<1)|x
  out.append(v)
 if bo=='reverse':out.reverse()
 return bytes(out)
def gf(m,p):
 if (m,p) in _GF:return _GF[m,p]
 n=(1<<m)-1;e=[0]*(2*n+2);l=[-1]*(n+1);x=1
 for i in range(n):
  e[i]=x;l[x]=i;x<<=1
  if x&(1<<m):x^=p
  x&=n
 for i in range(n,2*n+2):e[i]=e[i-n]
 _GF[m,p]=(e,l);return e,l
def mul(a,b,e,l,n):return 0 if not a or not b else e[(l[a]+l[b])%n]
def pmul(a,b,e,l,n):
 c=[0]*(len(a)+len(b)-1)
 for i,x in enumerate(a):
  for j,y in enumerate(b):c[i+j]^=mul(x,y,e,l,n)
 return c
def gen(m,t,p):
 k=(m,t,p)
 if k in _GEN:return _GEN[k]
 n=(1<<m)-1;e,l=gf(m,p);seen=set();g=[1]
 for root in range(1,2*t+1):
  if root in seen:continue
  co=[];x=root%n
  while x not in co:co.append(x);seen.add(x);x=(x*2)%n
  mp=[1]
  for z in co:mp=pmul(mp,[1,e[z%n]],e,l,n)
  if any(x not in (0,1) for x in mp):_GEN[k]=None;return None
  c=[0]*(len(g)+len(mp)-1)
  for i,a in enumerate(g):
   if a:
    for j,b in enumerate(mp):
     if b:c[i+j]^=1
  g=c
 _GEN[k]=g;return g
def bch(data,m,t,p,io,bo,po,nbytes):
 g=gen(m,t,p)
 if not g:raise ValueError('invalid BCH generator')
 r=len(g)-1;msg=list(bits(data,io));w=msg+[0]*r;gd=list(reversed(g))
 for i in range(len(msg)):
  if w[i]:
   for j,v in enumerate(gd):
    if v:w[i+j]^=1
 return pack(w[-r:] if r else [],bo,po)[:nbytes].ljust(nbytes,b'\0')
def hamming(data,io,nbytes,secded=True):
 b=list(bits(data,io));r=1
 while (1<<r)<len(b)+r+1:r+=1
 c=[0]*(len(b)+r+1);di=0
 for p in range(1,len(c)):
  if p&(p-1):c[p]=b[di];di+=1
 q=[]
 for k in range(r):
  v=0
  for p in range(1,len(c)):
   if p&(1<<k):v^=c[p]
  q.append(v)
 if secded:q.append(sum(b)&1)
 return pack(q)[:nbytes].ljust(nbytes,b'\0')
def encode_step(data,profile):
 m=dict(profile.best_model or {}); fam=str(m.get('family') or profile.algorithm).lower(); n=profile.ecc_bytes_per_step
 if fam=='bch': raw=bch(data,int(m['m']),int(m['t']),int(str(m['primitive_polynomial']),0),m.get('input_bit_order','msb'),m.get('parity_byte_order','forward'),m.get('parity_bit_order','msb'),n)
 elif fam=='hamming': raw=hamming(data,m.get('input_bit_order','msb'),n,m.get('secded',True))
 else: raise ValueError('unsupported ECC family: '+fam)
 if m.get('invert_output',profile.invert_output):raw=bytes(255-x for x in raw)
 mask=bytes.fromhex(m.get('xor_mask',profile.xor_mask) or '')
 if mask:raw=bytes(x^mask[i%len(mask)] for i,x in enumerate(raw))
 return raw
def recalc_page(main,oob,profile,geom):
 out=bytearray(oob); n=profile.ecc_bytes_per_step
 starts=(profile.layout or {}).get('slot_starts') if getattr(profile,'layout',None) else None
 if not starts:
  pos=profile.oob_ecc_positions;starts=[pos[i*n] for i in range(profile.steps_per_page)]
 for k,s in enumerate(starts[:profile.steps_per_page]):
  d=main[k*profile.step_size:(k+1)*profile.step_size]
  out[int(s):int(s)+n]=encode_step(d,profile)
 return bytes(out)
