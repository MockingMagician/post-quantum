#!/usr/bin/env python3
"""Pin byte-oriented official ACVP primitive vectors; no runtime dependency."""
import argparse
import hashlib
import hmac
import json
from pathlib import Path
from urllib.request import urlopen
ROOT=Path(__file__).resolve().parent
COMMIT='975de31eb83d87039ec88934fdc47d8c312b892d'
BASE=f'https://raw.githubusercontent.com/usnistgov/ACVP-Server/{COMMIT}/gen-val/json-files/'
MODES=('SHA2-512-1.0','SHA3-256-2.0','SHA3-512-2.0','SHAKE-128-FIPS202','SHAKE-256-FIPS202','HMAC-SHA2-512-2.0','KDA-HKDF-Sp800-56Cr1')

def render(records):
 return ''.join(''.join(f'{k}={v}\n' for k,v in sorted(r.items()))+'\n' for r in records)

def hkdf(ikm,salt,info,length):
 prk=hmac.digest(salt,ikm,'sha512');out=b'';t=b''
 for i in range(1,(length+63)//64+1):t=hmac.digest(prk,t+info+bytes([i]),'sha512');out+=t
 return out[:length]

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
 output=ROOT/'kat/primitives.kat';manifestpath=ROOT/'kat/primitives-manifest.json'
 existing=json.loads(manifestpath.read_text()) if manifestpath.exists() else None
 if args.check:
  assert existing and hashlib.sha256(output.read_bytes()).hexdigest()==existing['outputSha256']
  print('Verified',existing['cases'],'official primitive vector cases');return
 records=[];sources=[]
 for mode in MODES:
  url=BASE+mode+'/internalProjection.json';raw=urlopen(url,timeout=60).read();digest=hashlib.sha256(raw).hexdigest()
  if existing:assert next(s for s in existing['sources'] if s['mode']==mode)['sha256']==digest
  document=json.loads(raw);selected=[]
  for group in document['testGroups']:
   if group['testType']!='AFT':continue
   if mode.startswith('KDA') and group['kdfConfiguration']['hmacAlg']!='SHA2-512':continue
   for case in group['tests']:
    r={'algorithm':mode,'tcId':case['tcId']}
    if mode.startswith('KDA'):
     p=case['kdfParameter'];config=group['kdfConfiguration'];assert config['fixedInfoPattern']=='uPartyInfo||vPartyInfo||l'
     info=b''.join(bytes.fromhex(case[party].get(field,'')) for party in ('fixedInfoPartyU','fixedInfoPartyV') for field in ('partyId','ephemeralData'))+int(config['l']).to_bytes(4,'big')
     expected=bytes.fromhex(case['dkm']);ikm=bytes.fromhex(p['z']);salt=bytes.fromhex(p['salt'])
     assert hkdf(ikm,salt,info,len(expected))==expected,('HKDF extraction error',case['tcId'])
     r.update(ikm=ikm.hex(),salt=salt.hex(),info=info.hex(),expected=expected.hex())
    elif mode.startswith('HMAC'):
     if any(case[k]%8 for k in ('keyLen','msgLen','macLen')):continue
     msg=bytes.fromhex(case['msg'])[:case['msgLen']//8];key=bytes.fromhex(case['key'])[:case['keyLen']//8];expected=bytes.fromhex(case['mac'])
     assert hmac.digest(key,msg,'sha512')[:case['macLen']//8]==expected
     r.update(message=msg.hex(),key=key.hex(),expected=expected.hex())
    else:
     if case['len']%8 or case.get('outLen',0)%8:continue
     msg=bytes.fromhex(case['msg'])[:case['len']//8];expected=bytes.fromhex(case['md'])
     name={'SHA2-512-1.0':'sha512','SHA3-256-2.0':'sha3_256','SHA3-512-2.0':'sha3_512','SHAKE-128-FIPS202':'shake_128','SHAKE-256-FIPS202':'shake_256'}[mode]
     hashobj=getattr(hashlib,name)(msg);actual=hashobj.digest(len(expected)) if name.startswith('shake') else hashobj.digest()
     assert actual==expected,('hash extraction error',mode,case['tcId'])
     r.update(message=msg.hex(),expected=expected.hex())
    records.append(r);selected.append(case['tcId'])
  sources.append({'mode':mode,'url':url,'sha256':digest,'selectedTcIds':selected,'cases':len(selected)})
 encoded=render(records).encode();output.write_bytes(encoded)
 manifest={'upstreamCommit':COMMIT,'selection':'All AFT cases with byte-aligned messages, keys and outputs; KDA-HKDF selects SHA2-512 groups from Sp800-56Cr1. No MCT/LDT or bit-oriented API claim.','cases':len(records),'outputSha256':hashlib.sha256(encoded).hexdigest(),'sources':sources}
 manifestpath.write_text(json.dumps(manifest,indent=2)+'\n');print('Wrote',len(records),'official primitive cases')
if __name__=='__main__':main()
