import csv,glob,collections,os
def load(d):
    R={}
    for f in sorted(glob.glob(f'{d}/batch*.tsv'), key=lambda p: (2 if 'pdf' in p else 1 if 'retry' in p else 0, p)):
        for r in csv.DictReader(open(f),delimiter='\t'):
            R[r['arxiv_id'].split('v')[0]]=r
    return R
A,B=load('A'),load('B')
print('A',len(A),'B',len(B), 'missing', set(A)^set(B))
def kappa(pairs):
    n=len(pairs); 
    if not n: return None
    po=sum(a==b for a,b in pairs)/n
    ca=collections.Counter(a for a,_ in pairs); cb=collections.Counter(b for _,b in pairs)
    pe=sum(ca[k]*cb[k] for k in set(ca)|set(cb))/n/n
    return po,(po-pe)/(1-pe) if pe<1 else 1.0
both=[k for k in A if A[k]['status']=='CODED' and B.get(k,{}).get('status')=='CODED']
print('status agree', sum(A[k]['status']==B[k]['status'] for k in A), 'of', len(A))
for q in ('Q1','Q2','Q3','Q4','outcome'):
    p=[(A[k][q].strip().upper(),B[k][q].strip().upper()) for k in both]
    po,k=kappa(p); print(q,'n',len(p),'agree',round(po,3),'kappa',round(k,3))
dis=[]
for k in A:
    a,b=A[k],B.get(k)
    if not b: continue
    fields=[f for f in ('status','Q1','Q2','Q3','Q4') if a[f].strip().upper()!=b[f].strip().upper()]
    if fields: dis.append((k,fields,a['outcome'],b['outcome']))
print('papers with any disagreement',len(dis))
for d in dis: print(' ',d)
print('outcomes A',collections.Counter(A[k]['outcome'] or A[k]['status'] for k in A))
print('outcomes B',collections.Counter(B[k]['outcome'] or B[k]['status'] for k in B))
