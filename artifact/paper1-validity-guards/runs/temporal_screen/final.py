import csv,glob,collections,random
def load(d,pat='batch*.tsv'):
    R={}
    for f in sorted(glob.glob(f'{d}/{pat}')):
        for r in csv.DictReader(open(f),delimiter='\t'): R[r['arxiv_id'].split('v')[0]]=r
    return R
A,B=load('A'),load('B')
C={}
for f in sorted(glob.glob('C/resolved*.tsv')):
    for r in csv.DictReader(open(f),delimiter='\t'):
        C.setdefault(r['arxiv_id'].split('v')[0],{})[r['question'].strip()]=r
sample=[l.split('\t') for l in open('/home/claude/chiron/work/screen_sample.tsv').read().splitlines()[1:]]
ds=collections.defaultdict(list)
for d,i,_,_ in sample: ds[i.split('v')[0]].append(d)
def outcome(q1,q2,q3,q4):
    if 'NO' in (q1,q2,q3): return 'NOT_EXPOSED'
    if 'UNSTATED' in (q1,q2,q3): return 'UNASSESSABLE'
    return 'MITIGATED' if q4=='HANDLED' else 'EXPOSED'
rows=[]
for k in A:
    a,b=A[k],B[k]; c=C.get(k,{})
    st=a['status'] if a['status']==b['status'] else (c.get('outcome',{}).get('resolved_code','?') if c.get('outcome',{}).get('resolved_code','') in ('NOT_DETECTION_EVAL','NOT_RETRIEVED') else 'CODED')
    if 'status' in c: st=c['status']['resolved_code']
    if st!='CODED':
        rows.append(dict(id=a['arxiv_id'],datasets='+'.join(ds[k]),status=st)); continue
    q={}
    for x in ('Q1','Q2','Q3','Q4'):
        q[x]=a[x].strip().upper() if a[x].strip().upper()==b[x].strip().upper() else c[x]['resolved_code'].strip().upper()
    o=outcome(q['Q1'],q['Q2'],q['Q3'],q['Q4'])
    co=c.get('outcome',{}).get('resolved_code','').strip().upper().replace(' ','_')
    rows.append(dict(id=a['arxiv_id'],datasets='+'.join(ds[k]),status=st,**q,outcome=o,adjudicated='yes' if c else 'no',c_outcome=co))
mism=[r for r in rows if r.get('c_outcome') and r['c_outcome'] not in (r['outcome'],)]
print('C outcome vs rule mismatches:',[(r['id'],r['outcome'],r['c_outcome']) for r in mism])
cnt=collections.Counter(r.get('outcome',r['status']) for r in rows); print('TOTAL',dict(cnt))
for d in ('CIC-IDS2017','UNSW-NB15','CTU-13','CSE-CIC-IDS2018'):
    print(d, dict(collections.Counter(r.get('outcome',r['status']) for r in rows if d in r['datasets'].split('+'))))
# Q-level among coded
cod=[r for r in rows if r['status']=='CODED']
for x in ('Q1','Q2','Q3','Q4'): print(x,dict(collections.Counter(r[x] for r in cod)))
print('Q1 YES and Q2 YES:',[(r['id'],r['Q3'],r['Q4'],r['outcome']) for r in cod if r['Q1']=='YES' and r['Q2']=='YES'])
# verification sample for the first author
rng=random.Random(20261014)
pos=[r['id'] for r in cod if r['outcome'] in ('EXPOSED','MITIGATED')]
rest=sorted(r['id'] for r in cod if r['outcome'] not in ('EXPOSED','MITIGATED'))
k=round(0.2*len(rest)); pick=sorted(rng.sample(rest,k))
print('verify: positives',pos,'random 20%',k,pick)
with open('TEMPORAL_SCREEN_CODES.tsv','w') as fh:
    keys=['id','datasets','status','Q1','Q2','Q3','Q4','outcome','adjudicated']
    fh.write('\t'.join(keys)+'\n')
    for r in rows: fh.write('\t'.join(str(r.get(x,'-')) for x in keys)+'\n')
open('VERIFY_LIST.txt','w').write('\n'.join(pos+pick)+'\n')
