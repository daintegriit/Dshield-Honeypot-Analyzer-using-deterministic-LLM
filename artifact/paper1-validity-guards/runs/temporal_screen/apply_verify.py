import csv,collections,sys
rows=list(csv.DictReader(open('TEMPORAL_SCREEN_CODES.tsv'),delimiter='\t'))
dec=list(csv.DictReader(open('VERIFY_DECISIONS.tsv'),delimiter='\t'))
def outcome(q1,q2,q3,q4):
    if 'NO' in (q1,q2,q3): return 'NOT_EXPOSED'
    if 'UNSTATED' in (q1,q2,q3): return 'UNASSESSABLE'
    return 'MITIGATED' if q4=='HANDLED' else 'EXPOSED'
by={r['id']:r for r in rows}
changed=0; papers=set()
for d in dec:
    r=by[d['arxiv']]
    if d['question']=='all': continue
    assert r[d['question']]==d['coded'],(d,r[d['question']])
    r[d['question']]=d['verified']; changed+=1; papers.add(d['arxiv'])
    if r['Q1']!='YES' and r['Q4']!='NA': r['Q4']='NA'
for r in rows:
    if r['status']=='CODED':
        o=outcome(r['Q1'],r['Q2'],r['Q3'],r['Q4'])
        r['verified_change']='yes' if r['id'] in papers else ('no' if r['id'] in {d['arxiv'] for d in dec} else '-')
        r['outcome']=o
cod=[r for r in rows if r['status']=='CODED']
print('verified papers',len({d['arxiv'] for d in dec}),'codes changed',changed,'papers changed',len(papers))
print('TOTAL',dict(collections.Counter(r['outcome'] if r['status']=='CODED' else r['status'] for r in rows)))
for ds in ('CIC-IDS2017','UNSW-NB15','CTU-13','CSE-CIC-IDS2018'):
    print(ds,dict(collections.Counter(r['outcome'] if r['status']=='CODED' else r['status'] for r in rows if ds in r['datasets'].split('+'))))
for x in ('Q1','Q2','Q3','Q4'): print(x,dict(collections.Counter(r[x] for r in cod)))
print('Q1&Q2 YES:',[(r['id'],r['Q3'],r['Q4'],r['outcome']) for r in cod if r['Q1']=='YES' and r['Q2']=='YES'])
out=sys.argv[1] if len(sys.argv)>1 else 'TEMPORAL_SCREEN_CODES_VERIFIED.tsv'
keys=['id','datasets','status','Q1','Q2','Q3','Q4','outcome','adjudicated','verified_change']
with open(out,'w') as fh:
    fh.write('\t'.join(keys)+'\n')
    for r in rows: fh.write('\t'.join(r.get(k,'-') or '-' for k in keys)+'\n')
