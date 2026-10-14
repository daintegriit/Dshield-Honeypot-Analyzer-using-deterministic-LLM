import json,sys
from datetime import datetime
P=lambda s: datetime.fromisoformat(s.replace('Z','+00:00'))
for f in sys.argv[1:]:
    d=json.load(open(f)); dc=d.get('detectorConfig') or {}; t0=P(d['injectionStart'])
    R=[r for r in d['results'] if r.get('truth') in ('Normal','Attack')]
    tp=sum(1 for r in R if r['truth']=='Attack' and r['detectorPredicted']!='Normal'); fn=sum(1 for r in R if r['truth']=='Attack' and r['detectorPredicted']=='Normal')
    fp=sum(1 for r in R if r['truth']=='Normal' and r['detectorPredicted']!='Normal'); tn=sum(1 for r in R if r['truth']=='Normal' and r['detectorPredicted']=='Normal')
    A=[r['riskScore'] for r in R if r['truth']=='Attack']; N=[r for r in R if r['truth']=='Normal']
    marg=sum(A)/len(A)-sum(r['riskScore'] for r in N)/len(N)
    f1=2*tp/(2*tp+fp+fn) if tp+fp else None; p=tp/(tp+fp) if tp+fp else None
    traffic=[r for r in N if r['attackMetrics'].get('attacksLast1Min',0)>0]
    maxT=max(((P(r['timestamp'])-t0).total_seconds()/60 for r in traffic),default=None)
    strad=sum(1 for r in d['results'] if r.get('truth') not in ('Normal','Attack'))
    print(f"{f.split('/')[-1][:40]:40} {'abl' if dc.get('normalised') else 'dep'} TP/FP/TN/FN={tp}/{fp}/{tn}/{fn} n={len(R)} strad={strad} F1={f1 if f1 is None else round(f1,3)} P={p if p is None else round(p,3)} margin={marg:+.2f} benign={len(N)} empty={len(N)-len(traffic)} traffic={len(traffic)} alerted={sum(1 for r in traffic if r['detectorPredicted']!='Normal')} maxT_traffic={maxT} maxrisk={max(r['riskScore'] for r in d['results'])}")
