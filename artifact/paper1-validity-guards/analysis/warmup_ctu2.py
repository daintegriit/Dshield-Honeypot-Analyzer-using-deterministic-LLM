import json,glob,sys,math
from datetime import datetime
P=lambda s: datetime.fromisoformat(s.replace('Z','+00:00'))
def pear(x,y):
    n=len(x); 
    if n<3: return None
    mx,my=sum(x)/n,sum(y)/n; sx=math.sqrt(sum((a-mx)**2 for a in x)); sy=math.sqrt(sum((b-my)**2 for b in y))
    return None if sx==0 or sy==0 else sum((a-mx)*(b-my) for a,b in zip(x,y))/(sx*sy)
def ci(r,neff):
    if r is None or neff<=3: return None
    z=math.atanh(max(min(r,0.999999),-0.999999)); h=1.96/math.sqrt(neff-3); return (math.tanh(z-h),math.tanh(z+h))
for f in sorted(glob.glob(sys.argv[1]+'/s9_norm_*.json'))+sorted(glob.glob(sys.argv[1]+'/s[1268]_norm_w1.json')):
    d=json.load(open(f)); t0=P(d['ingest_span']['from']); c=d['config']; W=d['windows']
    rows=[((P(w['windowEnd'])-t0).total_seconds()/60,w['riskScore'],w['botnet_fraction']) for w in W]
    def rep(sub,tag):
        r=pear([a[1] for a in sub],[a[2] for a in sub]); ne=len(sub)*c['step_minutes']/c['window_minutes']; iv=ci(r,ne)
        return f"{tag}: n={len(sub)} neff={ne:.0f} r={r if r is None else round(r,3)} CI={None if iv is None else tuple(round(v,2) for v in iv)}"
    print(f.split('/')[-1], 'stored', d['correlation']['risk_vs_botnet_fraction'], '|', rep(rows,'all'), '|', rep([r for r in rows if r[0]>=60],'T>=60'))
