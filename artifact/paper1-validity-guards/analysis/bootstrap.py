import json,random,sys,math
random.seed(20261014)
arms=[('Baseline','snap/snapshot/backend/grounding_baseline.json'),('v2','snap/snapshot/backend/grounding_v2.json'),('v3','snap/snapshot/backend/grounding_v3.json'),('ungov.','snap/snapshot/backend/grounding_ungoverned.json'),('live (v5)','runs/grounding_v5_scoped.json'),('dedup (v6)','runs/grounding_v6_dedup.json')]
def wilson(k,n,z=1.96):
    p=k/n; c=(p+z*z/(2*n))/(1+z*z/n); h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/(1+z*z/n); return c-h,c+h
B=10000
for name,f in arms:
    R=json.load(open(f))['runs']
    g=[(sum(1 for x in r.get('citations') or [] if x.get('via')=='literal'),len(r.get('citations') or [])) for r in R]
    k=sum(a for a,_ in g); n=sum(b for _,b in g)
    est=[]
    for _ in range(B):
        s=[random.choice(g) for _ in g]; nn=sum(b for _,b in s)
        if nn: est.append(sum(a for a,_ in s)/nn)
    est.sort(); lo,hi=est[int(.025*len(est))],est[int(.975*len(est))-1]
    wl,wh=wilson(k,n)
    print(f"{name:10} gens={len(g)} with_citations={sum(1 for _,b in g if b)} strict={k}/{n}={k/n:.3f}  cluster-boot95=[{lo*100:.1f}, {hi*100:.1f}]  wilson=[{wl*100:.1f}, {wh*100:.1f}]")
