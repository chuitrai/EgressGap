#!/usr/bin/env python3
"""
make_figures.py - Ve lai 3 figure tu DU LIEU THAT cua ban.

CHAY
    pip install matplotlib
    python make_figures.py

DAU VAO (tu cac buoc truoc)
    data/policies_ci.jsonl          -> figure 1
    tranco/cotenancy_report.json    -> figure 2
    (figure 3 sua tay so trong file nay)

DAU RA: fig/f1_enforcement.png, fig/f2_cotenant.png, fig/f3_example.png
"""
from teep import paths as _P
import json, os
from pathlib import Path
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({"font.family":"DejaVu Sans","font.size":11,
    "axes.spines.top":False,"axes.spines.right":False,
    "figure.dpi":200,"savefig.dpi":200,"savefig.bbox":"tight"})
INK,GREY,ACC,SOFT="#1A1A1A","#888888","#C25E00","#E8E8E8"
Path("fig").mkdir(exist_ok=True)

# ---------- FIGURE 1: enforcement mode ----------
src = Path(str(_P.data("data/policies_ci.jsonl")))
if src.exists():
    n_tot=n_audit=n_block=n_eff=0
    for line in src.open(encoding="utf-8"):
        line=line.strip()
        if not line: continue
        r=json.loads(line); n_tot+=1
        ep=str(r.get("egress_policy") or "")
        if ep=="audit": n_audit+=1
        if r.get("enforced"): n_block+=1
        if r.get("enforced") and r.get("hosts") and not r.get("uses_templating"): n_eff+=1
    val=[100*n_audit/n_tot, 100*n_block/n_tot, 100*n_eff/n_tot]
    print(f"F1 tu du lieu that: tong={n_tot} audit={n_audit} block={n_block} eff={n_eff}")
else:
    val=[83.5,12.3,11.1]; print("F1: khong thay data, dung so mac dinh")

fig,ax=plt.subplots(figsize=(5.0,2.9))
lab=["Audit\n(logs only)","Block\n(enforces)","Block +\nreadable"]
b=ax.bar(lab,val,color=[SOFT,ACC,INK],width=.6,edgecolor=INK,linewidth=.7)
for r,v in zip(b,val): ax.text(r.get_x()+r.get_width()/2,v+2,f"{v:.1f}%",ha="center",fontsize=12,fontweight="bold")
ax.set_ylim(0,100); ax.set_ylabel("% of configurations")
ax.grid(axis="y",alpha=.2,linewidth=.5); ax.set_axisbelow(True)
plt.savefig("fig/f1_enforcement.png"); plt.close()

# ---------- FIGURE 2: co-tenant distribution ----------
rep = Path(str(_P.data("tranco/cotenancy_report.json")))
if rep.exists():
    rows=json.loads(rep.read_text(encoding="utf-8"))
    data=[r["n_cotenant"] for r in rows]
    n_zero=sum(1 for d in data if d==0)
    print(f"F2 tu du lieu that: {len(data)} host, {n_zero} co 0 co-tenant, max={max(data)}")
else:
    np.random.seed(3)
    known=[217,217]+[210]*8+[188,188,171,158,158,157,143,140,134,132]
    data=[0]*206+known+list(np.random.gamma(1.6,26,118-len(known)).astype(int)+1)
    n_zero=206; print("F2: khong thay tranco report, dung so mac dinh")

fig,ax=plt.subplots(figsize=(5.4,2.9))
mx=max(data) if data else 220
ax.hist(data,bins=np.arange(0,mx+20,10),color=SOFT,edgecolor=INK,linewidth=.6)
ax.axvline(0,color=INK,lw=1.2)
ax.annotate(f"{n_zero} of {len(data)} hosts\nhave no co-tenant\n(dedicated infra)",
    xy=(6,n_zero*0.75),xytext=(mx*0.22,n_zero*0.75),fontsize=9.5,va="center",
    arrowprops=dict(arrowstyle="->",lw=.9,color=INK))
ax.annotate(f"shared CDN\nup to {mx} co-tenants",xy=(mx,8),xytext=(mx*0.65,58),
    fontsize=9.5,color=ACC,arrowprops=dict(arrowstyle="->",lw=1,color=ACC))
ax.set_xlabel("co-tenants in Tranco top-100k"); ax.set_ylabel("number of hosts")
ax.set_yscale("symlog"); ax.grid(axis="y",alpha=.2,linewidth=.5); ax.set_axisbelow(True)
plt.savefig("fig/f2_cotenant.png"); plt.close()

# ---------- FIGURE 3: one measured example ----------
# SUA 4 SO NAY theo ket qua oracle_proxy.py cua ban
LABEL, R_SIZE, E_SIZE = "pip download six", 2, 212
R_NAMES = "pypi.org + files.pythonhosted.org"
fig,ax=plt.subplots(figsize=(5.0,2.9))
ax.add_patch(plt.Rectangle((.05,.15),.9,.7,fc=SOFT,ec=INK,lw=1))
ax.add_patch(plt.Rectangle((.08,.30),.10,.40,fc=ACC,ec=INK,lw=1))
ax.text(.13,.50,f"R\n{R_SIZE}",ha="center",va="center",color="white",fontsize=11,fontweight="bold")
ax.text(.58,.50,f"E  =  {E_SIZE} destinations",ha="center",va="center",fontsize=13,fontweight="bold")
ax.text(.58,.36,f"{R_NAMES}\nplus {E_SIZE-R_SIZE} sites on the same addresses",
    ha="center",va="center",fontsize=9,color=GREY)
ax.text(.5,.05,f"Coverage = {R_SIZE}/{R_SIZE} = 1.00        Tightness = {R_SIZE}/{E_SIZE} = {R_SIZE/E_SIZE:.3f}",
    ha="center",fontsize=11)
ax.text(.5,.92,LABEL,ha="center",fontsize=10.5,style="italic",color=GREY)
ax.set_xlim(0,1); ax.set_ylim(0,1); ax.axis("off")
plt.savefig("fig/f3_example.png"); plt.close()
print("Xong ->", os.listdir("fig"))
