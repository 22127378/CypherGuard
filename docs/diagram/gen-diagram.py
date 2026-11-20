import html

# node: id -> (x,y,w,h,label,style_key)
STYLES = {
    "zone":   "rounded=1;arcSize=3;fillColor=%F;strokeColor=%S;strokeWidth=1;dashed=1;verticalAlign=top;align=left;spacingLeft=12;spacingTop=8;fontStyle=1;fontSize=13;html=1;",
    "ekszone":"rounded=1;arcSize=4;fillColor=none;strokeColor=#82b366;strokeWidth=2;dashed=1;dashPattern=8 4;verticalAlign=top;align=left;spacingLeft=10;spacingTop=6;fontStyle=1;fontSize=12;fontColor=#4a7a2a;html=1;",
    "gh":     "rounded=1;arcSize=10;fillColor=#dae8fc;strokeColor=#6c8ebf;html=1;fontSize=11;whiteSpace=wrap;",
    "sec":    "rounded=1;arcSize=10;fillColor=#d5e8d4;strokeColor=#82b366;html=1;fontSize=11;whiteSpace=wrap;",
    "siem":   "rounded=1;arcSize=10;fillColor=#e1d5e7;strokeColor=#9673a6;html=1;fontSize=11;whiteSpace=wrap;",
    "attack": "rounded=1;arcSize=10;fillColor=#f8cecc;strokeColor=#b85450;html=1;fontSize=11;whiteSpace=wrap;",
    "store":  "shape=cylinder3;boundedLbl=1;backgroundOutline=1;fillColor=#f5f5f5;strokeColor=#666666;html=1;fontSize=10;whiteSpace=wrap;",
    "cloud":  "rounded=1;arcSize=10;fillColor=#ffe6cc;strokeColor=#d79b00;html=1;fontSize=11;whiteSpace=wrap;",
    "eb":     "shape=rhombus;fillColor=#ffe6cc;strokeColor=#d79b00;html=1;fontSize=11;whiteSpace=wrap;",
    "note":   "rounded=1;arcSize=20;fillColor=#fff2cc;strokeColor=#d6b656;html=1;fontSize=10;whiteSpace=wrap;dashed=1;",
}

nodes = [
  # zones (drawn first = behind)
  ("z1", 20,20,1480,150,"Build &amp; deliver — GitHub Actions (OIDC federation, no static AWS keys)","zone","#eaf2ff","#6c8ebf"),
  ("z2", 20,190,1480,440,"AWS VPC   10.20.0.0/16   (hosts reached via SSM only — no SSH, no inbound)","zone","#fff6ee","#d79b00"),
  ("z3", 20,650,1480,170,"Cloud telemetry &amp; response","zone","#f3eefb","#9673a6"),
  ("eks",350,250,780,350,"EKS cluster — private subnets, API endpoint limited to admin IP","ekszone","",""),

  # z1 pipeline
  ("repo", 45,80,135,55,"Git repo\ncode · IaC · charts · rules","gh","",""),
  ("gates",215,80,190,55,"PR gates\ngitleaks · Semgrep · Checkov\nKyverno + rule replay","gh","",""),
  ("build",440,80,195,55,"build.yml\nTrivy gate · Syft SBOM · Cosign sign","gh","",""),
  ("ecr",  675,72,120,72,"ECR\nsigned images\n(immutable)","store","",""),
  ("tfdep",840,80,210,55,"terraform.yml / deploy.yml\nplan → manual approve → apply","gh","",""),
  ("oidc",1090,80,170,55,"3 OIDC roles\nplan · apply · ecr-push","note","",""),

  # z2 EKS internals
  ("kyv", 375,300,160,70,"Kyverno\nverify Cosign sig + SBOM\nPSS · ECR-only · RBAC","sec","",""),
  ("pod", 565,300,185,70,"demo-app pod\nIRSA · no API token\nread-only FS · PSS restricted","sec","",""),
  ("falco",375,440,160,60,"Falco DaemonSet\nmodern eBPF","sec","",""),
  ("agent",565,440,185,60,"Wazuh agent (on node)\ntails Falco JSON","siem","",""),
  ("np",   790,515,160,55,"NetworkPolicy\ndefault-deny egress","sec","",""),

  # z2 hosts
  ("attacker",1160,270,170,75,"Attacker host\nreceiver :8080\n(public subnet)","attack","",""),
  ("wazuh",1160,430,170,100,"Wazuh manager\nmanager·indexer·dashboard\nrules · Active Response","siem","",""),

  # z3 cloud telemetry
  ("ct",  60,705,155,55,"CloudTrail → S3","cloud","",""),
  ("cw",  245,705,175,55,"EKS audit →\nCloudWatch Logs","cloud","",""),
  ("gd",  455,705,120,55,"GuardDuty","cloud","",""),
  ("eb",  610,700,120,65,"EventBridge","eb","",""),
  ("lam", 760,705,200,55,"Lambda auto-fix\nquarantine role / disable key","cloud","",""),
]

edges = [
  ("repo","gates","",""),
  ("gates","build","",""),
  ("build","ecr","sign + push",""),
  ("ecr","kyv","","data"),
  ("kyv","pod","admit",""),
  ("tfdep","eks","provision + deploy","data"),
  ("falco","agent","events file",""),
  ("agent","wazuh","1514",""),
  ("cw","wazuh","","data"),
  ("ct","wazuh","",""),
  ("gd","eb","",""),
  ("eb","wazuh","findings",""),
  ("eb","lam","severity &gt;= 7",""),
  ("lam","eks","contain credential","resp"),
  ("wazuh","agent","Active Response: isolate container","resp"),
  ("pod","attacker","exfil (AES-256-GCM + RSA)","exfil"),
]

def esc(s): return html.escape(s).replace("\n","&#10;")

cells = []
cells.append('<mxCell id="0"/>')
cells.append('<mxCell id="1" parent="0"/>')
for n in nodes:
    nid,x,y,w,h,label,skey = n[0],n[1],n[2],n[3],n[4],n[5],n[6]
    style = STYLES[skey]
    if skey=="zone":
        style = style.replace("%F",n[7]).replace("%S",n[8])
    cells.append(
      f'<mxCell id="{nid}" value="{esc(label)}" style="{style}" vertex="1" parent="1">'
      f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')

EDGE_BASE = "edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;fontSize=10;endArrow=block;endFill=1;"
EDGE_KIND = {
  "":      "strokeColor=#555555;",
  "data":  "strokeColor=#6c8ebf;strokeWidth=2;",
  "resp":  "strokeColor=#d79b00;strokeWidth=2;dashed=1;dashPattern=6 4;",
  "exfil": "strokeColor=#b85450;strokeWidth=2;dashed=1;dashPattern=2 2;",
}
ROUTE = {
  ("ct","wazuh"):   ("exitX=0.5;exitY=1;exitDx=0;exitDy=0;entryX=1;entryY=0.35;entryDx=0;entryDy=0;",
                     [(137,800),(1405,800),(1405,465)]),
  ("cw","wazuh"):   ("exitX=0.5;exitY=1;exitDx=0;exitDy=0;entryX=1;entryY=0.6;entryDx=0;entryDy=0;",
                     [(332,835),(1440,835),(1440,490)]),
  ("eb","wazuh"):   ("exitX=0.5;exitY=0;exitDx=0;exitDy=0;entryX=0.5;entryY=1;entryDx=0;entryDy=0;", []),
  ("gd","eb"):      ("exitX=1;exitY=0.5;exitDx=0;exitDy=0;entryX=0;entryY=0.5;entryDx=0;entryDy=0;", []),
  ("eb","lam"):     ("exitX=1;exitY=0.5;exitDx=0;exitDy=0;entryX=0;entryY=0.5;entryDx=0;entryDy=0;", []),
}

for i,(s,t,lbl,kind) in enumerate(edges):
    rstyle, wps = ROUTE.get((s,t), ("", []))
    style = EDGE_BASE + EDGE_KIND.get(kind,EDGE_KIND[""]) + rstyle
    geo = '<mxGeometry relative="1" as="geometry">'
    if wps:
        geo += '<Array as="points">' + "".join(f'<mxPoint x="{x}" y="{y}"/>' for x,y in wps) + '</Array>'
    geo += '</mxGeometry>'
    cells.append(
      f'<mxCell id="e{i}" value="{esc(lbl)}" style="{style}" edge="1" parent="1" source="{s}" target="{t}">'
      f'{geo}</mxCell>')

xml = (
  '<mxfile host="app.diagrams.net"><diagram id="cg-arch-1" name="CipherGuard v2.0 architecture">'
  '<mxGraphModel dx="1600" dy="900" grid="0" gridSize="10" guides="1" tooltips="1" connect="1" '
  'arrows="1" fold="1" page="1" pageScale="1" pageWidth="1600" pageHeight="900" math="0" shadow="0">'
  '<root>' + "".join(cells) + '</root></mxGraphModel></diagram></mxfile>'
)
open("docs/diagram/cipherguard-architecture.drawio","w").write(xml)
print("wrote drawio:", len(xml), "bytes,", len(nodes), "nodes,", len(edges), "edges")
