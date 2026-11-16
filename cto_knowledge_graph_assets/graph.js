// Dependency-free Streamlit v2 renderer. Data is always drawn as text, never HTML.
export function ringLayout(nodes, edges, root, previous = {}) {
  const count = Math.max(nodes.length, 1);
  const radius = Math.max(130, Math.sqrt(count) * 38);
  const positions = Object.create(null);
  nodes.forEach((n, i) => {
    const prior = previous[n.id];
    const angle = i * Math.PI * 2 / count;
    positions[n.id] = prior && Number.isFinite(prior.x) && Number.isFinite(prior.y)
      ? {x: prior.x, y: prior.y}
      : {x: n.id === root ? 0 : Math.cos(angle) * radius,
         y: n.id === root ? 0 : Math.sin(angle) * radius};
  });
  if (nodes.every(n => previous[n.id])) return positions;
  // At higher counts, use a deterministic multi-ring layout instead of O(N^2)
  // repulsion. Keep the root centered and spread node categories across rings.
  if (nodes.length > 160) {
    const ordered = nodes.filter(n => n.id !== root).sort((a, b) =>
      String(a.kind || '').localeCompare(String(b.kind || '')) || String(a.id).localeCompare(String(b.id)));
    const ringSpacing = 92;
    let ring = 1, cursor = 0;
    for (const node of ordered) {
      const capacity = Math.max(8, Math.floor((2 * Math.PI * ring * ringSpacing) / 52));
      if (cursor >= capacity) { ring += 1; cursor = 0; }
      const angle = (2 * Math.PI * cursor / capacity) + ring * 0.27;
      positions[node.id] = {x: Math.cos(angle) * ring * ringSpacing,
                            y: Math.sin(angle) * ring * ringSpacing};
      cursor += 1;
    }
    positions[root] = {x: 0, y: 0};
    return positions;
  }
  // Small subgraphs use the original force-directed arrangement.
  for (let step = 0; step < 180; step++) {
    const forces = Object.fromEntries(nodes.map(n => [n.id, {x: 0, y: 0}]));
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i].id;
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j].id;
        let dx = positions[a].x - positions[b].x;
        let dy = positions[a].y - positions[b].y;
        if (Math.abs(dx) + Math.abs(dy) < 0.01) { dx = 0.2; dy = 0.1; }
        const d2 = Math.max(dx * dx + dy * dy, 36);
        const f = Math.min(40, 12500 / d2) / Math.sqrt(d2);
        forces[a].x += dx * f; forces[a].y += dy * f;
        forces[b].x -= dx * f; forces[b].y -= dy * f;
      }
    }
    for (const edge of edges) {
      const a = positions[edge.source], b = positions[edge.target];
      if (!a || !b || edge.source === edge.target) continue;
      const dx = b.x - a.x, dy = b.y - a.y;
      const distance = Math.max(Math.hypot(dx, dy), 1);
      const f = (distance - 150) * 0.018 / distance;
      forces[edge.source].x += dx * f; forces[edge.source].y += dy * f;
      forces[edge.target].x -= dx * f; forces[edge.target].y -= dy * f;
    }
    const cooling = 1 - step / 210;
    for (const n of nodes) {
      const p = positions[n.id], f = forces[n.id];
      p.x += Math.max(-15, Math.min(15, f.x - p.x * 0.002)) * cooling;
      p.y += Math.max(-15, Math.min(15, f.y - p.y * 0.002)) * cooling;
    }
  }
  return positions;
}


// Fast approximation of a force-directed graph: hub-seeded communities,
// edge springs and spatially-local repulsion.
// v11.1 spacing tune: increase inter-node distance for denser ObservedEvent clusters.
// Bounded linear-ish work for 3000 nodes.
export function forceLayout(nodes, edges, root, previous = {}) {
  const n = nodes.length;
  if (n <= 160) return ringLayout(nodes, edges, root, previous);
  const ids = nodes.map(node => node.id);
  const index = new Map(ids.map((id, i) => [id, i]));
  const adj = Array.from({length: n}, () => []);
  const links = [];
  for (const e of edges) {
    const a = index.get(e.source), b = index.get(e.target);
    if (a === undefined || b === undefined || a === b) continue;
    adj[a].push(b); adj[b].push(a); links.push([a,b]);
  }
  // Pick connected hubs as community anchors. Detached components get anchors too.
  const order = [...Array(n).keys()].sort((a,b) => adj[b].length - adj[a].length || ids[a].localeCompare(ids[b]));
  const community = new Int32Array(n).fill(-1);
  const anchors = [];
  const targetClusters = Math.min(35, Math.max(5, Math.round(Math.sqrt(n)/2)));
  for (const i of order) {
    if (anchors.length >= targetClusters) break;
    if (community[i] !== -1) continue;
    const k = anchors.length; anchors.push(i); community[i] = k;
    for (const j of adj[i]) if (community[j] === -1) community[j] = k;
  }
  for (let pass=0; pass<5; pass++) {
    let changed = 0;
    for (const i of order) {
      if (community[i] !== -1) continue;
      const votes = new Map();
      for (const j of adj[i]) if (community[j] !== -1) {
        const k=community[j]; votes.set(k,(votes.get(k)||0)+1);
      }
      let winner=-1, score=0;
      for (const [k,v] of votes) if(v>score){winner=k;score=v;}
      if(winner!==-1){community[i]=winner;changed++;}
    }
    if(!changed)break;
  }
  // Do not collapse isolated nodes into a single center.
  for(let i=0;i<n;i++) if(community[i]===-1) community[i]=anchors.length+(i%Math.max(1,targetClusters));
  const centers = new Map();
  const communities = [...new Set(community)].sort((a,b)=>a-b);
  for(let k=0;k<communities.length;k++){
    const angle=k*2.3999632297;
    const radius=360*Math.sqrt(k+1);
    centers.set(communities[k],{x:Math.cos(angle)*radius,y:Math.sin(angle)*radius});
  }
  const hash = (s) => {
    let h=2166136261;
    for(let k=0;k<s.length;k++) h=Math.imul(h^s.charCodeAt(k),16777619);
    return (h>>>0)/4294967296;
  };
  const pos = Array.from({length:n},(_,i)=>{
    const prior=previous[ids[i]];
    if(prior && Number.isFinite(prior.x) && Number.isFinite(prior.y)) return {x:prior.x,y:prior.y};
    const c=centers.get(community[i]);
    const a=hash(ids[i]+'a')*Math.PI*2, r=50+hash(ids[i]+'r')*320;
    return {x:c.x+Math.cos(a)*r,y:c.y+Math.sin(a)*r};
  });
  // Spatial-bucket repulsion avoids an O(N²) loop.
  const cell=110, iterations=n>2000?55:80;
  for(let step=0;step<iterations;step++){
    const dx=new Float64Array(n), dy=new Float64Array(n);
    const buckets=new Map();
    for(let i=0;i<n;i++){
      const cx=Math.floor(pos[i].x/cell),cy=Math.floor(pos[i].y/cell);
      const key=cx+','+cy;
      if(!buckets.has(key))buckets.set(key,[]);
      buckets.get(key).push(i);
    }
    for(let i=0;i<n;i++){
      const cx=Math.floor(pos[i].x/cell),cy=Math.floor(pos[i].y/cell);
      for(let ax=-1;ax<=1;ax++)for(let ay=-1;ay<=1;ay++){
        for(const j of buckets.get((cx+ax)+','+(cy+ay))||[]){
          if(j<=i)continue;
          let x=pos[i].x-pos[j].x,y=pos[i].y-pos[j].y;
          const d2=x*x+y*y+4;
          const f=Math.min(6,5200/d2)/Math.sqrt(d2);
          dx[i]+=x*f; dy[i]+=y*f;dx[j]-=x*f;dy[j]-=y*f;
        }
      }
    }
    for(const [a,b] of links){
      const x=pos[b].x-pos[a].x,y=pos[b].y-pos[a].y;
      const d=Math.max(1,Math.hypot(x,y));
      const f=Math.max(-2.8,Math.min(2.8,(d-125)*0.0045));
      dx[a]+=x/d*f;dy[a]+=y/d*f;dx[b]-=x/d*f;dy[b]-=y/d*f;
    }
    const speed=0.55*(1-step/iterations)+0.08;
    for(let i=0;i<n;i++){
      const c=centers.get(community[i]);
      dx[i]+=(c.x-pos[i].x)*0.0022;
      dy[i]+=(c.y-pos[i].y)*0.0022;
      pos[i].x+=Math.max(-6,Math.min(6,dx[i]))*speed;
      pos[i].y+=Math.max(-6,Math.min(6,dy[i]))*speed;
    }
  }
  const positions=Object.create(null);
  for(let i=0;i<n;i++)positions[ids[i]]=pos[i];
  return positions;
}


// Root-centered radial layout: BFS hops are spread into angular sectors and
// multiple concentric bands to avoid piling hundreds of nodes on one circle.
// v12.1 tune: wider radial spacing and always-visible node labels.
export function radialLayout(nodes, edges, root) {
  const ids = nodes.map(n => String(n.id));
  const n = ids.length;
  const pos = Object.create(null);
  if (!n) return pos;
  const index = new Map(ids.map((id, i) => [id, i]));
  const rootIndex = index.has(String(root)) ? index.get(String(root)) : 0;
  const neighbors = Array.from({length:n}, () => []);
  for (const edge of edges) {
    const a=index.get(String(edge.source)), b=index.get(String(edge.target));
    if (a === undefined || b === undefined || a === b) continue;
    neighbors[a].push(b);
    neighbors[b].push(a);
  }
  const dist = new Int32Array(n).fill(-1);
  const parent = new Int32Array(n).fill(-1);
  const firstBranch = new Int32Array(n).fill(-1);
  dist[rootIndex] = 0;
  const queue=[rootIndex];
  for(let q=0;q<queue.length;q++) {
    const a=queue[q];
    for(const b of neighbors[a]) {
      if(dist[b]!==-1)continue;
      dist[b]=dist[a]+1;
      parent[b]=a;
      firstBranch[b]=a===rootIndex?b:firstBranch[a];
      queue.push(b);
    }
  }
  // Allocate proportional angular sectors to spokes, based on descendants.
  const groups = new Map();
  for(let i=0;i<n;i++) {
    if(i===rootIndex)continue;
    const branch=dist[i] < 0 ? -1 : firstBranch[i];
    if(!groups.has(branch)) groups.set(branch, []);
    groups.get(branch).push(i);
  }
  const sorted=[...groups.entries()].sort((a,b) => {
    if(a[0]===-1)return 1;
    if(b[0]===-1)return -1;
    return b[1].length-a[1].length || ids[a[0]].localeCompare(ids[b[0]]);
  });
  const weights=sorted.map(([key, members])=>Math.max(1,Math.sqrt(members.length)));
  // Use sqrt weights to prevent one giant branch from monopolizing every angle.
  const sum=weights.reduce((a,b)=>a+b,0);
  let start=-Math.PI/2;
  const spacing=82, radialStep=88;
  pos[ids[rootIndex]]={x:0,y:0};
  sorted.forEach(([branch,members],gi)=>{
    const wedge=2*Math.PI*(weights[gi]/sum);
    const gap=Math.min(0.04,wedge*0.08);
    const usable=Math.max(0.0001,wedge-2*gap);
    const mid=start+wedge/2;
    // Widely separated spokes at large branch counts; radius grows as sectors narrow.
    const spokeRadius=Math.max(210, Math.min(7500, 78/wedge));
    if(branch>=0) {
      pos[ids[branch]]={x:spokeRadius*Math.cos(mid),y:spokeRadius*Math.sin(mid)};
    }
    const children=members.filter(i=>i!==branch).sort((a,b)=>
      dist[a]-dist[b] || ids[a].localeCompare(ids[b]));
    // Each band gets only as many nodes as fit at approx. >=54px arc spacing.
    let used=0, ring=0;
    while(used<children.length) {
      const radius=spokeRadius+145+ring*radialStep;
      const capacity=Math.max(1,Math.floor(radius*usable/spacing));
      const take=Math.min(capacity,children.length-used);
      for(let j=0;j<take;j++) {
        const angle=start+gap+usable*(j+0.5)/take;
        const i=children[used+j];
        pos[ids[i]]={x:radius*Math.cos(angle),y:radius*Math.sin(angle)};
      }
      used+=take;
      ring++;
    }
    start+=wedge;
  });
  return pos;
}

export function zoomView(view, factor, anchor) {
  const scale = Math.max(0.05, Math.min(3.5, view.scale * factor));
  const ratio = scale / view.scale;
  return {scale, x: anchor.x - (anchor.x - view.x) * ratio,
          y: anchor.y - (anchor.y - view.y) * ratio};
}

export function hitNode(nodes, positions, view, point) {
  const x = (point.x - view.x) / view.scale;
  const y = (point.y - view.y) / view.scale;
  return [...nodes].reverse().find(n => {
    const p = positions[n.id];
    return p && Math.hypot(x - p.x, y - p.y) <= 19;
  });
}

export default function render({parentElement, data, setTriggerValue}) {
  const canvas = parentElement.querySelector('canvas');
  const shell = parentElement.querySelector('.kg-shell');
  const tip = parentElement.querySelector('.kg-tip');
  const scaleLabel = parentElement.querySelector('.kg-scale');
  const context = canvas.getContext('2d');
  if (!context || !data) return;
  // Respect the server's bounded graph instead of silently clipping to 100/300.
  // These are client safety ceilings, not additional Neo4j queries.
  const nodes = (data.nodes || []).slice(0, 3000);
  const nodeIds = new Set(nodes.map(n => n.id));
  const edges = (data.edges || []).filter(e => nodeIds.has(e.source) && nodeIds.has(e.target)).slice(0, 8000);
  const storageKey = '3k1h-kg-view-' + data.view_key;
  const signature = JSON.stringify([data.root, nodes.map(n => n.id), edges.map(e => e.id)]);
  let saved;
  try { saved = JSON.parse(sessionStorage.getItem(storageKey) || 'null'); } catch (_) { saved = null; }
  // v12 intentionally resets the former force/ring default once to radial.
  const layoutVersion = 'radial-v12';
  let layoutMode = saved?.layoutVersion === layoutVersion &&
    ['radial', 'force', 'ring'].includes(saved?.layoutMode)
    ? saved.layoutMode : 'radial';
  const layouts = {radial: radialLayout, force: forceLayout, ring: ringLayout};
  let positions = layouts[layoutMode](nodes, edges, data.root,
    saved?.layoutVersion === layoutVersion && saved?.signature === signature ? (saved.positions || {}) : {});
  let view = saved?.signature === signature && Number.isFinite(saved?.view?.scale)
    ? {...saved.view} : {x: 0, y: 0, scale: 1};
  let selected = data.selected;
  let hovered = null;
  let width = 800, height = 560, gesture = null;
  const listeners = [];
  // Local visualization-only filters; Neo4j data and Streamlit selection stay intact.
  const kindSelect = parentElement.querySelector('.kg-kind-filter');
  const focusButton = parentElement.querySelector('[data-action="focus-edges"]');
  const kinds = [...new Set(nodes.map(n => String(n.kind || '기타')))].sort();
  if (kindSelect) {
    // Streamlit may re-render this component while reusing the same DOM.
    // Rebuild from an empty select so dynamically added options cannot pile up.
    kindSelect.replaceChildren();
    for (const [value, title] of [
      ['all', '전체 노드'],
      ['no-events', 'ObservedEvent 제외'],
      ...kinds.map(kind => ['kind:' + kind, kind]),
    ]) {
      const option = document.createElement('option');
      option.value = value;
      option.textContent = title;
      kindSelect.appendChild(option);
    }
  }
  let kindFilter = saved?.kindFilter || 'all';
  let focusEdgesOnly = Boolean(saved?.focusEdgesOnly);
  if (kindSelect) {
    if (![...kindSelect.options].some(o => o.value === kindFilter)) kindFilter = 'all';
    kindSelect.value = kindFilter;
  }
  if (focusButton) focusButton.setAttribute('aria-pressed', String(focusEdgesOnly));
  let visibleNodes = nodes, visibleEdges = edges;
  function filterGraph() {
    visibleNodes = nodes.filter(n => kindFilter === 'all' ||
      (kindFilter === 'no-events' ? n.kind !== 'ObservedEvent' :
        'kind:' + String(n.kind || '기타') === kindFilter));
    const ids = new Set(visibleNodes.map(n => n.id));
    visibleEdges = edges.filter(e => ids.has(e.source) && ids.has(e.target));
  }
  filterGraph();

  function persist() {
    try { sessionStorage.setItem(storageKey, JSON.stringify({signature, positions, view, kindFilter, focusEdgesOnly, layoutMode, layoutVersion})); } catch (_) { /* storage optional */ }
  }
  function fit() {
    const coords = visibleNodes.map(n => positions[n.id]).filter(Boolean);
    if (!coords.length) return;
    const minX = Math.min(...coords.map(p => p.x)) - 125;
    const maxX = Math.max(...coords.map(p => p.x)) + 125;
    const minY = Math.min(...coords.map(p => p.y)) - 90;
    const maxY = Math.max(...coords.map(p => p.y)) + 90;
    view.scale = Math.max(0.05, Math.min(1.4, (width - 30) / (maxX - minX), (height - 110) / (maxY - minY)));
    view.x = width / 2 - (minX + maxX) / 2 * view.scale;
    view.y = height / 2 + 10 - (minY + maxY) / 2 * view.scale;
    persist(); draw();
  }
  const groups = new Map();
  for (const edge of edges) {
    const pair = JSON.stringify([edge.source, edge.target].sort());
    if (!groups.has(pair)) groups.set(pair, []);
    groups.get(pair).push(edge);
  }
  const lanes = new Map();
  for (const values of groups.values()) values.forEach((e, i) => lanes.set(e.id, (i - (values.length - 1) / 2) * 32));
  function label(text, x, y, color, size = 10) {
    context.font = size + 'px system-ui,"Malgun Gothic",sans-serif';
    const w = context.measureText(text).width;
    context.fillStyle = '#0d1525dd';
    context.fillRect(x - w / 2 - 3, y - size, w + 6, size + 4);
    context.fillStyle = color; context.textAlign = 'center'; context.fillText(text, x, y);
  }
  function compactLabel(text, max = 18) {
    const value = String(text || '');
    return value.length <= max ? value : value.slice(0, Math.max(1, max - 1)) + '…';
  }
  function arrow(x, y, angle, color) {
    context.beginPath(); context.moveTo(x, y);
    context.lineTo(x - 9 * Math.cos(angle - 0.4), y - 9 * Math.sin(angle - 0.4));
    context.lineTo(x - 9 * Math.cos(angle + 0.4), y - 9 * Math.sin(angle + 0.4));
    context.closePath(); context.fillStyle = color; context.fill();
  }
  function draw() {
    const dense = visibleNodes.length > 70;
    const showEdgeNames = visibleNodes.length <= 45 && view.scale >= 0.55;
    const labelSize = visibleNodes.length > 1800 ? 8 : visibleNodes.length > 900 ? 8.5 : visibleNodes.length > 350 ? 9 : 10.5;
    const labelChars = visibleNodes.length > 1800 ? 10 : visibleNodes.length > 900 ? 12 : visibleNodes.length > 350 ? 14 : 20;
    const focusId = hovered || selected;
    const neighbors = new Set();
    for (const edge of visibleEdges) {
      if (edge.source === focusId) neighbors.add(edge.target);
      if (edge.target === focusId) neighbors.add(edge.source);
    }
    const ratio = window.devicePixelRatio || 1;
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    context.clearRect(0, 0, width, height);
    context.translate(view.x, view.y); context.scale(view.scale, view.scale);
    for (const edge of visibleEdges) {
      if (focusEdgesOnly && edge.source !== focusId && edge.target !== focusId) continue;
      const a = positions[edge.source], b = positions[edge.target];
      const active = edge.source === focusId || edge.target === focusId;
      const color = active ? '#c5d6ff' : '#566d8f';
      context.globalAlpha = dense && !active ? 0.28 : 1;
      context.strokeStyle = color; context.lineWidth = active ? 2 : 1.2;
      context.beginPath();
      if (edge.source === edge.target) {
        const r = 28 + Math.abs(lanes.get(edge.id) || 0);
        context.arc(a.x, a.y - r, r, 0.25 * Math.PI, 2.25 * Math.PI);
        context.stroke(); arrow(a.x + r * 0.7, a.y - r + r * 0.7, Math.PI * 0.75, color);
        if (showEdgeNames || (active && view.scale >= 0.85)) {
          context.globalAlpha = 1;
          label(edge.type, a.x, a.y - 2 * r - 3, active ? '#eef3ff' : '#a8b7d0');
        }
        context.globalAlpha = 1;
        continue;
      }
      const dx = b.x - a.x, dy = b.y - a.y, distance = Math.max(Math.hypot(dx, dy), 1);
      const lane = (lanes.get(edge.id) || 0) * (edge.source < edge.target ? 1 : -1);
      const mid = {x: (a.x + b.x) / 2 - dy / distance * lane, y: (a.y + b.y) / 2 + dx / distance * lane};
      const angle = Math.atan2(b.y - mid.y, b.x - mid.x);
      const end = {x: b.x - Math.cos(angle) * 18, y: b.y - Math.sin(angle) * 18};
      context.moveTo(a.x, a.y); context.quadraticCurveTo(mid.x, mid.y, end.x, end.y); context.stroke();
      arrow(end.x, end.y, angle, color);
      if (showEdgeNames || (active && view.scale >= 0.85)) {
        context.globalAlpha = 1;
        label(edge.type, (a.x + 2 * mid.x + b.x) / 4, (a.y + 2 * mid.y + b.y) / 4 - 5, active ? '#eef3ff' : '#a8b7d0');
      }
      context.globalAlpha = 1;
    }
    for (const node of visibleNodes) {
      const p = positions[node.id];
      if (node.id === selected || node.id === hovered) {
        context.beginPath(); context.arc(p.x, p.y, 22, 0, Math.PI * 2);
        context.strokeStyle = node.id === selected ? '#f0f4ff' : '#77dbff';
        context.lineWidth = 2.5; context.stroke();
      }
      context.beginPath(); context.arc(p.x, p.y, node.id === data.root ? 18 : 15, 0, Math.PI * 2);
      context.fillStyle = node.color; context.fill(); context.strokeStyle = '#0d1525'; context.lineWidth = 2; context.stroke();
      context.fillStyle = '#0a1020'; context.font = 'bold 11px system-ui'; context.textAlign = 'center';
      context.fillText(String(node.hop), p.x, p.y + 4);
      const focus = node.id === selected || node.id === hovered;
      const neighbor = neighbors.has(node.id);
      const name = focus ? String(node.label) : compactLabel(node.label, labelChars);
      const labelColor = focus ? '#ffffff' : neighbor ? '#eef6ff' : '#d9e4f8';
      const labelY = p.y + (node.id === data.root ? 37 : 34);
      context.globalAlpha = focus ? 1 : dense ? 0.84 : 0.92;
      label(name, p.x, labelY, labelColor, focus ? Math.max(11, labelSize + 1.5) : labelSize);
      context.globalAlpha = 1;
    }
    scaleLabel.textContent = Math.round(view.scale * 100) + '% · ' +
      visibleNodes.length + '/' + nodes.length + ' nodes · ' + visibleEdges.length + '/' + edges.length + ' links';
  }
  function resize() {
    width = Math.max(240, shell.clientWidth); height = shell.clientHeight;
    const ratio = window.devicePixelRatio || 1;
    canvas.width = Math.round(width * ratio); canvas.height = Math.round(height * ratio);
    draw();
  }
  function point(event) {
    const bounds = canvas.getBoundingClientRect();
    return {x: event.clientX - bounds.left, y: event.clientY - bounds.top};
  }
  function on(target, name, fn, options) {
    target.addEventListener(name, fn, options); listeners.push(() => target.removeEventListener(name, fn, options));
  }
  on(canvas, 'pointerdown', event => {
    if (event.button !== 0) return;
    const p = point(event), node = hitNode(visibleNodes, positions, view, p);
    gesture = {start: p, last: p, node, moved: false};
    hovered = null;
    canvas.setPointerCapture(event.pointerId); canvas.style.cursor = 'grabbing'; tip.style.display = 'none';
  });
  on(canvas, 'pointermove', event => {
    const p = point(event);
    if (gesture) {
      const dx = p.x - gesture.last.x, dy = p.y - gesture.last.y;
      if (Math.hypot(p.x - gesture.start.x, p.y - gesture.start.y) > 4) gesture.moved = true;
      if (gesture.node) {
        positions[gesture.node.id].x += dx / view.scale; positions[gesture.node.id].y += dy / view.scale;
      } else { view.x += dx; view.y += dy; }
      gesture.last = p; draw(); return;
    }
    const node = hitNode(visibleNodes, positions, view, p);
    const nextHovered = node ? node.id : null;
    if (hovered !== nextHovered) { hovered = nextHovered; draw(); }
    canvas.style.cursor = node ? 'pointer' : 'grab';
    tip.style.display = node ? 'block' : 'none';
    if (node) {
      tip.textContent = node.kind + '\n' + node.label + '\n' + node.identifier;
      tip.style.left = Math.max(8, Math.min(p.x + 14, width - 280)) + 'px';
      tip.style.top = Math.max(55, Math.min(p.y + 14, height - 110)) + 'px';
    }
  });
  on(canvas, 'pointerup', event => {
    if (!gesture) return;
    const last = gesture; gesture = null; canvas.style.cursor = 'grab';
    if (canvas.hasPointerCapture(event.pointerId)) canvas.releasePointerCapture(event.pointerId);
    if (last.node && !last.moved) {
      selected = last.node.id; draw(); persist();
      setTriggerValue('selection', {id: selected, revision: data.revision});
    } else persist();
  });
  on(canvas, 'pointercancel', () => {gesture = null; persist();});
  on(canvas, 'pointerleave', () => {tip.style.display = 'none'; hovered = null; draw();});
  // v12.2: hovering or scrolling over the canvas must never zoom the graph.
  // Explicit Ctrl + wheel still zooms; ordinary wheel/touchpad scrolling moves the page.
  on(canvas, 'wheel', event => {
    if (!event.ctrlKey || !event.isTrusted || !Number.isFinite(event.deltaY) || event.deltaY === 0) return;
    event.preventDefault();
    view = zoomView(view, Math.exp(-event.deltaY * 0.0015), point(event));
    draw(); persist();
  }, {passive: false});
  on(canvas, 'keydown', event => {
    if (['+', '=', '-', 'Home', 'ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(event.key)) event.preventDefault();
    if (['+', '=', '-'].includes(event.key)) view = zoomView(view, event.key === '-' ? 0.85 : 1.15, {x: width / 2, y: height / 2});
    if (event.key === 'Home') fit();
    if (event.key === 'ArrowLeft') view.x += 30;
    if (event.key === 'ArrowRight') view.x -= 30;
    if (event.key === 'ArrowUp') view.y += 30;
    if (event.key === 'ArrowDown') view.y -= 30;
    draw(); persist();
  });
  for (const button of parentElement.querySelectorAll('[data-action]')) on(button, 'click', () => {
    const action = button.dataset.action;
    if (action === 'fit') fit();
    if (action === 'layout') {
      layoutMode = layoutMode === 'radial' ? 'force' : layoutMode === 'force' ? 'ring' : 'radial';
      positions = layouts[layoutMode](nodes, edges, data.root);
      button.textContent = layoutMode === 'radial' ? '군집 배치' :
        layoutMode === 'force' ? '원형 배치' : '방사형 배치';
      fit(); persist();
    }
    if (action === 'zoom-in' || action === 'zoom-out') {
      view = zoomView(view, action === 'zoom-in' ? 1.2 : 1 / 1.2, {x: width / 2, y: height / 2}); draw(); persist();
    }
  });
  if (kindSelect) on(kindSelect, 'change', () => {
    kindFilter = kindSelect.value;
    filterGraph();
    hovered = null; tip.style.display = 'none';
    fit(); persist();
  });
  if (focusButton) on(focusButton, 'click', () => {
    focusEdgesOnly = !focusEdgesOnly;
    focusButton.setAttribute('aria-pressed', String(focusEdgesOnly));
    draw(); persist();
  });
  const layoutButton = parentElement.querySelector('[data-action="layout"]');
  if(layoutButton)layoutButton.textContent = layoutMode === 'radial' ? '군집 배치' :
    layoutMode === 'force' ? '원형 배치' : '방사형 배치';
  resize();
  if (saved?.signature !== signature || saved?.layoutVersion !== layoutVersion) fit();
  const observer = new ResizeObserver(resize); observer.observe(shell);
  return () => {persist(); observer.disconnect(); listeners.forEach(remove => remove());};
}
