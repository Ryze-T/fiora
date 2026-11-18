/* mermaid 仅在报告含图时内嵌（离线承诺：零外部资源）；无图时不初始化 */
if (window.mermaid) mermaid.initialize({
  startOnLoad:true, theme:'base', securityLevel:'loose',
  themeVariables:{
    background:'#1b222d', primaryColor:'#1b222d', primaryTextColor:'#eef1f6',
    primaryBorderColor:'#2a3243', lineColor:'#4b5468', fontFamily:'IBM Plex Mono, monospace',
    fontSize:'12px'
  }
});

/* ---------- 1) 扫描全部 .finding，自动生成统计卡 / 分布条 / 环形图 / 目录 ---------- */
(function(){
  const findings = Array.from(document.querySelectorAll('.finding'));
  const counts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
  let verified = 0;
  findings.forEach(f=>{
    const sev = f.dataset.sev || 'LOW';
    if(counts[sev]!==undefined) counts[sev]++;
    if(f.querySelector('.verdict:not(.fp)')) verified++;
  });
  const total = findings.length;
  const sevMeta = [
    ['CRITICAL','crit','var(--crit)'], ['HIGH','high','var(--high)'],
    ['MEDIUM','med','var(--med)'], ['LOW','low','var(--low)']
  ];

  // 统计卡
  const grid = document.getElementById('stat-grid');
  grid.innerHTML = `
    <div class="stat-card total"><div class="num">${total}</div><div class="lbl">发现总数</div></div>
    ${sevMeta.map(([k,c])=>`<div class="stat-card ${c}"><div class="num">${counts[k]}</div><div class="lbl">${k}</div></div>`).join('')}
    <div class="stat-card ok"><div class="num">${verified}</div><div class="lbl">已判定 TRUE-POSITIVE</div></div>
  `;

  // 分布条
  const bar = document.getElementById('sevbar');
  bar.innerHTML = sevMeta.map(([k,c])=>{
    const pct = total? (counts[k]/total*100):0;
    return pct>0 ? `<div class="seg ${c}" style="width:${pct}%">${counts[k]}</div>` : '';
  }).join('');

  // 环形图（纯 SVG，按比例画弧）
  const donut = document.getElementById('donut');
  const legend = document.getElementById('donut-legend');
  const r = 50, cx=64, cy=64, circ = 2*Math.PI*r;
  let offset = 0; let svg = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#1f2631" stroke-width="14"/>`;
  sevMeta.forEach(([k,c,colorVar])=>{
    const frac = total? counts[k]/total : 0;
    if(frac<=0) return;
    const len = frac*circ;
    const color = getComputedStyle(document.documentElement).getPropertyValue('--'+c).trim();
    svg += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${color}" stroke-width="14"
      stroke-dasharray="${len} ${circ-len}" stroke-dashoffset="${-offset}" transform="rotate(-90 ${cx} ${cy})"/>`;
    offset += len;
  });
  svg += `<text x="${cx}" y="${cy-2}" text-anchor="middle" font-family="IBM Plex Mono" font-size="22" fill="#eef1f6" font-weight="600">${total}</text>
          <text x="${cx}" y="${cy+16}" text-anchor="middle" font-family="IBM Plex Mono" font-size="9.5" fill="#828ba0">总发现</text>`;
  donut.innerHTML = svg;
  legend.innerHTML = sevMeta.map(([k,c])=>`<span><i style="background:var(--${c})"></i>${k} · ${counts[k]}</span>`).join('');

  // 目录自动生成（RCE / 其余 / PoC 三个子列表）
  function buildTocList(selector, targetId){
    const el = document.getElementById(targetId);
    const items = document.querySelectorAll(selector);
    el.innerHTML = Array.from(items).map(node=>{
      const id = node.id;
      if(!id) return '';
      const sev = (node.dataset && node.dataset.sev) || '';
      const sevClass = {CRITICAL:'crit',HIGH:'high',MEDIUM:'med',LOW:'low'}[sev] || 'low';
      let text = '';
      if(node.classList.contains('finding')){
        text = node.querySelector('.f-title').childNodes[0].textContent.trim();
      } else {
        text = node.querySelector('.ttl').childNodes[0].textContent.trim();
      }
      return `<li><a href="#${id}" class="jump-ref" data-target="${id}"><span class="sevdot" style="background:var(--${sevClass})"></span><span class="ttl">${text}</span></a></li>`;
    }).join('');
  }
  buildTocList('#rce .finding', 'toc-rce-list');
  buildTocList('#other .finding', 'toc-other-list');
  buildTocList('.poc-card', 'toc-poc-list');
})();

/* ---------- 2) 跳转 + 高亮闪烁（链路 ↔ PoC ↔ 目录 互相关联） ---------- */
document.addEventListener('click', function(e){
  const link = e.target.closest('.jump-ref, .toc-sec > a, .overview-table a.row-link');
  if(!link) return;
  const href = link.getAttribute('href');
  if(!href || href === '#' || !href.startsWith('#')) return;
  const target = document.getElementById(href.slice(1));
  if(!target) return;
  e.preventDefault();
  if(target.tagName === 'DETAILS') target.open = true;
  target.scrollIntoView({behavior:'smooth', block:'start'});
  target.classList.remove('flash'); void target.offsetWidth; target.classList.add('flash');
  history.replaceState(null, '', href);
});

/* ---------- 3) 目录滚动高亮当前所在章节 ---------- */
(function(){
  const sections = Array.from(document.querySelectorAll('section[id]'));
  const tocLinks = Array.from(document.querySelectorAll('.toc-sec > a'));
  const obs = new IntersectionObserver(entries=>{
    entries.forEach(en=>{
      if(en.isIntersecting){
        tocLinks.forEach(a=>a.classList.remove('active'));
        const match = tocLinks.find(a=>a.getAttribute('href') === '#'+en.target.id);
        if(match) match.classList.add('active');
      }
    });
  }, {rootMargin:'-10% 0px -75% 0px'});
  sections.forEach(s=>obs.observe(s));
})();

/* ---------- 4) 全部展开 / 收起 ---------- */
document.getElementById('expand-all').onclick = ()=>document.querySelectorAll('.finding').forEach(f=>f.open=true);
document.getElementById('collapse-all').onclick = ()=>document.querySelectorAll('.finding').forEach(f=>f.open=false);

/* ---------- 5) 严重度筛选（目录工具条） ---------- */
document.querySelectorAll('.toc-filter button').forEach(btn=>{
  btn.addEventListener('click', ()=>{
    document.querySelectorAll('.toc-filter button').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    const f = btn.dataset.filter;
    document.querySelectorAll('.finding').forEach(el=>{
      el.style.display = (f==='ALL' || el.dataset.sev===f) ? '' : 'none';
    });
  });
});

/* ---------- 6) 代码块一键复制 ---------- */
document.querySelectorAll('.copy-btn').forEach(btn=>{
  btn.addEventListener('click', ()=>{
    const pre = btn.parentElement.querySelector('pre');
    navigator.clipboard.writeText(pre.textContent).then(()=>{
      const old = btn.textContent; btn.textContent='已复制';
      setTimeout(()=>btn.textContent=old, 1400);
    });
  });
});

/* ---------- 7) 回到顶部 ---------- */
const backTop = document.getElementById('back-top');
window.addEventListener('scroll', ()=>{ backTop.classList.toggle('show', window.scrollY>500); });
backTop.addEventListener('click', ()=>window.scrollTo({top:0,behavior:'smooth'}));
