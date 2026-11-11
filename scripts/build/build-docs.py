#!/usr/bin/env python3
"""Build docs/guide.html — a single self-contained web page from docs/guide.md.

    python3 scripts/build/build-docs.py [--src docs/guide.md] [--out docs/guide.html]

No external requests: CSS, JS and the logo are inlined, so the file can be
dropped onto any web host as-is. Needs `markdown` (pip install markdown) and
Pillow for the logo (optional — falls back to a text logo).
"""
import argparse
import base64
import html
import io
import os
import re
from datetime import date

import markdown

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def slugify(value, separator="-"):
    """GitHub-style anchors so the guide's own [links](#2-first-login--initial-setup) work."""
    value = html.unescape(re.sub(r"<[^>]+>", "", value)).strip().lower()
    value = re.sub(r"[^\w\- ]", "", value)
    return value.replace(" ", separator)


def logo_data_uri():
    path = os.path.join(ROOT, "app", "static", "img", "logo-mark.png")
    try:
        from PIL import Image
        im = Image.open(path)
        im.thumbnail((96, 96))
        buf = io.BytesIO()
        im.save(buf, "PNG", optimize=True)
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return None


def version():
    m = re.search(r'__version__\s*=\s*"([^"]+)"', open(os.path.join(ROOT, "app", "version.py")).read())
    return m.group(1) if m else ""


# Per-page wording. The profile is picked from the source file name.
PROFILES = {
    "guide": {
        "tag": "User Guide",
        "description": "Install, configure and use PwnBroker — self-hosted vulnerability management, "
                       "scanning, threat intelligence and GRC.",
        "lead": "Install, configure and run PwnBroker — scanning, proven-exploitable vulnerability "
                "management, threat intelligence and GRC on your own infrastructure.",
        "meta": "Version {version} · Updated {built}",
        "foot": "PwnBroker {version} · © PwnBroker. All data stays on your infrastructure.",
        "search": "Search sections…",
    },
    "terms": {
        "tag": "Legal",
        "description": "PWNBroker Terms of Service — the agreement that governs use of the PWNBroker "
                       "software, license keys, updates and support.",
        "lead": "The agreement that governs your use of PWNBroker. Please read it carefully — "
                "Sections 3 and 7 cover authorized use and limits of liability.",
        "meta": "{effective}",
        "foot": "© PWNBroker. All rights reserved.",
        "search": "Search the terms…",
    },
    "privacy": {
        "tag": "Privacy",
        "description": "PWNBroker Privacy Policy — what we collect for licensing, updates and support. "
                       "Your scan and security data stays on your own servers.",
        "lead": "Your scan results and security data stay on your own servers — we never receive them. "
                "This policy covers the little we do collect for licensing, updates and support.",
        "meta": "{effective}",
        "foot": "© PWNBroker. All rights reserved.",
        "search": "Search the policy…",
    },
}


def build(src, out, profile=None):
    text = open(src, encoding="utf-8").read()
    if not profile:
        name = os.path.basename(src).lower()
        profile = next((k for k in PROFILES if k in name), "guide")
    prof = PROFILES[profile]
    text = re.sub(r"<!--.*?-->\n?", "", text, flags=re.S)       # authoring notes stay out of the page

    # Title + intro come from the top of the file; the hand-written Table of
    # Contents is replaced by the generated sidebar.
    title_m = re.match(r"#\s+(.+)\n", text)
    title = title_m.group(1).strip() if title_m else "PwnBroker Guide"
    body_md = text[title_m.end():] if title_m else text
    body_md = re.sub(r"\n## Table of Contents\n.*?(?=\n## )", "\n", body_md, flags=re.S)
    body_md = re.sub(r"^---\s*$", "", body_md, flags=re.M)   # section rules are styled via h2
    # An "**Effective date:** … · **Last updated:** …" line moves into the hero.
    effective = ""
    eff_m = re.search(r"^\*\*Effective date:\*\*\s*(.+?)\s*·\s*\*\*Last updated:\*\*\s*(.+?)\s*$",
                      body_md, flags=re.M)
    if eff_m:
        effective = f"Effective {eff_m.group(1)} · Last updated {eff_m.group(2)}"
        body_md = body_md[:eff_m.start()] + body_md[eff_m.end():]

    md = markdown.Markdown(
        extensions=["tables", "fenced_code", "sane_lists", "toc", "attr_list"],
        extension_configs={"toc": {"slugify": slugify, "toc_depth": "2-3", "permalink": "#",
                                   "permalink_title": "Link to this section"}})
    content = md.convert(body_md)

    # Wrap tables so wide ones scroll on phones; tag code blocks with their language.
    content = content.replace("<table>", '<div class="table-wrap"><table>').replace("</table>", "</table></div>")

    nav = []
    for h2 in md.toc_tokens:
        if h2["level"] != 2:
            continue
        kids = "".join(f'<li><a href="#{c["id"]}">{c["name"]}</a></li>' for c in h2["children"])
        nav.append(f'<li class="nav-sec"><a href="#{h2["id"]}">{h2["name"]}</a>'
                   + (f'<ul>{kids}</ul>' if kids else "") + "</li>")
    nav_html = "\n".join(nav)

    logo = logo_data_uri()
    logo_html = (f'<img src="{logo}" alt="" width="34" height="37">' if logo else "")
    ver = version()
    fields = {"version": html.escape(ver), "built": date.today().isoformat(),
              "effective": html.escape(effective)}
    page = TEMPLATE.format(
        title=html.escape(title), logo=logo_html, nav=nav_html, content=content,
        favicon=f'<link rel="icon" href="{logo}">' if logo else "",
        tag=html.escape(prof["tag"]), description=html.escape(prof["description"]),
        lead=html.escape(prof["lead"]), search=html.escape(prof["search"]),
        meta=prof["meta"].format(**fields), foot=html.escape(prof["foot"].format(**fields)))
    with open(out, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"Wrote {out} ({len(page) / 1024:.0f} KB, {len(nav)} sections)")


TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<meta name="description" content="{description}">
{favicon}
<style>
:root {{
  --bg: #f3f6f8; --card: #ffffff; --side: #eaf1f4; --line: #d5e0e6; --ink: #0b2a4f;
  --muted: #5b7088; --accent: #13798c; --accent-dim: #0e5f70; --orange: #ef7318;
  --code-bg: #0b2a4f; --code-ink: #e6eef5; --inline-bg: #e8f1f4;
  --font: "Inter", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
}}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{
    --bg: #0a1626; --card: #0f2036; --side: #0c1b2e; --line: #1f3550; --ink: #e2ebf4;
    --muted: #8ea3ba; --accent: #3bb3c7; --accent-dim: #62c6d6; --orange: #f68b3c;
    --code-bg: #06101c; --code-ink: #dbe7f2; --inline-bg: #16304d;
  }}
}}
:root[data-theme="dark"] {{
  --bg: #0a1626; --card: #0f2036; --side: #0c1b2e; --line: #1f3550; --ink: #e2ebf4;
  --muted: #8ea3ba; --accent: #3bb3c7; --accent-dim: #62c6d6; --orange: #f68b3c;
  --code-bg: #06101c; --code-ink: #dbe7f2; --inline-bg: #16304d;
}}
* {{ box-sizing: border-box; }}
html {{ scroll-behavior: smooth; scroll-padding-top: 76px; }}
body {{ margin: 0; background: var(--bg); color: var(--ink); font: 16px/1.65 var(--font);
       -webkit-font-smoothing: antialiased; }}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}

/* top bar */
.topbar {{ position: sticky; top: 0; z-index: 20; height: 60px; display: flex; align-items: center;
          gap: 12px; padding: 0 20px; background: var(--card); border-bottom: 1px solid var(--line); }}
.topbar::after {{ content: ""; position: absolute; left: 0; right: 0; bottom: -3px; height: 3px;
                 background: linear-gradient(90deg, var(--ink), var(--accent) 55%, var(--orange)); }}
.brand {{ display: flex; align-items: center; gap: 10px; color: var(--ink); font-size: 1.2rem; }}
.brand:hover {{ text-decoration: none; }}
.brand b {{ font-weight: 800; }}
.brand span {{ font-weight: 400; }}
.tag {{ font-size: .72rem; font-weight: 600; letter-spacing: .04em; text-transform: uppercase;
       color: var(--muted); border: 1px solid var(--line); border-radius: 999px; padding: 2px 10px; }}
.spacer {{ flex: 1; }}
.icon-btn {{ background: none; border: 1px solid var(--line); color: var(--ink); border-radius: 8px;
            height: 36px; min-width: 36px; padding: 0 10px; cursor: pointer; font: inherit; font-size: .9rem; }}
.icon-btn:hover {{ border-color: var(--accent); color: var(--accent); }}
#menu-btn {{ display: none; }}

/* layout */
.layout {{ display: grid; grid-template-columns: 300px minmax(0, 1fr); }}
.sidebar {{ position: sticky; top: 63px; height: calc(100vh - 63px); overflow-y: auto; padding: 20px 14px 40px 20px;
           border-right: 1px solid var(--line); background: var(--side); }}
.search {{ width: 100%; padding: 9px 12px; border: 1px solid var(--line); border-radius: 8px; background: var(--card);
          color: var(--ink); font: inherit; font-size: .9rem; margin-bottom: 14px; }}
.search:focus {{ outline: 2px solid var(--accent); outline-offset: -1px; }}
.sidebar ul {{ list-style: none; margin: 0; padding: 0; }}
.sidebar .nav-sec > a {{ display: block; font-weight: 600; font-size: .9rem; padding: 6px 10px; border-radius: 6px; color: var(--ink); }}
.sidebar .nav-sec ul a {{ display: block; font-size: .84rem; padding: 3px 10px 3px 22px; color: var(--muted); border-radius: 6px; }}
.sidebar .nav-sec ul {{ display: none; margin-bottom: 6px; }}
.sidebar .nav-sec.open ul, .sidebar.searching .nav-sec ul {{ display: block; }}
.sidebar a:hover {{ background: var(--card); text-decoration: none; color: var(--accent); }}
.sidebar a.active {{ color: var(--accent); background: var(--card); box-shadow: inset 3px 0 0 var(--orange); }}
.sidebar .hidden {{ display: none !important; }}
.no-results {{ color: var(--muted); font-size: .85rem; padding: 6px 10px; display: none; }}

main {{ padding: 36px 56px 80px; min-width: 0; }}
.icon-btn svg {{ width: 18px; height: 18px; vertical-align: -4px; }}
.doc {{ max-width: 860px; }}
.hero {{ background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 28px 30px; margin-bottom: 36px; }}
.hero h1 {{ margin: 0 0 8px; font-size: 2rem; line-height: 1.2; }}
.hero p {{ margin: 0; color: var(--muted); }}
.hero .meta {{ margin-top: 14px; font-size: .82rem; color: var(--muted); }}

.doc h2 {{ font-size: 1.6rem; line-height: 1.25; margin: 56px 0 16px; padding-top: 22px; border-top: 1px solid var(--line); }}
.doc h2:first-of-type {{ border-top: 0; padding-top: 0; margin-top: 0; }}
.doc h3 {{ font-size: 1.2rem; margin: 34px 0 10px; }}
.doc h4 {{ font-size: 1rem; margin: 24px 0 8px; }}
.doc .headerlink {{ margin-left: 8px; opacity: 0; color: var(--muted); font-weight: 400; }}
.doc h2:hover .headerlink, .doc h3:hover .headerlink, .doc h4:hover .headerlink {{ opacity: 1; }}
.doc p, .doc li {{ color: var(--ink); }}
.doc ul, .doc ol {{ padding-left: 1.4em; }}
.doc li {{ margin: 4px 0; }}
.doc strong {{ font-weight: 650; }}
.doc code {{ font-family: var(--mono); font-size: .86em; background: var(--inline-bg); padding: 2px 6px; border-radius: 5px; }}
.doc pre {{ position: relative; background: var(--code-bg); color: var(--code-ink); border-radius: 10px;
           padding: 16px 18px; overflow-x: auto; font-size: .86rem; line-height: 1.55; margin: 16px 0; }}
.doc pre code {{ background: none; padding: 0; font-size: inherit; color: inherit; }}
.copy {{ position: absolute; top: 8px; right: 8px; font: 600 .72rem var(--font); color: var(--code-ink);
        background: rgba(255,255,255,.08); border: 1px solid rgba(255,255,255,.18); border-radius: 6px;
        padding: 4px 9px; cursor: pointer; opacity: 0; transition: opacity .15s; }}
.doc pre:hover .copy, .copy:focus {{ opacity: 1; }}
.table-wrap {{ overflow-x: auto; margin: 16px 0; border: 1px solid var(--line); border-radius: 10px; background: var(--card); }}
.doc table {{ border-collapse: collapse; width: 100%; font-size: .9rem; }}
.doc th {{ text-align: left; font-size: .74rem; letter-spacing: .05em; text-transform: uppercase; color: var(--muted);
          background: var(--side); padding: 10px 14px; border-bottom: 1px solid var(--line); }}
.doc td {{ padding: 10px 14px; border-bottom: 1px solid var(--line); vertical-align: top; }}
.doc tr:last-child td {{ border-bottom: 0; }}
.doc blockquote {{ margin: 16px 0; padding: 12px 18px; border-left: 4px solid var(--orange);
                  background: var(--card); border-radius: 0 10px 10px 0; color: var(--muted); }}
.doc hr {{ border: 0; border-top: 1px solid var(--line); margin: 32px 0; }}
.foot {{ margin-top: 64px; padding-top: 20px; border-top: 1px solid var(--line); font-size: .82rem; color: var(--muted); }}
#top-btn {{ position: fixed; right: 20px; bottom: 20px; opacity: 0; pointer-events: none; transition: opacity .2s;
           background: var(--card); }}
#top-btn.show {{ opacity: 1; pointer-events: auto; }}

@media (max-width: 960px) {{
  .layout {{ grid-template-columns: 1fr; }}
  #menu-btn {{ display: inline-block; }}
  .sidebar {{ position: fixed; top: 63px; left: 0; bottom: 0; width: min(320px, 86vw); height: auto; z-index: 15;
             transform: translateX(-100%); transition: transform .2s; box-shadow: 4px 0 24px rgba(0,0,0,.15); }}
  body.nav-open .sidebar {{ transform: none; }}
  main {{ padding: 24px 16px 64px; }}
  .hero {{ padding: 20px; }}
  .hero h1 {{ font-size: 1.55rem; }}
  .tag {{ display: none; }}
}}
@media print {{
  .topbar, .sidebar, #top-btn, .copy, .headerlink {{ display: none !important; }}
  .layout {{ display: block; }}
  main {{ padding: 0; }}
  .doc pre {{ white-space: pre-wrap; }}
  .doc h2 {{ break-before: page; }}
}}
</style>
</head>
<body>
<header class="topbar">
  <button class="icon-btn" id="menu-btn" aria-label="Open navigation"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 6h18M3 12h18M3 18h18"/></svg></button>
  <a class="brand" href="#">{logo}<span><b>Pwn</b>Broker</span></a>
  <span class="tag">{tag}</span>
  <div class="spacer"></div>
  <button class="icon-btn" id="theme-btn" aria-label="Toggle dark mode" title="Toggle dark mode"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg></button>
</header>
<div class="layout">
  <nav class="sidebar" id="sidebar" aria-label="Guide contents">
    <input class="search" id="search" type="search" placeholder="{search}" aria-label="{search}">
    <ul id="nav">
{nav}
    </ul>
    <div class="no-results" id="no-results">No matching sections.</div>
  </nav>
  <main>
    <article class="doc">
      <div class="hero">
        <h1>{title}</h1>
        <p>{lead}</p>
        <div class="meta">{meta}</div>
      </div>
{content}
      <div class="foot">{foot}</div>
    </article>
  </main>
</div>
<button class="icon-btn" id="top-btn" aria-label="Back to top">Back to top</button>
<script>
(function () {{
  var root = document.documentElement;
  try {{ var t = localStorage.getItem('pb-doc-theme'); if (t) root.setAttribute('data-theme', t); }} catch (e) {{}}
  document.getElementById('theme-btn').addEventListener('click', function () {{
    var dark = root.getAttribute('data-theme') === 'dark' ||
      (!root.getAttribute('data-theme') && matchMedia('(prefers-color-scheme: dark)').matches);
    var next = dark ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try {{ localStorage.setItem('pb-doc-theme', next); }} catch (e) {{}}
  }});

  // Mobile nav
  var body = document.body;
  document.getElementById('menu-btn').addEventListener('click', function () {{ body.classList.toggle('nav-open'); }});
  document.getElementById('nav').addEventListener('click', function (e) {{
    if (e.target.tagName === 'A') body.classList.remove('nav-open');
  }});

  // Copy buttons
  document.querySelectorAll('.doc pre').forEach(function (pre) {{
    var b = document.createElement('button');
    b.className = 'copy'; b.type = 'button'; b.textContent = 'Copy';
    b.addEventListener('click', function () {{
      var txt = pre.querySelector('code') ? pre.querySelector('code').innerText : pre.innerText;
      navigator.clipboard.writeText(txt).then(function () {{
        b.textContent = 'Copied'; setTimeout(function () {{ b.textContent = 'Copy'; }}, 1400);
      }});
    }});
    pre.appendChild(b);
  }});

  // Scroll spy
  var links = {{}};
  document.querySelectorAll('#nav a').forEach(function (a) {{ links[a.getAttribute('href').slice(1)] = a; }});
  var heads = Array.prototype.filter.call(document.querySelectorAll('.doc h2[id], .doc h3[id]'),
    function (h) {{ return links[h.id]; }});
  var current = null;
  function spy() {{
    var y = window.scrollY + 90, hit = heads[0];
    for (var i = 0; i < heads.length; i++) {{ if (heads[i].offsetTop <= y) hit = heads[i]; else break; }}
    if (!hit || hit === current) return;
    current = hit;
    document.querySelectorAll('#nav a.active').forEach(function (a) {{ a.classList.remove('active'); }});
    document.querySelectorAll('#nav .nav-sec.open').forEach(function (s) {{ s.classList.remove('open'); }});
    var a = links[hit.id]; a.classList.add('active');
    var sec = a.closest('.nav-sec'); if (sec) sec.classList.add('open');
    var side = document.getElementById('sidebar');
    var r = a.getBoundingClientRect(), sr = side.getBoundingClientRect();
    if (r.top < sr.top + 50 || r.bottom > sr.bottom - 20) side.scrollTop += r.top - sr.top - sr.height / 3;
  }}
  var topBtn = document.getElementById('top-btn');
  window.addEventListener('scroll', function () {{
    spy(); topBtn.classList.toggle('show', window.scrollY > 800);
  }}, {{ passive: true }});
  topBtn.addEventListener('click', function () {{ window.scrollTo({{ top: 0 }}); }});
  spy();

  // Section search: filters the sidebar by heading text and section content.
  var sections = {{}};
  heads.forEach(function (h, i) {{
    var txt = h.textContent, n = h.nextElementSibling;
    while (n && !(n.tagName === 'H2' || n.tagName === 'H3')) {{ txt += ' ' + n.textContent; n = n.nextElementSibling; }}
    sections[h.id] = txt.toLowerCase();
  }});
  var side = document.getElementById('sidebar');
  document.getElementById('search').addEventListener('input', function () {{
    var q = this.value.trim().toLowerCase(), any = false;
    side.classList.toggle('searching', !!q);
    document.querySelectorAll('#nav .nav-sec').forEach(function (sec) {{
      var secHit = false;
      sec.querySelectorAll('ul a').forEach(function (a) {{
        var ok = !q || (sections[a.getAttribute('href').slice(1)] || '').indexOf(q) >= 0;
        a.parentNode.classList.toggle('hidden', !ok); secHit = secHit || ok;
      }});
      var own = (sections[sec.firstElementChild.getAttribute('href').slice(1)] || '').indexOf(q) >= 0;
      sec.classList.toggle('hidden', !!q && !secHit && !own);
      any = any || !q || secHit || own;
    }});
    document.getElementById('no-results').style.display = any ? 'none' : 'block';
  }});
}})();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=os.path.join(ROOT, "docs", "guide.md"))
    ap.add_argument("--out", help="output HTML (default: next to --src, .md -> .html)")
    ap.add_argument("--profile", choices=sorted(PROFILES), help="page wording (default: from file name)")
    a = ap.parse_args()
    build(a.src, a.out or os.path.splitext(a.src)[0] + ".html", a.profile)
