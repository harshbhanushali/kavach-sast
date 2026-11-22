/**
 * Stylesheet for the printable report.
 *
 * Pagination model: the document is a series of `.pg` groups. A group with the
 * `newpage` class starts on a fresh sheet; inside a group content flows and
 * breaks between rows/cards, never inside one. Every finding is its own `.pg`.
 *
 * Running header/footer use `@page` margin boxes, which Chromium honours and
 * other engines ignore. That is a progressive enhancement only: every page
 * already carries its own identity (finding banners, section openers), so a
 * browser without margin boxes loses page numbers, not meaning.
 */
import { BRAND, markDataUri } from '../brand';
import { GOOD, SEV, cssStr } from './kit';

/** Fonts that can draw Devanagari, tried in order; the browser falls back to whatever the machine has. */
const DEVA = '"Noto Sans Devanagari", "Kohinoor Devanagari", "Devanagari Sangam MN", "Nirmala UI", Mukta, sans-serif';

export function reportCss(meta: { title: string; digest: string; icon?: string; edition?: string }): string {
  const S = SEV;
  return `
  @page {
    size: A4;
    margin: 19mm 14mm 17mm;
    @top-left {
      /* The mark is a background (a margin box cannot hold an <img>); the name beside it is in both scripts. */
      content: "KAVACH  ${BRAND.devanagari}  \\00b7  STATIC ANALYSIS${meta.edition ? `  \\00b7  ${meta.edition}` : ''}";
      font: 700 7.5pt/1 -apple-system, "Segoe UI", Roboto, Helvetica, ${DEVA};
      letter-spacing: .14em; color: #3a424c; vertical-align: bottom; padding-bottom: 5mm; padding-left: 9.5mm;
      background: url("${markDataUri('hd')}") no-repeat left 0 bottom 2.4mm / 7.2mm 8.1mm;
    }
    @top-right {
      content: "${cssStr(meta.title, 64)}";
      font: 600 6.5pt/1 ui-monospace, "SF Mono", Menlo, monospace;
      color: #66707c; vertical-align: bottom; padding-bottom: 5mm;${
        meta.icon
          ? `
      /* The app icon, tiny, after the file name. A margin box cannot hold an <img>, so it is a background. */
      padding-right: 6.5mm; text-align: right;
      background: url("${meta.icon}") no-repeat right 0 bottom 3.6mm / 4.8mm 4.8mm;`
          : ''
      }
    }
    @bottom-left {
      content: "DIGEST  ${cssStr(meta.digest.slice(0, 16))}";
      font: 600 6.5pt/1 ui-monospace, "SF Mono", Menlo, monospace;
      color: #8a929b; vertical-align: top; padding-top: 5mm;
    }
    @bottom-center {
      content: "KAVACH  ${BRAND.devanagari}";
      font: 700 7.5pt/1 -apple-system, "Segoe UI", Roboto, Helvetica, ${DEVA};
      width: 36mm; text-align: left;
      letter-spacing: .14em; color: #3a424c; vertical-align: top; padding-top: 4.2mm; padding-left: 8.5mm;
      background: url("${markDataUri('ft')}") no-repeat left 0 top 2.4mm / 6.4mm 7.2mm;
    }
    @bottom-right {
      content: "PAGE " counter(page) " / " counter(pages);
      font: 700 6.5pt/1 -apple-system, "Segoe UI", Roboto, Helvetica, sans-serif;
      letter-spacing: .14em; color: #3a424c; vertical-align: top; padding-top: 5mm;
    }
  }
  @page :first {
    margin: 0;
    @top-left { content: none; background: none; } @top-right { content: none; background: none; }
    @bottom-left { content: none; } @bottom-center { content: none; background: none; } @bottom-right { content: none; }
  }

  :root {
    --ink: #12161c; --ink2: #3a424c; --mute: #5f6873; --faint: #8a929b;
    --line: #d9dde1; --line2: #eceef0; --wash: #f6f7f8; --paper: #fff;
    --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  }
  *, *::before, *::after { box-sizing: border-box; }
  html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body {
    font: 9.5pt/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, sans-serif;
    color: var(--ink); background: #e6e8eb; margin: 0;
    font-variant-numeric: tabular-nums;
  }
  a { color: inherit; text-decoration: none; }
  a.lnk { border-bottom: 1px dotted var(--faint); }
  code, .mono { font-family: var(--mono); font-size: .86em; }
  code { background: #f1f3f4; padding: 1px 4px; border-radius: 3px; word-break: break-all; }
  code.cmdl { background: #eef7f1; border: 1px solid #bcd9c7; color: #14532d; padding: 1px 5px; }
  code.cmdl::before { content: '$ '; color: #5b8a6c; }
  .muted { color: var(--mute); }
  .small { font-size: 8.5pt; }
  .na { color: var(--faint); }
  h1, h2, h3, h4, p, ul, ol, dl, dd, figure { margin: 0; }

  /* ---- sheets ------------------------------------------------------------- */
  .pg { position: relative; }
  .newpage { break-before: page; page-break-before: always; }
  /* ---- compact finding cards (medium, low, info) -------------------------------- */
  .fc-title { display: flex; justify-content: space-between; align-items: baseline; font-size: 12pt; font-weight: 800; letter-spacing: .02em;
              padding-bottom: 5px; border-bottom: 2px solid var(--ink); margin-bottom: 4px; break-after: avoid; page-break-after: avoid; }
  .fc { border: 1px solid var(--line); border-left: 4px solid; border-radius: 3px; padding: 7px 11px 8px; margin-top: 8px; background: #fff;
        break-inside: avoid; page-break-inside: avoid; }
  .fc-h { display: flex; align-items: baseline; gap: 9px; }
  .fc-sev { font-size: 6.8pt; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; white-space: nowrap; }
  .fc-sev .gl { margin-right: 3px; }
  .fc-t { font-size: 10.2pt; font-weight: 700; }
  .fc-n { margin-left: auto; font-size: 7pt; color: var(--mute); white-space: nowrap; font-variant-numeric: tabular-nums; }
  .fc-meta { font-size: 7.6pt; color: var(--mute); margin: 2px 0 5px; overflow-wrap: anywhere; }
  .fc-meta .dot { color: #b4bcc4; }
  .fc-cols { display: grid; grid-template-columns: 1.15fr 1fr; gap: 12px; }
  .fc-cols h5 { margin: 0 0 2px; font-size: 6.8pt; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; color: var(--mute); }
  .fc-cols p { margin: 0 0 3px; font-size: 8.6pt; line-height: 1.45; }
  .fc-cols .fc-risk { color: var(--ink2); }
  .fc-ev { margin-top: 5px; }
  .fc-ev .code { margin-bottom: 4px; } .fc-ev .code-body { font-size: 6.8pt; }
  .fc-ev table.ev td, .fc-ev table.ev th { font-size: 7.2pt; }
  ul.cl { list-style: none; margin: 4px 0 0; padding: 0; columns: 2; column-gap: 10mm; font-size: 8.4pt; }
  ul.cl li { break-inside: avoid; padding: 3px 0; border-bottom: 1px solid var(--line2); }
  .pg.flowing { margin-top: 9mm; }
  .pg.flowing + .pg.flowing { padding-top: 0; }
  .pg.keep { break-inside: avoid; page-break-inside: avoid; }
  .keepnext { break-after: avoid; page-break-after: avoid; }
  .stick { break-inside: avoid; page-break-inside: avoid; }
  .secret-strip { margin-top: 10px; padding: 6px 10px; border-left: 4px solid ${S.critical.fill}; background: ${S.critical.tint}; font-size: 8pt; line-height: 1.4; }
  .secret-strip strong { color: ${S.critical.text}; }
  .nw { white-space: nowrap; }
  @media screen {
    .pg { width: 210mm; margin: 14px auto; padding: 19mm 14mm 17mm; background: var(--paper);
          box-shadow: 0 2px 16px rgb(0 0 0 / .14); border-radius: 3px; }
    .pg.cover { padding: 0; }
    .pg.cont { margin-top: -14px; border-radius: 0; padding-top: 4mm; box-shadow: 0 8px 16px -10px rgb(0 0 0 / .14); }

    /* Preview as standard A4 pages. Each sheet is at least one A4 page tall, and a
       small script rounds it up to a whole number of pages (--sheet-h), with a faint
       divider where each page would end. Sheets of arbitrary height read as "big
       and small pages"; this makes the preview look like the A4 pages the PDF has.
       Where the divider falls is an approximation: the PDF breaks between rows and
       cards, so it is the PDF that paginates exactly. */
    .pg { min-height: var(--sheet-h, 297mm); isolation: isolate; }
    .pg.cont { min-height: 0; }
    .pg:not(.cont)::after { content: ""; position: absolute; inset: 0; pointer-events: none; border-radius: inherit;
      background: repeating-linear-gradient(to bottom, transparent 0, transparent calc(297mm - 1.5px), #dfe3e8 calc(297mm - 1.5px), #dfe3e8 297mm); }
    .pg.cover::after { display: none; }
    .preview-note { width: 210mm; margin: 14px auto 0; padding: 8px 12px; font: 12px/1.4 -apple-system, "Segoe UI", sans-serif;
      color: #4a5560; background: #eef3f8; border: 1px solid #d3dde8; border-radius: 4px; }
  }
  @media print {
    /* The first page has no margins, so that offset would be wrong there; the cover masks the watermark instead. */
    .cover { position: relative; z-index: 10000; background: #fff; }
    .preview-note { display: none; }
    body { background: #fff; }
    .pg { margin: 0; padding: 0; }
  }

  /* ---- cover -------------------------------------------------------------- */
  .cover { height: 296mm; overflow: hidden; display: flex; flex-direction: column;
           break-after: page; page-break-after: always; }
  .cover-band { position: relative; background: #0f141a; color: #fff; padding: 15mm 16mm 12mm; flex: 0 0 auto;
    background-image: repeating-linear-gradient(135deg, rgb(255 255 255 / .045) 0 1px, transparent 1px 10px); }
  .cover-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14mm; }
  .cover-id { display: flex; align-items: center; gap: 9mm; }
  .cover-id-t { min-width: 0; flex: 1 1 auto; }
  .brandmark { display: flex; align-items: center; gap: 11px; font-weight: 800; font-size: 14pt; letter-spacing: .2em; }
  .brandmark .deva { font-size: 15pt; font-weight: 700; letter-spacing: 0; color: #fcd34d; font-family: ${DEVA}; }
  .brandmark svg { display: block; }
  .classif { border: 1px solid rgb(255 255 255 / .55); border-radius: 3px; padding: 3px 9px;
             font-size: 6.8pt; font-weight: 700; letter-spacing: .18em; text-transform: uppercase; }
  .cover-kicker { font-size: 8pt; font-weight: 700; letter-spacing: .28em; text-transform: uppercase; color: #9fb0c2; }
  .cover-title { font-size: 33pt; line-height: 1.02; font-weight: 800; letter-spacing: -.02em; margin: 4mm 0 4mm;
                 word-break: break-word; overflow-wrap: anywhere; }
  .cover-title.long { font-size: 24pt; }
  .cover-sub { display: flex; flex-wrap: wrap; gap: 8px 14px; align-items: center; font-size: 10pt; color: #d5dde6; }
  .cover-sub .plat { background: #fff; color: #0f141a; font-weight: 800; letter-spacing: .12em; text-transform: uppercase;
                     font-size: 7.5pt; padding: 3px 9px; border-radius: 3px; }
  .cover-sub .id { font-family: var(--mono); font-size: 9pt; }
  .cover .stripe { position: absolute; left: 0; right: 0; bottom: 0; border-radius: 0; }
  .cover-main { padding: 12mm 16mm 0; flex: 1 1 auto; display: flex; flex-direction: column; }
  .cover-hero { display: grid; grid-template-columns: 62mm 1fr; gap: 10mm; align-items: center; }
  .cover-hero .ring { display: block; }
  .verdict-tag { display: inline-block; font-size: 8pt; font-weight: 800; letter-spacing: .16em; text-transform: uppercase;
                 padding: 4px 10px; border-radius: 3px; margin-bottom: 8px; }
  .verdict { font-size: 17pt; line-height: 1.22; font-weight: 750; letter-spacing: -.01em; }
  .verdict-sub { font-size: 9pt; color: var(--mute); margin-top: 8px; max-width: 90mm; }
  .cover-sev { display: grid; grid-template-columns: repeat(5, 1fr); gap: 6px; margin: 9mm 0 8mm; }
  .csev { border: 1px solid var(--line); border-top-width: 5px; border-radius: 4px; padding: 7px 9px 8px; }
  .csev-n { font-size: 23pt; font-weight: 800; line-height: 1; }
  .csev-l { display: flex; align-items: center; gap: 5px; margin-top: 5px; font-size: 7.5pt; font-weight: 800;
            letter-spacing: .1em; text-transform: uppercase; }
  .cover-meta { margin-top: 0; }
  .cover-hash { margin-top: auto; border-top: 2px solid var(--ink); padding: 4mm 0 0; }
  .hash-row { display: grid; grid-template-columns: 40mm 1fr; gap: 8px; align-items: baseline; margin-bottom: 5px; }
  .hash-k { white-space: nowrap; font-size: 6.8pt; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; color: var(--mute); }
  .hash-v { font-family: var(--mono); font-size: 7.8pt; word-break: break-all; line-height: 1.35; }
  .hash-v.strong { font-weight: 700; font-size: 8.2pt; }
  .cover-foot { display: flex; justify-content: space-between; padding: 3mm 16mm 9mm; font-size: 7pt; color: var(--faint);
                letter-spacing: .04em; }
  .cover-alert { margin-top: 5mm; }

  /* ---- app icon ------------------------------------------------------------- */
  .appicon { display: inline-flex; align-items: center; justify-content: center; flex: 0 0 auto; overflow: hidden;
             background: #f4f6f8; color: #fff; font-weight: 800; }
  .appicon img { display: block; width: 100%; height: 100%; object-fit: cover; }
  .ico-cover { width: 34mm; height: 34mm; border-radius: 7.6mm; font-size: 40pt;
               box-shadow: 0 0 0 1.2px rgb(255 255 255 / .38), 0 3mm 6mm rgb(0 0 0 / .45); }
  .ico-page { width: 20mm; height: 20mm; border-radius: 4.5mm; font-size: 24pt; box-shadow: 0 0 0 1px var(--line), 0 1mm 2.4mm rgb(0 0 0 / .16); }
  .app-id { display: flex; align-items: center; gap: 5mm; margin: 0 0 9px; padding: 3.5mm 4.5mm; border: 1px solid var(--line);
            border-radius: 6px; background: var(--wash); break-inside: avoid; }
  .app-id .nm { font-size: 15pt; font-weight: 800; letter-spacing: -.01em; line-height: 1.15; overflow-wrap: anywhere; }
  .app-id .bid { font-family: var(--mono); font-size: 8.4pt; color: var(--mute); margin-top: 1px; overflow-wrap: anywhere; }
  .app-id-c { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px; }

  /* ---- section openers ------------------------------------------------------ */
  .opener { display: flex; gap: 14px; align-items: flex-end; border-top: 5px solid var(--ink);
            padding: 9px 0 10px; margin-bottom: 12px; border-bottom: 1px solid var(--line);
            break-after: avoid; page-break-after: avoid; }
  .opener-num { font-size: 40pt; font-weight: 800; line-height: .8; color: #cdd2d8; letter-spacing: -.04em; min-width: 24mm; }
  .opener h2 { font-size: 15pt; font-weight: 800; text-transform: uppercase; letter-spacing: .08em; line-height: 1.1; }
  .opener p { font-size: 9pt; color: var(--mute); margin-top: 3px; max-width: 120mm; }
  h3.sub { display: flex; justify-content: space-between; align-items: baseline; gap: 10px; margin: 15px 0 6px;
           padding-bottom: 4px; border-bottom: 1.5px solid var(--ink); font-size: 8.5pt; font-weight: 800;
           text-transform: uppercase; letter-spacing: .12em; break-after: avoid; page-break-after: avoid; }
  h3.sub .aside { font-size: 8pt; font-weight: 600; letter-spacing: 0; text-transform: none; color: var(--mute); }
  h3.sub:first-child { margin-top: 0; }
  .lead { font-size: 9pt; color: var(--mute); margin: 0 0 8px; max-width: 150mm; break-after: avoid; page-break-after: avoid; }

  /* ---- atoms ---------------------------------------------------------------- */
  .chip { display: inline-flex; align-items: center; gap: 4px; font-size: 7.3pt; font-weight: 700; letter-spacing: .06em;
          text-transform: uppercase; border: 1px solid #b8bec5; color: var(--ink2); border-radius: 3px;
          padding: 1px 6px; line-height: 1.5; white-space: nowrap; background: #fff; vertical-align: middle; }
  .chip.mono { font-family: var(--mono); text-transform: none; letter-spacing: 0; font-weight: 600; }
  .chip.cap { text-transform: none; letter-spacing: 0; font-weight: 600; font-size: 7.8pt; }
  .chip.solid { background: var(--ink); color: #fff; border-color: var(--ink); }
  .sevchip .g { font-size: .95em; }
  .meter { display: inline-flex; gap: 1.5px; vertical-align: middle; }
  .meter i { display: block; width: 4px; height: 8px; border: 1px solid currentColor; border-radius: 1px; }
  .sevchip .meter i { border-color: currentColor; }
  .st { font-weight: 700; white-space: nowrap; font-size: .95em; }
  .st.good { color: ${GOOD}; } .st.bad { color: ${S.critical.text}; } .st.neutral { color: var(--ink2); }
  .stripe { display: flex; gap: 2px; width: 100%; border-radius: 3px; overflow: hidden; }
  .stripe span { display: block; min-width: 3px; }

  .facts { display: grid; gap: 9px 16px; }
  .facts.c2 { grid-template-columns: repeat(2, 1fr); } .facts.c3 { grid-template-columns: repeat(3, 1fr); }
  .facts.c4 { grid-template-columns: repeat(4, 1fr); }
  .fact { min-width: 0; break-inside: avoid; } .fact.wide { grid-column: 1 / -1; }
  .fact dt { font-size: 6.8pt; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; color: var(--mute); }
  .fact dd { margin-top: 1px; font-size: 9.3pt; overflow-wrap: anywhere; }
  .fact dd.mono { font-size: 8pt; }

  .tiles { display: grid; grid-template-columns: repeat(var(--n, 4), 1fr); gap: 6px; }
  .tile { border: 1px solid var(--line); border-radius: 4px; padding: 7px 9px; background: #fff; break-inside: avoid; }
  .tile-n { font-size: 17pt; font-weight: 800; line-height: 1.05; }
  .tile-l { font-size: 6.9pt; font-weight: 800; letter-spacing: .1em; text-transform: uppercase; color: var(--mute); margin-top: 3px; }
  .tile-s { font-size: 7.6pt; color: var(--mute); margin-top: 2px; line-height: 1.35; }

  .callout { border: 1px solid var(--line); border-left-width: 4px; border-radius: 0 5px 5px 0; padding: 8px 12px 9px;
             background: var(--wash); break-inside: avoid; }
  .callout-t { font-size: 6.9pt; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; margin-bottom: 3px; }
  .callout p { max-width: 150mm; }
  .callout.risk { border-left-color: ${S.high.fill}; background: ${S.high.tint}; border-color: #f3d3bd; }
  .callout.risk .callout-t { color: ${S.high.text}; }
  .callout.fix { border-left-color: ${GOOD}; background: #eef8ef; border-color: #cbe5ce; }
  .callout.fix .callout-t { color: ${GOOD}; }
  .callout.warn { border-left-color: ${S.critical.fill}; background: ${S.critical.tint}; border-color: #ecc3cb; }
  .callout.warn .callout-t { color: ${S.critical.text}; }
  .callout.note .callout-t { color: var(--ink2); }

  /* ---- tables --------------------------------------------------------------- */
  table.tbl { width: 100%; border-collapse: collapse; font-size: 8.6pt; }
  table.tbl thead { display: table-header-group; }
  table.tbl tr { break-inside: avoid; page-break-inside: avoid; }
  table.tbl th { text-align: left; font-size: 6.9pt; font-weight: 800; letter-spacing: .1em; text-transform: uppercase;
                 color: var(--mute); border-bottom: 1.5px solid var(--ink); padding: 4px 8px 4px 0; background: #fff; }
  table.tbl td { padding: 3.8px 8px 3.8px 0; border-bottom: 1px solid var(--line2); vertical-align: top; overflow-wrap: anywhere; }
  table.tbl td.c, table.tbl th.c { text-align: center; }
  table.tbl td.r, table.tbl th.r { text-align: right; }
  table.tbl tr.flag td { background: ${S.critical.tint}; }
  table.tbl tr.flag td:first-child { box-shadow: inset 3px 0 0 ${S.critical.fill}; padding-left: 7px; }
  table.tbl tr.warn td { background: ${S.medium.tint}; }
  table.tbl tr.dim td { color: var(--mute); }
  table.tbl tr.zebra td { background: var(--wash); }
  table.cov td { padding: 2.2px 8px 2.2px 0; font-size: 8pt; }

  /* ---- executive summary ---------------------------------------------------- */
  .verdict-panel { display: grid; grid-template-columns: 1fr; gap: 5px; margin-bottom: 8px; }
  .verdict-panel .vhead { font-size: 15pt; font-weight: 800; line-height: 1.2; letter-spacing: -.01em; }
  .two { display: grid; grid-template-columns: 1.15fr 1fr; gap: 18px; align-items: start; }
  .dist { margin-top: 2px; } .dist .stripe { margin-bottom: 5px; height: 12px !important; }
  table.dist-rows { width: 100%; border-collapse: collapse; font-size: 9pt; }
  table.dist-rows td { padding: 0.5px 0; }
  table.dist-rows .dr-g { width: 16px; font-size: 9pt; }
  table.dist-rows .dr-l { font-weight: 700; width: 62px; }
  table.dist-rows .dr-n { font-weight: 800; text-align: right; width: 28px; font-size: 11pt; }
  table.dist-rows .dr-p { text-align: right; width: 38px; color: var(--mute); font-size: 8pt; }
  table.dist-rows tr.zero { color: var(--faint); }
  .tri-list { display: grid; gap: 6px; }
  .tri-row { display: grid; grid-template-columns: 34px 1fr; gap: 8px; align-items: center; border: 1px solid var(--line);
             border-radius: 4px; padding: 3px 9px; }
  .tri-row .n { font-size: 15pt; font-weight: 800; line-height: 1; text-align: center; }
  .tri-row .t { font-size: 7.3pt; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; }
  .tri-row .d { font-size: 7.8pt; color: var(--mute); line-height: 1.3; }

  ol.top { list-style: none; padding: 0; counter-reset: top; }
  ol.top li { counter-increment: top; display: grid; grid-template-columns: 22px 78px 1fr 56px; gap: 8px; align-items: baseline;
              padding: 5px 0; border-bottom: 1px solid var(--line2); break-inside: avoid; }
  ol.top li::before { content: counter(top); font-weight: 800; color: var(--faint); font-size: 10pt; }
  ol.top .tt { font-weight: 700; font-size: 9.5pt; }
  ol.top .ti { font-size: 8.2pt; color: var(--mute); margin-top: 1px; }
  ol.top .tm { font-size: 7.4pt; color: var(--mute); text-align: right; line-height: 1.35; font-family: var(--mono); }
  ul.signals { list-style: none; padding: 0; margin: 0; display: flex; flex-wrap: wrap; gap: 5px; }
  ul.signals li { display: inline-flex; align-items: baseline; gap: 6px; border: 1px solid; border-radius: 4px; padding: 2px 8px 3px; font-size: 8pt; background: #fff; }
  ul.signals .sg { font-weight: 800; font-size: 8pt; } ul.signals .sl { color: var(--ink2); }

  .catgrid { column-count: 3; column-gap: 7px; }
  .catblock { break-inside: avoid; page-break-inside: avoid; margin-bottom: 7px; }
  .catblock .cat { border-radius: 4px 4px 0 0; }
  .catlist { list-style: none; margin: 0; padding: 0; border: 1px solid var(--line); border-top: 0; border-radius: 0 0 4px 4px; }
  .catlist li { border-top: 1px solid var(--line); }
  .catlist li:first-child { border-top: 0; }
  .catlist a { display: flex; align-items: center; flex-wrap: wrap; gap: 3px 6px; padding: 4px 7px; font-size: 7.6pt; color: inherit; text-decoration: none; }
  .catlist a span { flex: 1 1 auto; }
  .catlist a b { color: var(--mute); font-weight: 600; font-size: 7.4pt; }
  .catreview { font-size: 7.4pt; color: var(--mute); margin: 4px 2px 0; line-height: 1.4; }
  table.scoremath td, table.scoremath th { padding: 4px 8px; }
  table.scoremath tr.total td { border-top: 2px solid var(--ink); font-size: 10pt; }
  .cats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 5px; }
  .cat { border: 1px solid var(--line); border-radius: 4px; padding: 6px 9px 7px; break-inside: avoid; background: #fff; }
  .cat.fail { border-color: #e6b8c1; background: #fdf5f6; }
  .cat.pass { border-color: #c5e0c8; background: #f6fbf6; }
  .cat.none { background: var(--wash); border-style: dashed; }
  .cat-h { display: flex; align-items: baseline; gap: 6px; }
  .cat-h .gl { font-size: 10pt; font-weight: 800; }
  .cat-h .ti { font-weight: 750; font-size: 9pt; flex: 1 1 auto; }
  .cat-h .stt { font-size: 6.9pt; font-weight: 800; letter-spacing: .1em; text-transform: uppercase; }
  .cat-b { font-size: 7.2pt; color: var(--mute); line-height: 1.4; margin-top: 2px; }
  .cat-f { display: flex; align-items: center; gap: 3px; flex-wrap: wrap; margin-top: 5px; font-size: 7.4pt; color: var(--mute); }
  .cell { display: inline-flex; align-items: center; justify-content: center; width: 16px; height: 16px; border-radius: 3px;
          font-size: 7.6pt; font-weight: 800; line-height: 1; }

  /* ---- findings index ------------------------------------------------------- */
  .map { display: grid; grid-template-columns: repeat(2, 1fr); gap: 3px 22px; margin-bottom: 4px; }
  .map a { display: grid; grid-template-columns: 22px 1fr; gap: 6px; padding: 4px 0; border-bottom: 1px solid var(--line2); }
  .map .mn { font-weight: 800; color: var(--faint); font-size: 9pt; }
  .map .mt { font-weight: 700; font-size: 9pt; } .map .md { font-size: 7.8pt; color: var(--mute); display: block; font-weight: 400; }
  table.idx td.n { font-weight: 800; width: 28px; color: var(--ink2); white-space: nowrap; }
  table.idx td.t { font-weight: 650; }
  table.idx td.t .rid { display: block; font-family: var(--mono); font-size: 7.3pt; color: var(--mute); font-weight: 400; margin-top: 1px; }

  /* ---- finding page --------------------------------------------------------- */
  .f-band { display: flex; justify-content: space-between; align-items: center; padding: 9px 14px;
            border-radius: 6px 6px 0 0; }
  .f-lvl { display: flex; align-items: center; gap: 10px; font-size: 14pt; font-weight: 800; letter-spacing: .16em; text-transform: uppercase; }
  .f-lvl .gl { font-size: 15pt; }
  .f-lvl .meter i { width: 7px; height: 13px; }
  .f-of { font-size: 8pt; font-weight: 800; letter-spacing: .18em; text-transform: uppercase; text-align: right; }
  .f-of b { font-size: 15pt; letter-spacing: 0; margin-left: 4px; }
  .f-titlebox { border: 1px solid; border-top: 0; border-radius: 0 0 6px 6px; padding: 11px 14px 12px; }
  .f-title { font-size: 17pt; line-height: 1.18; font-weight: 800; letter-spacing: -.012em; overflow-wrap: anywhere; }
  .f-chips { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 9px; }
  .f-note { font-size: 8.4pt; color: var(--ink2); margin-top: 9px; padding: 6px 10px; background: #fff; border: 1px dashed #b8bec5; border-radius: 4px; }
  .f-sec { margin-top: 13px; }
  .f-sec > h4 { display: flex; align-items: center; gap: 8px; font-size: 7.6pt; font-weight: 800; letter-spacing: .16em;
                text-transform: uppercase; color: var(--ink); margin-bottom: 6px; break-after: avoid; page-break-after: avoid; }
  .f-sec > h4 .k { display: inline-flex; align-items: center; justify-content: center; min-width: 20px; height: 17px; padding: 0 4px;
                   background: var(--ink); color: #fff; border-radius: 3px; font-size: 7pt; letter-spacing: .04em; }
  .f-sec > h4::after { content: ""; flex: 1 1 auto; height: 1px; background: var(--line); }
  .f-sec p { max-width: 158mm; font-size: 9.6pt; line-height: 1.55; }
  ol.steps { list-style: none; padding: 0; counter-reset: st; position: relative; }
  ol.steps li { counter-increment: st; position: relative; padding: 0 0 8px 30px; font-size: 9.2pt; line-height: 1.5; max-width: 158mm; break-inside: avoid; }
  ol.steps li::before { content: counter(st); position: absolute; left: 0; top: 0; width: 20px; height: 20px; border-radius: 50%;
                        background: var(--ink); color: #fff; font-weight: 800; font-size: 8pt; text-align: center; line-height: 20px; }
  ol.steps li::after { content: ""; position: absolute; left: 9.5px; top: 22px; bottom: 2px; width: 1px; background: #b8bec5; }
  ol.steps li:last-child::after { display: none; }
  ol.steps li:last-child { padding-bottom: 0; }

  .code { border: 1px solid var(--line); border-radius: 5px; overflow: hidden; margin-bottom: 8px; break-inside: avoid; page-break-inside: avoid; }
  .code-head { background: #eef0f2; border-bottom: 1px solid var(--line); padding: 4px 9px; font-family: var(--mono);
               font-size: 7.4pt; color: var(--ink2); line-height: 1.45; display: flex; justify-content: space-between; gap: 10px; align-items: flex-start; }
  .code-head .ch-l { min-width: 0; flex: 1 1 auto; }
  .code-head .dexref { font-weight: 700; color: var(--ink); overflow-wrap: anywhere; }
  .code-head .srcref { color: var(--mute); overflow-wrap: anywhere; }
  table.code-body { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 7.6pt; line-height: 1.55; }
  table.code-body td { padding: 0 4px; vertical-align: top; }
  table.code-body .gut { width: 12px; color: ${S.critical.text}; font-weight: 800; text-align: center; }
  table.code-body .num { width: 46px; padding-right: 10px; text-align: right; color: #8a929b; }
  table.code-body .src { white-space: pre-wrap; overflow-wrap: anywhere; color: var(--ink2); }
  table.code-body tr.vuln { background: ${S.critical.tint}; box-shadow: inset 3px 0 0 ${S.critical.fill}; }
  table.code-body tr.vuln .src { color: var(--ink); font-weight: 700; }
  table.code-body tr.vuln .num { color: ${S.critical.text}; font-weight: 800; }
  table.ev td.ln { font-weight: 800; text-align: right; color: var(--ink2); width: 40px; }
  table.ev .snip { display: block; background: var(--wash); font-size: 7.4pt; line-height: 1.4; }
  .ev-more { font-size: 8pt; color: var(--mute); margin-top: 5px; max-width: 160mm; }
  .prov { flex: 0 0 auto; font-family: -apple-system, "Segoe UI", Roboto, Helvetica, sans-serif; font-size: 6.8pt; font-weight: 700; letter-spacing: .06em;
          text-transform: uppercase; color: var(--mute); border: 1px solid #b8bec5; border-radius: 3px; padding: 0 5px; background: #fff; white-space: nowrap; }
  .prov.mine { color: #4b3a8f; border-color: #a99bdc; background: #f3f0fc; }
  table.ev-run { width: 100%; border-collapse: collapse; }
  table.ev-run thead { display: table-header-group; }
  table.ev-run tr { break-inside: avoid; page-break-inside: avoid; }
  table.ev-run td { padding: 0; }
  table.ev-run thead tr.ctx th { text-align: left; font-size: 6.4pt; font-weight: 800; letter-spacing: .12em; text-transform: uppercase;
                                 color: var(--faint); padding: 0 0 3px; background: #fff; }
  table.ev td.lc { width: 44%; }
  table.ev td.lc .dx { display: block; margin-top: 2px; font-family: var(--mono); font-size: 7pt; color: #7a5200; overflow-wrap: anywhere; }
  table.ev td.pv { text-align: right; padding-right: 0; }

  .boxes { display: flex; gap: 10px; font-size: 8pt; white-space: nowrap; }
  .boxes span::before { content: "\\2610"; margin-right: 3px; font-size: 10pt; }

  /* ---- hotspots & secure ---------------------------------------------------- */
  .hs { border: 1px solid var(--line); border-left: 5px solid ${S.medium.fill}; border-radius: 0 5px 5px 0; padding: 9px 13px 10px;
        margin-bottom: 9px; background: #fff; }
  .hs.keep { break-inside: avoid; page-break-inside: avoid; }
  .hs-h, .hs-id { break-after: avoid; page-break-after: avoid; }
  .hs .hs-ev { margin-top: 6px; }
  .hs ol.hs-steps { margin: 2px 0 6px; } .hs ol.hs-steps li { font-size: 8.6pt; }
  .hs-h { display: flex; gap: 9px; align-items: baseline; }
  .hs-n { font-weight: 800; font-size: 8pt; letter-spacing: .1em; color: ${S.medium.text}; }
  .hs-t { font-weight: 750; font-size: 10.5pt; flex: 1 1 auto; }
  .hs-id { font-family: var(--mono); font-size: 7.4pt; color: var(--mute); margin: 1px 0 5px; }
  .hs p { font-size: 8.8pt; max-width: 160mm; margin-bottom: 4px; }
  .hs .ask { background: ${S.medium.tint}; border-left: 3px solid ${S.medium.fill}; padding: 5px 9px; border-radius: 0 3px 3px 0; }
  table.hs-locs { width: 100%; border-collapse: collapse; margin-top: 5px; }
  table.hs-locs td { padding: 2px 8px 2px 0; border-bottom: 1px solid var(--line2); vertical-align: top; font-size: 7.4pt; }
  table.hs-locs .lf { font-family: var(--mono); width: 38%; color: var(--ink2); overflow-wrap: anywhere; }
  table.hs-locs .lx { font-family: var(--mono); color: var(--mute); overflow-wrap: anywhere; }
  table.hs-locs tr { break-inside: avoid; }
  .hsi { column-count: 2; column-gap: 22px; }
  .hsi a { break-inside: avoid; display: grid; grid-template-columns: 26px 1fr auto; gap: 6px; padding: 3px 0; border-bottom: 1px solid var(--line2); font-size: 8.4pt; }
  .hsi .rn { font-weight: 800; color: ${S.medium.text}; font-size: 7.6pt; white-space: nowrap; } .hsi .rt { font-weight: 600; }
  .hsi .rh { color: var(--mute); font-size: 7.6pt; }
  table.ev thead tr.ctx th { border-bottom: 0; padding-bottom: 0; font-size: 6.4pt; letter-spacing: .12em; color: var(--faint); }
  ul.locs { list-style: none; padding: 0; margin-top: 5px; }
  ul.locs li { font-size: 8pt; padding: 2px 0; border-bottom: 1px solid var(--line2); }
  ul.locs .excerpt { display: block; color: var(--mute); font-family: var(--mono); font-size: 7.3pt; overflow-wrap: anywhere; }
  .secure { display: grid; grid-template-columns: repeat(2, 1fr); gap: 6px; }
  .sec-item { border: 1px solid #c5e0c8; background: #f6fbf6; border-radius: 4px; padding: 6px 10px 7px 30px; position: relative; break-inside: avoid; }
  .sec-item::before { content: "\\2713"; position: absolute; left: 10px; top: 5px; font-weight: 800; color: ${GOOD}; font-size: 10pt; }
  .sec-item .t { font-weight: 700; font-size: 8.8pt; } .sec-item .d { font-size: 7.8pt; color: var(--mute); line-height: 1.4; margin-top: 1px; }

  /* ---- ios dossier ---------------------------------------------------------- */
  .dist-hero { display: grid; grid-template-columns: auto 1fr; gap: 14px; align-items: center; border: 1px solid var(--line);
               border-radius: 6px; padding: 10px 14px; background: var(--wash); break-inside: avoid; }
  .dist-badge { font-size: 12pt; font-weight: 800; letter-spacing: .1em; text-transform: uppercase; padding: 8px 14px;
                border-radius: 4px; border: 2px solid; text-align: center; min-width: 38mm; }
  .verdict-line { font-size: 10pt; font-weight: 700; }
  .caps { display: flex; flex-wrap: wrap; gap: 5px; }
  .kv { width: 100%; border-collapse: collapse; font-size: 8.8pt; }
  .kv td { padding: 4px 8px 4px 0; border-bottom: 1px solid var(--line2); vertical-align: top; }
  .kv td:first-child { width: 42mm; color: var(--mute); font-size: 8pt; }
  .kv tr { break-inside: avoid; }
  .exp-banner { display: flex; align-items: center; gap: 10px; padding: 7px 12px; border-radius: 4px; font-weight: 800;
                font-size: 9pt; letter-spacing: .04em; margin-bottom: 8px; break-inside: avoid; }
  .exp-banner.bad { background: ${S.critical.fill}; color: #fff; }
  .exp-banner.ok { background: #eef8ef; color: ${GOOD}; border: 1px solid #cbe5ce; }
  .exp-banner.warn { background: ${S.medium.fill}; color: ${S.medium.ink}; }
  .mx td.gap, .mx th.gap { text-align: center; }
  .mx .who { font-weight: 700; } .mx .who small { display: block; font-weight: 400; color: var(--mute); font-family: var(--mono); font-size: 7pt; }
  .pips { display: inline-flex; gap: 2px; vertical-align: middle; }
  .pips i { width: 8px; height: 8px; border: 1px solid var(--ink2); border-radius: 50%; display: block; }
  .pips i.on { background: var(--ink2); }
  .weak-tag { font-size: 6.6pt; font-weight: 800; letter-spacing: .1em; text-transform: uppercase; color: #fff;
              background: ${S.critical.fill}; padding: 1px 5px; border-radius: 2px; margin-left: 5px; vertical-align: middle; }
  .libs { font-family: var(--mono); font-size: 7.4pt; line-height: 1.7; margin-top: 3px; }
  .libs .sep { color: var(--faint); }
  .swatch { display: inline-block; width: 9px; height: 9px; border-radius: 2px; vertical-align: -1px; margin-right: 4px; }

  ul.libcols { list-style: none; padding: 0; margin: 0; column-count: 2; column-gap: 16px; font-family: var(--mono); font-size: 7pt; line-height: 1.55; }
  ul.libcols li { break-inside: avoid; overflow-wrap: anywhere; color: var(--ink2); }
  ul.libcols .wk { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, sans-serif; font-size: 6.4pt; font-weight: 800; letter-spacing: .08em;
                   text-transform: uppercase; color: ${S.medium.text}; }

  /* ---- android dossier & reference tables ------------------------------------ */
  table.tbl tbody tr.grp td { background: var(--wash); border-bottom: 1px solid var(--line); padding: 4px 6px; font-size: 8pt; }
  table.tbl tbody tr.grp { break-after: avoid; page-break-after: avoid; }
  table.comp td code { font-size: .8em; }
  table.dom td { padding-right: 8px; }
  table.dom .mono { font-size: 8.4pt; }
  ul.urls { list-style: none; padding: 0; margin: 2px 0 0; font-family: var(--mono); font-size: 7.2pt; line-height: 1.5; color: var(--ink2); }
  ul.urls li { overflow-wrap: anywhere; }
  ul.urls .bad, .bad { color: ${S.critical.text}; font-weight: 700; }
  table.sec td code.snip { display: block; }

  /* ---- security controls ------------------------------------------------------ */
  .ctl-frame { border-left: 4px solid var(--ink2); background: var(--wash); border-radius: 0 5px 5px 0; padding: 7px 12px 8px; margin-bottom: 8px; }
  .ctl-frame p { font-size: 8.5pt; line-height: 1.45; max-width: 170mm; }
  .ctl-tiles .tile { padding: 5px 9px 6px; } .ctl-tiles .tile-n { font-size: 15pt; }
  .eff { display: inline-flex; align-items: center; gap: 5px; white-space: nowrap; }
  .eff b { font-size: 8pt; font-weight: 800; }
  .eff .meter i { width: 5px; height: 9px; }
  .eff-k { display: inline-flex; align-items: center; gap: 3px; white-space: nowrap; font-weight: 700; }
  .eff-k .meter i { width: 4px; height: 7px; }
  table.ctl-sum td { padding: 2.6px 6px 2.6px 0; vertical-align: middle; }
  table.ctl-sum td.t { font-weight: 650; }
  table.ctl-sum .chip { font-size: 6.9pt; }
  .ctl-weak { margin-top: 10px; break-inside: avoid; }
  ul.weaklist { list-style: none; padding: 0; margin: 6px 0 0; display: grid; grid-template-columns: repeat(2, 1fr); gap: 0 18px; }
  ul.weaklist li { border-top: 1px solid #f3d3bd; break-inside: avoid; }
  ul.weaklist a { display: flex; justify-content: space-between; align-items: center; gap: 8px; padding: 2.5px 0; font-size: 8.2pt; font-weight: 600; }

  .ctl { border: 1px solid var(--line); border-left: 5px solid ${GOOD}; border-radius: 0 5px 5px 0; padding: 8px 12px 9px; margin-bottom: 9px;
         background: #fff; break-inside: avoid; page-break-inside: avoid; }
  .ctl.st-missing { border-left-color: ${S.medium.fill}; }
  .ctl.st-unknown { border-left-color: #b8bec5; border-left-style: dashed; background: var(--wash); padding: 6px 12px 7px; }
  .ctl-h { display: flex; justify-content: space-between; align-items: flex-start; gap: 10px; break-after: avoid; page-break-after: avoid; }
  .ctl-g { font-size: 6.4pt; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; color: var(--faint); margin-bottom: 1px; }
  .ctl-t { font-size: 10.6pt; font-weight: 800; line-height: 1.25; letter-spacing: -.005em; }
  .ctl-m { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 4px; flex: 0 0 auto; max-width: 92mm; }
  .ctl-eff { display: flex; align-items: center; gap: 8px; margin-top: 3px; }
  .ctl-eff .lab { font-size: 6.8pt; font-weight: 800; letter-spacing: .1em; text-transform: uppercase; color: var(--mute); }
  .ctl-what { font-size: 8.8pt; line-height: 1.45; margin-top: 5px; max-width: 168mm; }
  .ctl-note { margin-top: 6px; }
  .ctl-note .callout { padding: 5px 10px 6px; } .ctl-note .callout p { max-width: none; }
  .ctl-cols { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-top: 7px; }
  .ctl h5 { font-size: 6.9pt; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; color: var(--ink2); margin: 0 0 3px;
            padding-bottom: 2px; border-bottom: 1px solid var(--line); display: flex; justify-content: space-between; gap: 8px; }
  .ctl h5 .cnt { letter-spacing: 0; text-transform: none; font-weight: 600; color: var(--mute); font-size: 7.4pt; }
  ul.ctl-ul { list-style: none; margin: 0; padding: 0; }
  ul.ctl-ul li { position: relative; padding: 0 0 3px 11px; font-size: 8.2pt; line-height: 1.4; overflow-wrap: anywhere; }
  ul.ctl-ul li::before { content: ""; position: absolute; left: 1px; top: .5em; width: 4px; height: 4px; background: var(--ink2); }
  .ctl.st-missing ul.ctl-ul li { font-size: 7.9pt; padding-bottom: 2px; }
  .ctl-ev { margin-top: 6px; }
  table.ctl-evt { width: 100%; border-collapse: collapse; }
  table.ctl-evt tr { break-inside: avoid; }
  table.ctl-evt td { padding: 1.5px 6px 1.5px 0; border-bottom: 1px solid var(--line2); vertical-align: top; font-size: 7.2pt; }
  table.ctl-evt code { word-break: normal; overflow-wrap: anywhere; }
  table.ctl-evt td.lc { width: 40%; } table.ctl-evt td.lc code { background: none; padding: 0; color: var(--ink2); font-weight: 600; }
  table.ctl-evt td.ex code { background: none; padding: 0; color: var(--mute); word-break: break-word; }

  /* ---- how to verify ---------------------------------------------------------- */
  .vf { margin: 0 0 9px; border: 1px solid var(--line); border-radius: 5px; padding: 6px 10px 5px; break-inside: avoid; page-break-inside: avoid; }
  .vf-h { display: flex; align-items: baseline; gap: 8px; margin-bottom: 4px; }
  .vf-h .ref { font-weight: 800; font-size: 7.6pt; letter-spacing: .08em; color: var(--ink2); border-bottom: 1px dotted var(--faint); }
  .vf-h .vt { font-weight: 700; font-size: 9pt; flex: 1 1 auto; }
  .vf-h .vl { font-family: var(--mono); font-size: 7pt; color: var(--mute); max-width: 68mm; text-align: right; overflow-wrap: anywhere; }
  .vc { margin: 0 0 4px; break-inside: avoid; }
  .vc .why { font-size: 7.6pt; color: var(--mute); margin: 0 0 1px; }
  pre.cmd { margin: 0; padding: 3px 7px; background: var(--wash); border-left: 3px solid var(--ink2); font-family: var(--mono); font-size: 7.2pt;
            line-height: 1.45; white-space: pre-wrap; overflow-wrap: anywhere; }

  /* ---- editions, themes, scope, roadmap, how to read --------------------------- */
  .classif-row { display: flex; gap: 8px; align-items: center; }
  .classif.ed { background: #fff; color: #0f141a; border-color: #fff; }
  .cover-edition { margin-top: 5mm; padding: 3mm 4mm; border-left: 4px solid #0f141a; background: var(--wash); font-size: 8.8pt; line-height: 1.45; }
  .map.tri a { padding: 1.5px 0 2px; }
  table.idx.tri td { padding-top: 2.6px; padding-bottom: 2.6px; line-height: 1.4; }
  table.idx.tri td.t .rid { font-size: 7pt; line-height: 1.3; }
  table.idx.tri .ow-n { line-height: 1.2; }
  .map.compact { gap: 0 22px; } .map.compact a { padding: 3px 0; } .map.compact .md { display: none; }
  .ed-note { margin: 0 0 10px; padding: 5px 10px; border-left: 4px solid var(--ink); background: var(--wash); font-size: 8.4pt; }
  .fref { font-family: var(--mono); font-size: .86em; font-weight: 700; color: var(--ink2); border: 1px solid #b8bec5; border-radius: 3px; padding: 0 4px; background: #fff; white-space: nowrap; }
  a.fref { border-bottom: 1px solid var(--ink2); }
  .chip.owasp { text-transform: none; letter-spacing: 0; font-weight: 700; font-size: 7.8pt; background: #eef2f8; border-color: #9fb0c8; color: #1f3a5f; }
  .ow-c { display: block; font-weight: 800; font-size: 8pt; color: #1f3a5f; line-height: 1.25; }
  .ow-n { display: block; font-size: 7.4pt; color: var(--mute); line-height: 1.25; }
  td.comp { font-family: var(--mono); font-size: 7.4pt; color: var(--ink2); overflow-wrap: anywhere; }
  .f-comp { display: flex; gap: 8px; align-items: baseline; margin-top: 6px; padding: 4px 8px; background: #fff; border: 1px solid var(--line); border-left: 3px solid var(--ink2); border-radius: 0 3px 3px 0; }
  .f-comp .lab { flex: 0 0 auto; font-size: 6.6pt; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; color: var(--mute); }
  .f-comp .val { font-family: var(--mono); font-size: 8pt; font-weight: 600; overflow-wrap: anywhere; min-width: 0; }

  .assess { border-left: 4px solid var(--ink); background: var(--wash); padding: 6px 11px 7px; margin-bottom: 4px; }
  #summary h3.sub { margin-top: 10px; margin-bottom: 4px; }
  #summary .secret-strip { margin-top: 6px; }
  #summary table.dist-rows td { line-height: 1.1; }
  #summary .verdict-panel { margin-bottom: 4px; }
  .assess p { font-size: 8.4pt; line-height: 1.4; max-width: none; }
  .assess .assess-b { margin-top: 4px; }
  ol.themes { list-style: none; margin: 0; padding: 0; }
  li.theme { display: grid; grid-template-columns: 22mm 1fr 44mm; gap: 8px; align-items: start; padding: 3px 0 4px; border-bottom: 1px solid var(--line2); break-inside: avoid; }
  .th-t { font-weight: 800; font-size: 8.8pt; line-height: 1.3; }
  .th-r { font-size: 7.8pt; color: var(--ink2); line-height: 1.32; margin-top: 1px; }
  .th-c { text-align: right; font-size: 7.4pt; color: var(--mute); line-height: 1.3; white-space: nowrap; }
  .th-c b { font-size: 10.5pt; color: var(--ink); } .th-c span { font-family: var(--mono); margin-left: 3px; }
  .th-f { margin-top: 2px; display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 3px; font-size: 7.2pt; align-items: center; }

  .two.eq { grid-template-columns: 1fr 1fr; gap: 18px; }
  ul.plain { list-style: none; margin: 0; padding: 0; }
  ul.plain.cols2 { column-count: 2; column-gap: 18px; } ul.plain.cols2 li { break-inside: avoid; }
  ul.plain li { position: relative; padding: 0 0 2.5px 11px; font-size: 8.4pt; line-height: 1.4; }
  ul.plain li::before { content: ""; position: absolute; left: 1px; top: .55em; width: 4px; height: 4px; background: var(--ink2); }
  .two.eq h3.sub { margin-top: 10px; }
  .two.eq p.small { line-height: 1.45; }

  table.rm { table-layout: fixed; }
  table.rm td.n { white-space: nowrap; }
  table.rm td.t .tt { display: block; font-weight: 650; margin-top: 2px; }
  table.rm td.comp { font-size: 7.2pt; }
  .rm-b { margin-top: 10px; }
  .rm-sec { margin-top: 16px; }
  .rm-h { display: flex; justify-content: space-between; align-items: center; gap: 10px; padding: 4px 0 4px; border-bottom: 2px solid var(--ink);
          break-after: avoid; page-break-after: avoid; }
  .rm-t { display: flex; align-items: center; gap: 6px; }
  .rm-w { font-size: 9.5pt; font-weight: 800; }
  .rm-c { font-size: 8pt; color: var(--mute); }
  .rm-none { margin: 4px 0 0; }
  .rm-b table.tbl th { border-bottom-width: 1px; }
  .rm-close { margin-top: 12px; padding: 6px 10px; border-left: 4px solid var(--ink); background: var(--wash); font-size: 8.6pt; line-height: 1.45; break-inside: avoid; break-before: avoid; page-break-before: avoid; }

  table.hr-sev td { padding: 4px 8px 4px 0; vertical-align: top; }
  table.hr-leg td { padding: 2.5px 6px 2.5px 0; vertical-align: top; }
  table.hr-leg td.lg { width: 14px; font-weight: 800; font-size: 10pt; line-height: 1.2; }
  table.hr-leg td.lw { width: 26mm; font-weight: 700; font-size: 8.4pt; }
  dl.defs { margin: 0; }
  dl.defs dt { font-weight: 800; font-size: 8.6pt; margin-top: 4px; }
  dl.defs dd { margin: 0; font-size: 8.2pt; line-height: 1.4; color: var(--ink2); }
  .gloss { display: grid; grid-template-columns: 1fr 1fr; gap: 3px 18px; } .gloss p { font-size: 8pt; line-height: 1.38; color: var(--ink2); break-inside: avoid; } .gloss b { color: var(--ink); }
  dl.defs.cols2 { display: grid; grid-template-columns: 1fr 1fr; gap: 0 18px; } dl.defs.cols2 > div { break-inside: avoid; margin-bottom: 3px; }
  table.owt td { padding: 1.5px 8px 1.5px 0; line-height: 1.36; }
  #howto .two, #howto table, #howto-2 .two, #howto-2 table { break-inside: avoid; }
  #howto-2 h3.sub:first-child { margin-top: 0; }
  #howto-2 h3.sub { margin-top: 11px; }

  /* ---- triage ---------------------------------------------------------------- */
  /* Status chips: glyph + word, so no state rests on colour. Excluded states are grey or green, active ones warm or violet. */
  .stc { display: inline-flex; align-items: center; gap: 4px; font-size: 7.4pt; font-weight: 700; border: 1px solid #b8bec5; color: var(--ink2);
         border-radius: 3px; padding: 1px 6px; line-height: 1.5; white-space: nowrap; background: #fff; vertical-align: middle; }
  .stc .g { font-size: .98em; }
  .stc.s-confirmed { color: #4b3a8f; border-color: #a99bdc; background: #f3f0fc; }
  .stc.s-false_positive { color: #3a424c; border-color: #aeb5bd; background: #eef0f2; }
  .stc.s-accepted_risk { color: ${S.medium.text}; border-color: ${S.medium.fill}; background: ${S.medium.tint}; }
  .stc.s-fixed { color: ${GOOD}; border-color: #9fd0a4; background: #eef8ef; }
  .stw { display: inline-flex; flex-direction: column; align-items: flex-start; gap: 2px; }
  .stx { font-size: 6.8pt; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; color: ${S.critical.text}; }
  table.tbl tr.xrow td { color: var(--mute); }
  table.tbl tr.xrow td.t, table.tbl tr.xrow td .lnk { font-weight: 500; }
  table.tbl tr.xrow .sevchip { opacity: .6; }
  .xm { color: var(--mute); }
  .catlist li.xm a { color: var(--mute); }
  .catlist li.xm .sevchip { opacity: .6; }
  .xt { font-size: 6.9pt; font-weight: 800; letter-spacing: .02em; color: var(--ink2); white-space: nowrap; }
  .xt.exp { color: ${S.critical.text}; }
  .cell.x { background: #fff; color: var(--faint); border: 1px dashed #8a929b; }

  .f-status { margin-top: 9px; padding: 7px 12px 7px; border: 1px solid #aeb5bd; border-left-width: 6px; border-radius: 0 5px 5px 0;
              background: #f1f3f5; break-inside: avoid; page-break-inside: avoid; }
  .f-status.s-confirmed { border-color: #a99bdc; background: #f3f0fc; }
  .f-status.s-accepted_risk { border-color: ${S.medium.fill}; background: ${S.medium.tint}; }
  .f-status.s-fixed { border-color: #9fd0a4; background: #eef8ef; }
  .f-status.lapsed { border-color: ${S.critical.fill}; background: ${S.critical.tint}; }
  .fs-h { display: flex; align-items: baseline; justify-content: space-between; flex-wrap: wrap; gap: 1px 14px; color: var(--ink); }
  .fs-t { display: inline-flex; align-items: baseline; gap: 7px; font-size: 9pt; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
  .f-status.s-confirmed .fs-t { color: #4b3a8f; } .f-status.s-fixed .fs-t { color: ${GOOD}; }
  .f-status.s-accepted_risk .fs-t { color: ${S.medium.text}; } .f-status.lapsed .fs-t { color: ${S.critical.text}; }
  .fs-r { margin-top: 3px; font-size: 9.2pt; line-height: 1.45; white-space: pre-line; overflow-wrap: anywhere; max-width: 165mm; }
  .fs-r .lab { display: inline-block; margin-right: 7px; font-size: 6.8pt; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; color: var(--mute); }
  .fs-m { display: inline-flex; flex-wrap: wrap; gap: 0 12px; font-size: 7.8pt; color: var(--ink2); font-weight: 500; }
  .boxes span.on { font-weight: 800; }
  .boxes span.on::before { content: "\\2611"; }

  .hs.xm { border-left-color: #b8bec5; }
  .hs.xm .hs-t { color: var(--ink2); }
  .hs-h .stc { align-self: center; }
  .hs-tri { margin: 2px 0 6px; padding: 5px 9px; background: #f1f3f5; border-left: 3px solid #aeb5bd; border-radius: 0 3px 3px 0; font-size: 8.2pt; line-height: 1.4; }
  .hs-tri.lapsed { background: ${S.critical.tint}; border-left-color: ${S.critical.fill}; }
  .hs-tri .eff { font-size: 6.9pt; font-weight: 800; letter-spacing: .1em; text-transform: uppercase; color: var(--mute); }
  .hs-tri.lapsed .eff { color: ${S.critical.text}; }
  .hs-tri .hs-tri-r { display: block; margin-top: 2px; white-space: pre-line; overflow-wrap: anywhere; max-width: none; }
  .hs-tri .hs-tri-m { display: block; margin-top: 1px; font-size: 7.4pt; color: var(--mute); }
  .hsi a.xm .rt { color: var(--ink2); font-weight: 500; }
  .hsi .rt .stc { margin-left: 4px; font-size: 6.8pt; padding: 0 5px; }

  .verdict-asis { margin-top: 7px; font-size: 8.6pt; color: var(--ink2); max-width: 96mm; line-height: 1.4; }
  .verdict-asis span { display: block; color: var(--mute); font-size: 8pt; margin-top: 1px; }
  .asis { margin-top: 8px; padding: 6px 10px; border-left: 4px solid #8a929b; background: var(--wash); font-size: 8.4pt; line-height: 1.45; break-inside: avoid; }
  .score2 { grid-template-columns: 1.9fr 1fr; gap: 14px; }
  .score2 table.scoremath td, .score2 table.scoremath th { padding: 3px 6px; }
  .score2 .asis { margin-top: 0; }
  #roadmap.tri .rm-none { display: none; }
  #roadmap.tri .rm-b { margin-top: 6px; }
  #roadmap.tri .rm-sec { margin-top: 8px; }
  #roadmap.tri table.rm td { padding-top: 2.8px; padding-bottom: 2.8px; }
  #roadmap.tri .rm-close { margin-top: 8px; }
  .rm-tri { margin-top: 10px; padding: 5px 10px; border-left: 4px solid #8a929b; background: var(--wash); font-size: 8.4pt; line-height: 1.4; break-inside: avoid; }

  table.tri-fx td, table.tri-fx th { padding: 4px 8px 4px 0; }
  table.tri-fx { max-width: 140mm; }
  table.tri-t { table-layout: fixed; }
  table.tri-t td.n { white-space: nowrap; }
  table.tri-t td.t .tt { display: block; font-weight: 650; }
  table.tri-t .rid { display: block; font-family: var(--mono); font-size: 7pt; color: var(--mute); font-weight: 400; margin-top: 1px; overflow-wrap: anywhere; }
  table.tri-t td.reason { white-space: pre-line; font-size: 8.4pt; line-height: 1.4; }
  table.tri-t .exp-flag { display: block; margin-top: 2px; font-size: 7pt; font-weight: 800; letter-spacing: .02em; color: ${S.critical.text}; }
  .tri-two { grid-template-columns: 1.25fr 1fr; gap: 16px; margin: 12px 0 0; }
  .tri-two table.tri-fx { max-width: none; }
  .tri-two .callout { padding: 6px 11px 7px; }
  .tri-dg code { word-break: normal; }
  .tri-two .callout p.small { margin: 0; line-height: 1.4; }
  .tri-dg { margin-top: 6px; line-height: 1.4; max-width: none; }
  .tri-fp { margin-top: 4px; display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
  .tri-fp .k { font-size: 6.9pt; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; color: var(--mute); }
  .tri-fp code { font-size: 11pt; font-weight: 700; letter-spacing: .04em; background: #fff; border: 1px solid var(--line); }
  .tleg { display: grid; grid-template-columns: 1fr 1fr; gap: 2px 18px; }
  .tleg p { font-size: 8pt; line-height: 1.38; color: var(--ink2); break-inside: avoid; padding: 1px 0 2px; border-bottom: 1px solid var(--line2); }
  .tleg p .stc { margin-right: 4px; }
  .tleg p.tn { color: var(--mute); font-size: 7.8pt; }

  /* ---- closing --------------------------------------------------------------- */
  .end { margin-top: 12px; break-inside: avoid; padding-top: 10px; border-top: 2px solid var(--ink); display: flex; justify-content: space-between;
         gap: 20px; font-size: 7.8pt; color: var(--mute); break-inside: avoid; }
  .end b { color: var(--ink); letter-spacing: .14em; text-transform: uppercase; }
  #scope .callout { padding: 6px 12px 7px; }
  #scope ul.plain li { font-size: 8.1pt; line-height: 1.35; padding-bottom: 1.5px; }
  #scope h3.sub { margin-top: 11px; }
  #scope .two.eq h3.sub { margin-top: 9px; }
  #scope .facts { gap: 6px 14px; }
  #scope.tri .facts { gap: 3px 14px; }
  #scope.tri h3.sub { margin-top: 7px; }
  #scope.tri .two.eq h3.sub { margin-top: 6px; }
  #scope.tri ul.plain li { padding-bottom: 0.5px; line-height: 1.32; }
  #scope.tri p.small { line-height: 1.38; }
  table.idx { table-layout: fixed; }
  .hosts { line-height: 2; }
  .ok { color: ${GOOD}; font-weight: 600; }
  `;
}
