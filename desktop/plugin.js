// Talaria — desktop half.
// Plain ESM, loaded uncompiled by Hermes Desktop. No JSX, no build step, no network.
// Contract per facts/DESKTOP-SDK.md: namespace import so an older Desktop that does not
// export an area yields `undefined` instead of failing the whole module.
import * as sdk from '@hermes/plugin-sdk'
import { jsx, jsxs } from 'react/jsx-runtime'

const { host, useValue } = sdk
const useQuery = sdk.useQuery
const relativeTime = sdk.relativeTime

// Every tool this package registers in plugin.yaml. Ownership is enforced by the host:
// a renderer only wins for tools whose backend owner package == this package.
const TOOLS = [
  'talaria_status',
  'talaria_setup',
  'talaria_actions',
  'talaria_build',
  'talaria_sign',
  'talaria_inspect',
  'talaria_library'
]

// ---------------------------------------------------------------- tokens
// Styling rule (DESKTOP-SDK Q5): theme variables only. The workspace look is
// square corners, 1px hairlines, mono for every figure. No hardcoded hex here,
// because the user's active theme owns the palette.
const C = {
  text: 'var(--ui-text-primary)',
  text2: 'var(--ui-text-secondary)',
  text3: 'var(--ui-text-tertiary)',
  rule: 'var(--ui-stroke-secondary)',
  well: 'var(--ui-bg-tertiary)',
  accent: 'var(--ui-accent)',
  ok: 'var(--ui-green)',
  warn: 'var(--ui-yellow)',
  bad: 'var(--ui-red)',
  info: 'var(--ui-cyan)'
}

const MONO = 'var(--font-mono)'
const SANS = 'var(--font-sans)'

// ---------------------------------------------------------------- brand (da/BRAND.md)
// The panel carries the talaria field, the wordmark and one seal. Values are the
// brand sheet's tokens: field 2843F1, navy 000F3B, ink D5DAF7, ochre EDB030.
// They are scoped to the masthead only, so the workspace theme still owns every
// other surface (DESKTOP-SDK Q5: no hardcoded hex outside this block).
const BRAND = {
  field: '#2843F1',
  navy: '#000F3B',
  ink: '#D5DAF7',
  inkSoft: '#BAC5F1',
  ochre: '#EDB030'
}
const DISPLAY = '"Cinzel", "Playfair Display", Georgia, serif'
const SERIF = '"Cormorant Garamond", Georgia, serif'

// Masthead: navy plate, TALARIA in Cinzel tracked, one ochre seal, tagline in Cormorant.
function Masthead({ signedCount }) {
  return jsxs('div', {
    'data-talaria': 'masthead',
    style: {
      background: BRAND.navy,
      color: BRAND.ink,
      padding: '18px 20px 16px',
      display: 'flex',
      alignItems: 'flex-end',
      justifyContent: 'space-between',
      gap: 12,
      flexWrap: 'wrap',
      borderBottom: '2px solid ' + BRAND.field
    },
    children: [
      jsxs('div', { style: { display: 'flex', flexDirection: 'column', gap: 6 }, children: [
        jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: 10 }, children: [
          jsx('span', {
            style: { fontFamily: DISPLAY, fontWeight: 600, fontSize: 26, letterSpacing: '0.26em', textTransform: 'uppercase', lineHeight: 1 },
            children: 'Talaria'
          }),
          jsx('span', {
            title: 'signed artifacts',
            style: { width: 9, height: 9, background: signedCount > 0 ? BRAND.ochre : BRAND.inkSoft, display: 'block', opacity: signedCount > 0 ? 1 : 0.45 }
          })
        ] }),
        jsx('span', {
          style: { fontFamily: SERIF, fontSize: 14, color: BRAND.inkSoft, letterSpacing: '0.01em' },
          children: 'Apple Shortcuts for Hermes. Built, signed and delivered with no Mac.'
        })
      ] }),
      jsx('span', {
        style: { fontFamily: MONO, fontSize: 10, letterSpacing: '0.18em', textTransform: 'uppercase', color: BRAND.inkSoft },
        children: 'shortcut bench'
      })
    ]
  })
}
const label = { fontFamily: MONO, fontSize: 10, letterSpacing: '0.09em', textTransform: 'uppercase', color: C.text3 }
const figure = { fontFamily: MONO, fontSize: 12, fontVariantNumeric: 'tabular-nums', color: C.text }
const hair = { height: 1, background: C.rule, border: 0, margin: 0 }
const rowStyle = { display: 'flex', alignItems: 'baseline', gap: 10, padding: '4px 0', minWidth: 0 }
const rowLabel = { ...label, flex: '0 0 74px' }
const rowValue = { ...figure, flex: '1 1 auto', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }

// ---------------------------------------------------------------- helpers

// Live, `result` is the JSON string the tool returned. A reopened chat can hand it
// over already parsed. Anything else is not ours to draw.
function parseResult(result) {
  if (result && typeof result === 'object') return result
  if (typeof result !== 'string') return null
  try {
    const parsed = JSON.parse(result)
    return parsed && typeof parsed === 'object' ? parsed : null
  } catch {
    return null
  }
}

function str(value) {
  return typeof value === 'string' ? value : ''
}

function shortHash(hash) {
  const h = str(hash).trim()
  return /^[0-9a-f]{64}$/i.test(h) ? h.slice(0, 12) : h
}

function listOf(value) {
  return Array.isArray(value) ? value : []
}

function countLabel(n, singular, plural) {
  return n + ' ' + (n === 1 ? singular : plural || singular + 's')
}

function oneLine(text) {
  return str(text).replace(/\s+/g, ' ').trim()
}

// host.composer.submit exists on current hosts; older ones pass sessionId undefined.
function followUp(os, sessionId, text) {
  const submit = host && host.composer && host.composer.submit
  if (typeof submit !== 'function') return false
  const sent = submit(sessionId || null, text)
  if (!sent && host.notify) {
    host.notify({ kind: 'warning', message: 'Open that chat to send the follow-up' })
  }
  return sent
}

function copy(os, text) {
  if (!os || typeof os.writeClipboard !== 'function' || !text) return
  os.writeClipboard(text)
}

// ---------------------------------------------------------------- state model
// One normalisation pass per result, so the card body stays dumb. Field names are
// Talaria's own (we define them in the Python tools), not SDK names.
function readTool(toolName, data) {
  const verdictRaw = oneLine(data.verdict || data.audit?.verdict).toLowerCase()
  const verdict =
    verdictRaw === 'pass' || verdictRaw === 'ok' || verdictRaw === 'no-findings' ? 'pass'
      : verdictRaw === 'warn' || verdictRaw === 'warning' || verdictRaw === 'review' ? 'warn'
        : verdictRaw === 'fail' || verdictRaw === 'error' || verdictRaw === 'dangerous' ? 'fail'
          : ''

  const signed = data.signed === true || data.signState === 'signed' || data.sign === 'signed'
  const signedKnown = data.signed === true || data.signed === false || typeof data.signState === 'string'

  const actions = listOf(data.actions)
  const findings = listOf(data.findings || data.audit?.findings)
  const diagnostics = listOf(data.diagnostics)

  return {
    toolName,
    // primary badge: what this artifact *is* after the call
    state:
      signed ? { word: 'signed', tone: C.accent }
        : verdict === 'fail' ? { word: 'audit fail', tone: C.bad }
          : verdict === 'warn' ? { word: 'audit warn', tone: C.warn }
            : verdict === 'pass' ? { word: 'audit pass', tone: C.ok }
              : toolName === 'talaria_build' ? { word: 'built · unsigned', tone: C.warn }
                : signedKnown && !signed ? { word: 'unsigned', tone: C.text3 }
                  : { word: 'ok', tone: C.info },
    title: oneLine(data.name || data.title || data.label),
    hash: str(data.sha256 || data.hash),
    actions,
    findings,
    diagnostics,
    path: oneLine(data.path || data.outputPath),
    artifactId: oneLine(data.artifactId || data.id),
    issuer: oneLine(data.certIssuer || data.issuer || data.aea?.issuer),
    when: str(data.builtAt || data.signedAt || data.at || data.timestamp),
    count: typeof data.count === 'number' ? data.count : actions.length,
    compiler: data.compiler || null,
    signer: data.signer || null,
    sandbox: data.sandbox || null,
    items: listOf(data.items),
    error: oneLine(data.error || data.message)
  }
}

// ---------------------------------------------------------------- atoms

function Badge({ word, tone }) {
  return jsxs('span', {
    style: {
      display: 'inline-flex',
      alignItems: 'center',
      gap: 6,
      fontFamily: MONO,
      fontSize: 10,
      letterSpacing: '0.08em',
      textTransform: 'uppercase',
      color: tone,
      border: '1px solid ' + tone,
      borderRadius: 2,
      padding: '1px 6px',
      whiteSpace: 'nowrap',
      flex: '0 0 auto'
    },
    children: [jsx('span', { style: { width: 4, height: 4, background: tone, display: 'block' } }), word]
  })
}

function Row({ k, v, mono = true, tone }) {
  if (!v) return null
  return jsxs('div', {
    style: rowStyle,
    children: [
      jsx('span', { style: rowLabel, children: k }),
      jsx('span', { style: { ...rowValue, fontFamily: mono ? MONO : SANS, color: tone || C.text }, children: v })
    ]
  })
}

function Ghost({ children, onClick, title }) {
  return jsx('button', {
    type: 'button',
    title: title,
    onClick: onClick,
    style: {
      fontFamily: MONO,
      fontSize: 10,
      letterSpacing: '0.08em',
      textTransform: 'uppercase',
      color: C.text2,
      background: 'transparent',
      border: '1px solid ' + C.rule,
      borderRadius: 0,
      padding: '4px 8px',
      cursor: 'pointer'
    },
    children: children
  })
}

// ---------------------------------------------------------------- tool card

// props from the host: file, toolName, toolCallId, args, result, sessionId, fallback, os
function ToolCard({ toolName, result, sessionId, fallback, os }) {
  const data = parseResult(result)
  if (!data) return fallback // never draw a card we cannot read: keep the built-in file row
  const m = readTool(str(toolName), data)

  const viewport = useValue(host.state.viewport)
  const narrow = !!(viewport && viewport.narrow)

  const firstAction = m.actions[0]
  const firstActionName = firstAction ? oneLine(firstAction.name || firstAction.identifier) : ''

  const detail = m.error
    ? m.error
    : m.findings.length
      ? countLabel(m.findings.length, 'finding') + ' · ' + oneLine(m.findings[0].severity || 'info') + ' ' + oneLine(m.findings[0].action || m.findings[0].detail)
      : m.actions.length
        ? [countLabel(m.actions.length, 'action'), firstActionName]
          .filter(Boolean)
          .join(' · ') + (m.actions.length > 1 ? ' +' + (m.actions.length - 1) : '')
        : m.items.length
          ? countLabel(m.items.length, 'artifact')
          : ''

  const nudge = m.artifactId
    ? 'talaria_inspect ' + m.artifactId
    : m.path
      ? 'talaria_inspect ' + m.path
      : 'talaria_status'

  return jsxs('div', {
    'data-talaria': 'card',
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: 8,
      padding: '10px 12px',
      border: '1px solid ' + C.rule,
      borderLeft: '2px solid ' + (m.state.tone === C.text3 ? C.rule : m.state.tone),
      borderRadius: 0,
      background: C.well,
      fontFamily: SANS,
      fontSize: 12,
      color: C.text,
      minWidth: 0
    },
    children: [
      jsxs('div', {
        style: {
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 8,
          flexWrap: narrow ? 'wrap' : 'nowrap'
        },
        children: [
          jsxs('div', {
            style: { display: 'flex', alignItems: 'baseline', gap: 8, minWidth: 0 },
            children: [
              jsx('span', {
                style: {
                  fontFamily: MONO,
                  fontSize: 10,
                  letterSpacing: '0.14em',
                  textTransform: 'uppercase',
                  color: C.text3
                },
                children: 'talaria'
              }),
              jsx('span', {
                style: {
                  fontFamily: MONO,
                  fontSize: 11,
                  color: C.text2,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap'
                },
                children: m.toolName
              })
            ]
          }),
          jsx(Badge, { word: m.state.word, tone: m.state.tone })
        ]
      }),
      m.title ? jsx('div', { style: { fontFamily: SANS, fontSize: 13, color: C.text }, children: m.title }) : null,
      jsx('hr', { style: hair }),
      jsxs('div', {
        style: {
          display: 'grid',
          gridTemplateColumns: narrow ? '1fr' : '1fr 1fr',
          columnGap: 18,
          rowGap: 0
        },
        children: [
          jsx(Row, { k: 'sha256', v: m.hash ? shortHash(m.hash) : '', tone: C.text2 }),
          jsx(Row, { k: 'actions', v: m.actions.length ? String(m.actions.length) : '' }),
          jsx(Row, { k: 'signed', v: m.issuer ? 'yes · ' + m.issuer : m.state.word === 'signed' ? 'yes' : m.state.word === 'unsigned' || m.state.word === 'built · unsigned' ? 'no' : '' }),
          jsx(Row, { k: 'built', v: m.when ? safeTime(m.when) : '' }),
          jsx(Row, { k: 'findings', v: m.findings.length ? String(m.findings.length) : '', tone: m.findings.length ? C.warn : C.text }),
          jsx(Row, { k: 'detail', v: detail, tone: m.error ? C.bad : C.text2 })
        ]
      }),
      diagnosticsBlock(m),
      jsxs('div', {
        style: { display: 'flex', gap: 6, flexWrap: 'wrap', paddingTop: 2 },
        children: [
          m.hash ? jsx(Ghost, { onClick: () => copy(os, m.hash), children: 'copy sha256' }) : null,
          jsx(Ghost, {
            onClick: () => followUp(os, sessionId, nudge),
            children: m.artifactId || m.path ? 'inspect' : 'status'
          })
        ]
      })
    ]
  })
}

// sdk.relativeTime takes epoch milliseconds and throws on anything that is not a finite
// number. The backend sends ISO strings ("2026-11-11T14:12:36+0100"), so convert first and
// fall back to the raw value instead of taking the whole page down.
function toMillis(value) {
  if (typeof value === 'number') return value < 1e12 ? value * 1000 : value
  if (typeof value !== 'string' || !value) return NaN
  return Date.parse(value.replace(/([+-]\d{2})(\d{2})$/, '$1:$2'))
}

function safeTime(value) {
  const ms = toMillis(value)
  if (!Number.isFinite(ms) || typeof relativeTime !== 'function') return str(value)
  try {
    return relativeTime(ms) || str(value)
  } catch (_) {
    return str(value)
  }
}

function diagnosticsBlock(m) {
  if (!m.diagnostics.length) return null
  const first = m.diagnostics[0]
  const text = typeof first === 'string' ? first : first.message || first.detail || ''
  return jsxs('div', {
    style: {
      fontFamily: MONO,
      fontSize: 11,
      color: C.warn,
      borderLeft: '1px solid ' + C.rule,
      paddingLeft: 8,
      overflow: 'hidden',
      textOverflow: 'ellipsis',
      whiteSpace: 'nowrap'
    },
    children: ['diag: ', oneLine(text)]
  })
}

// ---------------------------------------------------------------- older Desktop
// Older Desktops do not export TOOL_MEDIA_RENDERER_AREA. The documented old path is a
// model-emitted directive. Attributes are untrusted model output: validate before use.
function DirectiveCard({ attrs }) {
  const name = oneLine(attrs && attrs.name)
  const state = oneLine(attrs && attrs.state).toLowerCase()
  const hash = oneLine(attrs && attrs.sha256)
  if (!name && !hash) return null
  const tone = state === 'signed' ? C.accent : state === 'fail' ? C.bad : C.warn
  return jsxs('div', {
    'data-talaria': 'directive',
    style: {
      border: '1px solid ' + C.rule,
      borderLeft: '2px solid ' + tone,
      padding: '8px 12px',
      background: C.well,
      fontFamily: SANS,
      fontSize: 12,
      color: C.text
    },
    children: [
      jsxs('div', { style: { display: 'flex', gap: 8, alignItems: 'baseline' }, children: [
        jsx('span', { style: label, children: 'talaria' }),
        jsx('span', { style: figure, children: name || 'artifact' }),
        jsx(Badge, { word: state || 'built', tone: tone })
      ] }),
      hash ? jsx('div', { style: { ...rowValue, color: C.text3, paddingTop: 4 }, children: shortHash(hash) }) : null
    ]
  })
}

// ---------------------------------------------------------------- library page
// Data path: ctx.rest('/items') -> GET /api/plugins/talaria-shortcuts/items (plugin_api.py).
// Paired with the shared QueryClient via useQuery, never a hand-rolled fetch loop.
function LibraryPage({ rest }) {
  const query = useQuery({
    queryKey: ['talaria', 'items'],
    queryFn: () => rest('/items'),
    staleTime: 5000
  })
  const data = query && query.data
  const items = Array.isArray(data && data.items) ? data.items : []
  const loading = !!(query && query.isLoading)
  const error = query && query.error
  const viewport = useValue(host.state.viewport)
  const narrow = !!(viewport && viewport.narrow)

  return jsxs('div', {
    'data-talaria': 'bench',
    style: {
      padding: narrow ? 14 : 20,
      display: 'flex',
      flexDirection: 'column',
      gap: 12,
      fontFamily: SANS,
      color: C.text,
      minHeight: '100%',
      boxSizing: 'border-box'
    },
    children: [
      jsx('div', {
        style: { margin: narrow ? '-14px -14px 0' : '-20px -20px 0' },
        children: jsx(Masthead, { signedCount: items.filter(it => it && it.signed === true).length })
      }),
      jsxs('header', {
        style: { display: 'flex', flexDirection: 'column', gap: 4, paddingBottom: 10, borderBottom: '1px solid ' + C.rule },
        children: [
          jsxs('div', { style: { display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }, children: [
            jsx('h1', {
              style: { margin: 0, fontFamily: MONO, fontSize: narrow ? 15 : 17, letterSpacing: '0.16em', textTransform: 'uppercase', color: C.text, fontWeight: 600 },
              children: 'Shortcut Bench'
            }),
            jsx('span', { style: { ...label, letterSpacing: '0.06em' }, children: 'talaria · artifacts on the backend' })
          ] }),
          jsx('p', {
            style: { margin: 0, fontSize: 12, color: C.text3, maxWidth: 640 },
            children: 'Compiled shortcuts, their action count, signing state and content hash as written by talaria_build. Nothing here leaves the machine unless you call talaria_sign.'
          })
        ]
      }),
      jsxs('div', {
        style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' },
        children: [
          jsxs('div', { style: { display: 'flex', gap: 14, alignItems: 'baseline', flexWrap: 'wrap' }, children: [
            jsx('span', { style: label, children: 'items' }),
            jsx('span', { style: { ...figure, fontSize: 13 }, children: loading ? '—' : String(items.length) }),
            jsx('span', { style: label, children: 'signed' }),
            jsx('span', {
              style: { ...figure, fontSize: 13, color: C.accent },
              children: loading ? '—' : String(items.filter(it => it && it.signed === true).length)
            })
          ] }),
          jsx(Ghost, {
            onClick: () => { if (query && typeof query.refetch === 'function') query.refetch() },
            title: 'Re-read /api/plugins/talaria-shortcuts/items',
            children: 'refresh'
          })
        ]
      }),
      jsx('hr', { style: hair }),
      error
        ? EmptyState('backend not reachable', 'the gateway mounts /api/plugins/talaria-shortcuts/ only while the plugin is enabled — enable it, then restart the gateway', C.bad)
        : loading
          ? jsx('div', { style: { ...figure, color: C.text3, padding: '14px 0' }, children: 'reading library…' })
          : items.length === 0
            ? EmptyState('no builds yet', 'talaria_build writes into the library folder; the bench lists it the next time it is read', C.text2)
            : jsxs('div', { style: { display: 'flex', flexDirection: 'column' }, children: [
              jsxs('div', {
                style: {
                  display: narrow ? 'none' : 'grid',
                  gridTemplateColumns: 'minmax(0,2.2fr) 70px 92px 140px 116px',
                  columnGap: 12,
                  padding: '0 0 6px',
                  borderBottom: '1px solid ' + C.rule
                },
                children: ['name', 'actions', 'signed', 'sha256', 'built'].map(h => jsx('span', { style: label, children: h }, h))
              }),
              ...items.map((item, index) => LibraryRow({ item, index, narrow }))
            ] })
    ]
  })
}

function EmptyState(headline, body, tone) {
  return jsxs('div', {
    'data-talaria': 'empty',
    style: {
      border: '1px dashed ' + C.rule,
      padding: '18px 16px',
      display: 'flex',
      flexDirection: 'column',
      gap: 6,
      background: 'transparent'
    },
    children: [
      jsx('span', { style: { fontFamily: MONO, fontSize: 12, letterSpacing: '0.1em', textTransform: 'uppercase', color: tone }, children: headline }),
      jsx('span', { style: { fontFamily: SANS, fontSize: 12, color: C.text3, maxWidth: 560, lineHeight: 1.5 }, children: body })
    ]
  })
}

function LibraryRow({ item, index, narrow }) {
  const name = oneLine(item && item.name) || 'untitled'
  const signed = !!(item && item.signed === true)
  const actions = item && (typeof item.actions === 'number' ? item.actions : listOf(item.actions).length) || 0
  const hash = shortHash(item && (item.sha256 || item.hash))
  const when = item && (item.builtAt || item.at || item.mtime) ? safeTime(item.builtAt || item.at || item.mtime) : ''

  const cells = [
    jsx('span', { style: { ...figure, fontSize: 12.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }, children: name }, 'n'),
    jsx('span', { style: { ...figure, color: C.text2 }, children: String(actions) }, 'a'),
    jsx('span', {
      style: { fontFamily: MONO, fontSize: 10, letterSpacing: '0.08em', textTransform: 'uppercase', color: signed ? C.accent : C.text3 },
      children: signed ? 'signed' : 'unsigned'
    }, 's'),
    jsx('span', { style: { ...figure, color: C.text3, overflow: 'hidden', textOverflow: 'ellipsis' }, children: hash || '—' }, 'h'),
    jsx('span', { style: { ...figure, color: C.text3 }, children: when || '—' }, 'w')
  ]

  if (narrow) {
    return jsxs('div', {
      style: { display: 'flex', flexDirection: 'column', gap: 3, padding: '9px 0', borderBottom: '1px solid ' + C.rule },
      children: [
        jsxs('div', { style: { display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'baseline' }, children: [cells[0], cells[2]] }),
        jsxs('div', { style: { display: 'flex', gap: 12, alignItems: 'baseline' }, children: [
          jsx('span', { style: { ...label, flex: '0 0 auto' }, children: countLabel(actions, 'action') }),
          cells[3],
          cells[4]
        ] })
      ]
    }, name + ':' + index)
  }

  return jsx('div', {
    style: {
      display: 'grid',
      gridTemplateColumns: 'minmax(0,2.2fr) 70px 92px 140px 116px',
      columnGap: 12,
      alignItems: 'baseline',
      padding: '8px 0',
      borderBottom: '1px solid ' + C.rule
    },
    children: cells
  }, name + ':' + index)
}

// ---------------------------------------------------------------- registration

function registerToolCard(ctx) {
  // New Desktop: real tool media slot. Older Desktop: no such export -> directive path.
  if (typeof sdk.TOOL_MEDIA_RENDERER_AREA === 'string') {
    ctx.register({
      id: 'tool-card',
      area: sdk.TOOL_MEDIA_RENDERER_AREA, // 'transcript.toolMedia'
      data: { tools: TOOLS, render: props => jsx(ToolCard, { ...props, os: ctx.os }) }
    })
    return
  }
  // TODO(older Desktop): the directive below only renders when a skill line tells the
  // model to emit it. Which skill writes that line is not wired yet (see REPORT UNKNOWN).
  if (typeof sdk.TRANSCRIPT_DIRECTIVE_AREA === 'string') {
    ctx.register({
      id: 'directive-card',
      area: sdk.TRANSCRIPT_DIRECTIVE_AREA, // 'transcript.directives'
      data: { name: 'talaria-card', render: props => jsx(DirectiveCard, props) }
    })
  }
}

function registerLibrary(ctx) {
  // Both constants are exported on every Desktop that has pages at all; guard anyway so a
  // stripped SDK never throws during register.
  if (typeof sdk.ROUTES_AREA !== 'string' || typeof sdk.SIDEBAR_NAV_AREA !== 'string') return
  ctx.registerMany([
    { id: 'bench-page', area: sdk.ROUTES_AREA, data: { path: '/talaria' }, render: () => jsx(LibraryPage, { rest: ctx.rest }) },
    { id: 'bench-nav', area: sdk.SIDEBAR_NAV_AREA, data: { path: '/talaria', label: 'Shortcut Bench', codicon: 'terminal' } }
  ])
}

export default {
  id: 'talaria-shortcuts', // must equal the package folder and the manifest name
  name: 'Talaria',
  register(ctx) {
    registerToolCard(ctx)
    registerLibrary(ctx)
  }
}
