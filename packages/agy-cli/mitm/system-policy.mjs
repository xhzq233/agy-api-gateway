import {createHash} from 'node:crypto'

// Identity-only excerpt observed in official AGY1.5.9's native request. Do not
// import native tool/sandbox instructions or its USER_REQUEST wrapper claim.
export const AGY_IDENTITY = 'You are Antigravity, a powerful agentic AI assistant designed by the Google Deepmind team.\nYou are working with a USER to solve their task.'
// Exact security instruction from the captured AGY 1.5.9 native system prompt.
export const AGY_NATIVE_SECURITY = 'Never defeat or bypass an access control, permission check, credential requirement, network/proxy restriction, or sandbox/environment boundary - including writing to the state or processes such a check reads, spoofing identity, intercepting the check, probing undocumented local/host services, or modifying host, harness, or test infrastructure outside your task scope. Use documented, sanctioned paths only; if none of them work, you are blocked - report the error and stop.'
const SDK_BILLING = /^x\s*[-_]\s*(?:anthropic|antigravity|anti\s+gravity)\s*[-_]\s*billing\s*[-_]\s*header\s*:/i
const DSH_IDENTITY = /^you are an ai agent powered by deepseek harness\.$/i
const DSH_MODEL_IDENTITY = /^you are a coding agent powered by the [a-z0-9][a-z0-9._/-]* model\.$/i
export const isDshUserAgent = value => typeof value === 'string' && /^deepseek-harness\/[a-z0-9][a-z0-9.+_-]*(?:\s|$)/i.test(value)
function isSupportedClientIdentity(line) {
  if (DSH_IDENTITY.test(line)) return true
  if (/^you are a claude agent, built on anthropic's claude agent sdk\.$/i.test(line)) return true
  return /^you(?:\s+are|'re)\s+/i.test(line) && /\bclaude\s+code\b/i.test(line) && /\bofficial\b/i.test(line) && /\bcli\b/i.test(line)
}
export function assertSupportedClient(body, userAgent) {
  if (isDshUserAgent(userAgent)) return
  const fields=[body?.system,...(Array.isArray(body?.messages)?body.messages.filter(m=>m?.role==='system').map(m=>m.content):[])]
  const texts=fields.flatMap(field=>typeof field==='string'?[field]:Array.isArray(field)?field.filter(b=>b?.type==='text'&&typeof b.text==='string').map(b=>b.text):[])
  if(!texts.some(text=>text.split(/\r?\n|\r/).some(line=>isSupportedClientIdentity(line.trim())))) {
    throw Object.assign(new Error('Unsupported client identity: a recognized Claude Code or DeepSeek Harness system identity is required'),{status:400})
  }
}
function isClientIdentity(line) {
  if (DSH_IDENTITY.test(line)) return true
  if(!/^you(?:\s+are|'re)\s+/i.test(line)) return false
  const client='(?:claude|antigravity|anti\\s+gravity)'
  const code=new RegExp(`\\b${client}\\s+code\\b`,'i').test(line) && /\bofficial\b/i.test(line) && /\bcli\b/i.test(line)
  const agent=new RegExp(`\\b${client}\\s+agent\\b`,'i').test(line) && /\bagent\s+sdk\b/i.test(line)
  return code || agent
}
export function rewriteSystemIdentity(text, {dsh=false}={}) {
  // Match client identity and billing lines, preserving surrounding rules.
  return text.split(/(\r\n|\n|\r)/).map(line=>{
    const trimmed=line.trim()
    if(SDK_BILLING.test(trimmed))return ''
    if(isClientIdentity(trimmed) || (dsh && DSH_MODEL_IDENTITY.test(trimmed))) {
      const indent=line.match(/^\s*/)[0],trailing=line.match(/\s*$/)[0]
      return indent+AGY_IDENTITY+trailing
    }
    return line.replace(/claude(?!\.md\b)|anthropic/gi,'Antigravity')
  }).join('')
}

// Remove only the DSH source and Web GUI guidance paragraphs, including their
// older value-bearing versions. Other system instructions remain intact.
export function removeDshProductNotes(text) {
  return text.split(/(\r?\n\s*\r?\n)/).map(part => {
    const p = part.trim()
    if (/^The (?:DeepSeek Harness implementation checkout is at |runtime context names the DeepSeek Harness implementation checkout\.)/i.test(p)) return ''
    if (/^You are interacting with the user through the DeepSeek Harness Web GUI (?:at |whose URL the runtime context names\.)/i.test(p)) return ''
    return part
  }).join('')
}

// Preserve paths, URLs and filenames in tool descriptions: they may be
// executable instructions, unlike product names in ordinary prose.
export function rewriteToolDescription(text) {
  return text.split(/(\s+)/).map(token=>{
    if (/[\\/]/.test(token) || /(?:^|[(`'"\[])\.(?:claude|anthropic)\b/i.test(token) || /\b(?:claude|anthropic)\.[a-z0-9]{2,}\b/i.test(token)) return token
    return token.replace(/\b(?:claude|anthropic)\b/gi,'Antigravity')
  }).join('')
}

// CC describes its own products, model catalog and fast mode in environment
// bullets. Remove only matching complete bullets; keep adjacent instructions.
export function removeClientProductNotes(text) {
  const lines=text.split(/(?<=\n)/)
  const result=[]
  for(let i=0;i<lines.length;) {
    if(!/^\s*[-*]\s+\S/.test(lines[i])) {result.push(lines[i++]);continue}
    const start=i++
    while(i<lines.length && /^\s+\S/.test(lines[i]) && !/^\s*[-*]\s+\S/.test(lines[i])) i++
    const bullet=lines.slice(start,i).join(''), normalized=bullet.toLowerCase().replace(/\s+/g,' ')
    const product=/\b(?:claude|antigravity|anti gravity)\s+code\b/.test(normalized) && /\bcli\b/.test(normalized) && /desktop app/.test(normalized) && /\bide\b/.test(normalized)
    const fast=/\bfast mode\b/.test(normalized) && /\/fast\b/.test(normalized) && /\b(?:claude|antigravity|anti gravity)\b/.test(normalized)
    const models=/\bmodel ids\b/.test(normalized) && /\b(?:claude|antigravity|anti gravity)\b/.test(normalized) && /\b(?:opus|sonnet)\b/.test(normalized)
    if(!product && !fast && !models) result.push(bullet)
  }
  return result.join('')
}

// Evidence fingerprint for the paragraph replaced by the default policy.
export const KNOWN_REFUSED_SYSTEM_HASHES = new Set([
  '10591efdcea75a1645b7f19037b36c979849ad4ec27f11ce87a8393423597b44',
])
export const systemFingerprint = text => createHash('sha256').update(text.trim().replace(/\s+/g,' ')).digest('hex')
export function removeKnownRefusedParagraphs(text) {
  return text.split(/(\r?\n\s*\r?\n)/).map(p => {
    const trimmed = p.trim()
    if (/^#\s*(?:Harness|System)\b/i.test(trimmed)) return ''
    return p
  }).join('')
}
// CC may append an unrelated line to the same paragraph. Match only a full
// paragraph or a complete leading line sequence, retaining the following text.
function securityPrefixLength(paragraph, hashes) {
  if (hashes.has(systemFingerprint(paragraph))) return paragraph.length
  for (const match of paragraph.matchAll(/\r?\n/g)) {
    if (hashes.has(systemFingerprint(paragraph.slice(0, match.index)))) return match.index
  }
  return 0
}
export function replaceKnownSecurity(text, hashes=KNOWN_REFUSED_SYSTEM_HASHES) {
  return text.split(/(\r?\n\s*\r?\n)/).map(p => {
    const length=securityPrefixLength(p,hashes)
    return length ? AGY_NATIVE_SECURITY+p.slice(length) : p
  }).join('')
}
export function assertForwardableSystem(projected, hashes=KNOWN_REFUSED_SYSTEM_HASHES) {
  for(const part of projected.systemInstruction?.parts||[])for(const paragraph of part.text.split(/\r?\n\s*\r?\n/)) {
    if(securityPrefixLength(paragraph,hashes))throw Object.assign(new Error(
      'CC system instructions contain a paragraph previously refused by official AGY. Instructions were preserved; no model request was sent. This full-system combination is not yet supported by the bridge.'
    ),{status:422,code:'known_refused_system'})
  }
}
