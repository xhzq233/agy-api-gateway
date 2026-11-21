// Experimental: data conversion only. This module never connects to a provider.
import fs from 'node:fs'
import path from 'node:path'
import { createHash, randomUUID } from 'node:crypto'
import { rewriteSystemIdentity, replaceKnownSecurity, removeKnownRefusedParagraphs, removeClientProductNotes, removeDshProductNotes, rewriteToolDescription } from './system-policy.mjs'
export const stable = value => JSON.stringify(value, (_k, v) => v && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.keys(v).sort().map(k => [k,v[k]])) : v)
export const fail = (message, status = 400) => Object.assign(new Error(message), { status })
const object = v => v && typeof v === 'object' && !Array.isArray(v)
const blocks = content => typeof content === 'string' ? [{ type:'text', text:content }] : content
// CC may add cache hints/caller metadata when persisting a response. These are
// transport metadata, not tool arguments or conversation text. Normalize only
// the known protocol fields; never fuzzy-match text or tool inputs.
const canonicalBlocks = value => (blocks(value)||[]).map(b => {
  if(b.type==='text')return {type:'text',text:b.text}
  if(b.type==='thinking')return {type:'thinking',thinking:b.thinking,signature:b.signature}
  if(b.type==='image')return {type:'image',source:b.source}
  if(b.type==='tool_use')return {type:'tool_use',id:b.id,name:b.name,input:b.input}
  if(b.type==='tool_result')return {type:'tool_result',tool_use_id:b.tool_use_id,is_error:b.is_error===true,content:canonicalBlocks(b.content??'')}
  return b
})
const hash = v => createHash('sha256').update(stable(v)).digest('hex')

// Auxiliary metadata only. Exact-history records remain readable; retained tool
// messages also have an immutable index so CC may replace/remove older history.
// The index matches the ENTIRE assistant message (including random CC IDs), not
// tool names/arguments alone. It never supplies old user messages or tool results.
export class WireStore {
  constructor(dir) { this.dir=dir; this.memory=new Map(); this.retained=new Map(); this.cross=new Map(); if(dir) fs.mkdirSync(dir,{recursive:true,mode:0o700}) }
  key(model, history, content) { return hash([model,history.filter(m=>m.role!=='system').map(m=>({role:m.role,content:canonicalBlocks(m.content)})),canonicalBlocks(content)]) }
  messageKey(model,content) { return blocks(content)?.some(b=>b.type==='tool_use'||b.type==='thinking') ? hash([model,canonicalBlocks(content)]) : null }
  read(file) {
    try { return JSON.parse(fs.readFileSync(file,'utf8')) }
    catch(e) { if(e.code==='ENOENT')return undefined; throw fail('Unreadable wire metadata',409) }
  }
  write(file,value) {
    fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700})
    const tmp=file+'.'+randomUUID()+'.tmp'
    try { fs.writeFileSync(tmp,JSON.stringify(value),{mode:0o600});fs.renameSync(tmp,file) }
    finally { fs.rmSync(tmp,{force:true}) }
  }
  raw(key) {
    if(!this.memory.has(key)&&this.dir) {
      const value=this.read(path.join(this.dir,key+'.json'))
      if(value!==undefined)this.memory.set(key,value)
    }
    return this.memory.get(key)
  }
  index(messageKey) {
    if(!this.retained.has(messageKey)&&this.dir) {
      const record=this.read(path.join(this.dir,'retained',messageKey+'.json'))
      if(record!==undefined)this.retained.set(messageKey,record)
    }
    const record=this.retained.get(messageKey)
    if(record!==undefined && (![1,2].includes(record?.version)||record.messageKey!==messageKey||!/^[a-f0-9]{64}$/.test(record.wireKey)||!/^[a-f0-9]{64}$/.test(record.version===1?record.partsHash:record.recordHash)))throw fail('Invalid retained wire metadata',409)
    return record&&{...record,recordHash:record.version===1?record.partsHash:record.recordHash}
  }
  retain(messageKey,key,parts) {
    if(!messageKey)return
    const record=this.index(messageKey),recordHash=hash(parts)
    if(record && record.recordHash!==recordHash)throw fail('Conflicting retained wire metadata',409)
    if(!record) {
      const next={version:2,messageKey,wireKey:key,recordHash}
      if(this.dir)this.write(path.join(this.dir,'retained',messageKey+'.json'),next)
      this.retained.set(messageKey,next)
    }
  }
  save(model, history, content, parts) {
    const key=this.key(model,history,content),messageKey=this.messageKey(model,content)
    const value=messageKey?{version:2,content:canonicalBlocks(structuredClone(content)),parts:structuredClone(parts)}:structuredClone(parts)
    const existing=this.raw(key),record=messageKey&&this.index(messageKey)
    if(messageKey && ((existing!==undefined&&hash(existing)!==hash(value))||(record&&record.recordHash!==hash(value))))throw fail('Conflicting wire metadata',409)
    if(this.dir)this.write(path.join(this.dir,key+'.json'),value)
    this.memory.set(key,value);this.retain(messageKey,key,value)
  }
  // Look up the exact assistant message across models, including records
  // created before cross-model replay was supported. Never guess tool inputs.
  // If CC normalized a persisted tool_use input, changed an opaque thinking
  // signature, or dropped an empty thinking block, the unique tool_use ID (or
  // a unique thinking signature) still identifies the signed provider call.
  // Only a record with such an anchor may be used; the signed wire part is
  // replayed, and a thinking block without a match is dropped rather than
  // inventing a signature.
  getCross(content, model=null) {
    const canonical=canonicalBlocks(content), contentKey=hash([model,canonical])
    const exactMatches=value=>{
      let offset=0
      const matches=[]
      for(const block of canonical) {
        const index=value.content.findIndex((part,i)=>i>=offset&&stable(part)===stable(block))
        if(index<0)return undefined
        matches.push({block,part:value.content[index]});offset=index+1
      }
      return matches
    }
    const relaxedMatches=value=>{
      const ids=new Set(value.content.filter(b=>b.type==='tool_use').map(b=>b.id))
      const signatures=new Set(value.content.filter(b=>b.type==='thinking').map(b=>b.signature).filter(Boolean))
      const anchored=canonical.some(block=>block.type==='tool_use'?ids.has(block.id):block.type==='thinking'&&signatures.has(block.signature))
      if(!anchored)return undefined
      const used=new Set(), pinned=new Map(), matches=[]
      for(const block of canonical) {
        if(block.type==='text') {
          const i=value.content.findIndex((part,j)=>!used.has(j)&&stable(part)===stable(block))
          if(i>=0){used.add(i);matches.push({block,part:value.content[i]})}
          else matches.push({block,part:null})
          continue
        }
        if(block.type==='thinking') {
          let i=value.content.findIndex((part,j)=>!used.has(j)&&part.type==='thinking'&&part.signature===block.signature)
          if(i<0)i=value.content.findIndex((part,j)=>!used.has(j)&&stable(part)===stable(block))
          if(i>=0){used.add(i);matches.push({block,part:value.content[i]})}
          else matches.push({block,part:null})
          continue
        }
        if(block.type==='redacted_thinking'){matches.push({block,part:null});continue}
        if(block.type!=='tool_use')return undefined
        let i=value.content.findIndex((part,j)=>!used.has(j)&&part.type==='tool_use'&&part.id===block.id)
        if(i<0) {
          // IDs changed (or all were stripped): pair same-name calls in order,
          // but only when both sides have the same number of that name.
          const wanted=canonical.filter(b=>b.type==='tool_use'&&b.name===block.name).length
          const available=value.content.filter(part=>part.type==='tool_use'&&part.name===block.name).length
          if(wanted===available) {
            const nth=pinned.get(block.name)||0
            const candidates=value.content.map((part,j)=>({part,j})).filter(({part,j})=>!used.has(j)&&part.type==='tool_use'&&part.name===block.name)
            if(candidates[nth])i=candidates[nth].j
            pinned.set(block.name,nth+1)
          }
        }
        if(i<0||value.content[i].name!==block.name)return undefined
        used.add(i);matches.push({block,part:value.content[i]})
      }
      return matches
    }
    const partsFor=value=>{
      if(value?.version!==2||!Array.isArray(value.content)||!Array.isArray(value.parts))return undefined
      const exact=exactMatches(value)
      const matches=exact||relaxedMatches(value)
      if(!matches)return undefined
      const calls=canonical.filter(b=>b.type==='tool_use')
      if(matches.filter(m=>m.block.type==='tool_use'&&m.part).length!==calls.length)return undefined
      const toolIndex=new Map()
      let n=0
      for(let i=0;i<value.content.length;i++)if(value.content[i]?.type==='tool_use')toolIndex.set(i,n++)
      const wireCalls=value.parts.filter(p=>p?.functionCall)
      const out=[]
      for(const {block,part} of matches) {
        if(block.type==='thinking') {
          if(part)out.push(...(model?structuredClone(value.parts.filter(p=>p.thought===true)):[]))
        } else if(block.type==='text') {
          out.push({text:block.text})
        } else if(block.type==='tool_use') {
          const i=value.content.indexOf(part),wire=wireCalls[toolIndex.get(i)]
          if(!wire||wire.functionCall.name!==block.name)return undefined
          out.push(structuredClone(wire))
        } else if(block.type==='redacted_thinking') {
          // No signed provider part exists for a redacted block; dropping it
          // is the only replay that does not fabricate a signature.
        } else {
          return undefined
        }
      }
      return out
    }
    let value=this.cross.get(contentKey)
    if(!value) {
      let names=[...this.retained.keys()].map(key=>key+'.json')
      if(this.dir) {
        try { names=[...new Set([...names,...fs.readdirSync(path.join(this.dir,'retained'))])] }
        catch(e) { if(e.code!=='ENOENT')throw e }
      }
      for(const name of names) {
        if(!/^[a-f0-9]{64}\.json$/.test(name))continue
        const record=this.index(name.slice(0,-5))
        if(record?.version!==2)continue
        const candidate=this.raw(record.wireKey)
        if(partsFor(candidate)===undefined||model&&this.messageKey(model,candidate.content)!==record.messageKey)continue
        if(hash(candidate)!==record.recordHash)throw fail('Damaged retained wire metadata',409)
        value=candidate;this.cross.set(contentKey,value);break
      }
    }
    if(!value)return undefined
    const parts=partsFor(value)
    if(parts===undefined)throw fail('Invalid retained wire metadata',409)
    // Retain only the blocks CC actually sent, even if the original response
    // contained more blocks. Old reasoning does not cross models, but the
    // original function-call part and its signature must remain together.
    return parts
  }
  get(model, history, content) {
    const key=this.key(model,history,content),messageKey=this.messageKey(model,content)
    let value=this.raw(key)
    const exact=value!==undefined
    if(!exact&&messageKey) {
      const record=this.index(messageKey)
      if(record) {
        value=this.raw(record.wireKey)
        if(value===undefined||hash(value)!==record.recordHash)throw fail('Missing or damaged retained wire metadata',409)
      }
    }
    let parts
    if(value!==undefined) {
      const legacy=Array.isArray(value)
      parts=legacy?value:value?.parts
      if(!Array.isArray(parts)||!legacy&&(value?.version!==2||stable(value.content)!==stable(canonicalBlocks(content))))throw fail('Invalid wire metadata or emitted tool content',409)
      const cc=(blocks(content)||[]).filter(b=>b.type==='tool_use'),wire=parts.filter(p=>p?.functionCall).map(p=>p.functionCall)
      // New records attest the exact content issued to CC, including explicit
      // client defaults. Legacy records required identical upstream arguments.
      if(cc.length!==wire.length||cc.some((c,i)=>c.name!==wire[i].name||legacy&&stable(c.input)!==stable(wire[i].args||{})))throw fail('Tool call differs from wire metadata',409)
    }
    if(exact)this.retain(messageKey,key,value)
    return structuredClone(parts)
  }
}
function textParts(content) {
  const values=blocks(content)
  if(!Array.isArray(values)) throw fail('Expected text content')
  return values.map(b=>{ if(b?.type!=='text'||typeof b.text!=='string') throw fail('MITM prototype accepts text only; multimodal/unknown blocks are not silently dropped'); return {text:b.text} })
}
// Embedded images only: no remote fetches, path reads or implicit conversions.
function inputParts(content) {
  const values=blocks(content)
  if(!Array.isArray(values))throw fail('Expected text/image content')
  return values.map(b=>{
    if(b?.type==='text'&&typeof b.text==='string')return {text:b.text}
    if(b?.type!=='image'||b.source?.type!=='base64')throw fail('Only text and embedded base64 images are supported here; URL/document blocks are not fetched or dropped')
    const {media_type:mimeType,data}=b.source
    if(!['image/png','image/jpeg','image/webp'].includes(mimeType))throw fail('Unsupported image MIME type')
    if(typeof data!=='string'||!data.length||data.length%4)throw fail('Invalid base64 image')
    if(data.length>Math.ceil(5*1024*1024/3)*4)throw fail('Embedded image exceeds 5 MiB',413)
    const raw=Buffer.from(data,'base64')
    if(raw.toString('base64')!==data)throw fail('Invalid canonical base64 image')
    if(raw.length>5*1024*1024)throw fail('Embedded image exceeds 5 MiB',413)
    const valid=mimeType==='image/png'?raw.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])):mimeType==='image/jpeg'?raw.subarray(0,3).equals(Buffer.from([255,216,255])):raw.subarray(0,4).toString()==='RIFF'&&raw.subarray(8,12).toString()==='WEBP'
    if(!valid)throw fail('Image bytes do not match declared MIME type')
    return {inlineData:{mimeType,data}}
  })
}
function resultPayload(result,label) {
  const projected=inputParts(result.content??''),field=result.is_error?'error':'output'
  if(!projected.some(p=>p.inlineData))return {response:{[field]:projected.map(p=>p.text).join('\n')}}
  const parts=[],output=projected.map((p,i)=>{
    if(p.text!==undefined)return {text:p.text}
    const displayName=`${label}_${i}`
    parts.push({inlineData:{...p.inlineData,displayName}})
    return {$ref:displayName}
  })
  return {response:{[field]:output},parts}
}
function thinkingDisplay(body) {
  const value=body.thinking
  if(value===undefined)return null
  if(!object(value))throw fail('Invalid thinking configuration')
  if(value.type==='disabled'&&Object.keys(value).every(k=>k==='type'))return null
  if(value.type==='enabled') {
    if(Object.keys(value).some(k=>!['type','budget_tokens','display'].includes(k))||!Number.isInteger(value.budget_tokens)||value.budget_tokens<1||value.display!==undefined&&!['omitted','summarized','updates'].includes(value.display))throw fail('Invalid numeric thinking configuration')
    // AGY chooses its own thinking configuration; the Anthropic token budget
    // has no portable equivalent for newer Gemini models.
    return value.display||'summarized'
  }
  if(value.type!=='adaptive')throw fail('Unsupported thinking configuration')
  if(Object.keys(value).some(k=>!['type','display'].includes(k))||value.display!==undefined&&!['omitted','summarized','updates'].includes(value.display))throw fail('Unsupported adaptive thinking configuration')
  return value.display||'omitted'
}
// Each Claude signature closes its own thought block, including when two
// signed blocks arrive consecutively with no intervening visible content.
function replayParts(model, wire) {
  const clean=wire.filter(part=>!(part.text===''&&Object.keys(part).length===1))
  if(!/claude/i.test(model))return clean
  const result=[]
  for(let i=0;i<clean.length;) {
    if(clean[i].thought!==true) {result.push(clean[i++]);continue}
    const group=[]
    while(i<clean.length&&clean[i].thought===true)group.push(clean[i++])
    if(group.some(p=>Object.keys(p).some(k=>!['thought','text','thoughtSignature'].includes(k))||typeof p.text!=='string'))throw fail('Unsupported Claude thinking history',409)
    let text='',pending=false
    for(const part of group) {
      text+=part.text
      pending=true
      if(!part.thoughtSignature)continue
      if(typeof part.thoughtSignature!=='string')throw fail('Unsupported Claude thinking history',409)
      if(!text)throw fail('Claude thinking history has no replayable text',409)
      result.push({thought:true,text,thoughtSignature:part.thoughtSignature})
      text=''
      pending=false
    }
    if(pending)throw fail('Claude thinking history is missing its final signature',409)
  }
  return result
}
// Gemini requires its signed tool history. For a switch to Claude, AGY's
// observed model-switch request omits the previous model's signatures.
function crossModelParts(wire, targetModel) {
  return wire.filter(part=>part.thought!==true).map(part=>{
    const result={...part};if(!result.functionCall||!/^gemini[.-]/i.test(targetModel))delete result.thoughtSignature;return result
  }).filter(part=>Object.keys(part).length&&!(part.text===''&&Object.keys(part).length===1))
}
export function projectCc(body, store, {dsh=false}={}) {
  if(!object(body)||typeof body.model!=='string'||!Array.isArray(body.messages)||!body.messages.length)throw fail('model and messages required')
  const display=thinkingDisplay(body)
  if(body.stop_sequences?.length || body.output_format || body.output_config && Object.keys(body.output_config).some(k=>k!=='effort'))throw fail('Stop sequences and structured output are not implemented')
  const declarations=(body.tools||[]).map(t=>{
    if(!/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(t.name)||!object(t.input_schema))throw fail('Unsupported tool name or schema')
    // Keep JSON Schema intact, rather than silently weakening constraints.
    return {name:t.name,description:rewriteToolDescription(t.description||''),parametersJsonSchema:structuredClone(t.input_schema)}
  })
  if(new Set(declarations.map(t=>t.name)).size!==declarations.length)throw fail('Duplicate tool names')
  // Standard CC emits an Environment system message inside messages (often
  // after the user). Preserve its priority by lifting it into systemInstruction.
  const messages=body.messages.filter(m=>m.role!=='system')
  const systemMessages=body.messages.filter(m=>m.role==='system')
  if(!messages.length)throw fail('At least one conversational message is required')
  const contents=[];let pending=[];const seen=new Set()
  for(let i=0;i<messages.length;i++) {
    const m=messages[i], bs=blocks(m.content)
    if(!['user','assistant'].includes(m.role)||!Array.isArray(bs))throw fail('Only user/assistant messages are supported')
    if(m.role==='assistant') {
      if(pending.length)throw fail('Missing tool_result before next assistant message')
      for(const b of bs) {
        if(b.type==='tool_use') {
          if(!b.id||seen.has(b.id)||!object(b.input)||typeof b.name!=='string')throw fail('Invalid or duplicate tool_use')
          seen.add(b.id);pending.push(b)
        } else if(b.type==='thinking') {
          if(typeof b.thinking!=='string'||typeof b.signature!=='string'||!b.signature)throw fail('Invalid thinking history')
        } else if(b.type!=='text')throw fail('Unsupported assistant content')
      }
      let wire=store.get(body.model,messages.slice(0,i),bs),crossModel=false
      if(!wire&&(pending.length||bs.some(b=>b.type==='thinking'))) {
        wire=store.getCross(bs,body.model)
        if(!wire) { wire=store.getCross(bs);crossModel=!!wire }
      }
      if((pending.length||bs.some(b=>b.type==='thinking')) && !wire)throw fail('Tool/thinking history has no matching wire metadata; do not regenerate or invent signatures',409)
      // AGY can stream empty untyped text fragments. Claude rejects an empty
      // historical text block; discard only inert fragments, never signatures.
      const parts=wire ? (crossModel?crossModelParts(wire,body.model):replayParts(body.model,wire)) : textParts(bs)
      if(parts.length)contents.push({role:'model',parts})
    } else {
      const results=bs.filter(b=>b.type==='tool_result'), other=bs.filter(b=>b.type!=='tool_result')
      if(results.length!==pending.length || new Set(results.map(r=>r.tool_use_id)).size!==results.length || results.some(r=>!pending.some(c=>c.id===r.tool_use_id)))throw fail('Incomplete, duplicate or orphan tool_result')
      const parts=[]
      if(pending.length) {
        const original=contents.at(-1).parts.filter(p=>p.functionCall)
        if(original.length!==pending.length)throw fail('Wire tool metadata mismatch',409)
        for(let n=0;n<pending.length;n++) {
          const cc=pending[n], fc=original[n].functionCall, result=results.find(r=>r.tool_use_id===cc.id)
          // WireStore already verifies the complete issued CC content. Provider
          // args retain their signed original form, which may omit CC defaults.
          if(cc.name!==fc.name)throw fail('Tool call differs from wire metadata',409)
          const payload=resultPayload(result,`cc_attachment_${i}_${n}`)
          parts.push({functionResponse:{name:fc.name,...(fc.id?{id:fc.id}:{}),...payload}})
        }
      }
      pending=[];parts.push(...inputParts(other));contents.push({role:'user',parts})
    }
  }
  if(pending.length)throw fail('Cannot generate until every pending tool_result has arrived')
  if(contents.at(-1).role!=='user')throw fail('Assistant prefill is not implemented')
  const system=[...textParts(body.system||''),...systemMessages.flatMap(m=>textParts(m.content))].map(p=>{const text=removeKnownRefusedParagraphs(removeDshProductNotes(removeClientProductNotes(rewriteSystemIdentity(p.text,{dsh}))));return {text:process.env.AGY_CC_NATIVE_SECURITY_SWAP==='0' ? text : replaceKnownSecurity(text)}})
  const generationConfig={}
  if(display)generationConfig.thinkingConfig={includeThoughts:display==='summarized'}
  if(body.output_config?.effort!==undefined) {
    const level={low:'LOW',medium:'MEDIUM',high:'HIGH'}[body.output_config.effort]
    if(!level)throw fail('Unsupported effort level')
    generationConfig.thinkingConfig={...generationConfig.thinkingConfig,thinkingLevel:level}
  }
  for(const [cc,wire] of [['max_tokens','maxOutputTokens'],['temperature','temperature'],['top_p','topP'],['top_k','topK']]) {
    if(body[cc]!==undefined) { if(!Number.isFinite(body[cc])||body[cc]<0||(cc==='max_tokens'&&(!Number.isInteger(body[cc])||body[cc]<1)))throw fail(`Invalid ${cc}`); generationConfig[wire]=body[cc] }
  }
  const choice=body.tool_choice||{type:'auto'}
  if(choice.disable_parallel_tool_use)throw fail('disable_parallel_tool_use is not implemented')
  const mode={auto:'AUTO',none:'NONE',any:'ANY',tool:'ANY'}[choice.type]
  if(!mode || choice.type==='tool'&&!declarations.some(d=>d.name===choice.name))throw fail('Invalid tool_choice')
  return {systemInstruction:{parts:system},contents,tools:declarations.length?[{functionDeclarations:declarations}]:[],toolConfig:{functionCallingConfig:{mode,...(choice.type==='tool'?{allowedFunctionNames:[choice.name]}:{})}},generationConfig}
}
export function replaceRequest(envelope, body, store, options) {
  if(!object(envelope.request)||envelope.model!==body.model)throw fail('Official CLI model/envelope mismatch',409)
  const p=projectCc(body,store,options)
  // Drop CLI tools, context, metadata and unknown request-level additions. The
  // official authentication/routing envelope is retained, never fabricated.
  return {...structuredClone(envelope),request:{...(envelope.request.sessionId?{sessionId:envelope.request.sessionId}:{}),...p,generationConfig:{...p.generationConfig,...((envelope.request.generationConfig?.thinkingConfig||p.generationConfig.thinkingConfig)?{thinkingConfig:{...structuredClone(envelope.request.generationConfig?.thinkingConfig||{}),...p.generationConfig.thinkingConfig}}:{})}}}
}

// Handle the observed generateContent SSE format, not the Interactions API.
// Text is delivered as it arrives. A tool block is exposed only after a complete
// successful response, so malformed/truncated arguments cannot execute in CC.
export class WireTurn {
  constructor(body, store, emit, onSse) { this.body=body;this.store=store;this.emit=emit;this.onSse=onSse;this.parts=[];this.content=[];this.tail='';this.decoder=new TextDecoder();this.index=-1;this.textOpen=false;this.finished=false;this.reason=null;this.usage={};this.id='msg_'+randomUUID().replaceAll('-','');this.bytes=0;this.thinkingDisplay=thinkingDisplay(body);this.thinkingBlock=null;this.thinkingOpen=false }
  start() { this.emit('message_start',{type:'message_start',message:{id:this.id,type:'message',role:'assistant',model:this.body.model,content:[],stop_reason:null,stop_sequence:null,usage:{input_tokens:0,output_tokens:0}}}) }
  closeText() { if(this.textOpen){this.emit('content_block_stop',{type:'content_block_stop',index:this.index});this.textOpen=false} }
  startThinking() {
    if(this.thinkingBlock)return
    this.closeText();this.index++
    // This is a bridge-local opaque reference, NOT a fabricated provider
    // signature. The issued whole message is attested against the original
    // provider parts in WireStore before completion/tool dispatch. References
    // never enter an AGY request; missing/tampered bindings fail closed.
    this.thinkingBlock={type:'thinking',thinking:'',signature:'agyref_'+randomUUID().replaceAll('-','')}
    this.content.push(this.thinkingBlock);this.thinkingOpen=true
    this.emit('content_block_start',{type:'content_block_start',index:this.index,content_block:{type:'thinking',thinking:'',signature:''}})
  }
  closeThinking() {
    if(!this.thinkingOpen)return
    this.emit('content_block_delta',{type:'content_block_delta',index:this.index,delta:{type:'signature_delta',signature:this.thinkingBlock.signature}})
    this.emit('content_block_stop',{type:'content_block_stop',index:this.index});this.thinkingOpen=false
  }
  push(chunk) {
    this.bytes+=Buffer.byteLength(chunk);if(this.bytes>32*1024*1024)throw fail('Model response exceeds prototype limit',502)
    this.tail+=this.decoder.decode(chunk,{stream:true});this.tail=this.tail.replace(/\r\n/g,'\n')
    let end
    while((end=this.tail.indexOf('\n\n'))>=0) {
      const event=this.tail.slice(0,end);this.tail=this.tail.slice(end+2)
      const data=event.split('\n').filter(l=>l.startsWith('data:')).map(l=>l.slice(5).trimStart()).join('\n')
      if(!data||data==='[DONE]')continue
      this.onSse?.()
      this.onSse=undefined
      const packet=JSON.parse(data),r=packet.response||packet
      if(r.error||packet.error)throw fail('Upstream model error',Number((r.error||packet.error).code)||502)
      if(r.usageMetadata)this.usage=r.usageMetadata
      if(r.promptFeedback?.blockReason)throw fail('Upstream blocked the prompt',502)
      if((r.candidates||[]).length>1)throw fail('Multiple candidates are unsupported',502)
      for(const c of r.candidates||[]) {
        if(c.finishReason)this.reason=c.finishReason
        for(const p of c.content?.parts||[]) {
          this.parts.push(structuredClone(p))
          if(this.thinkingDisplay) {
            this.startThinking()
            if(p.thought&&typeof p.text==='string'&&p.text&&this.thinkingDisplay==='summarized') {
              if(!this.thinkingOpen)throw fail('Thought summary after visible content is unsupported',502)
              this.thinkingBlock.thinking+=p.text
              this.emit('content_block_delta',{type:'content_block_delta',index:this.index,delta:{type:'thinking_delta',thinking:p.text}})
            }
            if(!p.thought)this.closeThinking()
          }
          if(p.thought || p.text==='')continue // AGY emits an empty text part on the terminal STOP frame.
          if(p.functionCall) { this.closeText(); continue }
          if(typeof p.text==='string' && p.text) {
            if(this.parts.some(x=>x.functionCall))throw fail('Text after tool calls requires an explicit mixed-output adapter',502)
            if(!this.textOpen) {this.index++;this.content.push({type:'text',text:''});this.emit('content_block_start',{type:'content_block_start',index:this.index,content_block:{type:'text',text:''}});this.textOpen=true}
            this.content.at(-1).text+=p.text;this.emit('content_block_delta',{type:'content_block_delta',index:this.index,delta:{type:'text_delta',text:p.text}})
          } else if(!p.thoughtSignature&&!p.functionCall)throw fail('Unsupported model content',502)
        }
      }
    }
  }
  finish() {
    this.tail+=this.decoder.decode()
    if(this.tail.trim())throw fail('Incomplete upstream SSE frame',502)
    if(!['STOP','MAX_TOKENS'].includes(this.reason))throw fail('Missing or unsupported upstream finish reason',502)
    this.closeThinking();this.closeText()
    const calls=this.parts.filter(p=>p.functionCall)
    if(calls.length&&this.body.tool_choice?.type==='none')throw fail('Model called tools despite tool_choice=none',502)
    if(calls.length&&this.reason!=='STOP')throw fail('Incomplete tool generation',502)
    const ids=new Set()
    for(const p of calls) {
      const f=p.functionCall
      if(!this.body.tools?.some(t=>t.name===f.name)) {
        // Escape and bound the returned name in the caller's error; do not
        // include tool arguments or other model output.
        const name=typeof f.name==='string'&&/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(f.name)?` "${f.name}"`:''
        const shape=name?'':` (name ${f.name===undefined?'missing':typeof f.name==='string'?`invalid ${JSON.stringify(f.name.slice(0,128))}${f.name.length>128?'…':''}`:'not a string'}; fields: ${Object.keys(f).filter(k=>/^[A-Za-z][A-Za-z0-9_]{0,31}$/.test(k)).sort().join(',')||'none'})`
        throw fail(`Upstream called an undeclared tool${name}${shape}`,502)
      }
      if((f.partialArgs!==undefined && (!Array.isArray(f.partialArgs)||f.partialArgs.length>0)) || f.willContinue)throw fail('Upstream streamed tool arguments are unsupported',502)
      if(!object(f.args))throw fail('Upstream tool call omitted or returned invalid arguments',502)
      if(f.id && ids.has(f.id))throw fail('Duplicate upstream functionCall ID',502)
      if(f.id)ids.add(f.id)
      const input=structuredClone(f.args),schema=this.body.tools.find(t=>t.name===f.name).input_schema
      // Observed CC Edit normalizes this optional default after execution. Emit
      // it up front so persistence/resume sees exactly what we issued. Do not
      // infer arbitrary JSON Schema defaults or rewrite signed provider args.
      if(f.name==='Edit'&&!Object.hasOwn(input,'replace_all')&&schema?.properties?.replace_all?.type==='boolean'&&schema.properties.replace_all.default===false&&!schema.required?.includes('replace_all'))input.replace_all=false
      this.content.push({type:'tool_use',id:'toolu_'+randomUUID().replaceAll('-',''),name:f.name,input})
    }
    // Persist exact raw parts (including opaque thoughtSignature) before a tool
    // is exposed to CC. Nothing here is a tool result or a fabricated success.
    this.store.save(this.body.model,this.body.messages,this.content,this.parts)
    for(const b of this.content.filter(b=>b.type==='tool_use')) {
      this.index++;this.emit('content_block_start',{type:'content_block_start',index:this.index,content_block:{type:'tool_use',id:b.id,name:b.name,input:{}}})
      this.emit('content_block_delta',{type:'content_block_delta',index:this.index,delta:{type:'input_json_delta',partial_json:JSON.stringify(b.input)}})
      this.emit('content_block_stop',{type:'content_block_stop',index:this.index})
    }
    const u=this.usage,cached=u.cachedContentTokenCount||0
    this.outputUsage={input_tokens:Math.max(0,(u.promptTokenCount||0)-cached),output_tokens:(u.candidatesTokenCount||0)+(u.thoughtsTokenCount||0),cache_read_input_tokens:cached,output_tokens_details:{thinking_tokens:u.thoughtsTokenCount||0}}
    this.stop=calls.length?'tool_use':this.reason==='MAX_TOKENS'?'max_tokens':'end_turn'
    this.emit('message_delta',{type:'message_delta',delta:{stop_reason:this.stop,stop_sequence:null},usage:this.outputUsage})
    this.emit('message_stop',{type:'message_stop'});this.finished=true
    return {id:this.id,type:'message',role:'assistant',model:this.body.model,content:this.content,stop_reason:this.stop,stop_sequence:null,usage:this.outputUsage}
  }
}
