import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { MitmBroker } from '../packages/agy-cli/mitm/broker.mjs'
import { WireStore, WireTurn, projectCc, replaceRequest } from '../packages/agy-cli/mitm/protocol.mjs'
import { AGY_IDENTITY, AGY_NATIVE_SECURITY, KNOWN_REFUSED_SYSTEM_HASHES, systemFingerprint, assertForwardableSystem, assertSupportedClient, removeKnownRefusedParagraphs } from '../packages/agy-cli/mitm/system-policy.mjs'

test('only paragraphs beginning with the selected headings are removed', () => {
  const text = 'Keep this instruction.\n\n# Harness\nHarness instruction.\n\n## System\nKeep this subsection.\n\n# System\nSystem instruction.\n\nKeep the last instruction.'
  const result = removeKnownRefusedParagraphs(text)
  assert.doesNotMatch(result, /Harness instruction|System instruction/)
  assert.match(result, /Keep this instruction/)
  assert.match(result, /## System\nKeep this subsection/)
  assert.match(result, /Keep the last instruction/)
})

test('numeric thinking budget is ignored while preserving AGY thinking and requested display', () => {
  const body={model:'gemini-4-argon-high',messages:[{role:'user',content:'hello'}],thinking:{type:'enabled',budget_tokens:4096,display:'summarized'}}
  const envelope={model:body.model,request:{generationConfig:{thinkingConfig:{thinkingLevel:'HIGH'}}}}
  const result=replaceRequest(envelope,body,new WireStore())
  assert.deepEqual(result.request.generationConfig.thinkingConfig,{thinkingLevel:'HIGH',includeThoughts:true})
  assert.throws(()=>projectCc({...body,thinking:{type:'enabled',budget_tokens:'bad'}},new WireStore()),/Invalid numeric thinking/)
})

test('client identity is required in system instructions before forwarding', async () => {
  const cc="You are Claude Code, Anthropic's official CLI for Claude."
  const dsh='You are an AI agent powered by DeepSeek Harness.'
  assert.doesNotThrow(()=>assertSupportedClient({system:[{type:'text',text:cc}]}))
  assert.doesNotThrow(()=>assertSupportedClient({system:"You are a Claude agent, built on Anthropic's Claude Agent SDK."}))
  assert.doesNotThrow(()=>assertSupportedClient({messages:[{role:'system',content:dsh}]}))
  assert.doesNotThrow(()=>assertSupportedClient({system:'Custom DSH agent'},'deepseek-harness/1.0.0 (+https://example.test)'))
  assert.throws(()=>assertSupportedClient({system:'Custom agent'},'unrelated/1.0'),/Unsupported client identity/)
  assert.throws(()=>assertSupportedClient({system:'You are another assistant.',messages:[{role:'user',content:cc}]}),/Unsupported client identity/)
  let forwarded=0
  const broker=new MitmBroker({token:'control',drive:async()=>{forwarded++}})
  const response=await broker.fetch('/v1/messages',{body:JSON.stringify({model:'fixture',system:'You are another assistant.',messages:[{role:'user',content:'hello'}]})})
  assert.equal(response.status,400);assert.equal(forwarded,0)
})

test('DSH system identity is replaced without changing surrounding instructions or user text', () => {
  const identity = 'You are an AI agent powered by DeepSeek Harness.'
  const request = {model:'fixture', system:`${identity}\nKeep the configured tools.`, messages:[{role:'user',content:identity}]}
  const projected = projectCc(request, new WireStore())
  assert.equal(projected.systemInstruction.parts[0].text, `${AGY_IDENTITY}\nKeep the configured tools.`)
  assert.equal(projected.contents[0].parts[0].text, identity)
  const other = projectCc({...request, system:`Explain: ${identity}`}, new WireStore())
  assert.equal(other.systemInstruction.parts[0].text, `Explain: ${identity}`)
})

test('recognized DSH source and web guidance is removed from system text only', () => {
  const notes = [
    'The DeepSeek Harness implementation checkout is at /example. Use this checkout only to inspect or extend DSH itself.',
    'You are interacting with the user through the DeepSeek Harness Web GUI at http://localhost. Only dsh web injects window.__DSH_BOOT__.',
    'The runtime context names the DeepSeek Harness implementation checkout. Use pwd.',
    'You are interacting with the user through the DeepSeek Harness Web GUI whose URL the runtime context names. GUI instructions.'
  ]
  const user=notes.join('\n\n')
  const projected=projectCc({model:'fixture',system:`Keep before.\n\n${user}\n\nKeep after.`,messages:[{role:'user',content:user}]},new WireStore())
  const system=projected.systemInstruction.parts[0].text
  assert.match(system,/Keep before\./);assert.match(system,/Keep after\./)
  for(const note of notes) assert.ok(!system.includes(note))
  assert.equal(projected.contents[0].parts[0].text,user)
})

test('undeclared tool errors identify valid and invalid names', () => {
  const body={model:'fixture',messages:[{role:'user',content:'hello'}],tools:[{name:'allowed',input_schema:{type:'object'}}]}
  const invoke=name=>{
    const t=new WireTurn(body,new WireStore(),()=>{})
    t.push(Buffer.from('data: '+JSON.stringify({response:{candidates:[{content:{parts:[{functionCall:{name,args:{}}}]},finishReason:'STOP'}]}})+'\n\n'))
    return ()=>t.finish()
  }
  assert.throws(invoke('unknown_tool'),/undeclared tool "unknown_tool"/)
  assert.throws(invoke('arbitrary output with spaces'),e=>e.message==='Upstream called an undeclared tool (name invalid "arbitrary output with spaces"; fields: args,name)')
  assert.throws(invoke(undefined),e=>e.message==='Upstream called an undeclared tool (name missing; fields: args)')
})

test('a completed upstream response with an undeclared tool settles the proxy event', async t => {
  let endResult
  const broker=new MitmBroker({token:'control',logger:()=>{},drive:async job=>{
    const ctl=async(route,data)=>fetch(`http://127.0.0.1:${broker.server.address().port}${route}`,{method:'POST',headers:{authorization:'Bearer control'},body:JSON.stringify(data)})
    const claim=await ctl('/claim',{ticket:job.ticket,envelope:{model:'fixture',request:{contents:[{role:'user',parts:[{text:job.marker}]}]}}})
    assert.equal(claim.status,200)
    await ctl('/event',{ticket:job.ticket,kind:'headers',status:200})
    const packet={response:{candidates:[{content:{parts:[{functionCall:{name:'unknown_tool',args:{}}}]},finishReason:'STOP'}]}}
    await ctl('/event',{ticket:job.ticket,kind:'chunk',data:Buffer.from('data: '+JSON.stringify(packet)+'\n\n').toString('base64')})
    const end=await ctl('/event',{ticket:job.ticket,kind:'end'})
    endResult=[end.status,await end.json()]
  }})
  await broker.listen();t.after(()=>broker.close())
  const body={model:'fixture',system:'You are an AI agent powered by DeepSeek Harness.',messages:[{role:'user',content:'hello'}],tools:[{name:'allowed',input_schema:{type:'object'}}]}
  const response=await broker.fetch('/v1/messages',{body:JSON.stringify(body)})
  assert.equal(response.status,502)
  assert.match((await response.json()).error.message,/undeclared tool "unknown_tool"/)
  while(!endResult)await new Promise(resolve=>setTimeout(resolve,1))
  assert.deepEqual(endResult,[200,{ok:true,adapter_error:true}])
})

test('complete tool calls accept empty partialArgs but reject actual partial arguments', () => {
  const body={model:'fixture',messages:[{role:'user',content:'hello'}],tools:[{name:'get_goal',input_schema:{type:'object',properties:{}}}]}
  const turn=partialArgs=>{
    const t=new WireTurn(body,new WireStore(),()=>{})
    t.push(Buffer.from('data: '+JSON.stringify({response:{candidates:[{content:{parts:[{functionCall:{name:'get_goal',args:{},partialArgs}}]},finishReason:'STOP'}]}})+'\n\n'))
    return t
  }
  assert.deepEqual(turn([]).finish().content[0].input,{})
  assert.throws(()=>turn([{jsonPath:'$.value',stringValue:'partial'}]).finish(),/streamed tool arguments/)
})

test('default safety substitution reaches the model while user and tool text remain intact', () => {
  const paragraph = 'Synthetic security instruction.', hash = systemFingerprint(paragraph)
  const previous = process.env.AGY_CC_NATIVE_SECURITY_SWAP
  KNOWN_REFUSED_SYSTEM_HASHES.add(hash)
  try {
    delete process.env.AGY_CC_NATIVE_SECURITY_SWAP
    const request = { model:'fixture', system:`Before\n\n${paragraph}\n\nAfter`, messages:[{role:'user',content:paragraph}], tools:[{name:'Read',description:paragraph,input_schema:{type:'object'}}] }
    const projected = projectCc(request, new WireStore())
    assert.equal(projected.systemInstruction.parts[0].text, `Before\n\n${AGY_NATIVE_SECURITY}\n\nAfter`)
    const appended = projectCc({ ...request, system:`${paragraph}\nKeep this adjacent instruction.` }, new WireStore())
    assert.equal(appended.systemInstruction.parts[0].text, `${AGY_NATIVE_SECURITY}\nKeep this adjacent instruction.`)
    assert.equal(projected.contents[0].parts[0].text, paragraph)
    assert.equal(projected.tools[0].functionDeclarations[0].description, paragraph)
    assert.doesNotThrow(() => assertForwardableSystem(projected))
    process.env.AGY_CC_NATIVE_SECURITY_SWAP = '0'
    assert.throws(() => assertForwardableSystem(projectCc(request, new WireStore())), error => error.status === 422)
    assert.throws(() => assertForwardableSystem(projectCc({ ...request, system:`${paragraph}\nKeep this adjacent instruction.` }, new WireStore())), error => error.status === 422)
  } finally {
    KNOWN_REFUSED_SYSTEM_HASHES.delete(hash)
    if (previous === undefined) delete process.env.AGY_CC_NATIVE_SECURITY_SWAP
    else process.env.AGY_CC_NATIVE_SECURITY_SWAP = previous
  }
})

test('Claude streamed thought fragments replay as one signed thinking block', () => {
  const store=new WireStore(), model='claude-opus-fixture'
  const user={role:'user',content:'synthetic'}, call={type:'tool_use',id:'toolu_test',name:'Read',input:{path:'x'}}
  const content=[{type:'thinking',thinking:'',signature:'agyref_fixture'},call]
  const parts=[{text:''},{thought:true,text:'think '},{thought:true,text:'once'}, {thought:true,text:'',thoughtSignature:'provider-signature'},{functionCall:{name:'Read',args:{path:'x'}}},{text:''}]
  store.save(model,[user],content,parts)
  const projected=projectCc({model,messages:[user,{role:'assistant',content},{role:'user',content:[{type:'tool_result',tool_use_id:'toolu_test',content:'done'}]}],tools:[{name:'Read',input_schema:{type:'object'}}]},store)
  assert.deepEqual(projected.contents[1].parts,[{thought:true,text:'think once',thoughtSignature:'provider-signature'},{functionCall:{name:'Read',args:{path:'x'}}}])
})

test('adjacent signed Claude thought blocks replay independently with a signed tool call',()=>{
  const model='claude-opus-fixture',first={role:'user',content:'synthetic'}
  const tool={name:'Read',input_schema:{type:'object'}}
  const thought=text=>({thought:true,text})
  const signature=(text,thoughtSignature)=>({thought:true,text,thoughtSignature})
  const wireCall={functionCall:{id:'fixture-call',name:'Read',args:{path:'sample'}},thoughtSignature:'tool-signature'}
  const replay=parts=>{
    const store=new WireStore()
    const turn=new WireTurn({model,messages:[first],tools:[tool],thinking:{type:'adaptive',display:'summarized'}},store,()=>{})
    const packet={response:{candidates:[{finishReason:'STOP',content:{parts:[...parts,wireCall]}}]}}
    turn.push(Buffer.from('data: '+JSON.stringify(packet)+'\n\n'))
    const {content}=turn.finish()
    const messages=[first,{role:'assistant',content},{role:'user',content:[{type:'tool_result',tool_use_id:content.at(-1).id,content:'synthetic result'}]}]
    return projectCc({model,messages,tools:[tool]},store)
  }
  const result=replay([thought('first'),signature(' block','first-signature'),thought('second'),thought(' block'),signature('','second-signature')])
  assert.deepEqual(result.contents[1].parts,[signature('first block','first-signature'),signature('second block','second-signature'),wireCall])
  assert.equal(result.contents[2].parts[0].functionResponse.id,'fixture-call')
  assert.throws(()=>replay([signature('first','first-signature'),thought('unsigned')]),error=>error.status===409)
})

test('switching models retains tool signatures without old reasoning', t => {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'agy-cross-'))
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}))
  const source='gemini-4-carbon-medium', target='gemini-4-hydrogen-medium'
  const user={role:'user',content:'synthetic'}, content=[{type:'thinking',thinking:'',signature:'agyref_fixture'}, {type:'text',text:'visible'}, {type:'tool_use',id:'toolu_cross',name:'Read',input:{path:'x'}}]
  const original=[{thought:true,text:'secret thought',thoughtSignature:'thought-signature'}, {text:'visible',thoughtSignature:'text-signature'}, {functionCall:{name:'Read',args:{path:'x'},id:'original-id'},thoughtSignature:'tool-signature'}]
  new WireStore(dir).save(source,[user],content,original)
  const messages=[user,{role:'assistant',content},{role:'user',content:[{type:'tool_result',tool_use_id:'toolu_cross',content:'done'}]}]
  const store=new WireStore(dir)
  const projected=projectCc({model:target,messages,tools:[{name:'Read',input_schema:{type:'object'}}]},store)
  assert.deepEqual(projected.contents[1].parts,[{text:'visible'},{functionCall:{name:'Read',args:{path:'x'},id:'original-id'},thoughtSignature:'tool-signature'}])
  assert.equal(projected.contents[2].parts[0].functionResponse.response.output,'done')
  const split=[user,...content.map(block=>({role:'assistant',content:[block]})),messages[2]]
  const splitProjection=projectCc({model:target,messages:split,tools:[{name:'Read',input_schema:{type:'object'}}]},new WireStore(dir))
  assert.deepEqual(splitProjection.contents.filter(x=>x.role==='model').flatMap(x=>x.parts),[{text:'visible'},{functionCall:{name:'Read',args:{path:'x'},id:'original-id'},thoughtSignature:'tool-signature'}])
  const claudeProjection=projectCc({model:'claude-opus-fixture',messages,tools:[{name:'Read',input_schema:{type:'object'}}]},new WireStore(dir))
  assert.deepEqual(claudeProjection.contents[1].parts,[{text:'visible'},{functionCall:{name:'Read',args:{path:'x'},id:'original-id'}}])
  assert.deepEqual(projectCc({model:source,messages,tools:[{name:'Read',input_schema:{type:'object'}}]},store).contents[1].parts,original)
})

test('normalized persisted tool input replays the signed wire call',()=>{
  const store=new WireStore(), model='gemini-4-carbon-medium'
  const user={role:'user',content:'synthetic'}
  const issued=[{type:'text',text:'visible'},{type:'tool_use',id:'toolu_fixture',name:'Read',input:{path:'sample'}}]
  const signed={functionCall:{id:'wire-call',name:'Read',args:{path:'sample'}},thoughtSignature:'tool-signature'}
  store.save(model,[user],issued,[{text:'visible',thoughtSignature:'text-signature'},signed])
  const persisted=[{type:'text',text:'visible'},{type:'tool_use',id:'toolu_fixture',name:'Read',input:{path:'sample',offset:0}}]
  const messages=[user,{role:'assistant',content:persisted},{role:'user',content:[{type:'tool_result',tool_use_id:'toolu_fixture',content:'done'}]}]
  const projected=projectCc({model,messages,tools:[{name:'Read',input_schema:{type:'object',properties:{path:{type:'string'},offset:{type:'number'}}}}]},store)
  assert.deepEqual(projected.contents[1].parts,[{text:'visible'},signed])
  assert.equal(projected.contents[2].parts[0].functionResponse.id,'wire-call')
})

test('changed thinking signature is dropped while the anchored tool call replays',()=>{
  const store=new WireStore(), model='gemini-4-carbon-medium'
  const user={role:'user',content:'synthetic'}
  const issued=[{type:'thinking',thinking:'plan',signature:'source-signature'},{type:'tool_use',id:'toolu_fixture',name:'Read',input:{path:'sample'}}]
  const signed={functionCall:{id:'wire-call',name:'Read',args:{path:'sample'}},thoughtSignature:'tool-signature'}
  store.save(model,[user],issued,[{thought:true,text:'plan',thoughtSignature:'thought-signature'},signed])
  const persisted=[{type:'thinking',thinking:'plan',signature:'changed-signature'},{type:'tool_use',id:'toolu_fixture',name:'Read',input:{path:'sample'}}]
  const messages=[user,{role:'assistant',content:persisted},{role:'user',content:[{type:'tool_result',tool_use_id:'toolu_fixture',content:'done'}]}]
  const projected=projectCc({model,messages,tools:[{name:'Read',input_schema:{type:'object'}}]},store)
  assert.deepEqual(projected.contents[1].parts,[signed])
})

test('changed tool IDs pair by a unique anchor and matching name counts',()=>{
  const store=new WireStore(), model='gemini-4-carbon-medium'
  const user={role:'user',content:'synthetic'}
  const signedA={functionCall:{id:'wire-a',name:'Read',args:{path:'a'}},thoughtSignature:'sig-a'}
  const signedB={functionCall:{id:'wire-b',name:'Read',args:{path:'b'}},thoughtSignature:'sig-b'}
  store.save(model,[user],[{type:'tool_use',id:'toolu_a',name:'Read',input:{path:'a'}},{type:'tool_use',id:'toolu_b',name:'Read',input:{path:'b'}}],[signedA,signedB])
  const persisted=[{type:'tool_use',id:'toolu_a',name:'Read',input:{path:'a'}},{type:'tool_use',id:'toolu_new',name:'Read',input:{path:'b'}}]
  assert.deepEqual(store.getCross(persisted),[signedA,signedB])
})

test('changed tool IDs or names without a signed anchor are not guessed',()=>{
  const store=new WireStore(), model='gemini-4-carbon-medium'
  const user={role:'user',content:'synthetic'}
  const signed={functionCall:{id:'wire-call',name:'Read',args:{path:'sample'}},thoughtSignature:'tool-signature'}
  store.save(model,[user],[{type:'tool_use',id:'toolu_old',name:'Read',input:{path:'sample'}}],[signed])
  assert.equal(store.getCross([{type:'tool_use',id:'toolu_new',name:'Read',input:{path:'sample'}}]),undefined)
  assert.equal(store.getCross([{type:'tool_use',id:'toolu_old',name:'Write',input:{path:'sample'}}]),undefined)
})
