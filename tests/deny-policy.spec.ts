import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import SystemPrompt, { renderPrompt } from '@deepseek-ai/dsh-system-prompt'
import type { PreToolDecision, ToolExecution } from '@deepseek-ai/dsh-tools'
import * as DenyPolicy from '../src/index.ts'
import type { ConfigInput } from '../src/index.ts'

function execOf(name: string, args: unknown, cwd?: string): ToolExecution {
  const signal = new AbortController().signal
  return {
    callId: 'call-1',
    rootCallId: 'call-1',
    name,
    arguments: args,
    signal,
    token: Symbol('token') as ToolExecution['token'],
    ...(cwd !== undefined ? { agent: { session: { header: { cwd } } } as unknown as ToolExecution['agent'] } : {}),
  } as unknown as ToolExecution
}

/** The decision a real waterfall would fall through to. */
const PASS_THROUGH: PreToolDecision = { kind: 'allow' }

async function mounted(config: ConfigInput = {}): Promise<Context> {
  const ctx = new Context()
  await ctx.plugin(DenyPolicy, config)
  return ctx
}

function dispatch(ctx: Context, exec: ToolExecution): Promise<PreToolDecision> {
  return ctx.waterfall('tools/pre-execute', exec, () => Promise.resolve(PASS_THROUGH))
}

interface WorkTree {
  root: string
  secret: string
  publicDir: string
}

let work: WorkTree
let homeScratch: string

beforeEach(() => {
  work = makeWorkTree()
  homeScratch = realpathSync(mkdtempSync(join(homedir(), '.fs-deny-policy-test-')))
})

afterEach(() => {
  rmSync(work.root, { recursive: true, force: true })
  rmSync(homeScratch, { recursive: true, force: true })
})

/** Lay down `<root>/{secret,public}` with one file each and a symlink into `secret`. */
function makeWorkTree(): WorkTree {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'fs-deny-policy-')))
  const secret = join(root, 'secret')
  const publicDir = join(root, 'public')
  mkdirSync(secret, { recursive: true })
  mkdirSync(publicDir, { recursive: true })
  writeFileSync(join(secret, 'x.txt'), 'top secret')
  writeFileSync(join(publicDir, 'y.txt'), 'public')
  symlinkSync(join(secret, 'x.txt'), join(root, 'shortcut.txt'))
  return { root, secret, publicDir }
}

describe('mount-time validation', () => {
  it('rejects a relative or empty deny-list entry', async () => {
    const ctx = new Context()
    await expect(ctx.plugin(DenyPolicy, { deniedRoots: ['relative/path'] })).rejects.toThrow(/absolute/)
    await expect(ctx.plugin(DenyPolicy, { deniedRoots: [''] })).rejects.toThrow(/absolute/)
  })

  it('rejects a duplicate entry', async () => {
    const ctx = new Context()
    await expect(ctx.plugin(DenyPolicy, { deniedRoots: ['/a', '/a'] })).rejects.toThrow(/unique/)
  })

  it('rejects an unknown config key', async () => {
    const ctx = new Context()
    const bad = { deniedRoots: [], bogus: true } as unknown as ConfigInput
    await expect(ctx.plugin(DenyPolicy, bad)).rejects.toThrow()
  })
})

describe('the empty default fence is inert', () => {
  it('mounts with no services and denies nothing', async () => {
    const ctx = await mounted({ deniedRoots: [] })
    expect((ctx as Context & { denyPolicy?: unknown }).denyPolicy).toBeUndefined()
    expect(await dispatch(ctx, execOf('read', { file_path: join(work.secret, 'x.txt') }))).toEqual(PASS_THROUGH)
    expect(await dispatch(ctx, execOf('bash', { command: `cat ${work.secret}/x.txt` }))).toEqual(PASS_THROUGH)
  })
})

describe('read, search, and content-search families', () => {
  it('denies a read under the denied root and names the root and argument', async () => {
    const ctx = await mounted({ deniedRoots: [work.secret] })
    const decision = await dispatch(ctx, execOf('read', { file_path: join(work.secret, 'x.txt') }, work.root))
    expect(decision).toMatchObject({ kind: 'deny' })
    if (decision.kind === 'deny') {
      expect(decision.reason).toContain('x.txt')
      expect(decision.reason).toContain(work.secret)
      expect(decision.reason).toContain('fs-deny-policy')
    }
  })

  it('passes a read outside the denied root', async () => {
    const ctx = await mounted({ deniedRoots: [work.secret] })
    expect(await dispatch(ctx, execOf('read', { file_path: join(work.publicDir, 'y.txt') }, work.root))).toEqual(PASS_THROUGH)
  })

  it('passes reads entirely when fenceReads is false', async () => {
    const ctx = await mounted({ deniedRoots: [work.secret], fenceReads: false })
    expect(await dispatch(ctx, execOf('read', { file_path: join(work.secret, 'x.txt') }, work.root))).toEqual(PASS_THROUGH)
    expect(await dispatch(ctx, execOf('glob', { pattern: '*', path: work.secret }))).toEqual(PASS_THROUGH)
  })

  it('denies read_image and glob under the denied root', async () => {
    const ctx = await mounted({ deniedRoots: [work.secret] })
    expect(await dispatch(ctx, execOf('read_image', { file_path: join(work.secret, 'img.png') }))).toMatchObject({ kind: 'deny' })
    expect(await dispatch(ctx, execOf('glob', { pattern: '*', path: work.secret }))).toMatchObject({ kind: 'deny' })
  })

  it('denies grep under its own switch and passes with the switch off', async () => {
    const on = await mounted({ deniedRoots: [work.secret] })
    expect(await dispatch(on, execOf('grep', { pattern: 'secret', path: work.secret }))).toMatchObject({ kind: 'deny' })
    const off = await mounted({ deniedRoots: [work.secret], fenceContentSearch: false })
    expect(await dispatch(off, execOf('grep', { pattern: 'secret', path: work.secret }))).toEqual(PASS_THROUGH)
  })
})

describe('the write family is fenced unconditionally', () => {
  it('denies write, edit, and str_replace_editor under the denied root even with fenceReads off', async () => {
    const ctx = await mounted({ deniedRoots: [work.secret], fenceReads: false })
    expect(await dispatch(ctx, execOf('write', { file_path: join(work.secret, 'new.txt'), content: 'x' }))).toMatchObject({ kind: 'deny' })
    expect(await dispatch(ctx, execOf('edit', { file_path: join(work.secret, 'x.txt'), old_string: 'a', new_string: 'b' }))).toMatchObject({ kind: 'deny' })
    expect(await dispatch(ctx, execOf('str_replace_editor', { command: 'view', path: join(work.secret, 'x.txt') }))).toMatchObject({ kind: 'deny' })
  })

  it('passes a str_replace_editor view outside the denied root', async () => {
    const ctx = await mounted({ deniedRoots: [work.secret] })
    expect(await dispatch(ctx, execOf('str_replace_editor', { command: 'view', path: join(work.publicDir, 'y.txt') }))).toEqual(PASS_THROUGH)
  })
})

describe('the shell family', () => {
  it('denies a call whose workdir resolves under the denied root', async () => {
    const ctx = await mounted({ deniedRoots: [work.secret] })
    expect(await dispatch(ctx, execOf('bash', { command: 'ls', workdir: work.secret }))).toMatchObject({ kind: 'deny' })
  })

  it('denies a command embedding a denied path, bare or quoted', async () => {
    const ctx = await mounted({ deniedRoots: [work.secret] })
    expect(await dispatch(ctx, execOf('bash', { command: `cat ${work.secret}/x.txt` }))).toMatchObject({ kind: 'deny' })
    expect(await dispatch(ctx, execOf('bash', { command: `cat "${work.secret}/x.txt"` }))).toMatchObject({ kind: 'deny' })
    expect(await dispatch(ctx, execOf('pwsh', { command: `Get-Content ${work.secret}/x.txt` }))).toMatchObject({ kind: 'deny' })
  })

  it('still extracts a bare path after the end-of-options marker', async () => {
    const ctx = await mounted({ deniedRoots: [work.secret] })
    expect(await dispatch(ctx, execOf('bash', { command: `cat -- ${work.secret}/x.txt` }))).toMatchObject({ kind: 'deny' })
  })

  it('expands a leading ~ to the user\'s home directory, where the shell itself would', async () => {
    const ctx = await mounted({ deniedRoots: [homeScratch] })
    const name = homeScratch.split(/[\\/]/).pop() ?? ''
    expect(await dispatch(ctx, execOf('bash', { command: `cat ~/${name}/x.txt` }))).toMatchObject({ kind: 'deny' })
  })

  it('denies terminal_open by cwd and terminal_send by embedded path', async () => {
    const ctx = await mounted({ deniedRoots: [work.secret] })
    expect(await dispatch(ctx, execOf('terminal_open', { type: 'shell', name: 'm', cwd: work.secret }))).toMatchObject({ kind: 'deny' })
    expect(await dispatch(ctx, execOf('terminal_send', { sessionId: 's', text: `cat ${work.secret}/x.txt` }))).toMatchObject({ kind: 'deny' })
  })

  it('passes a command whose candidates all resolve outside the denied root', async () => {
    const ctx = await mounted({ deniedRoots: [work.secret] })
    expect(await dispatch(ctx, execOf('bash', { command: `cat ${work.publicDir}/y.txt` }))).toEqual(PASS_THROUGH)
  })

  it('passes every shell tool when fenceShell is off', async () => {
    const ctx = await mounted({ deniedRoots: [work.secret], fenceShell: false })
    expect(await dispatch(ctx, execOf('bash', { command: 'ls', workdir: work.secret }))).toEqual(PASS_THROUGH)
    expect(await dispatch(ctx, execOf('terminal_open', { type: 'shell', name: 'm', cwd: work.secret }))).toEqual(PASS_THROUGH)
  })
})

describe('resolution and containment', () => {
  it('resolves a relative argument against the session cwd', async () => {
    const ctx = await mounted({ deniedRoots: [work.secret] })
    expect(await dispatch(ctx, execOf('read', { file_path: 'secret/x.txt' }, work.root))).toMatchObject({ kind: 'deny' })
  })

  it('resolves a no-agent call against the process cwd', async () => {
    const ctx = await mounted({ deniedRoots: [process.cwd()] })
    expect(await dispatch(ctx, execOf('read', { file_path: 'package.json' }))).toMatchObject({ kind: 'deny' })
    expect(await dispatch(ctx, execOf('read', { file_path: join(work.publicDir, 'y.txt') }))).toEqual(PASS_THROUGH)
  })

  it('follows a symlink whose target lies under the denied root', async () => {
    const ctx = await mounted({ deniedRoots: [work.secret] })
    expect(await dispatch(ctx, execOf('read', { file_path: join(work.root, 'shortcut.txt') }))).toMatchObject({ kind: 'deny' })
  })

  it('matches a forward-slash denied root against a native-separator target', async () => {
    const ctx = await mounted({ deniedRoots: [work.secret.replaceAll('\\', '/')] })
    expect(await dispatch(ctx, execOf('read', { file_path: join(work.secret, 'x.txt') }))).toMatchObject({ kind: 'deny' })
  })

  it('denies lexically when the target does not exist', async () => {
    const ctx = await mounted({ deniedRoots: [work.secret] })
    expect(await dispatch(ctx, execOf('read', { file_path: join(work.secret, 'no-such-file.txt') }))).toMatchObject({ kind: 'deny' })
  })
})

describe('unfenced and malformed input', () => {
  it('passes tools outside the table without inspecting them', async () => {
    const ctx = await mounted({ deniedRoots: [work.secret] })
    expect(await dispatch(ctx, execOf('web_search', { query: 'top secret' }))).toEqual(PASS_THROUGH)
    expect(await dispatch(ctx, execOf('mystery_tool', { file_path: join(work.secret, 'x.txt') }))).toEqual(PASS_THROUGH)
  })

  it('yields no candidates for arguments that do not conform, leaving rejection to the tool\'s own schema', async () => {
    const ctx = await mounted({ deniedRoots: [work.secret] })
    expect(await dispatch(ctx, execOf('read', { file_path: 123 }))).toEqual(PASS_THROUGH)
    expect(await dispatch(ctx, execOf('bash', 'not an object'))).toEqual(PASS_THROUGH)
  })
})

describe('the system-prompt section', () => {
  it('renders the canonical roots when the plugin mounts before systemPrompt', async () => {
    const ctx = new Context()
    await ctx.plugin(DenyPolicy, { deniedRoots: [work.secret] })
    await ctx.plugin(SystemPrompt, { persona: '' })
    const prompt = renderPrompt(await ctx.systemPrompt.assemble())
    expect(prompt).toContain('fs-deny-policy')
    // .native matches the plugin's canonicalPath: it expands Windows 8.3
    // aliases (a runner's TEMP is short-named), the JS realpath does not.
    expect(prompt).toContain(JSON.stringify(realpathSync.native(work.secret)))
  })

  it('renders nothing with an empty deny list', async () => {
    const ctx = new Context()
    await ctx.plugin(DenyPolicy, { deniedRoots: [] })
    await ctx.plugin(SystemPrompt, { persona: '' })
    expect(renderPrompt(await ctx.systemPrompt.assemble())).not.toContain('fs-deny-policy')
  })
})

describe('disposal unwinds every registration', () => {
  it('drops the fence listener and the prompt section', async () => {
    const ctx = new Context()
    const fiber = await ctx.plugin(DenyPolicy, { deniedRoots: [work.secret] })
    expect(await dispatch(ctx, execOf('read', { file_path: join(work.secret, 'x.txt') }))).toMatchObject({ kind: 'deny' })

    await fiber.dispose()
    expect(await dispatch(ctx, execOf('read', { file_path: join(work.secret, 'x.txt') }))).toEqual(PASS_THROUGH)

    await ctx.plugin(SystemPrompt, { persona: '' })
    expect(renderPrompt(await ctx.systemPrompt.assemble())).not.toContain('fs-deny-policy')
  })
})
