import { homedir } from 'node:os'
import { isAbsolute, join, resolve } from 'node:path'
import { z } from 'zod'

export interface PathCandidate {
  readonly display: string
  readonly absolute: string
}

export type FenceFamily = 'read' | 'write' | 'contentSearch' | 'shell'

export interface FenceSwitches {
  readonly fenceReads: boolean
  readonly fenceShell: boolean
  readonly fenceContentSearch: boolean
}

export function isFamilyEnabled(family: FenceFamily, switches: FenceSwitches): boolean {
  switch (family) {
    case 'write': return true
    case 'read': return switches.fenceReads
    case 'contentSearch': return switches.fenceContentSearch
    case 'shell': return switches.fenceShell
  }
}

export interface ToolRule {
  readonly family: FenceFamily
  readonly extract: (args: unknown, cwd: string) => readonly PathCandidate[]
}

const nonEmpty = z.string().min(1)

const filePathArgs = z.looseObject({ file_path: nonEmpty })
const editorArgs = z.looseObject({ path: nonEmpty })
const searchRootArgs = z.looseObject({ path: nonEmpty })
const shellArgs = z.looseObject({ command: nonEmpty, workdir: nonEmpty.optional() })
const terminalOpenArgs = z.looseObject({ cwd: nonEmpty })
const terminalSendArgs = z.looseObject({ text: nonEmpty })

function parsed<T extends z.ZodType>(schema: T, input: unknown): z.output<T> | undefined {
  const result = schema.safeParse(input)
  return result.success ? result.data : undefined
}

// `~` expands only in shell tokens, where the shell itself would expand it;
// the file tools pass their argument to the backend unresolved.
function candidate(raw: string, cwd: string, expandTilde: boolean): PathCandidate {
  const trimmed = raw.trim()
  const expanded = expandTilde ? expandHome(trimmed) : trimmed
  return { display: trimmed, absolute: resolve(cwd, expanded) }
}

function expandHome(path: string): string {
  if (path === '~') return homedir()
  if (path.startsWith('~/') || path.startsWith('~\\')) return join(homedir(), path.slice(2))
  return path
}

function singleArg<T extends z.ZodType>(schema: T, key: keyof z.output<T>): (args: unknown, cwd: string) => readonly PathCandidate[] {
  return (args, cwd) => {
    const value = parsed(schema, args)?.[key]
    return typeof value === 'string' ? [candidate(value, cwd, false)] : []
  }
}

function shellCandidates(args: unknown, cwd: string): readonly PathCandidate[] {
  const data = parsed(shellArgs, args)
  if (data === undefined) return []
  return [
    ...(data.workdir !== undefined ? [candidate(data.workdir, cwd, false)] : []),
    ...shellPathTokens(data.command).map(p => candidate(p, cwd, true)),
  ]
}

export const TOOL_RULES: Readonly<Record<string, ToolRule>> = {
  read: { family: 'read', extract: singleArg(filePathArgs, 'file_path') },
  read_image: { family: 'read', extract: singleArg(filePathArgs, 'file_path') },
  glob: { family: 'read', extract: singleArg(searchRootArgs, 'path') },
  grep: { family: 'contentSearch', extract: singleArg(searchRootArgs, 'path') },
  write: { family: 'write', extract: singleArg(filePathArgs, 'file_path') },
  edit: { family: 'write', extract: singleArg(filePathArgs, 'file_path') },
  'str_replace_editor': { family: 'write', extract: singleArg(editorArgs, 'path') },
  bash: { family: 'shell', extract: shellCandidates },
  pwsh: { family: 'shell', extract: shellCandidates },
  terminal_open: { family: 'shell', extract: singleArg(terminalOpenArgs, 'cwd') },
  terminal_send: { family: 'shell', extract: (args, cwd) => shellPathTokens(parsed(terminalSendArgs, args)?.text ?? '').map(p => candidate(p, cwd, true)) },
}

export function shellPathTokens(command: string): readonly string[] {
  const tokens: string[] = []
  let current = ''
  let quote: '"' | "'" | undefined

  const flush = () => {
    if (current.length > 0) {
      tokens.push(current)
      current = ''
    }
  }

  for (let i = 0; i < command.length; i += 1) {
    const ch = command.charAt(i)
    if (quote !== undefined) {
      if (ch === quote) quote = undefined
      else current += ch
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      continue
    }
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') {
      flush()
      continue
    }
    current += ch
  }
  flush()

  // a pre-filter over what the command plainly names, not a shell parser:
  // no expansion, substitution or redir eval
  const paths: string[] = []
  let endOfOptions = false
  for (const token of tokens) {
    if (!endOfOptions) {
      if (token === '--') {
        endOfOptions = true
        continue
      }
      if (token.startsWith('-')) continue
    }
    if (looksLikePath(token)) paths.push(token)
  }
  return paths
}

function looksLikePath(token: string): boolean {
  if (token.length === 0) return false
  if (token === '.' || token === '..') return true
  if (isAbsolute(token)) return true
  if (token.startsWith('./') || token.startsWith('../')) return true
  if (token.startsWith('~')) return true
  return token.includes('/') || token.includes('\\')
}
