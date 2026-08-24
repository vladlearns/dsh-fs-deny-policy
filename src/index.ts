import { isAbsolute } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { canonicalPath } from '@deepseek-ai/dsh-sandbox'
import type { PreToolDecision, ToolExecution } from '@deepseek-ai/dsh-tools'
import type {} from '@deepseek-ai/dsh-system-prompt'
import { z } from 'zod'
import { isPathUnder } from './containment.ts'
import { isFamilyEnabled, TOOL_RULES } from './tool-surface.ts'
import type { FenceSwitches } from './tool-surface.ts'

export const name = 'fs-deny-policy'

const deniedRoot = z.string().refine(root => root.trim().length > 0 && isAbsolute(root), {
  message: 'must be a non-empty absolute path',
})

export const Config = z.strictObject({
  deniedRoots: z.array(deniedRoot)
    .refine(roots => new Set(roots).size === roots.length, { message: 'entries must be unique' })
    .default([]),
  fenceReads: z.boolean().default(true),
  fenceShell: z.boolean().default(true),
  fenceContentSearch: z.boolean().default(true),
})

export type Config = z.infer<typeof Config>

export type ConfigInput = z.input<typeof Config>

function deniedRootsSection(roots: readonly string[]): string {
  const list = roots.map(root => JSON.stringify(root)).join(', ')
  return 'You are forbidden from accessing certain folders (deployment fs-deny-policy). '
    + `Any tool call whose target path resolves under one of these roots is denied by the host: ${list}. `
    + 'Do not read, write, search, or run shell commands against them. '
    + 'If a task requires content under such a path, ask the user to widen the list or copy the file out of it.'
}

export function apply(ctx: Context, config: ConfigInput): void {
  const { deniedRoots, fenceReads, fenceShell, fenceContentSearch } = Config.parse(config)
  const roots = deniedRoots.map(root => canonicalPath(root))
  const switches: FenceSwitches = { fenceReads, fenceShell, fenceContentSearch }

  ctx.on('tools/pre-execute', async (exec: ToolExecution, next): Promise<PreToolDecision> => {
    if (roots.length === 0) return next()
    const rule = TOOL_RULES[exec.name]
    if (rule === undefined || !isFamilyEnabled(rule.family, switches)) return next()

    const cwd = exec.agent?.session.header.cwd ?? process.cwd()
    for (const path of rule.extract(exec.arguments, cwd)) {
      const targetKey = canonicalPath(path.absolute)
      for (const root of roots) {
        if (await isPathUnder(targetKey, root)) {
          return {
            kind: 'deny',
            reason: `path "${path.display}" is under the denied root "${root}" (fs-deny-policy)`,
          }
        }
      }
    }
    return next()
  })

  if (roots.length > 0) {
    ctx.inject(['systemPrompt'], (scope: Context) => {
      scope.systemPrompt.section({
        name: 'fs-deny-policy:denied-roots',
        order: 90,
        text: deniedRootsSection(roots),
      })
    })
  }
}
