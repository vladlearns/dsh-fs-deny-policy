# dsh-fs-deny-policy

[![npm](https://img.shields.io/npm/v/dsh-fs-deny-policy)](https://www.npmjs.com/package/dsh-fs-deny-policy)
[![CI](https://github.com/vladlearns/dsh-fs-deny-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/vladlearns/dsh-fs-deny-policy/actions/workflows/ci.yml)

A [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) plugin that keeps the model out of folders you don't want it touching.

The harness sandbox can stop the model from *writing* to places, but every sandbox mode still allows reading. This plugin closes that gap: you list a few directories (your `~/.ssh`, a license folder, whatever), and any tool call, that resolves inside them gets denied - reads, writes, searches, and shell commands alike. The model also gets told about the list up front, so it doesn't burn turns bumping into it.

## Install

You need Node.js 22.19 or newer and the `dsh` CLI.

```sh
npx @deepseek-ai/dsh plugin --profile main add dsh-fs-deny-policy
```

That's the whole install — the npm package ships prebuilt, nothing to compile.

Prefer living on source, or want to pin an exact commit? Install from GitHub instead:

```sh
npx @deepseek-ai/dsh plugin --profile main add github:vladlearns/dsh-fs-deny-policy
```

The first run will fail - that's pnpm (≥10) refusing to run a git dependency's build script until you say it's okay. Add this to `~/.dsh/profiles/YOUR_PROFILE/pnpm-workspace.yaml` and run the `add` again:

```yaml
allowBuilds:
  dsh-fs-deny-policy: true
```

That allowance means "I trust this package enough to run its code at install time", so it's worth skimming the source first. Pinning a commit (`github:vladlearns/dsh-fs-deny-policy#<sha>`) keeps a later push from changing what runs.

## Telling it what to deny

The plugin starts out doing nothing (empty deny list, no prompt changes). Deny roots go in your profile's own patch file at `~/.dsh/profiles/YOUR_PROFILE/cordis.patch.yml`:

```yaml
- id: fs-deny-policy
  config:
    deniedRoots:
      - C:/Users/you/.ssh
      - C:/Users/you/Desktop/license-dongle
```

Paths must be absolute. A relative or duplicated entry fails the load with an error naming the offender - better than silently protecting nothing.

Two things:

1. **Install before configuring.** The config above overrides the plugin's row by id; if the plugin isn't installed in that profile yet, there's no row to override and nothing happens. `dsh plugin add` first, then edit the patch file.
2. **Restart after changing the bundle list.** Editing `deniedRoots` in the patch file is picked up live by the running app, but adding or removing the plugin itself needs a restart.

On the first registry install, pnpm may hold the package back as too-new (its supply-chain "minimum release age" gate) and add an exception to the profile's `pnpm-workspace.yaml`. That's expected for a fresh publish; the `add` output tells you when it happened.

`npx @deepseek-ai/dsh --profile main --dump-config` shows the composed configuration - if you can see the deny list in there, it's wired up correctly.

If you only care about writes, `fenceReads: false` turns off the read/search side (write tools are always fenced). There's also `fenceShell` and `fenceContentSearch`, both on by default.

## What it actually checks

Every tool call passes through the `tools/pre-execute` hook before it runs. The plugin parses out the paths the call is about to touch - `file_path` for file tools, the search root for `glob`/`grep`, the workdir plus anything path-shaped in the command text for `bash`/`pwsh` - resolves them against the session's working directory, follows symlinks, and denies anything that lands inside a deny root. Paths under a symlink pointing into a deny root get caught; so do Windows path quirks like differing casing.

## What it won't do

The shell check reads the command text and picks out things that look like paths. It doesn't run the shell, so anything indirect - `$VAR`, `$(...)`, redirections - can slip past it. It's a net, not a wall; if you need a hard guarantee, use it alongside the sandbox, not instead of it.

It also only sees calls that go through the tool pipeline, and there's an unavoidable gap between the check and the file actually being touched (an ancestor symlink swapped in that window wouldn't be caught). And it denies paths lexically, so a nonexistent file inside a deny root is still denied - that's intentional.

## Developing

```sh
npm install
npm test
npm run build
```

`prepare` runs the build automatically on git install, so a fresh clone builds itself.

## License

[MIT](LICENSE)
