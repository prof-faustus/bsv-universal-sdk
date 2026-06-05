// Build a single-file native Windows .exe with Node's Single Executable Application (SEA).
// Bundles the REAL app + engine into one CJS file, generates the SEA blob, copies node.exe, and
// injects the blob with postject. No Tauri, no webview — a true native PE executable.

import { spawnSync } from 'node:child_process';
import { writeFileSync, copyFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..'); // apps/desktop
const dist = join(root, 'dist');
mkdirSync(dist, { recursive: true });

function run(cmd, args, useShell = process.platform === 'win32') {
  // Note: never use a shell for an absolute path containing spaces (e.g. C:\Program Files\…).
  const r = spawnSync(cmd, args, { stdio: 'inherit', shell: useShell, cwd: root });
  if (r.status !== 0) {
    console.error(`\nstep failed: ${cmd} ${args.join(' ')}`);
    process.exit(1);
  }
}

// 1) bundle ESM app + workspace deps (+ @noble) into one CJS file
run('npx', ['esbuild', 'src/main.ts', '--bundle', '--platform=node', '--format=cjs', '--target=node20', '--outfile=dist/desktop.cjs']);

// 2) SEA config
writeFileSync(
  join(root, 'sea-config.json'),
  JSON.stringify({ main: 'dist/desktop.cjs', output: 'dist/sea-prep.blob', disableExperimentalSEAWarning: true }, null, 2),
);

// 3) generate the SEA blob from this Node (no shell — execPath may contain spaces)
run(process.execPath, ['--experimental-sea-config', 'sea-config.json'], false);

// 4) copy the Node binary to our exe name
const exe = join(dist, 'in-between.exe');
copyFileSync(process.execPath, exe);

// 5) inject the blob (postject) — invoke its CLI directly via Node so paths with spaces and the
// .cmd shim are both avoided (array args, no shell).
const candidates = [
  join(root, 'node_modules', 'postject', 'dist', 'cli.js'),
  join(root, '..', '..', 'node_modules', 'postject', 'dist', 'cli.js'),
];
const postjectCli = candidates.find((p) => existsSync(p));
if (!postjectCli) {
  console.error('postject CLI not found in node_modules');
  process.exit(1);
}
run(
  process.execPath,
  [postjectCli, exe, 'NODE_SEA_BLOB', join(dist, 'sea-prep.blob'), '--sentinel-fuse', 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2'],
  false,
);

console.log(`\n✓ Built native executable: ${exe}`);
