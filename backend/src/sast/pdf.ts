/**
 * Rendering a report to a PDF file, on the server.
 *
 * The report is a print-styled HTML document: A4 pages, running headers, page
 * numbers. Chrome's own print-to-PDF is the one engine that honours all of it,
 * so that is what runs here. Without it the console falls back to the browser's
 * print dialog, which produces the same pages with one more click.
 *
 * The HTML arrives from the console, which builds it. That makes this endpoint
 * a way to make the server open arbitrary markup, so it is treated as untrusted:
 * scripts, frames and anything that would fetch a resource are stripped, and the
 * browser is started with name resolution switched off so a link that survives
 * still has nowhere to go. The report needs none of those things — every image
 * in it is an embedded data URL.
 */
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { accessSync, constants, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';

/** Upper bound on the HTML we will render. A 180-page report is about 2 MB. */
export const MAX_REPORT_HTML_BYTES = 24 * 1024 * 1024;
const RENDER_TIMEOUT_MS = 90_000;

const CANDIDATES = [
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/snap/bin/chromium',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
];

/** The browser to render with: `KAVACH_CHROME` if set, otherwise the first one found. */
export function findChrome(env: NodeJS.ProcessEnv = process.env): string | undefined {
  if (env.KAVACH_CHROME) return existsSync(env.KAVACH_CHROME) ? env.KAVACH_CHROME : undefined;
  return CANDIDATES.find((path) => existsSync(path));
}

const QPDF_FALLBACKS = ['/opt/homebrew/bin/qpdf', '/usr/local/bin/qpdf', '/usr/bin/qpdf'];

function isExecutable(path: string): boolean {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * `qpdf`, which locks the finished PDF with a password. Chrome cannot encrypt, so
 * this is a second step: `KAVACH_QPDF` if set, then PATH, then the usual install
 * locations.
 */
export function findQpdf(env: NodeJS.ProcessEnv = process.env): string | undefined {
  if (env.KAVACH_QPDF) return isExecutable(env.KAVACH_QPDF) ? env.KAVACH_QPDF : undefined;
  for (const dir of (env.PATH ?? '').split(delimiter)) {
    if (dir && isExecutable(join(dir, 'qpdf'))) return join(dir, 'qpdf');
  }
  return QPDF_FALLBACKS.find((path) => isExecutable(path));
}

/** Longest password qpdf's 256-bit scheme will honour: it ignores everything past 127 bytes. */
export const MAX_PASSWORD_BYTES = 127;
export const MIN_PASSWORD_LENGTH = 8;

/** Why a password cannot be used, or undefined when it is fine. */
export function passwordProblem(password: unknown): string | undefined {
  if (typeof password !== 'string') return 'password must be text';
  if ([...password].length < MIN_PASSWORD_LENGTH) return `password must be at least ${MIN_PASSWORD_LENGTH} characters`;
  if (Buffer.byteLength(password) > MAX_PASSWORD_BYTES) return `password must be at most ${MAX_PASSWORD_BYTES} bytes`;
  if (/[\r\n\0]/.test(password)) return 'password must be on one line';
  // qpdf reads a leading dash as the start of another option.
  if (password.startsWith('-')) return 'password must not start with a dash';
  return undefined;
}

/**
 * Encrypts a PDF so it asks for `password` to open (AES-256).
 *
 * The password goes to qpdf on standard input as an argument file, never on the
 * command line, where any local user could read it from the process list. The
 * owner password is random and thrown away: it exists only so the document's
 * restrictions cannot be lifted with the one the reader was given. Printing and
 * copying stay allowed (a reader copies a digest out of this report); editing and
 * form changes do not.
 */
export async function protectPdf(pdf: Buffer, password: string, qpdf: string): Promise<Buffer> {
  const problem = passwordProblem(password);
  if (problem) throw new Error(problem);
  const dir = mkdtempSync(join(tmpdir(), 'kavach-pdf-'));
  const input = join(dir, 'in.pdf');
  const output = join(dir, 'out.pdf');
  writeFileSync(input, pdf, { mode: 0o600 });
  try {
    await new Promise<void>((resolve, reject) => {
      const child = spawn(qpdf, ['@-'], { stdio: ['pipe', 'ignore', 'pipe'] });
      let stderr = '';
      child.stderr.on('data', (chunk) => { stderr += String(chunk).slice(0, 500); });
      child.on('error', reject);
      child.on('exit', (code) => {
        // Exit 3 is "finished with warnings", which still wrote a valid file.
        if ((code === 0 || code === 3) && existsSync(output)) resolve();
        else reject(new Error(`qpdf failed (${code}): ${stderr.replace(password, '***').trim()}`));
      });
      // One argument per line; the passwords are the only lines that vary.
      const args = ['--encrypt', password, randomBytes(24).toString('hex'), '256', '--modify=none', '--', input, output];
      child.stdin.end(args.join('\n') + '\n');
    });
    return readFileSync(output);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Removes everything that could run code or fetch a resource.
 *
 * Deliberately blunt: the report contains no scripts, frames or remote
 * resources, so anything that looks like one is not ours. Only fragment links,
 * mail links and embedded data URLs are kept.
 */
export function sanitizeReportHtml(html: string): string {
  return html
    .replace(/<script\b[\s\S]*?<\/script\s*>/gi, '')
    .replace(/<(iframe|object|embed|frame|frameset|applet|base|link|form)\b[\s\S]*?(<\/\1\s*>|\/?>)/gi, '')
    .replace(/<meta\b[^>]*http-equiv[^>]*>/gi, '')
    .replace(/\son[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    .replace(/\s(src|href|poster|action|formaction|xlink:href)\s*=\s*("([^"]*)"|'([^']*)')/gi, (match, attr, _q, dq, sq) => {
      const value = String(dq ?? sq ?? '').trim();
      return /^(#|mailto:|data:image\/(png|jpe?g|gif|webp);base64,)/i.test(value) ? match : ` ${attr}="#"`;
    })
    // The look-ahead has to take the optional quote itself: with the quote in a capture group the
    // engine backtracks to "no quote", and a quoted data URL then fails the check and is stripped.
    .replace(/url\(\s*(?!['"]?(?:data:image\/|#))[^)]*\)/gi, 'none')
    .replace(/@import\s+[^;]+;/gi, '');
}

/** One render at a time: Chrome is heavy and a queue is kinder than a stampede. */
let queue: Promise<unknown> = Promise.resolve();

export async function renderPdf(html: string, chrome: string): Promise<Buffer> {
  const run = queue.then(() => render(html, chrome));
  queue = run.catch(() => undefined);
  return run;
}

async function render(html: string, chrome: string): Promise<Buffer> {
  const dir = mkdtempSync(join(tmpdir(), 'kavach-pdf-'));
  const input = join(dir, 'report.html');
  const output = join(dir, 'report.pdf');
  writeFileSync(input, sanitizeReportHtml(html));

  const args = [
    '--headless=new',
    '--disable-gpu',
    '--no-pdf-header-footer',
    // Bookmarks: the app name from the cover heading, with the report's sections and findings under it.
    '--generate-pdf-document-outline',
    `--user-data-dir=${join(dir, 'profile')}`,
    // No name resolution: a reference that slipped past the sanitiser cannot reach anything.
    '--host-resolver-rules=MAP * ~NOTFOUND',
    '--disable-extensions',
    '--no-first-run',
    `--print-to-pdf=${output}`,
  ];
  // A container usually runs as root, where Chrome's sandbox refuses to start. A host that cannot give it
  // unprivileged user namespaces can opt out with KAVACH_CHROME_NO_SANDBOX (see DEPLOYMENT.md).
  const asRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  if (asRoot || /^(1|true|yes)$/i.test(process.env.KAVACH_CHROME_NO_SANDBOX ?? '')) args.push('--no-sandbox');
  args.push(`file://${input}`);

  const child = spawn(chrome, args, { stdio: 'ignore' });
  let exited = false;
  child.on('exit', () => { exited = true; });

  try {
    const deadline = Date.now() + RENDER_TIMEOUT_MS;
    let lastSize = -1;
    // Chrome sometimes writes the file and then lingers, so the file is the signal,
    // not the exit. Wait for it to stop growing before reading it.
    for (;;) {
      if (existsSync(output)) {
        const size = statSync(output).size;
        if (size > 0 && size === lastSize) break;
        lastSize = size;
      }
      if (exited && !existsSync(output)) throw new Error('the browser exited without producing a PDF');
      if (Date.now() > deadline) throw new Error('rendering timed out');
      await new Promise((resolve) => setTimeout(resolve, 400));
    }
    return readFileSync(output);
  } finally {
    child.kill('SIGKILL');
    rmSync(dir, { recursive: true, force: true });
  }
}
