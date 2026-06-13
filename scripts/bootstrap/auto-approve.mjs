#!/usr/bin/env node
// auto-approve.mjs — drive the single GitHub click the App Manifest flow mandates.
//
// GitHub has no API to create or install an App; this is the browser robot that performs the one
// human-consent step on your behalf, using a logged-in browser profile (org owner).
//
// Invoked by `fxapp register`. Inputs come from env; the ONLY thing written to stdout is a single
// JSON result line — all diagnostics go to stderr — so the Rust caller can parse it cleanly.
//
//   FXAPP_MODE            "create" | "install"
//   FXAPP_AUTO_APPROVE    "1" => headless auto-click; "0" => headful, human clicks once
//   FXAPP_BROWSER_PROFILE chromium user-data-dir with a GitHub session (org owner). Empty => fresh
//                         headful context so you can log in interactively.
//   create mode:  FXAPP_CREATE_URL, FXAPP_MANIFEST (JSON string), FXAPP_STATE, FXAPP_REDIRECT
//   install mode: FXAPP_INSTALL_URL
//
// create  → stdout {"code": "...", "state": "..."}
// install → stdout {"installed": true, "installation_id": <number|null>}

import { chromium } from 'playwright';

const log = (...a) => console.error('[approver]', ...a);
const emit = (obj) => process.stdout.write(JSON.stringify(obj) + '\n');
const env = (k, d) => (process.env[k] !== undefined && process.env[k] !== '' ? process.env[k] : d);

const mode = env('FXAPP_MODE', 'create');
const auto = env('FXAPP_AUTO_APPROVE', '0') === '1';
const profile = env('FXAPP_BROWSER_PROFILE', '');

async function openContext() {
  // auto-approve ⇒ headless (needs a profile already logged in). Otherwise headful for the human.
  const headless = auto && profile !== '';
  const userDataDir = profile || ''; // '' => ephemeral persistent context
  log(`launching chromium (headless=${headless}, profile=${profile || '<ephemeral>'})`);
  return chromium.launchPersistentContext(userDataDir, {
    headless,
    args: ['--no-first-run', '--no-default-browser-check'],
  });
}

async function shot(page, tag) {
  try {
    const path = `/tmp/fxapp-approver-${mode}-${tag}.png`;
    await page.screenshot({ path, fullPage: true });
    log(`screenshot → ${path}`);
  } catch (e) {
    log(`screenshot failed: ${e.message}`);
  }
}

async function create(ctx) {
  const createUrl = env('FXAPP_CREATE_URL');
  const manifest = env('FXAPP_MANIFEST');
  const redirect = env('FXAPP_REDIRECT');
  if (!createUrl || !manifest) throw new Error('create mode needs FXAPP_CREATE_URL + FXAPP_MANIFEST');

  const page = await ctx.newPage();
  // GitHub's manifest flow is a cross-origin form POST of the `manifest` field. Auto-submit it.
  const html = `<!doctype html><meta charset="utf-8"><body>
    <form id="f" method="post" action="${createUrl.replace(/"/g, '&quot;')}">
      <input type="hidden" name="manifest" id="m">
    </form>
    <script>
      document.getElementById('m').value = ${JSON.stringify(manifest)};
      document.getElementById('f').submit();
    </script></body>`;
  await page.setContent(html, { waitUntil: 'domcontentloaded' });
  log('submitted manifest to GitHub; awaiting the create page…');

  if (auto) {
    const candidates = [
      page.getByRole('button', { name: /Create GitHub App/i }),
      page.locator('button[type="submit"]'),
      page.locator('input[type="submit"]'),
    ];
    let clicked = false;
    for (const c of candidates) {
      try {
        await c.first().click({ timeout: 20000 });
        clicked = true;
        log('clicked "Create GitHub App"');
        break;
      } catch { /* try next selector */ }
    }
    if (!clicked) {
      await shot(page, 'no-create-button');
      throw new Error('could not find the "Create GitHub App" button (see screenshot)');
    }
  } else {
    log('MANUAL: click "Create GitHub App" in the opened window (you have 3 min)…');
  }

  await page.waitForURL(
    (u) => {
      try {
        return new URL(u).searchParams.has('code');
      } catch {
        return false;
      }
    },
    { timeout: 180000 },
  );
  const url = new URL(page.url());
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state') || '';
  if (!code) throw new Error('redirect carried no ?code=');
  log(`captured code (state=${state})`);
  emit({ code, state });
}

async function install(ctx) {
  const installUrl = env('FXAPP_INSTALL_URL');
  if (!installUrl) throw new Error('install mode needs FXAPP_INSTALL_URL');
  const page = await ctx.newPage();
  await page.goto(installUrl, { waitUntil: 'domcontentloaded' });

  // The install screen offers "Install" (or "Install & Authorize"). For a single org target GitHub
  // often shows one primary button; if it asks where to install, the org should already be selected.
  const candidates = [
    page.getByRole('button', { name: /Install & Authorize|^Install$/i }),
    page.getByRole('button', { name: /Install/i }),
    page.locator('button[type="submit"]'),
  ];
  let clicked = false;
  for (const c of candidates) {
    try {
      await c.first().click({ timeout: 20000 });
      clicked = true;
      log('clicked Install');
      break;
    } catch { /* try next */ }
  }
  if (!clicked) {
    await shot(page, 'no-install-button');
    throw new Error('could not find the Install button (see screenshot)');
  }

  let installationId = null;
  try {
    await page.waitForURL((u) => /installation_id=\d+/.test(u) || /installations\/\d+/.test(u), {
      timeout: 120000,
    });
    const m = page.url().match(/installation_id=(\d+)/) || page.url().match(/installations\/(\d+)/);
    if (m) installationId = Number(m[1]);
  } catch {
    log('installed, but could not read installation_id from the URL');
  }
  emit({ installed: true, installation_id: installationId });
}

const ctx = await openContext();
try {
  if (mode === 'create') await create(ctx);
  else if (mode === 'install') await install(ctx);
  else throw new Error(`unknown FXAPP_MODE: ${mode}`);
} catch (e) {
  log(`ERROR: ${e.message}`);
  process.exitCode = 1;
} finally {
  await ctx.close();
}
