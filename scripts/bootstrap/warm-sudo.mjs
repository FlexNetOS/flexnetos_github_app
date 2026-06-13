#!/usr/bin/env node
// warm-sudo.mjs — clear GitHub "sudo mode" ONCE in a visible window so the subsequent headless
// approver can perform the sudo-protected App-creation without a passkey prompt. Opens the org
// App-creation page (sudo-protected); you complete the passkey/2FA challenge; it detects that the
// registration form rendered (sudo cleared) and closes. Prints SUDO_OK / SUDO_TIMEOUT.

import { chromium } from 'playwright';

const profile = process.env.FXAPP_BROWSER_PROFILE || `${process.env.HOME}/.fxapp-gh-profile`;
const channel = process.env.FXAPP_BROWSER_CHANNEL || 'chrome';
const org = process.env.FXAPP_ORG || 'FlexNetOS';
const log = (...a) => console.error('[warm-sudo]', ...a);

const ctx = await chromium.launchPersistentContext(profile, {
  headless: false,
  channel,
  args: ['--no-first-run', '--no-default-browser-check'],
});
const page = ctx.pages()[0] || (await ctx.newPage());
await page
  .goto(`https://github.com/organizations/${org}/settings/apps/new`, { waitUntil: 'domcontentloaded' })
  .catch(() => {});
log('Complete the "Confirm access" passkey/2FA challenge. I will detect + close automatically…');

let ok = false;
for (let i = 0; i < 210; i++) {
  // ~7 min
  const url = page.url();
  // sudo cleared ⇒ the "Register new GitHub App" form renders (and we're off the /sessions/ page)
  const onSudo = /\/sessions\/|confirm/i.test(url);
  const hasForm = await page
    .getByRole('heading', { name: /Register new GitHub App/i })
    .isVisible()
    .catch(() => false);
  const hasField = await page
    .locator('#github_app_name, input[name="github_app[name]"]')
    .first()
    .isVisible()
    .catch(() => false);
  if (!onSudo && (hasForm || hasField)) {
    ok = true;
    break;
  }
  await page.waitForTimeout(2000);
}
console.log(ok ? 'SUDO_OK' : 'SUDO_TIMEOUT');
await ctx.close();
