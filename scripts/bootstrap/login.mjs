#!/usr/bin/env node
// login.mjs — seed the approver's browser profile with a GitHub session, using the SAME engine
// (playwright + system channel) the approver uses, so the cookie store is guaranteed reusable.
// Opens a visible window, waits for you to log in (as a FlexNetOS org owner), auto-detects the
// logged-in account, then closes cleanly (flushing cookies). Prints LOGGED_IN_AS=<login>.

import { chromium } from 'playwright';

const profile = (process.env.FXAPP_BROWSER_PROFILE || `${process.env.HOME}/.fxapp-gh-profile`);
const channel = process.env.FXAPP_BROWSER_CHANNEL || 'chrome';
const log = (...a) => console.error('[login]', ...a);

const ctx = await chromium.launchPersistentContext(profile, {
  headless: false,
  channel,
  args: ['--no-first-run', '--no-default-browser-check'],
});
const page = ctx.pages()[0] || (await ctx.newPage());
await page.goto('https://github.com/login', { waitUntil: 'domcontentloaded' }).catch(() => {});
log('Log in as a FlexNetOS org owner (drdave-flexnetos). I will auto-detect and close…');

let who = null;
for (let i = 0; i < 210; i++) {
  // ~7 min
  try {
    const m = await page
      .locator('meta[name="octolytics-actor-login"]')
      .getAttribute('content', { timeout: 1000 });
    if (m) {
      who = m;
      break;
    }
  } catch {
    /* not logged in yet / element absent */
  }
  await page.waitForTimeout(2000);
}
console.log(`LOGGED_IN_AS=${who || 'NONE'}`);
await ctx.close();
