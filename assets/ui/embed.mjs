import { runCommand } from '/lib.mjs';
const allowedOrigins = __EMBED_ALLOWED_ORIGINS__;
window.addEventListener('message', (event) => {
  try {
    const hostname = new URL(event.origin).hostname;
    const allowed = allowedOrigins.some((value) => {
      if (value === event.origin) return true;
      const domain = value.replace(/^https?:\/\//, '').replace(/^\./, '').split('/')[0];
      return domain && (hostname === domain || hostname.endsWith('.' + domain));
    });
    if (allowed) runCommand(event);
  } catch {}
});
