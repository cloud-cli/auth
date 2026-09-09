import { runCommand } from '/lib.mjs';
const allowedOrigins = __EMBED_ALLOWED_ORIGINS__;
window.addEventListener('message', (event) => {
  if (allowedOrigins.includes(event.origin)) runCommand(event);
});
