import express from 'express';
import { readFileSync } from 'fs';
import { findByUserId, userAsJSON } from './user.js';
import { User, initStore } from './store.js';
import session from './session.js';
import log from './log.js';
import passport, { googleCallback, githubCallback } from './passport.js';
import { getProperties, removeProperty, getProperty, setProperty } from './properties.js';

const googleSvg = readFileSync('./assets/google.svg', 'utf8');
const githubSvg = readFileSync('./assets/github.svg', 'utf8');
const esLibrary = readFileSync('./assets/index.mjs', 'utf8');
const esHelper = readFileSync('./assets/lib.mjs', 'utf8');

function protectedRoute(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated() || !req.user?.id) {
    return res.status(401).send(makeLoginPage());
  }

  next();
}

function protectedRouteWithRedirect(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated() || !req.user?.id) {
    const returnUrl = req.get('referrer') || req.get('referer');
    res.set('Location', '/login?url=' + returnUrl);
    return res.status(401).send('');
  }

  next();
}

function logout(req, res) {
  req.logout((err) => (err ? res.status(500).send('') : res.status(202).send('OK')));
}

async function getProfile(req, res) {
  const user = await findByUserId(req.user?.id);

  if (user) {
    res.send(await makeProfile(user));
    return;
  }

  res.status(404).send('{}');
}

function makePage(title: string, page: string) {
  return [
    `<!DOCTYPE html>
  <html lang="en">
  <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>${title}</title>
      <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.16/dist/tailwind.min.css" rel="stylesheet" />
      <script type="module">
      async function load() {
        globalThis.Auth = await import('/index.mjs');
      }
      load();
      </script>
  </head>
  <body>`,
    page,
    `</body>
  </html>`,
  ].join('');
}

function makeLoginPage() {
  return makePage(
    'Sign in to continue',
    `<div class="bg-gray-100 h-screen w-screen flex items-center justify-center px-4">
      <div class="text-center p-4 bg-white rounded-lg shadow">
        <h1 class="text-2xl font-bold mb-6">Hello!</h1>
        <a href="/auth/google" class="bg-white border text-gray-800 px-4 py-2 rounded shadow flex items-center justify-center">
          ${googleSvg}
          Sign in with Google
        </a>
        <a href="/auth/github" class="bg-white border mt-4 text-gray-800 px-4 py-2 rounded shadow flex items-center justify-center mt-2">
          ${githubSvg}
          Sign in with GitHub
        </a>
      </div>
      <script>
      (function(){sessionStorage.url=[...new URLSearchParams(location.search)].find(p=>p[0]==="url")?.[1] || ''})();
      </script>`,
  );
}

async function makeProfile(user: User) {
  const profile = JSON.stringify(user);
  const fields = ['userId', 'profileId', 'accessToken', 'refreshToken'] as Array<keyof User>;
  const fieldsText = fields
    .map((key) => ({ key, value: user[key] || '' }))
    .map(
      ({ key, value }) => `<div class="flex items-center font-mono border-b">
        <span class="w-1/3 p-1">${key}</span>
        <span class="w-2/3 truncate p-1" onclick="$event.target.classList.toggle('truncate')">${value}</span>
      </div>`,
    )
    .join('\n');

  const properties = await getProperties(user.userId);
  const propertiesText = properties
    .map(({ key, value }) => {
      return `<div class="flex items-center font-mono border-b">
      <span class="w-1/3 p-1">${key}</span>
      <span class="w-2/3 flex-1 text-red-500 p-1 truncate">${value}</span>
      <button class="flex-1" onclick="if(confirm('Sure?')){Auth.deleteProperty('${key}');$event.target.parentNode.remove();}">&times;</button>
    </div>`;
    })
    .join('\n');

  return makePage(
    'Profile',
    `<div class="hidden" id="r">Redirecting</div>
    <div class="bg-gray-100 h-screen w-screen flex items-center justify-center p-4 hidden" id="p">
      <div class="bg-white rounded-xl mx-auto p-8 border shadow-lg max-w-full md:max-w-5xl max-h-full overflow-auto">
        <figure>
          <img class="w-24 h-24 rounded-full mx-auto" src="${user.photo}" alt="" width="384" height="512" />
          <figcaption class="block space-y-1">
            <div class="text-center py-4">Hello, ${user.name}!</div>
          </figcaption>
        </figure>
        <hr class="mt-4" />
        <button type="button" onclick="l()" class="block bg-white text-gray-800 p-2 text-sm rounded shadow border border-gray-200 mt-4 mx-auto">Logout</button>
        <hr class="mt-4" />
        <div class="text-sm text-gray-400 space-y-1">
          ${fieldsText}
          ${propertiesText}
        </div>
        <div class="flex items-centers justify-center p-2">
          <button onclick="Auth.setProperty( prompt('Key', ''), prompt('Value', '') );window.location.relaod()">Add</button>
        </div>
      </div>
    </div>
    <script>
    async function l(){await fetch('/',{method:'DELETE'});location.href='/login';}
    addEventListener('DOMContentLoaded',() => {
      const n = sessionStorage.url || '';
      if (n) {
        setTimeout(()=>location.href=n,1000);
        return window.r.classList.add('hidden');
      }

      window.p.classList.remove('hidden');
      (opener||window).postMessage({ event: 'signin', detail: ${profile} }, '*');
    });
    </script>`,
  );
}

async function makeEmbedPage(_req, res) {
  const allowedOrigins = (process.env.EMBED_ALLOWED_ORIGINS || '').split(',').map((s) => s.trim());

  res.send(`<script type="module">
import { runCommand } from '/lib.mjs';
const allowedOrigins = ${JSON.stringify(allowedOrigins)};
window.addEventListener("message", async function (event) {
  if (!allowedOrigins.some(o => event.origin.endsWith(o))) {
    console.log('Origin not allowed: ' + event.origin, event);
    return;
  }

  runCommand(event);
}, false);
</script>`);
}

const googleScopes = {
  scope: ['profile', 'email'],
  failureRedirect: '/login',
  successRedirect: '/me',
};

const githubScopes = {
  scope: ['repo', 'user'],
  failureRedirect: '/login',
  successRedirect: '/me',
};

const app = express();

app.set('trust proxy', 1);
app.use(session);
app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
  res.on('finish', () => {
    const date = new Date().toISOString().slice(0, 19);
    console.log(`[${date}] ${req.method} ${req.url} ${res.statusCode}`);
  });
  next();
});

app.get('/', protectedRouteWithRedirect, async (req, res) => {
  const user = await findByUserId(req.user?.id);
  if (user) {
    res.send(userAsJSON(user));
    return;
  }

  res.status(404).send('{}');
});
app.head('/', protectedRoute, (_req, res) => {
  res.status(204).send('');
});
app.delete('/', protectedRoute, logout);
app.get('/login', (_, res) => {
  res.send(makeLoginPage());
});
app.get('/embed', makeEmbedPage);
app.get('/me', protectedRoute, getProfile);
app.get('/auth/google', passport.authenticate('google', googleScopes));
app.get(googleCallback, passport.authenticate('google', googleScopes));

app.get('/auth/github', passport.authenticate('github', githubScopes));
app.get(githubCallback, passport.authenticate('github', githubScopes));

const serveEsModule = (source) => (req, res) => {
  console.log(req.headers);
  const host = req.headers['x-forwarded-host'] || req.headers['x-forwarded-for'] || 'localhost';
  const es = source.replace('__API_URL__', 'https://' + host);
  res.set('Content-Type', 'text/javascript').set('Access-Control-Allow-Origin', '*').send(es);
};

app.get('/auth.js', serveEsModule(esLibrary));
app.get('/index.js', serveEsModule(esLibrary));
app.get('/index.mjs', serveEsModule(esLibrary));
app.get('/lib.mjs', serveEsModule(esHelper));

app.put('/properties', protectedRoute, async (req, res) => {
  const buffer = Buffer.concat(await req.toArray()).toString('utf8');

  try {
    const payload = JSON.parse(buffer);
    const { key, value } = payload;
    const property = await setProperty(req.user?.id, key, value);
    res.status(200).send(property);
  } catch (e) {
    log(e);
    res.status(500).send('');
  }
});

app.get('/properties', protectedRoute, async (req, res) => {
  try {
    const properties = await getProperties(req.user?.id);
    res.status(200).send(properties);
  } catch (e) {
    res.status(500).send('');
    console.error(e);
  }
});

app.delete('/properties/:key', protectedRoute, async (req, res) => {
  const key = req.params.key;
  const userId = req.user?.id;

  if (!key) {
    res.status(400).send('');
    return;
  }

  try {
    await removeProperty(userId, key);
    res.status(202).send('');
  } catch (e) {
    res.status(500).send('');
    console.error(e);
  }
});

app.get('/properties/:key', protectedRoute, async (req, res) => {
  const key = req.params.key;
  const userId = req.user?.id;

  if (!key) {
    res.status(400).send('');
    return;
  }

  const property = await getProperty(userId, key);
  if (property) {
    res.status(200).send(property);
    return;
  }

  res.status(404).send('');
});

const PORT = Number(process.env.PORT);
app.listen(PORT, async () => {
  await initStore();
  log('Auth is running on port ' + PORT);
});
