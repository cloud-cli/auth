import express from "express";
import { readFileSync } from "fs";
import { User, findByProfileId, initUser } from "./user.js";
import session from "./session.js";
import passport, { callback } from "./passport.js";
import {
  getProperties,
  removeProperty,
  getProperty,
  setProperty,
} from "./properties.js";

const googleSvg = readFileSync("./assets/google.svg", "utf8");
const esLibrary = readFileSync("./assets/auth.js", "utf8");

function protectedRoute(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).send(makeLoginPage());
  }

  next();
}

function protectedRouteWithRedirect(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    const returnUrl = req.get("referrer") || req.get("referer");
    res.set("Location", "/login?url=" + returnUrl);
    return res.status(401).send("");
  }

  next();
}

function logout(req, res) {
  req.logout((err) =>
    err ? res.status(500).send("") : res.status(202).send("OK")
  );
}

async function getProfile(req, res) {
  res.send(makeProfile(await findByProfileId(req.user.id)));
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
  </head>
  <body>`,
    page,
    `</body>
  </html>`,
  ].join("");
}

function makeLoginPage() {
  return makePage(
    "Sign in to continue",
    `<div class="bg-gray-100 h-screen w-screen flex items-center justify-center">
      <div class="text-center p-4 bg-white rounded-lg shadow">
        <h1 class="text-2xl font-bold mb-6">Hello!</h1>
        <a href="/auth/google" class="bg-white border text-gray-800 px-4 py-2 rounded shadow flex items-center justify-center">
          ${googleSvg}
          Sign in with Google
        </a>
      </div>
      <script>(function(){sessionStorage.url=[...new URLSearchParams(location.search)].find(p=>p[0]==="url")?.[1] || ''})()</script>`
  );
}

function makeProfile(user: User) {
  return makePage(
    "Profile",
    `<div class="bg-gray-100 h-screen w-screen flex items-center justify-center">
      <div class="bg-white rounded-xl mx-auto p-8 border shadow-lg">
        <figure>
          <img class="w-24 h-24 rounded-full mx-auto" src="${user.photo}" alt="" width="384" height="512" />
          <figcaption class="block pt-4 text-center">Hello, ${user.name}!<br/><span class="text-sm text-gray-400">${user.userId}</span></figcaption>
        </figure>
        <hr class="mt-4" />
        <button type="button" onclick="l()" class="block bg-white text-gray-800 p-2 text-sm rounded shadow border border-gray-200 mt-4 mx-auto">Logout</button>
      </div>
    </div>
    <script>
    async function l(){await fetch('/',{method:'DELETE'});location.href='/login';}
    addEventListener('DOMContentLoaded',() => {const n = sessionStorage.url || '';n&&setTimeout(()=>location.href=n,1000);})
    </script>`
  );
}

const scopes = {
  scope: ["profile", "email"],
  failureRedirect: "/login",
  successRedirect: "/me",
};

const app = express();

app.use(session);
app.use(passport.initialize());
app.use(passport.session());

app.get("/", protectedRouteWithRedirect, (req, res) => res.send(req.user));
app.head("/", protectedRoute, (_req, res) => res.status(204).send(""));
app.delete("/", protectedRoute, logout);
app.get("/login", (_, res) => res.send(makeLoginPage()));
app.get("/me", protectedRoute, getProfile);
app.get("/auth/google", passport.authenticate("google", scopes));
app.get(callback, passport.authenticate("google", scopes));

app.get("/auth.js", (req, res) => {
  const es = esLibrary.replace("__API_URL__", req.get("x-forwarded-for"));
  res
    .set("Content-Type", "text/javascript")
    .set("Access-Control-Allow-Origin", "*")
    .send(es);
});

app.put("/properties", protectedRoute, (req, res) => {
  const a = [];
  req.on("data", (c: any) => a.push(c));
  req.on("end", async () => {
    try {
      const payload = JSON.parse(Buffer.concat(a).toString("utf8"));
      const { key, value } = payload;
      const property = await setProperty(req.user?.id, key, value);
      res.status(200).send(property);
    } catch (e) {
      console.log(e);
      res.status(500).send("");
    }
  });
});

app.get("/properties", protectedRoute, async (req, res) => {
  try {
    const properties = await getProperties(req.user.id);
    res.status(200).send(properties);
  } catch (e) {
    res.status(500).send("");
    console.error(e);
  }
});

app.delete("/properties/:key", protectedRoute, async (req, res) => {
  const key = req.params.key;
  const userId = req.user.id;

  if (!key) {
    res.status(400).send("");
    return;
  }

  try {
    await removeProperty(userId, key);
    res.status(202).send("");
  } catch (e) {
    res.status(500).send("");
    console.error(e);
  }
});

app.get("/properties/:key", protectedRoute, async (req, res) => {
  const key = req.params.key;
  const userId = req.user.id;

  if (!key) {
    res.status(400).send("");
    return;
  }

  const property = await getProperty(userId, key);
  if (property) {
    res.status(200).send(property);
    return;
  }

  res.status(404).send("");
});

const PORT = Number(process.env.PORT);
app.listen(PORT, async () => {
  await initUser();
  console.log("Auth is running on port " + PORT);
});
