import express from "express";
import { readFileSync } from "fs";
import { UserProperty, initUser } from "./user.js";
import session from "./session.js";
import passport, { callback } from "./passport.js";
import { Resource, Query } from "@cloud-cli/store";

const PORT = Number(process.env.PORT);
const googleSvg = readFileSync("./assets/google.svg", "utf8");

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

function getProfile(req, res) {
  res.send(makeProfile(req.user));
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
      <div class="text-center">
        <h1 class="text-2xl font-bold mb-6">Hello!</h1>
        <a href="/auth/google" class="bg-gray-200 text-gray-700 px-4 py-2 rounded shadow flex items-center justify-center">
          <img alt="Google Logo" class="w-6 h-6 mr-2" src="/google.svg">
          Sign in with Google
        </a>
      </div>
      <script>(function(){sessionStorage.url=[...new URLSearchParams(location.search)].find(p=>p[0]==="url")?.[1] || ''})()</script>`
  );
}

function makeProfile(user) {
  return makePage(
    "Profile",
    `<div class="bg-gray-100 h-screen w-screen flex items-center justify-center">
      <div class="bg-white rounded-xl mx-auto p-8 border shadow-lg">
        <figure>
          <img class="w-24 h-24 rounded-full mx-auto" src="${user.photo}" alt="" width="384" height="512" />
          <figcaption class="block pt-4 text-center">Hello, ${user.displayName}!<br/><span class="text-sm text-gray-400">${user.id}</span></figcaption>
        </figure>
        <button type="button" onclick="l()" class="bg-gray-300 text-gray-800 px-4 py-2 rounded shadow border border-gray-800">Logout</button>
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

app.get("/google.svg", (_, res) => res.send(googleSvg));
app.get("/login", (_, res) => res.send(makeLoginPage()));
app.head("/", protectedRoute, (_req, res) => res.status(204).send(""));
app.get("/", protectedRouteWithRedirect, (req, res) => res.send(req.user));
app.delete("/", protectedRoute, logout);
app.get("/me", protectedRoute, getProfile);
app.get("/auth/google", passport.authenticate("google", scopes));
app.get(callback, passport.authenticate("google", scopes));

app.put("/property", protectedRoute, (req, res) => {
  const a = [];
  req.on("data", (c) => a.push(c));
  req.on("end", async () => {
    try {
      const payload = JSON.parse(Buffer.concat(a).toString("utf8"));
      const { key, value } = payload;
      const propertyId = await new UserProperty({ userId: req.user?.id, key, value }).save();
      const property = await new UserProperty({ uid: propertyId }).find();

      res.status(200).send(property);
    } catch (e) {
      console.log(e);
      res.status(500).send("");
    }
  });
});

app.delete("/property/:key", protectedRoute, async (req, res) => {
  const key = req.params.key;
  const uid = req.user.id;

  if (!key) {
    res.status(400).send("");
    return;
  }

  const entries = await Resource.find(
    UserProperty,
    new Query<UserProperty>().where("key").is(key).where("userId").is(uid)
  );
  for (const p of entries) {
    await p.remove();
  }

  res.status(202).send("");
});

app.listen(PORT, async () => {
  await initUser();
  console.log("Auth is running on port " + PORT);
});
