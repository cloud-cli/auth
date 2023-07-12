import express from "express";
import { Resource, Query } from "@cloud-cli/store";
import { readFileSync } from "fs";
import { UserProperty, initUser } from "./user.js";
import session from "./session.js";
import passport, { callback } from "./passport.js";

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

function makeProfile(user) {
  return makePage(
    "Profile",
    `<div class="bg-gray-100 h-screen w-screen flex items-center justify-center">
      <div class="bg-white rounded-xl mx-auto p-8 border shadow-lg">
        <figure>
          <img class="w-24 h-24 rounded-full mx-auto" src="${user.photo}" alt="" width="384" height="512" />
          <figcaption class="block pt-4 text-center">Hello, ${user.displayName}!<br/><span class="text-sm text-gray-400">${user.id}</span></figcaption>
        </figure>
        <hr class="mt-4" />
        <button type="button" onclick="l()" class="block bg-white text-gray-800 p-2 text-sm rounded shadow border border-gray-800 mt-4 mx-auto">Logout</button>
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

app.get("/login", (_, res) => res.send(makeLoginPage()));
app.head("/", protectedRoute, (_req, res) => res.status(204).send(""));
app.get("/", protectedRouteWithRedirect, (req, res) => res.send(req.user));
app.delete("/", protectedRoute, logout);
app.get("/me", protectedRoute, getProfile);
app.get("/auth/google", passport.authenticate("google", scopes));
app.get(callback, passport.authenticate("google", scopes));
app.get("/auth.js", (req, res) => {
  const es = esLibrary.replace("__API_URL__", req.get("x-forwarded-for"));
  res.set("content-type", "text/javascript").send(es);
});

app.put("/properties", protectedRoute, (req, res) => {
  const a = [];
  req.on("data", (c) => a.push(c));
  req.on("end", async () => {
    try {
      const payload = JSON.parse(Buffer.concat(a).toString("utf8"));
      const { key, value } = payload;
      const found = await Resource.find(UserProperty, new Query<UserProperty>().where('userId').is(req.user?.id).where('key').is(key));

      if (found.length) {
        const property = found[0];
        property.value = value;
        await property.save();
        res.status(200).send(property);
        return;
      }

      const propertyId = await new UserProperty({
        userId: req.user?.id,
        key,
        value,
      }).save();

      const property = await new UserProperty({ uid: propertyId }).find();

      res.status(200).send(property);
    } catch (e) {
      console.log(e);
      res.status(500).send("");
    }
  });
});

app.get("/properties", protectedRoute, async (req, res) => {
  const uid = req.user.id;

  const entries = await Resource.find(
    UserProperty,
    new Query<UserProperty>().where("userId").is(uid)
  );

  const properties = entries.map((p) => ({ key: p.key, value: p.value }));
  res.status(200).send(properties);
});

app.delete("/properties/:key", protectedRoute, async (req, res) => {
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

const PORT = Number(process.env.PORT);
app.listen(PORT, async () => {
  await initUser();
  console.log("Auth is running on port " + PORT);
});
