import express from "express";
import { readFileSync } from "fs";
import { UserProperty, initUser } from "./user.js";
import session from "./session.js";
import passport, { callback } from "./passport.js";
import { Resource, Query } from "@cloud-cli/store";

const PORT = Number(process.env.PORT);
const loginPage = readFileSync("./assets/login.html", "utf8");
const successPage = readFileSync("./assets/success.html", "utf8");

function protectedRoute(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).send(loginPage);
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

function makeProfile(user) {
    return `
<html>
  <head>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css" />
  </head>
  <body>
    <div class="w-screen h-screen flex items-center">
      <div class="bg-gray-100 rounded-xl mx-auto p-8 border shadow-lg">
        <figure>
          <img class="w-24 h-24 rounded-full mx-auto" src="${user.photo}" alt="" width="384" height="512" />
          <figcaption class="block pt-6 text-center">${user.displayName}<br/><span class="text-sm text-gray-400">${user.id}</span></figcaption>
        </figure>
      </div>
    </div>
  </body>
</html>`;
}

const scopes = {
  scope: ["profile", "email"],
  failureRedirect: "/login",
  successRedirect: "/success",
};

const app = express();

app.use(session);
app.use(passport.initialize());
app.use(passport.session());

app.get("/login", (_, res) => res.send(loginPage));
app.get("/success", protectedRoute, (_, res) => res.send(successPage));

app.head("/", protectedRoute, (_req, res) => res.send(""));
app.get("/", protectedRoute, (_req, res) => res.send(true));
app.delete("/", protectedRoute, (req, res, next) =>
  req.logout((err) => (err ? next(err) : res.status(202).send("OK")))
);

app.get("/me", protectedRoute, (req, res) => res.send(makeProfile(req.user)));
app.head("/profile", protectedRoute, (_, res) => res.send(""));
app.get("/profile", protectedRouteWithRedirect, (req, res) =>
  res.send(req.user)
);
app.delete("/profile", protectedRoute, (req, res) =>
  req.logout(() => res.status(202).send("OK"))
);
app.get("/auth/google", passport.authenticate("google", scopes));
app.get(callback, passport.authenticate("google", scopes));

app.put("/property", protectedRoute, (req, res) => {
  const a = [];
  req.on("data", (c) => a.push(c));
  req.on("end", async () => {
    try {
      const payload = JSON.parse(Buffer.concat(a).toString("utf8"));
      const { key, value } = payload;
      const { id } = req.user;
      const propertyId = await new UserProperty({
        userId: id,
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
