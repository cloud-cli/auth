const authDomain = "https://__API_URL__";
const fetchOptions = { credentials: "include", mode: "cors" };

async function toJson(r) {
  if (r.ok) {
    return await r.json();
  }

  throw new Error(r.status + ": " + r.statusText);
}

function toBoolean(r) {
  if (r.ok) {
    return true;
  }

  throw new Error(r.status + ": " + r.statusText);
}

async function getProfile() {
  const r = await fetch(authDomain, fetchOptions);
  return toJson(r);
}

async function isAuthenticated() {
  const r = await fetch(authDomain, { ...fetchOptions, method: "HEAD" });
  return Boolean(r.ok && r.status < 300);
}

async function signOut() {
  const r = await fetch(authDomain, {
    ...fetchOptions,
    method: "DELETE",
  });

  const ok = await toBoolean(r);
  events.dispatchEvent(new CustomEvent("signout", { detail: ok }));
  return ok;
}

async function getProperties() {
  const r = await fetch(new URL("/properties", authDomain), fetchOptions);
  return await toJson(r);
}

async function getProperty(property) {
  const r = await fetch(
    new URL("/properties/" + property, authDomain),
    fetchOptions
  );
  return r.ok ? (await toJson(r)).value : "";
}

async function setProperty(property, value) {
  const r = await fetch(new URL("/properties", authDomain), {
    ...fetchOptions,
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ key: property, value }),
  });

  return toBoolean(r);
}

async function deleteProperty(key) {
  const r = await fetch(new URL("/properties/" + key, authDomain), {
    ...fetchOptions,
    method: "DELETE",
  });

  return toBoolean(r);
}

export const commands = {
  getProfile,
  isAuthenticated,
  signOut,
  getProperties,
  getProperty,
  setProperty,
  deleteProperty,
};
