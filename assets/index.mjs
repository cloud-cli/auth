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

export async function getProfile() {
  const r = await fetch(authDomain, fetchOptions);
  return toJson(r);
}

export function signIn() {
  location.href = new URL(
    "/login?url=" + encodeURIComponent(location.href),
    authDomain
  );
}

export async function signOut() {
  const r = await fetch(authDomain, {
    ...fetchOptions,
    method: "DELETE",
  });

  return toBoolean(r);
}

export async function getProperties() {
  const r = await fetch(new URL("/properties", authDomain), fetchOptions);
  return await toJson(r);
}

export async function getProperty(property) {
  const r = await fetch(new URL("/properties/" + property, authDomain), fetchOptions);
  return r.ok ? (await toJson(r)).value : '';
}

export async function setProperty(property, value) {
  const r = await fetch(new URL("/properties", authDomain), {
    ...fetchOptions,
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ key: property, value }),
  });

  return toBoolean(r);
}

export async function deleteProperty(key) {
  const r = await fetch(new URL("/properties/" + key, authDomain), {
    ...fetchOptions,
    method: "DELETE",
  });

  return toBoolean(r);
}

