const authDomain = "https://__API_URL__";
const fetchOptions = { credentials: "include", mode: "cors" };

export const events = new EventTarget();

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
  const url = new URL(
    "/login?url=" + encodeURIComponent(location.href),
    authDomain
  );

  if (popup && !navigator.userAgentData?.mobile) {
    const w = window.open(String(url), 'signin', 'popup');

    w.onmessage = async (e) => {
      const event = e.data;
      try {
        const detail = event === 'signin' ? await getProfile() : null;
        events.dispatchEvent(new CustomEvent(event, { detail }));
      } catch {
        events.dispatchEvent(new CustomEvent('signout', { detail: true }));
      }
    };
    return;
  }

  location.href = String(url);
}

export async function signOut() {
  const r = await fetch(authDomain, {
    ...fetchOptions,
    method: "DELETE",
  });

  const ok = await toBoolean(r);
  events.dispatchEvent(new CustomEvent('signout', { detail: ok }));
  return ok;
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

