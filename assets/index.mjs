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

export async function isAuthenticated() {
  const r = await fetch(authDomain, { ...fetchOptions, method: 'HEAD' });
  return Boolean(r.ok && r.status < 300);
}

let popup = null;
let embedded = null;

window.addEventListener('message', (e) => {
  if (e.origin !== authDomain) {
    console.log('Discarded event', e);
    return;
  }

  const { event, detail } = e.data;

  if (!event) {
    return;
  }

  if (event === 'signin' && popup) {
    popup.close();
    popup = null;
  }

  events.dispatchEvent(new CustomEvent(event, { detail }));
});

export function useEmbedded() {
  if (embedded) return;

  embedded = document.createElement('iframe');
  embedded.src = String(new URL("/embed", authDomain));
  document.body.append(embedded);

  setInterval(() => !popup && embedded.contentWindow.postMessage('ping', authDomain), 1000 * 30);
}

export function signIn(usePopUp) {
  if (usePopUp) {
    const { innerWidth, innerHeight } = window;
    const left = Math.round((innerWidth - 640)/2);
    const top = Math.round((innerHeight - 480)/2);

    popup = window.open(String(new URL("/login", authDomain)), 'signin', `popup,width=640,height=480,left=${left},top=${top}`);
    return;
  }

  const url = new URL(
    "/login?url=" + encodeURIComponent(location.href),
    authDomain
  );

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

let ns = location.host;
const getNS = (p) => ns + ':' + p;

export function setNS(newNS) {
  ns = newNS;
}

export function getPropertyNS(property) {
  return getProperty(getNS(property));
}

export function setPropertyNS(property, value) {
  return setProperty(getNS(property), value);
}

export function deletePropertyNS(property) {
  return deleteProperty(getNS(property));
}
