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

export function signIn(popup) {
  if (popup && !navigator.userAgentData?.mobile) {
    const {innerWidth, innerHeight} = window;
    const left = Math.round((innerWidth - 640)/2);
    const top = Math.round((innerHeight - 480)/2);
    const w = window.open(String(new URL("/login", authDomain)), 'signin', `popup,width=640,height=480,left=${left},top=${top}`);

    window.addEventListener('message', async (e) => {
      const event = e.data;
      try {
        const detail = event === 'signin' ? await getProfile() : null;
        events.dispatchEvent(new CustomEvent(event, { detail }));
        if (event === 'signin') {
          w.close();
        }
      } catch {
        events.dispatchEvent(new CustomEvent('signout', { detail: true }));
        w.close();
      }
    });
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

