const authDomain = "__API_URL__";
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

  return toBoolean(r);
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

function ping() {
  return 'pong';
}

const commands = {
  getProfile,
  isAuthenticated,
  signOut,
  getProperties,
  getProperty,
  setProperty,
  deleteProperty,
  ping,
};

/**
 * @param {MessageEvent} event
 */
export async function runCommand(event) {
  const { command, args, id } = event.data;

  try {
    if (command in commands === false) {
      throw new Error('Invalid command: ' + command);
    }

    const result = await commands[command].apply(null, args);
    event.source.postMessage({ event: 'success', detail: { id, result } }, event.origin);
  } catch (error) {
    event.source.postMessage({ event: 'error', detail: { id, error } }, event.origin);
  }
}