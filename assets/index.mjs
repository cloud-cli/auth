const authDomain = "https://__API_URL__";
const commandQueue = {};
let popup = null;

const embedded = new Promise((resolve, reject) => {
  const frame = document.createElement("iframe");
  frame.src = String(new URL("/embed", authDomain));

  Object.assign(frame.style, {
    width: "1px",
    height: "1px",
    visibility: "hidden",
    zIndex: "2",
    position: "absolute",
    bottom: "-10px",
    right: "-10px",
  });

  frame.onload = () => resolve(frame.contentWindow);
  frame.onerror = (e) => reject(e);

  const init = () => {
    document.body.append(frame);
    setInterval(
      () => !popup && frame.contentWindow.postMessage({ command: "ping" }, authDomain),
      1000 * 30
    );
  };

  if (['complete', 'interactive'].includes(document.readyState)) {
    init();
  } else {
    window.addEventListener("DOMContentLoaded", init);
  }
});

window.addEventListener("message", (e) => {
  if (e.origin !== authDomain) {
    console.log("Unsafe event", e);
  }

  const { event, detail } = e.data || {};

  if (!event) {
    return;
  }

  switch (event) {
    case "error":
      if (commandQueue[detail.id]) {
        commandQueue[detail.id].reject(detail.error);
        delete commandQueue[detail.id];
      }
      break;
    case "success":
      if (commandQueue[detail.id]) {
        commandQueue[detail.id].resolve(detail.result);
        delete commandQueue[detail.id];
      }
      break;
    case "signin":
      if (popup) {
        popup.close();
        popup = null;
      }

      events.dispatchEvent(new CustomEvent("state", { detail }));
      break;

    default:
      events.dispatchEvent(new CustomEvent(event, { detail }));
  }
});

export const events = new EventTarget();
export function postMessage(message) {
  embedded.then((window) => window.postMessage(message));
}

export function signIn(usePopUp) {
  if (usePopUp) {
    const { innerWidth, innerHeight } = window;
    const left = Math.round((innerWidth - 640) / 2);
    const top = Math.round((innerHeight - 480) / 2);

    popup = window.open(
      String(new URL("/login", authDomain)),
      "signin",
      `popup,width=640,height=480,left=${left},top=${top}`
    );
    return;
  }

  const url = new URL(
    "/login?url=" + encodeURIComponent(location.href),
    authDomain
  );

  location.href = String(url);
}

function fetchCommand(command, runAfter) {
  return async (...args) =>
    new Promise((resolve, reject) => {
      const id = Math.random();
      commandQueue[id] = {
        resolve: (x) => {
          runAfter && runAfter(x);
          resolve(x);
        },
        reject,
      };
      embedded.then((w) => w.postMessage({ id, command, args }, authDomain));
    });
}

let ns = location.host;
const getNS = (p) => ns + ":" + p;

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

export const getProperty = fetchCommand("getProperty");
export const setProperty = fetchCommand("setProperty");
export const deleteProperty = fetchCommand("deleteProperty");
export const getProperties = fetchCommand("getProperties");
export const getProfile = fetchCommand("getProfile");
export const isAuthenticated = fetchCommand("isAuthenticated");
export const signOut = fetchCommand("signOut", () => {
  events.dispatchEvent(new CustomEvent("signout"));
  events.dispatchEvent(new CustomEvent("state", { detail: null }));
});

async function onload() {
  try {
    const profile = await getProfile();
    events.dispatchEvent(new CustomEvent("signin"));
    events.dispatchEvent(new CustomEvent("state", { detail: profile }));
  } catch {
    events.dispatchEvent(new CustomEvent("signout"));
    events.dispatchEvent(new CustomEvent("state", { detail: null }));
  }
}

if (['complete', 'interactive'].includes(document.readyState)) {
  onload();
} else {
  window.addEventListener("DOMContentLoaded", onload);
}
