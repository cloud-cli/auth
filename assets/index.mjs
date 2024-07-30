const authDomain = "https://__API_URL__";
const commandQueue = {};

let popup = null;
let embedded = null;

export const events = new EventTarget();

window.addEventListener("message", (e) => {
  if (e.origin !== authDomain) {
    console.log("Discarded event", e);
    return;
  }

  const { event, detail } = e.data;

  if (!event) {
    return;
  }

  switch (event) {
    case "error":
      if (commandQueue[detail.id]) {
        commandQueue[detail.id].reject(detail.error);
      }
      break;
    case "success":
      if (commandQueue[detail.id]) {
        commandQueue[detail.id].resolve(detail.result);
      }
      break;
    case "signin":
      if (popup) {
        popup.close();
        popup = null;
      }
      break;

    default:
      events.dispatchEvent(new CustomEvent(event, { detail }));
  }
});

export function useEmbedded() {
  if (embedded) return;

  embedded = document.createElement("iframe");
  embedded.src = String(new URL("/embed", authDomain));
  document.body.append(embedded);

  setInterval(
    () => !popup && embedded.contentWindow.postMessage("ping", authDomain),
    1000 * 30
  );
}

window.addEventListener("DOMContentLoaded", useEmbedded);

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

function fetchCommand(command) {
  return async (...args) =>
    new Promise((resolve, reject) => {
      const id = Math.random();
      commandQueue[id] = { resolve, reject };
      embedded.contentWindow.postMessage({ id, command, args }, authDomain);
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
export const signOut = fetchCommand("signOut");
