const video = document.querySelector('#camera');
const message = document.querySelector('#message');
const approval = document.querySelector('#approval');
let stream;

function show(text) {
  message.textContent = text;
}

function tokenFromScan(value) {
  try {
    const url = new URL(value);
    return url.searchParams.get('transaction');
  } catch {
    return null;
  }
}

async function approve(token) {
  const response = await fetch('/qr-login/details?transaction=' + encodeURIComponent(token), { credentials: 'include' });
  if (response.status === 401) {
    show('Sign in on this phone first.');
    approval.innerHTML = '<a href="/login?url=%2Fpwa%2F">Sign in</a>';
    return;
  }
  if (!response.ok) throw new Error('This QR login has expired.');
  const details = await response.json();
  show('Approve sign-in to ' + (details.returnUrl || 'this application') + '?');
  approval.innerHTML = '<button id="yes">Approve</button> <button id="no">Deny</button>';
  document.querySelector('#yes').onclick = async () => {
    const result = await fetch('/qr-login/approve', { method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ transaction: token }) });
    show(result.ok ? 'Approved. You can return to the other device.' : 'Approval failed.');
    approval.textContent = '';
  };
  document.querySelector('#no').onclick = async () => {
    await fetch('/qr-login/deny', { method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ transaction: token }) });
    show('Denied.');
    approval.textContent = '';
  };
}

async function scan() {
  if (!('BarcodeDetector' in globalThis)) {
    show('QR scanning is not supported by this browser. Open this app in Chrome or use the browser camera QR scanner.');
    return;
  }
  const detector = new BarcodeDetector({ formats: ['qr_code'] });
  stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
  video.srcObject = stream;
  await video.play();
  show('Point the camera at the QR code on the other device.');
  const frame = async () => {
    if (video.readyState >= 2) {
      const results = await detector.detect(video);
      const token = results.map((result) => tokenFromScan(result.rawValue)).find(Boolean);
      if (token) {
        stream.getTracks().forEach((track) => track.stop());
        video.hidden = true;
        await approve(token);
        return;
      }
    }
    requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
}

document.querySelector('#scan').onclick = () => scan().catch((error) => show(error.message));
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/pwa/sw.js');
