import '@li3/web';
import { ref, templateRef } from '@li3/web';

export default function () {
  const message = ref('Tap scan to approve a sign-in from another device.');
  const approved = ref(false);
  const video = templateRef('camera');

  const scan = async () => {
    if (!('BarcodeDetector' in globalThis)) {
      message.value = 'QR scanning is not supported by this browser.';
      return;
    }
    const detector = new BarcodeDetector({ formats: ['qr_code'] });
    const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    video.value.srcObject = stream;
    video.value.hidden = false;
    await video.value.play();
    message.value = 'Point the camera at the login code.';
    const frame = async () => {
      const result = await detector.detect(video.value);
      const token = result.map((item) => new URL(item.rawValue).searchParams.get('transaction')).find(Boolean);
      if (!token) return requestAnimationFrame(frame);
      stream.getTracks().forEach((track) => track.stop());
      const detail = await fetch('/qr-login/details?transaction=' + encodeURIComponent(token), { credentials: 'include' });
      if (detail.status === 401) return location.href = '/login?url=/pwa/';
      if (!detail.ok) throw new Error('This QR code expired.');
      const login = await detail.json();
      if (!confirm('Approve sign-in to ' + login.returnUrl + '?')) return;
      const response = await fetch('/qr-login/approve', { method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ transaction: token }) });
      if (!response.ok) throw new Error('Approval failed.');
      approved.value = true;
      message.value = 'Approved. The other device is signing in now.';
    };
    requestAnimationFrame(() => frame().catch((error) => message.value = error.message));
  };

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/pwa/sw.js');
  return { video, message, approved, scan };
}
