import '@li3/web';
import { ref, templateRef } from '@li3/web';
import { deleteProperty, generateRecoveryCodes, getPasskeys, getProperties, registerPasskey, revokePasskey, setProperty, signInWithPasskey } from '/dashboard.mjs';

const page = document.body.dataset.page;
const value = (name) => new URL(location.href).searchParams.get(name) || '';

export default function () {
  const busy = ref(false);
  const message = ref('');
  const error = ref(false);
  const user = ref({ name: '', email: '', photo: '' });
  const passkeys = ref([]);
  const properties = ref([]);
  const codes = ref('');
  const qr = ref('');
  const pwaUrl = ref('/pwa/');
  const qrUrl = ref('/qr-login?url=' + encodeURIComponent(value('url') || '/me'));
  const passkeyUrl = ref('/webauthn/login?url=' + encodeURIComponent(value('url') || '/me'));
  const recoveryUrl = ref('/recovery?url=' + encodeURIComponent(value('url') || '/me'));
  const status = ref('Preparing a secure connection...');
  const approved = ref(false);
  const account = templateRef('account');
  const propertyKey = templateRef('propertyKey');
  const propertyValue = templateRef('propertyValue');

  const setMessage = (text, isError = false) => {
    message.value = text;
    error.value = isError;
  };

  async function signIn() {
    busy.value = true;
    setMessage('Waiting for your authenticator...');
    try {
      await signInWithPasskey(account.value?.value || '');
      setMessage('Passkey confirmed. Finishing sign-in...');
      setTimeout(() => location.href = value('url') || '/me', 450);
    } catch (reason) {
      setMessage(reason.message || 'Passkey sign-in was cancelled.', true);
    } finally {
      busy.value = false;
    }
  }

  async function loadProfile() {
    const profile = await fetch('/', { credentials: 'include' }).then((response) => response.json());
    user.value = profile;
    if (window.opener) window.opener.postMessage({ event: 'signin', detail: profile }, location.origin);
    const [keys, storedProperties] = await Promise.all([getPasskeys(), getProperties()]);
    passkeys.value = keys.filter((key) => !key.revokedAt);
    properties.value = storedProperties;
  }

  async function addPasskey() {
    const label = prompt('Name this passkey', 'My device');
    if (!label) return;
    await registerPasskey(label);
    await loadProfile();
  }

  async function revoke(credentialId) {
    if (!confirm('Revoke this passkey?')) return;
    await revokePasskey(credentialId);
    await loadProfile();
  }

  async function recoveryCodes() {
    if (!confirm('This invalidates any existing recovery codes. Continue?')) return;
    codes.value = (await generateRecoveryCodes()).join('\n');
  }

  async function saveProperty(property) {
    await setProperty(property.key, property.value);
  }

  async function removeProperty(property) {
    if (!confirm('Remove ' + property.key + '?')) return;
    await deleteProperty(property.key);
    properties.value = properties.value.filter((item) => item !== property);
  }

  async function addProperty() {
    const key = propertyKey.value?.value.trim();
    if (!key) return;
    await setProperty(key, propertyValue.value?.value || '');
    propertyKey.value.value = '';
    propertyValue.value.value = '';
    properties.value = await getProperties();
  }

  async function signOut() {
    await fetch('/', { method: 'DELETE', credentials: 'include' });
    location.href = '/login';
  }

  async function loadQr() {
    const response = await fetch('/qr-login/start?url=' + encodeURIComponent(value('url')), { credentials: 'include' });
    if (!response.ok) throw new Error('Could not start phone approval.');
    const transaction = await response.json();
    qr.value = transaction.qr;
    pwaUrl.value = transaction.pwaUrl;
    status.value = 'Waiting for approval on your phone...';
    const poll = async () => {
      const result = await fetch('/qr-login/status?transaction=' + encodeURIComponent(transaction.token), { credentials: 'include' });
      if (!result.ok) return setMessage('This QR code expired. Start again.', true);
      const current = await result.json();
      if (current.status === 'approved') {
        approved.value = true;
        status.value = 'Approved. Completing your secure sign-in...';
        return setTimeout(() => location.href = current.returnUrl, 700);
      }
      if (current.status === 'denied') return status.value = 'Approval was denied on your phone.';
      setTimeout(poll, 1000);
    };
    poll();
  }

  if (page === 'login' && value('url')) sessionStorage.setItem('auth.returnUrl', value('url'));
  if (page === 'profile') {
    const returnUrl = sessionStorage.getItem('auth.returnUrl');
    if (returnUrl) {
      sessionStorage.removeItem('auth.returnUrl');
      setTimeout(() => location.href = returnUrl, 300);
    }
    loadProfile().catch((reason) => setMessage(reason.message, true));
  }
  if (page === 'qr') loadQr().catch((reason) => setMessage(reason.message, true));

  return { account, propertyKey, propertyValue, busy, message, error, user, passkeys, properties, codes, qr, pwaUrl, qrUrl, passkeyUrl, recoveryUrl, status, approved, signIn, addPasskey, revoke, recoveryCodes, saveProperty, removeProperty, addProperty, signOut };
}
