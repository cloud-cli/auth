export function parseBasicClientCredentials(authorization: string) {
  if (!authorization.startsWith('Basic ')) {
    return null;
  }

  const credentials = Buffer.from(authorization.slice(6), 'base64').toString('utf8');
  const separator = credentials.indexOf(':');
  if (separator < 1) {
    return null;
  }

  try {
    const decodeFormValue = (value: string) => decodeURIComponent(value.replace(/\+/g, ' '));
    return {
      clientId: decodeFormValue(credentials.slice(0, separator)),
      clientSecret: decodeFormValue(credentials.slice(separator + 1)),
    };
  } catch {
    return null;
  }
}
