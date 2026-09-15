export async function getDb() {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error('DATABASE_URL is not configured');
  if (url.startsWith('http://') || url.startsWith('https://')) {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Could not load database module: ${response.status}`);
    const source = await response.text();
    return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  }
  return import(url);
}
