const enabled = !!process.env.DEBUG;

export default function (...args) {
  if (enabled) {
    console.log(...args);
  }
}
