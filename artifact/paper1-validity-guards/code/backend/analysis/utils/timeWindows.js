// analysis/utils/timeWindows.js
// ✅ Anchor-safe window helpers (event-time correct)

function asDate(d) {
  if (!d) return new Date();
  const dt = d instanceof Date ? d : new Date(d);
  if (Number.isNaN(dt.getTime())) throw new Error(`Invalid date: ${d}`);
  return dt;
}

function minusMs(anchor, ms) {
  const a = asDate(anchor);
  return new Date(a.getTime() - ms);
}

function last15m(anchor) {
  return minusMs(anchor, 15 * 60 * 1000);
}

function last60m(anchor) {
  return minusMs(anchor, 60 * 60 * 1000);
}

function last24h(anchor) {
  return minusMs(anchor, 24 * 60 * 60 * 1000);
}

function last7d(anchor) {
  return minusMs(anchor, 7 * 24 * 60 * 60 * 1000);
}

module.exports = {
  last15m,
  last60m,
  last24h,
  last7d,
};