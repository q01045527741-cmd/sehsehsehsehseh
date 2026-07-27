// Vendored fastest-levenshtein replacement
// Minimal implementation for eth-phishing-detect compatibility

function distance(a, b) {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const m = a.length, n = b.length;

  // Use single-row optimization
  let prev = new Array(n + 1);
  let curr = new Array(n + 1);

  for (let j = 0; j <= n; j++) prev[j] = j;

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        curr[j - 1] + 1,      // insertion
        prev[j] + 1,          // deletion
        prev[j - 1] + cost    // substitution
      );
    }
    [prev, curr] = [curr, prev];
  }

  return prev[n];
}

function closest(str, arr) {
  let min = Infinity;
  let best = '';
  for (const s of arr) {
    const d = distance(str, s);
    if (d < min) { min = d; best = s; }
  }
  return best;
}

module.exports = { distance, closest };
