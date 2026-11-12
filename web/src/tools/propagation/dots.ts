// Land of the propagation map as a dot matrix: grid of 7.2 units on the Equal Earth projection
// fitted to 1000x480 (fitExtent [[4,4],[996,476]] on the sphere), world-atlas land-110m.
// One string per grid row: runs "start.length" of land columns, base 36. 2239 dots.
// Generated once (geoContains on 9 000 points is too slow for the browser); to regenerate, run the
// same projection over the grid and keep the points inside the land.
export const GRID = { W: 1000, H: 480, step: 7.2 } as const;
export const ROWS: readonly string[] = ["","17.1 19.2 1c.4 1h.c 20.2 2l.1","13.2 17.1 19.2 1e.1 1k.8 2h.a 2s.1 2w.1","s.6 z.4 14.3 18.2 1c.1 1e.2 1k.7 22.4 2d.1 2f.s","m.2 p.l 1e.1 1g.1 1j.4 1r.3 21.2 24.3 28.11","o.k 1a.3 1k.2 1z.3 23.13 37.3","n.4 u.d 1b.3 1z.4 24.11 37.1","v.d 1b.4 1w.1 20.2 24.y 37.2","v.e 1a.7 1v.1 20.14 38.1","u.l 1w.18","v.i 1f.2 1w.19","u.k 1x.a 28.1 2a.3 2e.r","t.i 1x.3 21.1 23.4 2a.3 2e.r 37.2","t.h 1v.3 22.1 24.3 28.2 2b.3 2f.p","s.g 1u.3 24.1 26.8 2f.m 33.1 38.1","s.g 1v.2 1y.3 22.1 27.w 34.1 38.1","s.f 1v.6 2a.s 36.1","t.d 1u.9 24.1 29.u","u.8 13.2 1u.1a","t.6 14.1 1t.m 2g.o","t.6 14.1 1s.n 2h.n","v.3 1s.i 2b.7 2m.i","v.3 15.1 1r.k 2c.7 2n.7 2v.7","v.3 11.1 17.1 1r.k 2c.6 2o.5 2w.4 31.1","w.5 1s.k 2d.5 2o.4 2w.4 35.1","z.4 1r.l 2d.4 2p.2 2x.4","10.3 1r.o 2p.2 2y.4","11.1 16.2 1r.m 2p.2 30.2","12.1 15.6 1s.o 2q.1 30.1 35.1","13.9 1t.n 2r.1 2y.1 38.1","15.8 1u.4 1z.h 2z.1 35.1","15.9 21.e 2z.1 34.1","14.b 21.d 2y.2 32.4","13.c 21.c 2z.1 32.3","13.e 21.c 2z.2 33.2 36.1 3b.3","13.g 22.a 30.1 3c.4 3i.1","13.h 22.a 31.1 3b.1 3d.5 3j.1","14.g 22.a 33.1 3e.1 3g.1","14.g 22.a","15.e 22.a 3a.2","15.e 22.a 2f.1 38.3","16.d 22.a 2e.2 37.5 3d.2","18.b 22.9 2e.1 36.9","18.b 22.8 2d.2 34.b","18.a 23.7 2d.2 32.e","18.9 23.7 2d.1 32.e","18.8 23.6 32.e","18.8 23.6 32.d","18.8 24.4 32.d","19.6 24.3 31.3 38.6","19.5 39.4 3k.1","19.5 39.3 3k.1","19.4 3j.1","19.3 39.1","19.3 3g.1","1a.2","1a.2","1b.2 1f.1","1c.2","","","","1g.1 2b.2 2k.1 2o.1 2q.2 2t.4","1f.3 1z.1 21.2 24.b 2g.m","10.7 19.9 1t.18","z.i 1j.1 1l.1 1q.18",""];

let dotsPath: string | null = null;
/** The land as one SVG path of zero-length segments (draw with a round line cap), built once. */
export function dots(): string {
  if (dotsPath !== null) return dotsPath;
  const { step } = GRID;
  let d = '';
  ROWS.forEach((row, j) => {
    const y = (step / 2 + j * step).toFixed(1);
    for (const run of row.split(' ').filter(Boolean)) {
      const [s, l] = run.split('.').map((x) => parseInt(x, 36));
      for (let i = s; i < s + l; i++) d += `M${(step / 2 + i * step).toFixed(1)} ${y}h0`;
    }
  });
  return (dotsPath = d);
}
