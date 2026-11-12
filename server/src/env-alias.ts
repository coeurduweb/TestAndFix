// Environment variables are documented as TESTANDFIX_* (the product name since 2026-11-12). The code
// reads CHECK_* (the project's first name), and existing installations keep working with those: each
// TESTANDFIX_X is copied to CHECK_X when CHECK_X is not set. Imported first by config.ts.
for (const [k, v] of Object.entries(process.env)) {
  if (k.startsWith('TESTANDFIX_') && v !== undefined) {
    const legacy = 'CHECK_' + k.slice('TESTANDFIX_'.length);
    if (process.env[legacy] === undefined) process.env[legacy] = v;
  }
}
export {};
