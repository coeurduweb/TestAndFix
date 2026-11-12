import './env-alias.js';
import { buildApp } from './app.js';
import { config } from './config.js';
import { startRetentionJob } from './db.js';
import { passwordConfigured } from './auth.js';
import { startBackupJob } from './backup.js';
import { startSelfTestJob } from './mail/selftest.js';

const { app, ctx, tools } = await buildApp({ logger: true });
startRetentionJob(ctx.db);
for (const t of tools) await t.start?.(ctx);
// daily copy of the database into CHECK_BACKUP_DIR (US-098), first one 5 minutes after start
const backups = startBackupJob(ctx.db, app.log);
// reception self-test (US-099) once the SMTP server listens; off without CHECK_SELFTEST_SMTP_HOST
const selftest = startSelfTestJob(ctx, app.log);
if (!passwordConfigured()) app.log.warn('No CHECK_PASSWORD_HASH / CHECK_PASSWORD set: protected tools are unreachable.');
await app.listen({ host: config.host, port: config.port });

const shutdown = async () => {
  backups?.stop();
  selftest?.stop();
  for (const t of tools) await t.stop?.();
  await app.close();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
