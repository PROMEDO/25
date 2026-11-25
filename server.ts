/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import 'dotenv/config';
import crypto from 'node:crypto';
import express, { type NextFunction, type Request, type Response } from 'express';
import compression from 'compression';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  applyChanges,
  deleteInternalStoreItem,
  getInternalStoreItem,
  getMemoryStoreSnapshot,
  getRealtimeVersion,
  getStoreVersion,
  isReservedInternalKey,
  isSafeStoreKey,
  readAll,
  setInternalStoreItem,
  subscribeStoreChanges,
} from './server/neon-store.ts';
import {
  checkSupabaseHealth,
  getDatabaseUrlInfo,
  getSupabasePublicConfig,
  isSupabaseConfigured,
} from './server/supabase.ts';
import {
  readNotesDocument,
  saveNoteToFile,
  deleteNoteFromFile,
  replaceAllNotesInFile,
  type StoredNote,
} from './server/notes-store.ts';
import { searchWebImages, proxyExternalImage } from './server/image-search.ts';
import {
  deleteTelegramUserByPhone,
  getTelegramBotStatus,
  getTelegramOrderLinkStatus,
  handleIncomingTelegramMessage,
  initTelegramOrderLink,
  normalizePhoneKeys,
  sendOrderNotificationToTelegram,
  sendPartnerTestOrderNotification,
  startTelegramBotPolling,
  stopTelegramBotPolling,
  toggleTelegramForRestaurant,
  unlinkTelegramForRestaurant,
  updateAdminTelegramConfig,
  verifyTelegramBotLive,
} from './server/telegram-otp.ts';
import {
  attachAuthSession,
  clearAuthSessionsByTarget,
  createServerAuthSession,
  destroyServerAuthSession,
  FULL_OWNER_PERMISSIONS,
  hashPasswordScrypt,
  matchesPhoneCandidates,
  parseRequestCookies,
  requireAdminOrStaff,
  sanitizeAuthSessionForClient,
  signSid,
  updateServerAuthSession,
  verifyStoredCredential,
} from './server/auth.ts';
import { createAdminRouter } from './server/admin-routes.ts';
import {
  flushVisitorAnalytics,
  getVisitorAnalyticsStats,
  recordSiteOrMenuVisit,
} from './server/visitor-analytics.ts';
import {
  computePwaLogoVersion,
  getFallbackPwaIcon,
  getRestaurantRecordForPwa,
  resolveRestaurantPwaIcon,
} from './server/pwa-icon.ts';
import {
  ensureWebPushVapidKeys,
  getWebPushPublicKey,
  removePushSubscription,
  sendOrderWebPushNotifications,
  upsertPushSubscription,
} from './server/web-push.ts';
import {
  collectTakenMenuSlugs,
  createSubdomainRouter,
  extractPlansList,
  generateUniqueMenuCode,
  injectSubdomainHtmlMeta,
  isPaidPlanForRestaurant,
  isValidSixCharCode,
  normalizeSubdomainRules,
  sanitizeSubdomainValue,
  subdomainMiddleware,
  SYSTEM_RESERVED_SUBDOMAINS,
  validatePathSlugFormat,
  type ResolvedSubdomainResult,
  type StoreRecord,
} from './server/subdomain.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const rawPort = String(process.env.PORT || '3000').trim();
const PORT: number | string = /^\d+$/.test(rawPort) ? Number(rawPort) : rawPort;
const isProduction = process.env.NODE_ENV === 'production' || __filename.endsWith('.js');
const BASE_DOMAIN = String(process.env.BASE_DOMAIN || 'menuplus.io')
  .toLowerCase()
  .trim()
  .replace(/^https?:\/\//, '')
  .replace(/\/.*$/, '') || 'menuplus.io';

app.set('trust proxy', true);
app.set('etag', false);
app.disable('x-powered-by');
app.use((req, _res, next) => {
  if (req.url.startsWith('//')) {
    req.url = req.url.replace(/^\/{2,}/, '/');
  }
  next();
});
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));
app.use(
  compression({
    threshold: 1024,
    filter: (req, res) => {
      if (req.path === '/api/realtime/events') return false;
      return compression.filter(req, res);
    },
  })
);

// Baseline HTTP security & wildcard-subdomain CORS headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=()');

  const origin = String(req.headers.origin || '').trim();
  if (origin) {
    try {
      const originHost = new URL(origin).hostname.toLowerCase();
      if (
        originHost === BASE_DOMAIN ||
        originHost.endsWith(`.${BASE_DOMAIN}`) ||
        originHost === 'localhost' ||
        originHost.endsWith('.localhost')
      ) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Session-Id, X-Admin-Key');
      }
    } catch {
      // ignore invalid origin header
    }
  }
  next();
});

// Auth & OTP sliding-window rate limiters
const otpRateWindowMs = 60_000;
const otpRateMaxRequests = 25;
const otpRateBuckets = new Map<string, number[]>();
const loginRateMaxRequests = 20;
const loginRateBuckets = new Map<string, number[]>();

const otpCleanupTimer = setInterval(() => {
  const cutoff = Date.now() - otpRateWindowMs;
  for (const bucket of [otpRateBuckets, loginRateBuckets]) {
    for (const [ip, timestamps] of bucket.entries()) {
      const valid = timestamps.filter((ts) => ts > cutoff);
      if (valid.length === 0) {
        bucket.delete(ip);
      } else {
        bucket.set(ip, valid);
      }
    }
  }
}, otpRateWindowMs);
otpCleanupTimer.unref();

function otpRateLimiter(req: Request, res: Response, next: NextFunction) {
  const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const cutoff = now - otpRateWindowMs;
  const recent = (otpRateBuckets.get(clientIp) || []).filter((ts) => ts > cutoff);

  if (recent.length >= otpRateMaxRequests) {
    return res.status(429).json({
      success: false,
      error: 'طلبات كثيرة جداً، يرجى الانتظار دقيقة والمحاولة مرة أخرى.',
    });
  }

  recent.push(now);
  otpRateBuckets.set(clientIp, recent);
  return next();
}

function loginRateLimiter(req: Request, res: Response, next: NextFunction) {
  const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const cutoff = now - otpRateWindowMs;
  const recent = (loginRateBuckets.get(clientIp) || []).filter((ts) => ts > cutoff);

  if (recent.length >= loginRateMaxRequests) {
    return res.status(429).json({
      ok: false,
      error: 'محاولات دخول كثيرة جداً، يرجى الانتظار دقيقة والمحاولة مرة أخرى.',
    });
  }

  recent.push(now);
  loginRateBuckets.set(clientIp, recent);
  return next();
}

// Attach verified server session from signed HttpOnly cookie BEFORE any API routes
app.use(attachAuthSession);

// 0. Health Check endpoint for Hostinger / reverse proxies
app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    status: 'healthy',
    env: isProduction ? 'production' : 'development',
    uptime: Math.round(process.uptime()),
  });
});

function sanitizeRecordSecrets<T>(record: T): T {
  if (!record || typeof record !== 'object' || Array.isArray(record)) return record;
  const copy = { ...(record as Record<string, unknown>) };
  if ('telegramChatId' in copy || 'telegramPhone' in copy || 'telegramLinked' in copy) {
    const hasChat = Boolean(String(copy.telegramChatId || '').trim());
    const hasPhone = Boolean(String(copy.telegramPhone || '').trim()) && copy.telegramUnlinkedManually !== true;
    copy.telegramLinked = hasChat || hasPhone || Boolean(copy.telegramLinked);
  }
  delete copy.pw;
  delete copy.passwordHash;
  delete copy.jwtToken;
  delete copy.telegramChatId;
  return copy as T;
}

function resolveRestaurantEntryByIdOrSlug(
  allData: Record<string, unknown>,
  slugOrId?: string
): { rid: string; rest: Record<string, unknown> } | null {
  const raw = String(slugOrId || '').trim();
  if (!raw) return null;
  const direct = allData[`restaurants/${raw}`];
  if (direct && typeof direct === 'object' && !Array.isArray(direct)) {
    return { rid: raw, rest: direct as Record<string, unknown> };
  }
  const normalized = sanitizeSubdomainValue(raw);
  if (!normalized) return null;
  for (const [k, v] of Object.entries(allData)) {
    if (!k.startsWith('restaurants/') || k.slice('restaurants/'.length).includes('/') || !v || typeof v !== 'object') {
      continue;
    }
    const rec = v as Record<string, unknown>;
    const s1 = sanitizeSubdomainValue(String(rec.slug || ''));
    const s2 = sanitizeSubdomainValue(String(rec.subdomain || ''));
    if ((s1 && s1 === normalized) || (s2 && s2 === normalized)) {
      return { rid: k.slice('restaurants/'.length), rest: rec };
    }
  }
  if (normalized === 'cap-burger' || normalized === 'demo') {
    const demo = allData['restaurants/demo'];
    if (demo && typeof demo === 'object' && !Array.isArray(demo)) {
      return { rid: 'demo', rest: demo as Record<string, unknown> };
    }
  }
  return null;
}

function resolvePublicMenuFamily(
  allData: Record<string, unknown>,
  slugOrId?: string
): {
  rid: string;
  mainRid: string;
  rest: Record<string, unknown>;
  familyRids: Set<string>;
  slug: string;
  records: Record<string, unknown>;
  bootstrapRecords: Record<string, unknown>;
} | null {
  const resolved = resolveRestaurantEntryByIdOrSlug(allData, slugOrId);
  if (!resolved) return null;

  const { rid, rest } = resolved;

  // Walk up parentRid chain safely to find the true family root
  let mainRid = rid;
  const visitedUp = new Set<string>([rid]);
  let curRest: Record<string, unknown> | undefined = rest;
  for (let hop = 0; hop < 5 && curRest?.parentRid; hop++) {
    const pId: string = String(curRest.parentRid || '').trim();
    if (!pId || visitedUp.has(pId)) break;
    visitedUp.add(pId);
    mainRid = pId;
    const parentRec: unknown = allData[`restaurants/${pId}`];
    curRest = parentRec && typeof parentRec === 'object' && !Array.isArray(parentRec)
      ? (parentRec as Record<string, unknown>)
      : undefined;
  }

  // Collect all descendant branches in the family (regardless of isBranch flag)
  const familyRids = new Set<string>([rid, mainRid]);
  let expanded = true;
  while (expanded) {
    expanded = false;
    for (const [k, v] of Object.entries(allData)) {
      if (!k.startsWith('restaurants/') || k.slice('restaurants/'.length).includes('/') || !v || typeof v !== 'object') {
        continue;
      }
      const entryRid = k.slice('restaurants/'.length);
      const rec = v as Record<string, unknown>;
      const parentRid = String(rec.parentRid || '').trim();
      if (parentRid && familyRids.has(parentRid) && !familyRids.has(entryRid)) {
        familyRids.add(entryRid);
        expanded = true;
      }
    }
  }

  const records: Record<string, unknown> = {};
  const bootstrapRecords: Record<string, unknown> = {};
  const mainRest = allData[`restaurants/${mainRid}`] as Record<string, unknown> | undefined;
  const effectiveFamilyActive = mainRest ? mainRest.a !== 0 : rest.a !== 0;

  for (const [k, v] of Object.entries(allData)) {
    if (!v || typeof v !== 'object') continue;
    if (k === 'settings/plans' || k === 'settings/site' || k === 'settings/theme') {
      const clean = sanitizeRecordSecrets(v);
      records[k] = clean;
      bootstrapRecords[k] = clean;
    } else if (k.startsWith('restaurants/') && !k.slice('restaurants/'.length).includes('/')) {
      const entryRid = k.slice('restaurants/'.length);
      if (familyRids.has(entryRid)) {
        const clean = sanitizeRecordSecrets(v) as Record<string, unknown>;
        if (entryRid !== mainRid && effectiveFamilyActive && clean.a === 0 && clean.deleted !== true) {
          clean.a = mainRest?.a ?? 1;
        }
        records[k] = clean;
        // Strip large inline base64 images from HTML bootstrap only if oversized; full images arrive via /api/public/menu
        const lite: Record<string, unknown> = { ...clean };
        if (typeof lite.logo === 'string' && lite.logo.startsWith('data:') && lite.logo.length > 16000) {
          delete lite.logo;
        }
        if (Array.isArray(lite.coverImages)) {
          const hasLargeDataCover = lite.coverImages.some(
            (img) => typeof img === 'string' && img.startsWith('data:') && img.length > 16000
          );
          if (hasLargeDataCover) delete lite.coverImages;
        }
        bootstrapRecords[k] = lite;
      }
    } else if (k.startsWith('cats/') || k.startsWith('items/')) {
      const rec = v as Record<string, unknown>;
      if (familyRids.has(String(rec.rid || '').trim())) {
        const clean = sanitizeRecordSecrets(rec) as Record<string, unknown>;
        records[k] = clean;
        const lite: Record<string, unknown> = { ...clean };
        if (typeof lite.img === 'string' && lite.img.startsWith('data:') && lite.img.length > 16000) {
          delete lite.img;
        }
        bootstrapRecords[k] = lite;
      }
    }
  }

  const slug =
    sanitizeSubdomainValue(String(rest.slug || rest.subdomain || '')) ||
    (rid === 'demo' ? 'cap-burger' : '');

  return {
    rid,
    mainRid,
    rest,
    familyRids,
    slug,
    records,
    bootstrapRecords,
  };
}

function resolvePublicHomeRecords(allData: Record<string, unknown>): Record<string, unknown> {
  const records: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(allData)) {
    if (
      k === 'settings/site' ||
      k === 'settings/home' ||
      k === 'settings/plans' ||
      k === 'settings/theme' ||
      k === 'initialized_v6' ||
      k.startsWith('migrations/')
    ) {
      records[k] = sanitizeRecordSecrets(v);
    } else if (k === 'restaurants/demo' && v && typeof v === 'object') {
      const clean = sanitizeRecordSecrets(v) as Record<string, unknown>;
      records[k] = {
        id: clean.id || 'demo',
        n: clean.n || 'Cap Burger',
        slug: clean.slug || 'cap-burger',
        subdomain: clean.subdomain || 'cap-burger',
        projectType: clean.projectType || 'restaurant',
        currency: clean.currency || 'د.ع',
        done: clean.done ?? 1,
        a: clean.a ?? 1,
      };
    }
  }
  return records;
}

function injectInitialHomeBootstrapIntoHtml(
  html: string,
  allData: Record<string, unknown>
): string {
  const records = resolvePublicHomeRecords(allData);
  if (Object.keys(records).length === 0) return html;
  const payload = JSON.stringify({
    version: getStoreVersion(),
    records,
  })
    .replace(/</g, '\\u003c')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
  const tag = `<script>window.__MENUPLUS_INITIAL_HOME__=${payload};</script>`;
  if (html.includes('</head>')) {
    return html.replace('</head>', () => `  ${tag}\n  </head>`);
  }
  return `${tag}${html}`;
}

function injectInitialMenuBootstrapIntoHtml(
  html: string,
  family: ReturnType<typeof resolvePublicMenuFamily>
): string {
  if (!family) return html;
  const payload = JSON.stringify({
    rid: family.rid,
    mainRid: family.mainRid,
    slug: family.slug,
    records: family.bootstrapRecords,
  })
    .replace(/</g, '\\u003c')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
  const tag = `<script>window.__MENUPLUS_INITIAL_MENU__=${payload};</script>`;
  if (html.includes('</head>')) {
    return html.replace('</head>', () => `  ${tag}\n  </head>`);
  }
  return `${tag}${html}`;
}

function getOwnedPartnerRids(
  allData: Record<string, unknown>,
  ownerRid?: string,
  ses?: { accountId?: string; phone?: string; admin?: boolean } | null
): Set<string> {
  const owned = new Set<string>();
  if (ownerRid) owned.add(ownerRid);

  // Include all restaurants linked to accounts owned by the same user (via accountId or verified phone)
  if (ses && !ses.admin) {
    const sesPhone = String(ses.phone || '').trim();
    for (const [k, v] of Object.entries(allData)) {
      if (!k.startsWith('accounts/') || !v || typeof v !== 'object') continue;
      const acc = v as Record<string, unknown>;
      const accId = k.slice('accounts/'.length);
      if (acc.active === false) continue;
      if (acc.admin === true || acc.r === 'admin' || accId.startsWith('acc_admin_')) continue;
      if (accId === 'acc_menu_demo' && ses.accountId !== 'acc_menu_demo') continue;

      const accRid = String(acc.rid || '').trim();
      if (!accRid) continue;

      const matchesAccount = Boolean(ses.accountId && accId === ses.accountId);
      const matchesPhone = Boolean(
        sesPhone &&
          [acc.phone, acc.ph, acc.projectPhone, acc.em, acc.username].some(
            (candidate) =>
              typeof candidate === 'string' &&
              candidate.trim() &&
              matchesPhoneCandidates(candidate, sesPhone)
          )
      );

      if (matchesAccount || matchesPhone) {
        const rest = allData[`restaurants/${accRid}`] as Record<string, unknown> | undefined;
        if (!rest || rest.a !== 0 || accRid === ownerRid) {
          owned.add(accRid);
        }
      }
    }
  }

  // Expand to include any parent restaurant if ownerRid was a branch, then all child branches in the family
  let changed = true;
  while (changed) {
    changed = false;
    for (const [k, v] of Object.entries(allData)) {
      if (!k.startsWith('restaurants/') || k.slice('restaurants/'.length).includes('/')) continue;
      const rid = k.slice('restaurants/'.length);
      const rec = v as Record<string, unknown> | undefined;
      if (!rec) continue;
      const parentRid = String(rec.parentRid || '').trim();
      if (parentRid && owned.has(rid) && !owned.has(parentRid)) {
        const parentRec = allData[`restaurants/${parentRid}`] as Record<string, unknown> | undefined;
        if (parentRec && parentRec.deleted !== true) {
          owned.add(parentRid);
          changed = true;
        }
      }
      if (parentRid && owned.has(parentRid) && !owned.has(rid)) {
        owned.add(rid);
        changed = true;
      }
    }
  }
  return owned;
}

function collectTakenSlugsFromAllData(allData: Record<string, unknown>, excludeRid?: string): Set<string> {
  const taken = new Set<string>();
  for (const [k, v] of Object.entries(allData)) {
    if (!k.startsWith('restaurants/') || k.slice('restaurants/'.length).includes('/') || !v || typeof v !== 'object') {
      continue;
    }
    const rid = k.slice('restaurants/'.length);
    if (excludeRid && rid === excludeRid) continue;
    const rec = v as Record<string, unknown>;
    const s1 = sanitizeSubdomainValue(String(rec.slug || ''));
    const s2 = sanitizeSubdomainValue(String(rec.subdomain || ''));
    if (s1) taken.add(s1);
    if (s2) taken.add(s2);
  }
  return taken;
}

function todayIsoDate(): string {
  return new Date().toISOString().slice(0, 10);
}

function addDaysIso(days: number): string {
  const safe = Math.max(1, Math.min(3650, Math.round(days)));
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + safe);
  return d.toISOString().slice(0, 10);
}

// 1. Role-Scoped & Hardened Database Endpoints
app.get('/api/db', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const currentVersion = getStoreVersion();
    res.setHeader('X-Store-Version', String(currentVersion));
    const requestedVersion = Number(req.query.v || 0);
    if (Number.isFinite(requestedVersion) && requestedVersion > 0 && requestedVersion === currentVersion) {
      return res.json({ ok: true, unchanged: true, version: currentVersion });
    }

    const allData = await readAll(false);
    const ses = req.authSession;
    const out: Record<string, unknown> = {};

    if (ses?.admin) {
      const perms =
        ses.role === 'owner' || !ses.staffId
          ? FULL_OWNER_PERMISSIONS
          : { ...FULL_OWNER_PERMISSIONS, ...req.authPermissions };
      for (const [k, v] of Object.entries(allData)) {
        if (k.startsWith('accounts/')) {
          if (perms.canManageRestaurants || ses.accountId === k.slice('accounts/'.length)) {
            out[k] = sanitizeRecordSecrets(v);
          }
        } else if (k.startsWith('staff/')) {
          if (perms.canManageStaff || ses.staffId === k.slice('staff/'.length)) {
            out[k] = sanitizeRecordSecrets(v);
          }
        } else if (k.startsWith('notes/')) {
          if (perms.canUseNotes) {
            out[k] = v;
          }
        } else if (k.startsWith('reports/')) {
          if (perms.canViewReports !== false) {
            out[k] = v;
          }
        } else if (k.startsWith('finance_expenses/') || k.startsWith('finance_profits/') || k === 'settings/finance') {
          if (perms.canManageFinance) {
            out[k] = v;
          }
        } else if (k.startsWith('custom_font_files/')) {
          continue;
        } else {
          out[k] = sanitizeRecordSecrets(v);
        }
      }
      return res.json(out);
    }

    if (ses && ses.role === 'partner') {
      const ownerRid = ses.personalRid || ses.rid;
      const ownedRids = getOwnedPartnerRids(allData, ownerRid, ses);
      for (const [k, v] of Object.entries(allData)) {
        if (
          (k.startsWith('settings/') && k !== 'settings/finance') ||
          k.startsWith('restaurants/') ||
          k.startsWith('cats/') ||
          k.startsWith('items/') ||
          k === 'initialized_v6' ||
          k.startsWith('migrations/')
        ) {
          out[k] = sanitizeRecordSecrets(v);
        } else if (k.startsWith('orders/') || k.startsWith('reports/') || k.startsWith('loyalty/')) {
          const rec = v as Record<string, unknown> | undefined;
          if (rec && ownedRids.has(String(rec.rid || ''))) {
            out[k] = sanitizeRecordSecrets(v);
          }
        } else if (ses.accountId && k === `accounts/${ses.accountId}`) {
          out[k] = sanitizeRecordSecrets(v);
        }
      }
      return res.json(out);
    }

    // Unauthenticated visitor: public storefront catalog & settings only
    for (const [k, v] of Object.entries(allData)) {
      if (
        (k.startsWith('settings/') && k !== 'settings/finance') ||
        k.startsWith('restaurants/') ||
        k.startsWith('cats/') ||
        k.startsWith('items/') ||
        k === 'initialized_v6' ||
        k.startsWith('migrations/')
      ) {
        out[k] = sanitizeRecordSecrets(v);
      }
    }
    return res.json(out);
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'Database error' });
  }
});

app.post('/api/db', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({ error: 'Invalid database payload' });
    }
    const payload = body as { put?: Record<string, unknown>; del?: string[] };
    const allData = await readAll(false);
    const ses = req.authSession || null;
    const filteredPut: Record<string, unknown> = {};
    const filteredDel: string[] = [];

    const checkKeyWritable = (key: string, val: unknown, isDelete: boolean): boolean => {
      if (!isSafeStoreKey(key)) return false;

      // Guest visitor: only permitted to place new pending customer orders
      if (!ses) {
        if (isDelete || !key.startsWith('orders/')) return false;
        if (Object.prototype.hasOwnProperty.call(allData, key)) return false;
        if (!val || typeof val !== 'object' || Array.isArray(val)) return false;
        const ord = val as Record<string, unknown>;
        const rid = String(ord.rid || '').trim();
        if (!rid || !allData[`restaurants/${rid}`]) return false;
        const tot = Number(ord.tot ?? ord.total ?? 0);
        if (!Number.isFinite(tot) || tot < 0) return false;
        return true;
      }

      // Partner user: strictly scoped to own stores + child branches
      if (!ses.admin) {
        const ownerRid = ses.personalRid || ses.rid;
        const ownedRids = getOwnedPartnerRids(allData, ownerRid, ses);

        if (key.startsWith('restaurants/') && !key.slice('restaurants/'.length).includes('/')) {
          const rid = key.slice('restaurants/'.length);
          if (isDelete) {
            const existing = allData[key] as Record<string, unknown> | undefined;
            const isBranchRec = Boolean(existing && (existing.isBranch || existing.parentRid));
            return isBranchRec && rid !== ownerRid && ownedRids.has(rid);
          }
          if (!val || typeof val !== 'object' || Array.isArray(val)) return false;
          const existing = allData[key] as Record<string, unknown> | undefined;
          const nextObj = { ...(val as Record<string, unknown>) };
          const plansList = extractPlansList(allData['settings/plans']);
          const subRules = normalizeSubdomainRules((allData['settings/site'] as Record<string, unknown>) || null);
          const takenSlugs = collectTakenSlugsFromAllData(allData, rid);

          if (existing) {
            if (!ownedRids.has(rid)) return false;
            // Prevent client-side plan escalation, expiry extension, or suspension bypass
            nextObj.planId = existing.planId;
            nextObj.p = existing.p;
            nextObj.e = existing.e;
            nextObj.isPaid = existing.isPaid;
            nextObj.a = existing.a;
            if (existing.parentRid) nextObj.parentRid = existing.parentRid;
            if (existing.isBranch !== undefined) nextObj.isBranch = existing.isBranch;
            if (!nextObj.telegramChatId && existing.telegramChatId) nextObj.telegramChatId = existing.telegramChatId;
            if (!nextObj.telegramPhone && existing.telegramPhone) nextObj.telegramPhone = existing.telegramPhone;
            if (!nextObj.telegramUsername && existing.telegramUsername) nextObj.telegramUsername = existing.telegramUsername;
            if (
              nextObj.orderChannel === 'both' ||
              nextObj.orderChannel === 'telegram' ||
              nextObj.orderChannel === 'whatsapp' ||
              nextObj.orderChannel === 'app'
            ) {
              if (nextObj.telegramNotificationsEnabled === undefined) {
                nextObj.telegramNotificationsEnabled =
                  nextObj.orderChannel === 'both' || nextObj.orderChannel === 'telegram';
              }
              if (nextObj.whatsappNotificationsEnabled === undefined) {
                nextObj.whatsappNotificationsEnabled =
                  nextObj.orderChannel === 'both' || nextObj.orderChannel === 'whatsapp';
              }
            } else if (existing.orderChannel) {
              nextObj.orderChannel = existing.orderChannel;
            }
            if (nextObj.telegramNotificationsEnabled === undefined && existing.telegramNotificationsEnabled !== undefined) {
              nextObj.telegramNotificationsEnabled = existing.telegramNotificationsEnabled;
            }
            if (nextObj.whatsappNotificationsEnabled === undefined && existing.whatsappNotificationsEnabled !== undefined) {
              nextObj.whatsappNotificationsEnabled = existing.whatsappNotificationsEnabled;
            }
            if (nextObj.appNotificationsEnabled === undefined && existing.appNotificationsEnabled !== undefined) {
              nextObj.appNotificationsEnabled = existing.appNotificationsEnabled;
            }

            const { isPaid } = isPaidPlanForRestaurant(existing as StoreRecord, plansList);
            const existingSlug = sanitizeSubdomainValue(String(existing.slug || ''));
            const requestedSlug = sanitizeSubdomainValue(String(nextObj.slug || ''));

            if (!isPaid) {
              nextObj.slug = existingSlug && isValidSixCharCode(existingSlug) && !takenSlugs.has(existingSlug)
                ? existingSlug
                : existingSlug || generateUniqueMenuCode(takenSlugs);
              nextObj.subdomain = '';
            } else if (requestedSlug && requestedSlug !== existingSlug) {
              const check = validatePathSlugFormat(requestedSlug, subRules);
              if (check.valid && !takenSlugs.has(requestedSlug)) {
                nextObj.slug = requestedSlug;
                nextObj.subdomain = subRules.enabled ? requestedSlug : '';
              } else {
                nextObj.slug = existingSlug || generateUniqueMenuCode(takenSlugs);
                nextObj.subdomain = subRules.enabled ? String(nextObj.slug) : '';
              }
            } else {
              nextObj.slug = existingSlug || generateUniqueMenuCode(takenSlugs);
              nextObj.subdomain = subRules.enabled ? String(nextObj.slug) : '';
            }

            filteredPut[key] = nextObj;
            return false; // handled custom sanitized write
          } else {
            // Creating a new branch under any owned primary store
            const targetParentRid = String(nextObj.parentRid || ownerRid || '').trim();
            if (!targetParentRid || !ownedRids.has(targetParentRid)) return false;
            const parentRest = allData[`restaurants/${targetParentRid}`] as Record<string, unknown> | undefined;
            if (!parentRest) return false;
            nextObj.parentRid = targetParentRid;
            nextObj.isBranch = true;
            nextObj.planId = parentRest.planId;
            nextObj.p = parentRest.p;
            nextObj.e = parentRest.e;
            nextObj.isPaid = parentRest.isPaid;
            nextObj.a = parentRest.a === 0 ? 0 : 1;

            const { isPaid } = isPaidPlanForRestaurant(parentRest as StoreRecord, plansList);
            const requestedSlug = sanitizeSubdomainValue(String(nextObj.slug || ''));
            const check = requestedSlug ? validatePathSlugFormat(requestedSlug, subRules) : { valid: false };
            if (isPaid && requestedSlug && check.valid && !takenSlugs.has(requestedSlug)) {
              nextObj.slug = requestedSlug;
              nextObj.subdomain = subRules.enabled ? requestedSlug : '';
            } else {
              nextObj.slug = generateUniqueMenuCode(takenSlugs);
              nextObj.subdomain = '';
            }

            filteredPut[key] = nextObj;
            return false;
          }
        }

        if (key.startsWith('cats/') || key.startsWith('items/') || key.startsWith('orders/') || key.startsWith('loyalty/')) {
          if (isDelete) {
            const existing = allData[key] as Record<string, unknown> | undefined;
            return Boolean(existing && ownedRids.has(String(existing.rid || '')));
          }
          if (!val || typeof val !== 'object' || Array.isArray(val)) return false;
          const rec = val as Record<string, unknown>;
          return ownedRids.has(String(rec.rid || ''));
        }

        if (key.startsWith('reports/')) {
          if (isDelete || Object.prototype.hasOwnProperty.call(allData, key)) return false;
          if (!val || typeof val !== 'object' || Array.isArray(val)) return false;
          const rep = val as Record<string, unknown>;
          const rid = String(rep.rid || '').trim();
          const msg = String(rep.message || '').trim();
          return Boolean(rid && ownedRids.has(rid) && msg.length > 0);
        }

        if (key.startsWith('logs/') && !isDelete) {
          return true;
        }
        return false;
      }

      // Admin or Staff: check hierarchical permissions per collection
      const perms =
        ses.role === 'owner' || !ses.staffId
          ? FULL_OWNER_PERMISSIONS
          : { ...FULL_OWNER_PERMISSIONS, ...req.authPermissions };

      if (key === 'settings/finance' || key.startsWith('finance_expenses/') || key.startsWith('finance_profits/')) {
        return Boolean(perms.canManageFinance);
      }
      if (key === 'settings/plans') {
        return Boolean(perms.canManagePlans);
      }
      if (key === 'settings/theme') {
        return Boolean(perms.canManageSettings || perms.canManageThemeMode || perms.canEditHomePage);
      }
      if (key.startsWith('settings/')) {
        return Boolean(perms.canManageSettings || perms.canEditTabLabels || perms.canReorderTabs || perms.canManageThemeMode || perms.canManageSubdomains || perms.canEditHomePage);
      }
      if (key === 'restaurants/demo') {
        return Boolean(perms.canManageRestaurants);
      }
      if (key.startsWith('restaurants/')) {
        if (isDelete) return Boolean(perms.canDeletePartner || perms.canManageRestaurants);
        if (!perms.canManageRestaurants) return false;
        if (val && typeof val === 'object' && !Array.isArray(val)) {
          const existing = allData[key] as Record<string, unknown> | undefined;
          const nextObj = { ...(val as Record<string, unknown>) };
          if (existing) {
            if (!nextObj.telegramChatId && existing.telegramChatId) nextObj.telegramChatId = existing.telegramChatId;
            if (!nextObj.telegramPhone && existing.telegramPhone) nextObj.telegramPhone = existing.telegramPhone;
            if (!nextObj.telegramUsername && existing.telegramUsername) nextObj.telegramUsername = existing.telegramUsername;
            if (
              nextObj.orderChannel === 'both' ||
              nextObj.orderChannel === 'telegram' ||
              nextObj.orderChannel === 'whatsapp' ||
              nextObj.orderChannel === 'app'
            ) {
              if (nextObj.telegramNotificationsEnabled === undefined) {
                nextObj.telegramNotificationsEnabled =
                  nextObj.orderChannel === 'both' || nextObj.orderChannel === 'telegram';
              }
              if (nextObj.whatsappNotificationsEnabled === undefined) {
                nextObj.whatsappNotificationsEnabled =
                  nextObj.orderChannel === 'both' || nextObj.orderChannel === 'whatsapp';
              }
            } else if (existing.orderChannel) {
              nextObj.orderChannel = existing.orderChannel;
            }
            if (nextObj.telegramNotificationsEnabled === undefined && existing.telegramNotificationsEnabled !== undefined) {
              nextObj.telegramNotificationsEnabled = existing.telegramNotificationsEnabled;
            }
            if (nextObj.whatsappNotificationsEnabled === undefined && existing.whatsappNotificationsEnabled !== undefined) {
              nextObj.whatsappNotificationsEnabled = existing.whatsappNotificationsEnabled;
            }
            if (nextObj.appNotificationsEnabled === undefined && existing.appNotificationsEnabled !== undefined) {
              nextObj.appNotificationsEnabled = existing.appNotificationsEnabled;
            }
          }
          filteredPut[key] = nextObj;
          return false;
        }
        return true;
      }
      if (key.startsWith('cats/') || key.startsWith('items/')) {
        return Boolean(perms.canManageRestaurants);
      }
      if (key.startsWith('orders/') || key.startsWith('loyalty/')) {
        return Boolean(perms.canManageRestaurants);
      }
      if (key.startsWith('accounts/')) {
        if (isDelete) return Boolean(perms.canDeletePartner && ses.role === 'owner');
        if (ses.role !== 'owner') return false;
        // Preserve existing pw if sanitized client omitted it
        const existing = allData[key] as Record<string, unknown> | undefined;
        if (val && typeof val === 'object' && !Array.isArray(val)) {
          const nextObj = { ...(val as Record<string, unknown>) };
          if (!nextObj.pw && existing?.pw) nextObj.pw = existing.pw;
          filteredPut[key] = nextObj;
        }
        return false;
      }
      if (key.startsWith('staff/')) {
        if (!perms.canManageStaff) return false;
        if (!isDelete && val && typeof val === 'object' && !Array.isArray(val)) {
          const existing = allData[key] as Record<string, unknown> | undefined;
          const nextObj = { ...(val as Record<string, unknown>) };
          if (!nextObj.passwordHash && existing?.passwordHash) nextObj.passwordHash = existing.passwordHash;
          filteredPut[key] = nextObj;
          return false;
        }
        return true;
      }
      if (key.startsWith('notes/')) {
        return Boolean(perms.canUseNotes);
      }
      if (key.startsWith('reports/')) {
        return Boolean(perms.canViewReports !== false || perms.canManageRestaurants);
      }
      if (key.startsWith('logs/')) {
        return true;
      }
      if (key === 'initialized_v6' || key.startsWith('migrations/')) {
        return Boolean(perms.canManageSettings || ses.role === 'owner');
      }
      return false;
    };

    if (payload.put && typeof payload.put === 'object' && !Array.isArray(payload.put)) {
      for (const [k, v] of Object.entries(payload.put)) {
        if (checkKeyWritable(k, v, false)) {
          filteredPut[k] = v;
        }
      }
    }
    if (Array.isArray(payload.del)) {
      for (const k of payload.del) {
        if (typeof k === 'string' && checkKeyWritable(k, undefined, true)) {
          filteredDel.push(k);
        }
      }
    }

    const hasFilteredWrites = Object.keys(filteredPut).length > 0 || filteredDel.length > 0;
    const requestedWrites =
      (payload.put ? Object.keys(payload.put).length : 0) + (Array.isArray(payload.del) ? payload.del.length : 0);

    if (requestedWrites > 0 && !hasFilteredWrites) {
      return res.status(ses ? 403 : 401).json({
        ok: false,
        error: ses ? 'ليست لديك صلاحية لتعديل هذه البيانات.' : 'يرجى تسجيل الدخول لإجراء هذه العملية.',
      });
    }

    const newOrderEvents: Array<{ rest: Record<string, unknown>; ord: Record<string, unknown>; rid: string }> = [];
    if (hasFilteredWrites) {
      const ridOrderSeqTracker = new Map<string, number>();
      const countStoreOrders = (targetRid: string): number => {
        let count = 0;
        for (const [ak, av] of Object.entries(allData)) {
          if (
            ak.startsWith('orders/') &&
            av &&
            typeof av === 'object' &&
            !Array.isArray(av) &&
            String((av as Record<string, unknown>).rid || '').trim() === targetRid
          ) {
            count++;
          }
        }
        return count;
      };

      for (const [k, v] of Object.entries(filteredPut)) {
        if (
          k.startsWith('orders/') &&
          !Object.prototype.hasOwnProperty.call(allData, k) &&
          v &&
          typeof v === 'object' &&
          !Array.isArray(v)
        ) {
          const ord = v as Record<string, unknown>;
          const rid = String(ord.rid || '').trim();
          const currentRest = (filteredPut[`restaurants/${rid}`] || allData[`restaurants/${rid}`]) as
            | Record<string, unknown>
            | undefined;
          if (currentRest) {
            const baseCount = ridOrderSeqTracker.has(rid)
              ? (ridOrderSeqTracker.get(rid) as number)
              : Math.max(Number(currentRest.o || 0) || 0, countStoreOrders(rid));
            const nextSeq = baseCount + 1;
            ridOrderSeqTracker.set(rid, nextSeq);

            const updatedOrder: Record<string, unknown> = {
              ...ord,
              seq: nextSeq,
              orderSeq: nextSeq,
            };
            filteredPut[k] = updatedOrder;

            const updatedRest: Record<string, unknown> = {
              ...currentRest,
              o: Math.max(Number(currentRest.o || 0) || 0, nextSeq),
            };
            filteredPut[`restaurants/${rid}`] = updatedRest;

            newOrderEvents.push({ rest: updatedRest, ord: updatedOrder, rid });
          }
        }
      }
    }

    const newReportEvents: Array<{ rep: Record<string, unknown> }> = [];
    if (hasFilteredWrites) {
      let maxReportSeq = 0;
      for (const [ak, av] of Object.entries(allData)) {
        if (ak.startsWith('reports/') && av && typeof av === 'object' && !Array.isArray(av)) {
          const rec = av as Record<string, unknown>;
          const s = Number(rec.reportSeq || rec.seq || 0);
          if (Number.isFinite(s) && s > maxReportSeq) maxReportSeq = s;
        }
      }
      const existingReportsCount = Object.keys(allData).filter((ak) => ak.startsWith('reports/')).length;
      let nextReportSeqCursor = Math.max(maxReportSeq, existingReportsCount);

      for (const [k, v] of Object.entries(filteredPut)) {
        if (
          k.startsWith('reports/') &&
          !Object.prototype.hasOwnProperty.call(allData, k) &&
          v &&
          typeof v === 'object' &&
          !Array.isArray(v)
        ) {
          const rep = v as Record<string, unknown>;
          nextReportSeqCursor += 1;
          const updatedReport: Record<string, unknown> = {
            ...rep,
            seq: nextReportSeqCursor,
            reportSeq: nextReportSeqCursor,
          };
          filteredPut[k] = updatedReport;
          newReportEvents.push({ rep: updatedReport });
        }
      }
    }

    const loyaltyUpdates: Record<string, { phone: string; name: string; earned: number; points: number }> = {};
    if (newOrderEvents.length > 0) {
      for (const ev of newOrderEvents) {
        const addonsObj = (ev.rest.addons && typeof ev.rest.addons === 'object' ? ev.rest.addons : {}) as Record<string, any>;
        const lpCfg = addonsObj.loyaltyPoints;
        if (lpCfg && lpCfg.enabled) {
          const rawPhone = String(ev.ord.phone || '').trim();
          const digits = rawPhone.replace(/[\s\-()+]/g, '');
          const normPhone = digits.startsWith('964') && digits.length >= 12 ? `0${digits.slice(3)}` : digits;
          if (normPhone.length >= 7) {
            const rate = Math.max(1, Number(lpCfg.pointsPerThousand || 1));
            const amount = Math.max(0, Number(ev.ord.tot ?? ev.ord.total ?? 0));
            const earned = Math.floor(amount / 1000) * rate;
            const loyaltyKey = `loyalty/${ev.rid}__${normPhone}`;
            const existingLoyalty = (filteredPut[loyaltyKey] || allData[loyaltyKey]) as Record<string, unknown> | undefined;
            const prevPoints = Math.max(0, Number(existingLoyalty?.points || 0));
            const newPoints = prevPoints + earned;
            const customerName = String(ev.ord.name || '').trim() || String(existingLoyalty?.name || '').trim() || 'زبون';
            const nowTs = Date.now();
            filteredPut[loyaltyKey] = {
              id: `${ev.rid}__${normPhone}`,
              rid: ev.rid,
              phone: normPhone,
              name: customerName,
              points: newPoints,
              totalOrders: Math.max(0, Number(existingLoyalty?.totalOrders || 0)) + 1,
              totalSpent: Math.max(0, Number(existingLoyalty?.totalSpent || 0)) + amount,
              createdAt: Number(existingLoyalty?.createdAt || nowTs),
              updatedAt: nowTs,
            };
            if (ev.ord.id) {
              loyaltyUpdates[String(ev.ord.id)] = {
                phone: normPhone,
                name: customerName,
                earned,
                points: newPoints,
              };
            }
          }
        }
      }
    }

    const result = hasFilteredWrites
      ? await applyChanges({ put: filteredPut, del: filteredDel }, false)
      : { persistedToSupabase: false };

    let telegramDispatch: { sent: boolean; reason?: string } | undefined;
    if (newOrderEvents.length > 0) {
      for (const ev of newOrderEvents) {
        const restPayload = { ...ev.rest, id: ev.rest.id || ev.rid };
        const [tgRes] = await Promise.all([
          sendOrderNotificationToTelegram(restPayload, ev.ord).catch((err) => ({
            sent: false,
            reason: err instanceof Error ? err.message : 'error',
          })),
          sendOrderWebPushNotifications(restPayload, ev.ord).catch((err) => {
            console.warn('[WebPush Order]', err instanceof Error ? err.message : err);
            return { sent: 0, removed: 0 };
          }),
        ]);
        telegramDispatch = tgRes;
        if (
          !tgRes.sent &&
          tgRes.reason &&
          tgRes.reason !== 'channel_whatsapp_only' &&
          tgRes.reason !== 'store_notifications_disabled'
        ) {
          console.warn(`[Telegram Order] Store ${ev.rid} order #${String(ev.ord.orderSeq || ev.ord.seq || '').trim() || String(ev.ord.id || '').slice(-6)} not sent: ${tgRes.reason}`);
        }
      }
    }

    const assignedOrderSeqs =
      newOrderEvents.length > 0
        ? Object.fromEntries(
            newOrderEvents
              .map((ev): [string, number] => [String(ev.ord.id || ''), Number(ev.ord.orderSeq || 0)])
              .filter(([id, seq]) => Boolean(id) && seq > 0)
          )
        : undefined;

    const assignedReportSeqs =
      newReportEvents.length > 0
        ? Object.fromEntries(
            newReportEvents
              .map((ev): [string, number] => [String(ev.rep.id || ''), Number(ev.rep.reportSeq || 0)])
              .filter(([id, seq]) => Boolean(id) && seq > 0)
          )
        : undefined;

    return res.json({
      ok: true,
      driver: isSupabaseConfigured() ? 'supabase' : 'file-memory',
      persistedToSupabase: result.persistedToSupabase,
      ...(assignedOrderSeqs ? { assignedOrderSeqs } : {}),
      ...(assignedReportSeqs ? { assignedReportSeqs } : {}),
      ...(Object.keys(loyaltyUpdates).length > 0 ? { loyaltyUpdates } : {}),
      ...(telegramDispatch ? { telegramDispatch } : {}),
    });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'Database error' });
  }
});

const POPULAR_ITEMS_TTL_MS = 180_000;
const popularItemsCache = new Map<
  string,
  { counts: Record<string, number>; totalOrders: number; cachedAt: number }
>();

subscribeStoreChanges((ev) => {
  if (ev.changedKeys.includes('__full_sync__')) {
    popularItemsCache.clear();
    return;
  }
  const hasOrderChange = ev.changedKeys.some((k) => k.startsWith('orders/'));
  if (!hasOrderChange) return;
  if (ev.rids.length === 0) {
    popularItemsCache.clear();
  } else {
    for (const rid of ev.rids) {
      popularItemsCache.delete(rid);
    }
  }
});

app.get('/api/public/popular-items/:rid', async (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=120, stale-while-revalidate=60');
  try {
    const rid = String(req.params.rid || '').trim();
    if (!rid) {
      return res.json({ ok: true, counts: {}, totalOrders: 0 });
    }
    const now = Date.now();
    const cached = popularItemsCache.get(rid);
    if (cached && now - cached.cachedAt < POPULAR_ITEMS_TTL_MS) {
      return res.json({ ok: true, counts: cached.counts, totalOrders: cached.totalOrders });
    }

    const allData = await readAll(false);
    const counts: Record<string, number> = {};
    let totalOrders = 0;

    for (const [k, v] of Object.entries(allData)) {
      if (!k.startsWith('orders/') || !v || typeof v !== 'object') continue;
      const rec = v as Record<string, unknown>;
      if (String(rec.rid || '') !== rid) continue;
      if (rec.st === 'cancelled' || rec.status === 'cancelled') continue;
      totalOrders += 1;
      const items = Array.isArray(rec.items) ? rec.items : [];
      for (const rawLine of items) {
        if (!rawLine || typeof rawLine !== 'object') continue;
        const line = rawLine as Record<string, unknown>;
        const nameKey = String(line.n || line.name || '').trim().toLowerCase();
        if (!nameKey) continue;
        const qty = Math.max(1, Number(line.q ?? line.qty ?? 1) || 1);
        counts[nameKey] = (counts[nameKey] || 0) + qty;
      }
    }

    popularItemsCache.set(rid, { counts, totalOrders, cachedAt: now });
    return res.json({ ok: true, counts, totalOrders });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'Database error', counts: {}, totalOrders: 0 });
  }
});

const MAX_SSE_CLIENTS = 40;
const SSE_MAX_LIFETIME_MS = 25_000;
let activeSseClients = 0;

interface CachedPublicMenuEntry {
  menuVer: number;
  rid: string;
  mainRid: string;
  slug: string;
  familyRids: Set<string>;
  jsonPayload: string;
  unchangedMap?: Map<number, string>;
}

const publicMenuResponseCache = new Map<string, CachedPublicMenuEntry>();
let publicHomeResponseCache: { menuVer: number; jsonPayload: string; records: Record<string, unknown> } | null = null;
const MAX_PUBLIC_MENU_CACHE = 300;

function getOrResolvePublicMenuCached(
  allData: Record<string, unknown>,
  slugOrId: string
): CachedPublicMenuEntry | null {
  const cacheKey = slugOrId.toLowerCase();
  const cached = publicMenuResponseCache.get(cacheKey);
  if (cached) {
    const liveMenuVer = getRealtimeVersion('menu', cached.familyRids);
    if (liveMenuVer === cached.menuVer) {
      return cached;
    }
  }

  const family = resolvePublicMenuFamily(allData, slugOrId);
  if (!family) {
    publicMenuResponseCache.delete(cacheKey);
    return null;
  }

  const menuVer = getRealtimeVersion('menu', family.familyRids);
  const jsonPayload = JSON.stringify({
    ok: true,
    version: menuVer,
    buildId: SERVER_BUILD_ID,
    rid: family.rid,
    mainRid: family.mainRid,
    slug: family.slug,
    records: family.records,
  });

  if (publicMenuResponseCache.size >= MAX_PUBLIC_MENU_CACHE) {
    const firstKey = publicMenuResponseCache.keys().next().value;
    if (firstKey) publicMenuResponseCache.delete(firstKey);
  }

  const entry: CachedPublicMenuEntry = {
    menuVer,
    rid: family.rid,
    mainRid: family.mainRid,
    slug: family.slug,
    familyRids: family.familyRids,
    jsonPayload,
  };
  publicMenuResponseCache.set(cacheKey, entry);
  return entry;
}

function getOrResolvePublicHomeCached(allData: Record<string, unknown>): {
  menuVer: number;
  jsonPayload: string;
  records: Record<string, unknown>;
} {
  const menuVer = getRealtimeVersion('menu', ['demo']);
  if (publicHomeResponseCache && publicHomeResponseCache.menuVer === menuVer) {
    return publicHomeResponseCache;
  }
  const records = resolvePublicHomeRecords(allData);
  const jsonPayload = JSON.stringify({
    ok: true,
    version: menuVer,
    buildId: SERVER_BUILD_ID,
    records,
  });
  publicHomeResponseCache = { menuVer, jsonPayload, records };
  return publicHomeResponseCache;
}

// Lightweight version polling endpoint (replaces persistent long-lived SSE connections under high proxy/CDN load)
app.get('/api/realtime/version', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const scope = req.query.scope === 'menu' ? 'menu' : 'dashboard';
  const requestedRid = typeof req.query.rid === 'string' ? req.query.rid.trim() : '';

  if (scope === 'dashboard') {
    const ses = req.authSession;
    if (!ses) {
      return res.status(401).json({ ok: false, error: 'يتطلب تسجيل الدخول.' });
    }
    const allData = getMemoryStoreSnapshot(false);
    let targetRids: Iterable<string> | null = null;
    if (!ses.admin) {
      const ownerRid = ses.personalRid || ses.rid;
      const allowedRids = getOwnedPartnerRids(allData, ownerRid, ses);
      if (requestedRid && !allowedRids.has(requestedRid)) {
        return res.status(403).json({ ok: false, error: 'غير مصرح بالوصول.' });
      }
      targetRids = requestedRid ? [requestedRid] : allowedRids;
    } else if (requestedRid) {
      targetRids = [requestedRid];
    }
    const version = getRealtimeVersion('dashboard', targetRids);
    return res.json({ ok: true, scope: 'dashboard', version });
  }

  if (!requestedRid) {
    return res.status(400).json({ ok: false, error: 'Menu rid required' });
  }
  const cacheKey = requestedRid.toLowerCase();
  const cached = publicMenuResponseCache.get(cacheKey);
  if (cached) {
    const version = getRealtimeVersion('menu', cached.familyRids);
    return res.json({ ok: true, scope: 'menu', version });
  }
  const allData = getMemoryStoreSnapshot(false);
  const family = resolvePublicMenuFamily(allData, requestedRid);
  const familyRids = family ? family.familyRids : [requestedRid];
  const version = getRealtimeVersion('menu', familyRids);
  return res.json({ ok: true, scope: 'menu', version });
});

// Bounded SSE endpoint kept for backward compatibility (rotates cleanly every 25s to prevent 120s proxy 500s)
app.get('/api/realtime/events', (req, res) => {
  const scope = req.query.scope === 'menu' ? 'menu' : 'dashboard';
  const requestedRid = typeof req.query.rid === 'string' ? req.query.rid.trim() : '';

  const allData = getMemoryStoreSnapshot(false);
  let allowedRids: Set<string> | null = null;

  if (scope === 'dashboard') {
    const ses = req.authSession;
    if (!ses) {
      return res.status(401).json({ ok: false, error: 'يتطلب تسجيل الدخول.' });
    }
    if (!ses.admin) {
      const ownerRid = ses.personalRid || ses.rid;
      allowedRids = getOwnedPartnerRids(allData, ownerRid, ses);
      if (requestedRid && !allowedRids.has(requestedRid)) {
        return res.status(403).json({ ok: false, error: 'غير مصرح بالوصول.' });
      }
    }
  } else {
    if (!requestedRid) {
      return res.status(400).json({ ok: false, error: 'Menu rid required' });
    }
    const family = resolvePublicMenuFamily(allData, requestedRid);
    allowedRids = family ? family.familyRids : new Set([requestedRid]);
  }

  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();

  if (activeSseClients >= MAX_SSE_CLIENTS) {
    try {
      res.write(`event: reconnect\ndata: ${JSON.stringify({ reason: 'busy' })}\n\n`);
      res.end();
    } catch {
      // ignore closed socket
    }
    return;
  }

  activeSseClients += 1;
  let closed = false;

  const writeEvent = (eventName: string, data: unknown) => {
    if (closed || res.writableEnded || res.destroyed) return;
    try {
      res.write(`event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`);
    } catch {
      cleanup();
    }
  };

  let heartbeat: ReturnType<typeof setInterval> | null = null;
  let maxLifetimeTimer: ReturnType<typeof setTimeout> | null = null;
  let unsubscribe = () => {};

  const cleanup = () => {
    if (closed) return;
    closed = true;
    activeSseClients = Math.max(0, activeSseClients - 1);
    if (heartbeat) {
      clearInterval(heartbeat);
      heartbeat = null;
    }
    if (maxLifetimeTimer) {
      clearTimeout(maxLifetimeTimer);
      maxLifetimeTimer = null;
    }
    try {
      unsubscribe();
    } catch {
      // ignore
    }
  };

  writeEvent('ready', { version: getRealtimeVersion(scope, allowedRids) });

  heartbeat = setInterval(() => {
    if (closed || res.writableEnded || res.destroyed) {
      cleanup();
      return;
    }
    try {
      res.write(': ping\n\n');
    } catch {
      cleanup();
    }
  }, 15_000);
  heartbeat.unref?.();

  maxLifetimeTimer = setTimeout(() => {
    if (closed) return;
    try {
      if (!res.writableEnded && !res.destroyed) {
        res.write(`event: reconnect\ndata: ${JSON.stringify({ reason: 'rotate' })}\n\n`);
        res.end();
      }
    } catch {
      // ignore
    }
    cleanup();
  }, SSE_MAX_LIFETIME_MS);
  maxLifetimeTimer.unref?.();

  unsubscribe = subscribeStoreChanges((ev) => {
    if (closed) return;
    const publicKeys = ev.changedKeys.filter((k) => k === '__full_sync__' || !isReservedInternalKey(k));
    if (publicKeys.length === 0) return;

    const isFullSync = publicKeys.includes('__full_sync__');
    if (scope === 'menu') {
      const hasCatalogChange =
        isFullSync ||
        publicKeys.some(
          (k) =>
            k.startsWith('restaurants/') ||
            k.startsWith('cats/') ||
            k.startsWith('items/') ||
            k.startsWith('settings/')
        );
      if (!hasCatalogChange) return;
      if (
        !isFullSync &&
        allowedRids &&
        ev.rids.length > 0 &&
        !ev.rids.some((r) => allowedRids!.has(r)) &&
        !publicKeys.some((k) => k.startsWith('settings/'))
      ) {
        return;
      }
      writeEvent('update', { version: getRealtimeVersion('menu', allowedRids), scope: 'menu' });
      return;
    }

    // Dashboard / Owner notifications scope
    if (!isFullSync && allowedRids) {
      if (requestedRid) {
        const matchesRequested =
          ev.rids.includes(requestedRid) ||
          publicKeys.some((k) => k.startsWith('settings/'));
        if (!matchesRequested && ev.rids.length > 0) return;
      } else if (ev.rids.length > 0 && !ev.rids.some((r) => allowedRids!.has(r))) {
        return;
      }
    }
    writeEvent('update', { version: ev.version, rids: ev.rids });
  });

  req.on('close', cleanup);
  req.on('aborted', cleanup);
  res.on('close', cleanup);
  res.on('finish', cleanup);
  res.on('error', cleanup);
});

// Fast single-menu public payload (eliminates loading all restaurants/categories/items/orders on customer menu entry)
app.get('/api/public/menu/:slugOrId', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const slugOrId = decodeURIComponent(String(req.params.slugOrId || '')).trim();
    if (!slugOrId) {
      return res.status(400).json({ ok: false, error: 'Menu identifier required' });
    }
    const allData = await readAll(false);
    const cached = getOrResolvePublicMenuCached(allData, slugOrId);
    if (!cached) {
      return res.status(404).json({ ok: false, error: 'Menu not found' });
    }

    res.setHeader('X-Store-Version', String(cached.menuVer));
    res.setHeader('X-App-Build', SERVER_BUILD_ID);

    const requestedVersion = Number(req.query.v || 0);
    if (Number.isFinite(requestedVersion) && requestedVersion > 0 && requestedVersion === cached.menuVer) {
      return res.json({ ok: true, unchanged: true, version: cached.menuVer });
    }

    return res.status(200).setHeader('Content-Type', 'application/json; charset=utf-8').send(cached.jsonPayload);
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'Database error' });
  }
});

// Fast lightweight payload for landing home & auth pages (avoids downloading all restaurants/cats/items/orders)
app.get('/api/public/home-bootstrap', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const allData = await readAll(false);
    const cached = getOrResolvePublicHomeCached(allData);
    res.setHeader('X-Store-Version', String(cached.menuVer));
    res.setHeader('X-App-Build', SERVER_BUILD_ID);

    const requestedVersion = Number(req.query.v || 0);
    if (Number.isFinite(requestedVersion) && requestedVersion > 0 && requestedVersion === cached.menuVer) {
      return res.json({ ok: true, unchanged: true, version: cached.menuVer });
    }
    return res.status(200).setHeader('Content-Type', 'application/json; charset=utf-8').send(cached.jsonPayload);
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'Database error' });
  }
});

function getOrderEpochMs(rec: Record<string, unknown>): number {
  const rawAt = Number(rec.at || 0);
  if (Number.isFinite(rawAt) && rawAt > 0) {
    return rawAt < 1e12 ? rawAt * 1000 : rawAt;
  }
  if (rec.createdAt) {
    const parsed = Date.parse(String(rec.createdAt));
    if (Number.isFinite(parsed) && parsed > 0) return parsed;
  }
  return 0;
}

const BOOTSTRAP_RECENT_ORDER_LIMIT = 150;
const BOOTSTRAP_RECENT_WINDOW_MS = 60 * 24 * 60 * 60 * 1000;

// Fast authenticated dashboard bootstrap payload (scoped only to user's owned stores / target menu family)
app.get('/api/dashboard/bootstrap', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const ses = req.authSession;
  if (!ses) {
    return res.status(401).json({ ok: false, error: 'يرجى تسجيل الدخول للمتابعة.' });
  }
  try {
    const currentVersion = getStoreVersion();
    res.setHeader('X-Store-Version', String(currentVersion));

    const requestedRidRaw = typeof req.query.rid === 'string' ? req.query.rid.trim() : '';
    const requestedSlugRaw = typeof req.query.slug === 'string' ? req.query.slug.trim() : '';
    const requestedLookup = requestedSlugRaw || requestedRidRaw;
    const requestedVersion = Number(req.query.v || 0);

    if (
      Number.isFinite(requestedVersion) &&
      requestedVersion > 0 &&
      requestedVersion === currentVersion &&
      (!requestedLookup || requestedLookup === ses.rid)
    ) {
      return res.json({
        ok: true,
        unchanged: true,
        version: currentVersion,
        targetRid: String(ses.rid || ses.personalRid || '').trim(),
        session: sanitizeAuthSessionForClient(ses),
      });
    }

    const allData = await readAll(false);
    const ownerRid = ses.personalRid || ses.rid;
    const partnerOwnedRids = ses.admin ? null : getOwnedPartnerRids(allData, ownerRid, ses);

    let targetRid = String(ses.rid || ownerRid || '').trim();
    if (requestedLookup) {
      const resolved = resolveRestaurantEntryByIdOrSlug(allData, requestedLookup);
      if (resolved) {
        if (!ses.admin && partnerOwnedRids && !partnerOwnedRids.has(resolved.rid)) {
          return res.status(403).json({ ok: false, error: 'غير مصرح بالوصول إلى لوحة هذا المتجر.' });
        }
        targetRid = resolved.rid;
      }
    }

    if (
      Number.isFinite(requestedVersion) &&
      requestedVersion > 0 &&
      requestedVersion === currentVersion
    ) {
      return res.json({
        ok: true,
        unchanged: true,
        version: currentVersion,
        targetRid,
        session: sanitizeAuthSessionForClient(ses),
      });
    }

    const targetRest = allData[`restaurants/${targetRid}`] as Record<string, unknown> | undefined;
    const targetMainRid = String(targetRest?.parentRid || targetRid).trim() || targetRid;

    const scopedRids = new Set<string>();
    if (partnerOwnedRids) {
      for (const id of partnerOwnedRids) scopedRids.add(id);
    }
    if (targetRid) scopedRids.add(targetRid);
    if (targetMainRid) scopedRids.add(targetMainRid);
    for (const [k, v] of Object.entries(allData)) {
      if (!k.startsWith('restaurants/') || k.slice('restaurants/'.length).includes('/') || !v || typeof v !== 'object') {
        continue;
      }
      const rec = v as Record<string, unknown>;
      if (String(rec.parentRid || '') === targetMainRid) {
        scopedRids.add(k.slice('restaurants/'.length));
      }
    }

    const includeAllOrders = req.query.ordersScope === 'all';
    const scopedOrders: Array<{ key: string; rec: Record<string, unknown>; ts: number; isActive: boolean }> = [];
    const records: Record<string, unknown> = {};

    for (const [k, v] of Object.entries(allData)) {
      if (!v || (typeof v !== 'object' && k !== 'initialized_v6' && !k.startsWith('migrations/'))) continue;
      if (
        (k.startsWith('settings/') && k !== 'settings/finance') ||
        k === 'initialized_v6' ||
        k.startsWith('migrations/')
      ) {
        records[k] = sanitizeRecordSecrets(v);
      } else if (k.startsWith('restaurants/') && !k.slice('restaurants/'.length).includes('/')) {
        const entryRid = k.slice('restaurants/'.length);
        if (scopedRids.has(entryRid)) {
          records[k] = sanitizeRecordSecrets(v);
        }
      } else if (k.startsWith('orders/')) {
        const rec = v as Record<string, unknown>;
        if (scopedRids.has(String(rec.rid || ''))) {
          const st = String(rec.st || rec.status || 'new').toLowerCase();
          const isActive = st !== 'completed' && st !== 'cancelled';
          scopedOrders.push({ key: k, rec, ts: getOrderEpochMs(rec), isActive });
        }
      } else if (k.startsWith('cats/') || k.startsWith('items/') || k.startsWith('reports/') || k.startsWith('loyalty/')) {
        const rec = v as Record<string, unknown>;
        if (scopedRids.has(String(rec.rid || ''))) {
          records[k] = sanitizeRecordSecrets(v);
        }
      } else if (ses.accountId && k === `accounts/${ses.accountId}`) {
        records[k] = sanitizeRecordSecrets(v);
      }
    }

    // Always include active/pending orders + recent 60d/150 orders by default; full archive loads on demand
    let returnedOrdersCount = 0;
    if (includeAllOrders || scopedOrders.length <= BOOTSTRAP_RECENT_ORDER_LIMIT) {
      for (const entry of scopedOrders) {
        records[entry.key] = sanitizeRecordSecrets(entry.rec);
        returnedOrdersCount += 1;
      }
    } else {
      const cutoffMs = Date.now() - BOOTSTRAP_RECENT_WINDOW_MS;
      scopedOrders.sort((a, b) => b.ts - a.ts);
      const picked = new Set<string>();
      for (const entry of scopedOrders) {
        if (entry.isActive) {
          records[entry.key] = sanitizeRecordSecrets(entry.rec);
          picked.add(entry.key);
        }
      }
      for (const entry of scopedOrders) {
        if (picked.has(entry.key)) continue;
        if (picked.size < BOOTSTRAP_RECENT_ORDER_LIMIT || (entry.ts >= cutoffMs && picked.size < 250)) {
          records[entry.key] = sanitizeRecordSecrets(entry.rec);
          picked.add(entry.key);
        }
      }
      returnedOrdersCount = picked.size;
    }

    return res.json({
      ok: true,
      version: currentVersion,
      targetRid,
      session: sanitizeAuthSessionForClient(ses),
      ownedRids: Array.from(scopedRids),
      ordersTruncated: returnedOrdersCount < scopedOrders.length,
      totalOrdersCount: scopedOrders.length,
      returnedOrdersCount,
      records,
    });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'Database error' });
  }
});

// On-demand bounded/archived orders endpoint for dashboard Stats/Orders history
app.get('/api/dashboard/orders', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const ses = req.authSession;
  if (!ses) {
    return res.status(401).json({ ok: false, error: 'يرجى تسجيل الدخول للمتابعة.' });
  }
  try {
    const allData = await readAll(false);
    const ownerRid = ses.personalRid || ses.rid;
    const partnerOwnedRids = ses.admin ? null : getOwnedPartnerRids(allData, ownerRid, ses);
    const requestedRid = typeof req.query.rid === 'string' ? req.query.rid.trim() : '';
    const targetRid = requestedRid || String(ses.rid || ownerRid || '').trim();

    if (!ses.admin && partnerOwnedRids && targetRid && !partnerOwnedRids.has(targetRid)) {
      return res.status(403).json({ ok: false, error: 'غير مصرح بالوصول إلى طلبات هذا المتجر.' });
    }

    const scopedRids = new Set<string>();
    if (partnerOwnedRids) {
      for (const id of partnerOwnedRids) scopedRids.add(id);
    }
    if (targetRid) {
      scopedRids.add(targetRid);
      const targetRest = allData[`restaurants/${targetRid}`] as Record<string, unknown> | undefined;
      const mainRid = String(targetRest?.parentRid || targetRid).trim() || targetRid;
      scopedRids.add(mainRid);
      for (const [k, v] of Object.entries(allData)) {
        if (!k.startsWith('restaurants/') || k.slice('restaurants/'.length).includes('/') || !v || typeof v !== 'object') {
          continue;
        }
        if (String((v as Record<string, unknown>).parentRid || '') === mainRid) {
          scopedRids.add(k.slice('restaurants/'.length));
        }
      }
    }

    const orders: Array<{ key: string; order: Record<string, unknown>; ts: number }> = [];
    for (const [k, v] of Object.entries(allData)) {
      if (!k.startsWith('orders/') || !v || typeof v !== 'object') continue;
      const rec = v as Record<string, unknown>;
      if (scopedRids.size > 0 && !scopedRids.has(String(rec.rid || ''))) continue;
      orders.push({
        key: k,
        order: sanitizeRecordSecrets(rec),
        ts: getOrderEpochMs(rec),
      });
    }
    orders.sort((a, b) => b.ts - a.ts);

    const scopeAll = req.query.scope === 'all';
    const offset = Math.max(0, Number(req.query.offset || 0) || 0);
    const limit = scopeAll
      ? orders.length
      : Math.max(1, Math.min(500, Number(req.query.limit || 200) || 200));
    const slice = orders.slice(offset, offset + limit);

    const records: Record<string, unknown> = {};
    for (const entry of slice) {
      records[entry.key] = entry.order;
    }

    return res.json({
      ok: true,
      totalCount: orders.length,
      returnedCount: slice.length,
      hasMore: offset + slice.length < orders.length,
      records,
    });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'Database error' });
  }
});

app.get('/api/db-status', async (req, res) => {
  try {
    const supabaseHealth = await checkSupabaseHealth();
    const databaseUrl = getDatabaseUrlInfo();
    if (!req.authSession?.admin) {
      return res.json({
        connected: supabaseHealth.configured ? supabaseHealth.connected : true,
        status: !supabaseHealth.configured || supabaseHealth.connected ? 'operational' : 'degraded',
      });
    }
    const all = await readAll();
    const count = Object.keys(all).length;
    return res.json({
      connected: supabaseHealth.configured ? supabaseHealth.connected : true,
      driver: isSupabaseConfigured() ? 'supabase' : 'file-memory',
      supabase: supabaseHealth,
      databaseUrl,
      recordsCount: count,
      status: !supabaseHealth.configured || supabaseHealth.connected ? 'operational' : 'degraded',
    });
  } catch (err: any) {
    return res.status(500).json({
      connected: false,
      error: req.authSession?.admin ? err?.message || 'Database error' : 'Database unavailable',
    });
  }
});

// 1.5. Verified Cookie-Backed Authentication Endpoints
app.get('/api/auth/supabase-public-config', async (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const publicCfg = getSupabasePublicConfig();
  return res.json({
    ok: true,
    configured: Boolean(publicCfg),
    googleAuthEnabled: false,
    ...(publicCfg ? { url: publicCfg.url, anonKey: publicCfg.anonKey } : {}),
  });
});

app.get('/api/auth/me', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  return res.json({
    ok: true,
    authenticated: Boolean(req.authSession),
    session: sanitizeAuthSessionForClient(req.authSession || null),
    ...(req.authSession?.sid ? { token: signSid(req.authSession.sid) } : {}),
  });
});

app.post('/api/auth/login', loginRateLimiter, async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const body = (req.body || {}) as Record<string, unknown>;
    const identifier = String(body.identifier || '').trim();
    const fullPhone = String(body.fullPhone || '').trim();
    const password = String(body.password || '').trim();

    if (!identifier || !password) {
      return res.status(400).json({ ok: false, error: 'يرجى إدخال رقم الهاتف أو المعرف وكلمة المرور.' });
    }

    const allData = await readAll(false);
    const idCandidates = Array.from(new Set([identifier, fullPhone].filter(Boolean)));
    const matchesAnyId = (val: unknown): boolean => {
      if (typeof val !== 'string' || !val.trim()) return false;
      return idCandidates.some((c) => matchesPhoneCandidates(val, c));
    };

    const targetSlug = String(body.targetSlug || '').trim();
    const targetRidParam = String(body.targetRid || '').trim();

    const resolveInitialSessionRid = (
      defaultRid: string,
      isAdminAcc: boolean,
      accountId?: string,
      phoneVal?: string
    ): string => {
      const lookup = targetSlug || targetRidParam;
      if (!lookup) return defaultRid;
      const target = resolveRestaurantEntryByIdOrSlug(allData, lookup);
      if (!target) return defaultRid;
      if (isAdminAcc) return target.rid;
      const owned = getOwnedPartnerRids(allData, defaultRid, {
        admin: false,
        accountId,
        phone: phoneVal || '',
      });
      return owned.has(target.rid) ? target.rid : defaultRid;
    };

    // 1. Direct owner fallback bootstrap if acc_admin_owner not yet persisted
    const isOwnerPhone = idCandidates.some((c) => matchesPhoneCandidates('07711448594', c));
    let matchedAnyAccount = isOwnerPhone;
    if (isOwnerPhone && !allData['accounts/acc_admin_owner'] && password.toLowerCase() === 'admin') {
      const ownerAcc = {
        id: 'acc_admin_owner',
        username: '07711448594',
        em: '07711448594',
        phone: '+9647711448594',
        pw: hashPasswordScrypt('admin'),
        rid: 'demo',
        admin: true,
        active: true,
        at: todayIsoDate(),
        created: todayIsoDate(),
      };
      await applyChanges({ put: { 'accounts/acc_admin_owner': ownerAcc } }, false);
      const effectiveRid = resolveInitialSessionRid('demo', true, 'acc_admin_owner', '+9647711448594');
      const ses = await createServerAuthSession(req, res, {
        role: 'owner',
        admin: true,
        accountId: 'acc_admin_owner',
        rid: effectiveRid,
        personalRid: 'demo',
        impersonating: effectiveRid !== 'demo',
        name: 'مالك المنصة',
        phone: '+9647711448594',
        email: '07711448594',
        roleTitle: 'مالك المنصة والمدير العام',
        permissions: FULL_OWNER_PERMISSIONS,
      });
      return res.json({
        ok: true,
        token: signSid(ses.sid),
        session: sanitizeAuthSessionForClient(ses),
        restaurant: sanitizeRecordSecrets(allData[`restaurants/${effectiveRid}`] || allData['restaurants/demo'] || null),
      });
    }

    // 2. Staff accounts in staff/*
    for (const [key, val] of Object.entries(allData)) {
      if (!key.startsWith('staff/') || !val || typeof val !== 'object') continue;
      const stf = val as Record<string, any>;
      if (!matchesAnyId(stf.phone) && !matchesAnyId(stf.email)) continue;
      matchedAnyAccount = true;

      const credOk = verifyStoredCredential(
        stf.passwordHash || stf.pw,
        [stf.email, stf.phone, identifier, fullPhone],
        password,
        false
      );
      if (!credOk) continue;

      if (stf.active === false) {
        return res.status(403).json({ ok: false, error: 'تم إيقاف هذا الحساب من قبل إدارة المنصة.' });
      }
      const staffId = key.slice('staff/'.length);
      const perms = stf.permissions || {};
      const effectiveRid = resolveInitialSessionRid('demo', true, undefined, String(stf.phone || ''));
      const ses = await createServerAuthSession(req, res, {
        role: 'staff',
        admin: true,
        staffId,
        rid: effectiveRid,
        personalRid: 'demo',
        impersonating: effectiveRid !== 'demo',
        name: String(stf.name || 'موظف إدارة'),
        email: String(stf.email || stf.phone || ''),
        phone: String(stf.phone || ''),
        roleTitle: String(stf.roleTitle || 'موظف إدارة'),
        permissions: perms,
      });
      return res.json({
        ok: true,
        token: signSid(ses.sid),
        session: sanitizeAuthSessionForClient(ses),
        restaurant: sanitizeRecordSecrets(allData[`restaurants/${effectiveRid}`] || allData['restaurants/demo'] || null),
      });
    }

    // 3. Admin & Partner accounts in accounts/* (prioritize admin accounts first)
    const accountEntries = Object.entries(allData)
      .filter(([key, val]) => key.startsWith('accounts/') && Boolean(val) && typeof val === 'object')
      .sort(([kA, vA], [kB, vB]) => {
        const aRec = vA as Record<string, any>;
        const bRec = vB as Record<string, any>;
        const aIsAdmin = aRec.admin === true || aRec.r === 'admin' || kA.startsWith('accounts/acc_admin_') ? 0 : 1;
        const bIsAdmin = bRec.admin === true || bRec.r === 'admin' || kB.startsWith('accounts/acc_admin_') ? 0 : 1;
        return aIsAdmin - bIsAdmin;
      });

    for (const [key, val] of accountEntries) {
      const acc = val as Record<string, any>;
      const accId = key.slice('accounts/'.length);
      if (
        !matchesAnyId(acc.email) &&
        !matchesAnyId(acc.phone) &&
        !matchesAnyId(acc.projectPhone) &&
        !matchesAnyId(acc.em) &&
        !matchesAnyId(acc.username) &&
        !matchesAnyId(acc.e) &&
        !matchesAnyId(acc.u)
      ) {
        continue;
      }
      matchedAnyAccount = true;

      const credOk = verifyStoredCredential(
        acc.pw,
        [acc.email, acc.username, acc.em, acc.phone, acc.e, acc.u, identifier, fullPhone, '07711448594'],
        password,
        accId === 'acc_menu_demo'
      );
      if (!credOk) continue;

      if (acc.active === false) {
        return res.status(403).json({ ok: false, error: 'تم إيقاف هذا الحساب من قبل إدارة المنصة.' });
      }

      const isAdmin = Boolean(acc.admin === true || acc.r === 'admin' || accId.startsWith('acc_admin_'));
      const baseRid = String(acc.rid || (isAdmin ? 'demo' : '')).trim() || 'demo';
      const phoneStr = String(acc.phone || acc.ph || acc.projectPhone || '');
      const effectiveRid = resolveInitialSessionRid(baseRid, isAdmin, accId, phoneStr);
      const linkedRest = allData[`restaurants/${effectiveRid}`] as Record<string, any> | undefined;

      if (!isAdmin && linkedRest && linkedRest.a === 0) {
        return res.status(403).json({ ok: false, error: 'تم إيقاف هذا المتجر مؤقتاً، يرجى التواصل مع الدعم الفني.' });
      }

      if (isAdmin) {
        const ses = await createServerAuthSession(req, res, {
          role: 'owner',
          admin: true,
          accountId: accId,
          rid: effectiveRid,
          personalRid: baseRid,
          impersonating: effectiveRid !== baseRid,
          name: String(acc.n || 'مدير المنصة'),
          email: String(acc.em || acc.phone || identifier),
          phone: phoneStr,
          roleTitle: String(acc.roleTitle || 'مالك المنصة والمدير العام'),
          permissions: FULL_OWNER_PERMISSIONS,
        });
        return res.json({
          ok: true,
          token: signSid(ses.sid),
          session: sanitizeAuthSessionForClient(ses),
          restaurant: sanitizeRecordSecrets(linkedRest || null),
        });
      }

      const targetRestObj = allData[`restaurants/${effectiveRid}`] as Record<string, any> | undefined;
      const effectivePersonalRid =
        targetRestObj && !targetRestObj.isBranch && !targetRestObj.parentRid
          ? effectiveRid
          : String(targetRestObj?.parentRid || baseRid);

      const ses = await createServerAuthSession(req, res, {
        role: 'partner',
        admin: false,
        accountId: accId,
        rid: effectiveRid,
        personalRid: effectivePersonalRid,
        name: String(acc.n || acc.projectName || linkedRest?.n || 'شريك'),
        email: String(acc.em || acc.phone || ''),
        phone: phoneStr,
      });
      return res.json({
        ok: true,
        token: signSid(ses.sid),
        session: sanitizeAuthSessionForClient(ses),
        restaurant: sanitizeRecordSecrets(linkedRest || null),
      });
    }

    return res.status(401).json({
      ok: false,
      error: matchedAnyAccount ? 'كلمة المرور غير صحيحة.' : 'لا يوجد حساب بهذا الرقم.',
    });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'تعذر إتمام تسجيل الدخول.' });
  }
});

// List all menus & branches controlled by the signed-in session (multi-menu SSO)
app.get('/api/auth/owned-menus', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const ses = req.authSession;
  if (!ses) {
    return res.status(401).json({ ok: false, error: 'يرجى تسجيل الدخول للمتابعة.' });
  }
  try {
    const allData = await readAll(false);
    const ownedRids = ses.admin
      ? null
      : getOwnedPartnerRids(allData, ses.personalRid || ses.rid, ses);

    const menus: Array<{
      id: string;
      name: string;
      slug: string;
      branchName: string;
      isBranch: boolean;
      parentRid: string;
      logo: string;
      done: number;
      projectType: string;
      planId: string;
    }> = [];

    for (const [k, v] of Object.entries(allData)) {
      if (!k.startsWith('restaurants/') || k.slice('restaurants/'.length).includes('/') || !v || typeof v !== 'object') {
        continue;
      }
      const rid = k.slice('restaurants/'.length);
      if (ownedRids && !ownedRids.has(rid)) continue;
      const rec = v as Record<string, unknown>;
      const slug =
        sanitizeSubdomainValue(String(rec.slug || rec.subdomain || '')) ||
        (rid === 'demo' ? 'cap-burger' : rid);
      menus.push({
        id: rid,
        name: String(rec.n || 'متجر'),
        slug,
        branchName: String(rec.branchName || ''),
        isBranch: Boolean(rec.isBranch || rec.parentRid),
        parentRid: String(rec.parentRid || ''),
        logo: String(rec.logo || ''),
        done: Number(rec.done || 0),
        projectType: String(rec.projectType || 'restaurant'),
        planId: String(rec.planId || 'pro'),
      });
    }

    menus.sort((a, b) => {
      if (a.id === ses.rid) return -1;
      if (b.id === ses.rid) return 1;
      if (a.isBranch !== b.isBranch) return a.isBranch ? 1 : -1;
      return a.name.localeCompare(b.name, 'ar');
    });

    return res.json({ ok: true, menus });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'تعذر تحميل قائمة المنيوهات.' });
  }
});

// Switch active menu/branch within already authenticated SSO session (no re-login needed)
app.post('/api/auth/switch-menu', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const ses = req.authSession;
  if (!ses) {
    return res.status(401).json({ ok: false, error: 'يرجى تسجيل الدخول للمتابعة.' });
  }
  try {
    const body = (req.body || {}) as Record<string, unknown>;
    const lookup = String(body.slug || body.rid || '').trim();
    if (!lookup) {
      return res.status(400).json({ ok: false, error: 'معرف المنيو مطلوب.' });
    }
    const allData = await readAll(false);
    const target = resolveRestaurantEntryByIdOrSlug(allData, lookup);
    if (!target) {
      return res.status(404).json({ ok: false, error: 'المنيو المطلوب غير موجود.' });
    }

    if (!ses.admin) {
      const owned = getOwnedPartnerRids(allData, ses.personalRid || ses.rid, ses);
      if (!owned.has(target.rid)) {
        return res.status(403).json({ ok: false, error: 'غير مصرح بالوصول إلى لوحة هذا المنيو.' });
      }
      if (target.rest.a === 0) {
        return res.status(403).json({ ok: false, error: 'تم إيقاف هذا المتجر مؤقتاً.' });
      }
    } else if (target.rid !== 'demo') {
      const perms =
        ses.role === 'owner' || !ses.staffId
          ? FULL_OWNER_PERMISSIONS
          : { ...FULL_OWNER_PERMISSIONS, ...req.authPermissions };
      if (!perms.canImpersonatePartner && !perms.canManageRestaurants) {
        return res.status(403).json({ ok: false, error: 'ليست لديك صلاحية الدخول للوحة هذا المنيو.' });
      }
    }

    const isBranch = Boolean(target.rest.isBranch || target.rest.parentRid);
    const nextPersonalRid = ses.admin
      ? ses.personalRid || 'demo'
      : !isBranch
      ? target.rid
      : String(target.rest.parentRid || ses.personalRid || target.rid);

    const updated = {
      ...ses,
      rid: target.rid,
      personalRid: nextPersonalRid,
      menuLoggedOut: false,
      ...(ses.admin ? { impersonating: target.rid !== (ses.personalRid || 'demo') } : {}),
    };
    await updateServerAuthSession(ses.sid, updated);
    req.authSession = updated;

    return res.json({
      ok: true,
      token: signSid(updated.sid),
      session: sanitizeAuthSessionForClient(updated),
      restaurant: sanitizeRecordSecrets(target.rest),
    });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'تعذر التبديل إلى المنيو.' });
  }
});

app.post('/api/onboard/profile', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const ses = req.authSession;
    if (!ses) {
      return res.status(401).json({ ok: false, error: 'يرجى تسجيل الدخول للمتابعة.' });
    }
    const body = (req.body || {}) as Record<string, unknown>;
    const allData = await readAll(false);
    const ownerRid = ses.personalRid || ses.rid;
    const ownedRids = ses.admin ? null : getOwnedPartnerRids(allData, ownerRid, ses);
    const rid = String(body.rid || ses.rid || ownerRid || '').trim();
    if (!rid || (ownedRids && !ownedRids.has(rid))) {
      return res.status(403).json({ ok: false, error: 'غير مصرح بتعديل هذا المشروع.' });
    }

    const existingRest = (allData[`restaurants/${rid}`] as Record<string, any> | undefined) || { id: rid };
    const nextRest: Record<string, any> = { ...existingRest };

    if (typeof body.n === 'string' && body.n.trim()) {
      nextRest.n = body.n.trim().slice(0, 120);
      nextRest.ow = nextRest.n;
    }
    if (body.ph !== undefined) {
      nextRest.ph = String(body.ph || '').trim().slice(0, 32);
    }
    if (body.projectType === 'restaurant' || body.projectType === 'store') {
      nextRest.projectType = body.projectType;
    }
    if (typeof body.logo === 'string' && body.logo.length <= 450_000) {
      nextRest.logo = body.logo;
    }
    if (Array.isArray(body.coverImages)) {
      nextRest.coverImages = body.coverImages
        .filter((x): x is string => typeof x === 'string' && x.length <= 650_000)
        .slice(0, 5);
    }
    if (typeof body.tagline === 'string') {
      nextRest.tagline = body.tagline.trim().slice(0, 220);
    }
    if (typeof body.aboutText === 'string') {
      nextRest.aboutText = body.aboutText.trim().slice(0, 800);
    }
    if (body.themeMode === 'light' || body.themeMode === 'dark' || body.themeMode === 'auto') {
      nextRest.themeMode = body.themeMode;
    }
    if (typeof body.themePreset === 'string' && body.themePreset.trim()) {
      nextRest.themePreset = body.themePreset.trim().slice(0, 48);
    }
    if (typeof body.themeShape === 'string' && body.themeShape.trim()) {
      nextRest.themeShape = body.themeShape.trim().slice(0, 32);
    }
    if (typeof body.color === 'string' && /^#[0-9a-f]{3,8}$/i.test(body.color.trim())) {
      nextRest.color = body.color.trim();
    }
    if (
      body.lay === 'list' ||
      body.lay === 'grid' ||
      body.lay === 'grid3' ||
      body.lay === 'grid4' ||
      body.lay === 'cards'
    ) {
      nextRest.lay = body.lay;
    }
    if (nextRest.projectType === 'store') {
      nextRest.themeMode = 'light';
      nextRest.themePreset = 'estore';
      nextRest.themeShape = 'estore';
      nextRest.color = '#f15a29';
      delete nextRest.bgColor;
      if (String(nextRest.tagline || '').trim() === 'أشهى الأطباق المحضرة يومياً طازجة بجودة عالية') {
        nextRest.tagline = '';
      }
    }
    if (body.h && typeof body.h === 'object' && !Array.isArray(body.h)) {
      nextRest.h = body.h;
    }
    if (body.done === 0 || body.done === 1) {
      nextRest.done = body.done;
    }
    if (body.on === 0 || body.on === 1) {
      nextRest.on = body.on;
    }
    const plansList = extractPlansList(allData['settings/plans']);
    const subRules = normalizeSubdomainRules((allData['settings/site'] as Record<string, unknown>) || null);
    const takenSlugs = collectTakenSlugsFromAllData(allData, rid);
    const { isPaid: restIsPaid } = isPaidPlanForRestaurant(nextRest as StoreRecord, plansList);
    const canUseCustomSlug = Boolean(ses.admin) || restIsPaid;

    if (!canUseCustomSlug) {
      const curSlug = sanitizeSubdomainValue(String(nextRest.slug || ''));
      if (!isValidSixCharCode(curSlug) || takenSlugs.has(curSlug)) {
        nextRest.slug = generateUniqueMenuCode(takenSlugs);
      } else {
        nextRest.slug = curSlug;
      }
      nextRest.subdomain = '';
    } else {
      if (!nextRest.slug || !sanitizeSubdomainValue(String(nextRest.slug))) {
        nextRest.slug = generateUniqueMenuCode(takenSlugs);
      }
      if (typeof body.slug === 'string' && body.slug.trim()) {
        const cleanSlug = sanitizeSubdomainValue(body.slug);
        const validation = validatePathSlugFormat(cleanSlug, subRules);
        if (validation.valid && !takenSlugs.has(cleanSlug)) {
          nextRest.slug = cleanSlug;
          nextRest.subdomain = subRules.enabled ? cleanSlug : '';
        }
      } else if (!subRules.enabled) {
        nextRest.subdomain = '';
      }
    }

    const putMap: Record<string, unknown> = {
      [`restaurants/${rid}`]: nextRest,
    };

    if (ses.accountId && allData[`accounts/${ses.accountId}`]) {
      const existingAcc = allData[`accounts/${ses.accountId}`] as Record<string, any>;
      putMap[`accounts/${ses.accountId}`] = {
        ...existingAcc,
        ...(nextRest.n ? { projectName: nextRest.n, n: nextRest.n } : {}),
        ...(nextRest.projectType ? { projectType: nextRest.projectType } : {}),
        ...(body.ph !== undefined ? { projectPhone: nextRest.ph } : {}),
      };
      if (nextRest.n) {
        await updateServerAuthSession(ses.sid, { ...ses, name: nextRest.n }).catch(() => {});
      }
    }

    putMap[`logs/aud_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`] = {
      id: `aud_${Date.now().toString(36)}`,
      ts: Date.now(),
      actor: ses.phone || ses.name || nextRest.n || 'شريك',
      action: 'تحديث ملف المشروع والإعداد الأولي',
      details: `المشروع: ${nextRest.n || rid} (${rid})`,
      type: 'restaurant',
    };

    await applyChanges({ put: putMap }, false);
    return res.json({ ok: true, restaurant: nextRest });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'تعذر حفظ بيانات المشروع.' });
  }
});

app.post('/api/auth/impersonate', requireAdminOrStaff(), async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const ses = req.authSession!;
    const rawRid = (req.body as Record<string, unknown>)?.rid;
    const requestedRid = rawRid === null || rawRid === undefined ? '' : String(rawRid).trim();
    const exitToOwn = !requestedRid || requestedRid === '__exit__';
    const nextRid = exitToOwn ? (ses.personalRid || 'demo') : requestedRid;

    if (!exitToOwn) {
      const perms: Record<string, boolean | undefined> =
        ses.role === 'owner' || !ses.staffId ? FULL_OWNER_PERMISSIONS : (req.authPermissions as Record<string, boolean | undefined>) || {};
      if (nextRid === 'demo') {
        if (!perms.canEditDemoMenu && !perms.canImpersonatePartner) {
          return res.status(403).json({ ok: false, error: 'ليست لديك صلاحية تعديل المنيو التجريبي.' });
        }
      } else if (!perms.canImpersonatePartner) {
        return res.status(403).json({ ok: false, error: 'ليست لديك صلاحية فتح لوحة تحكم الشركاء.' });
      }

      const targetRest = await getInternalStoreItem(`restaurants/${nextRid}`);
      if (!targetRest) {
        return res.status(404).json({ ok: false, error: 'المتجر المستهدف غير موجود.' });
      }
    }

    const updated = {
      ...ses,
      rid: nextRid,
      personalRid: exitToOwn ? (ses.personalRid || 'demo') : (ses.personalRid || nextRid),
      impersonating: !exitToOwn && nextRid !== (ses.personalRid || 'demo'),
      menuLoggedOut: false,
    };
    await updateServerAuthSession(ses.sid, updated);
    req.authSession = updated;
    return res.json({ ok: true, token: signSid(updated.sid), session: sanitizeAuthSessionForClient(updated) });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'تعذر تبديل الجلسة.' });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const body = (req.body || {}) as Record<string, unknown>;
  const scope = String(body.scope || 'all').trim();
  const ses = req.authSession;
  if (scope === 'menu' && ses && ses.admin && !ses.menuLoggedOut) {
    const updated = {
      ...ses,
      rid: undefined,
      personalRid: undefined,
      impersonating: false,
      menuLoggedOut: true,
    };
    await updateServerAuthSession(ses.sid, updated);
    req.authSession = updated;
    return res.json({
      ok: true,
      partial: true,
      token: signSid(updated.sid),
      session: sanitizeAuthSessionForClient(updated),
    });
  }
  await destroyServerAuthSession(req, res);
  return res.json({ ok: true, partial: false });
});

// Validated public review submission (without granting full write access to restaurants/*)
app.post('/api/reviews', otpRateLimiter, async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const body = (req.body || {}) as Record<string, unknown>;
    const rid = String(body.rid || '').trim();
    const name = String(body.name || 'زبون').trim().slice(0, 60) || 'زبون';
    const rate = Math.max(1, Math.min(5, Math.round(Number(body.rate || 5))));
    const comment = String(body.comment || '').trim().slice(0, 500);
    if (!rid || !comment) {
      return res.status(400).json({ ok: false, error: 'يرجى كتابة التقييم قبل الإرسال.' });
    }

    const rest = await getInternalStoreItem<Record<string, any>>(`restaurants/${rid}`);
    if (!rest) {
      return res.status(404).json({ ok: false, error: 'المتجر غير موجود.' });
    }

    const existingReviews = Array.isArray(rest.reviews) ? rest.reviews : [];
    const newReview = {
      id: `rev_${Date.now().toString(36)}_${crypto.randomBytes(2).toString('hex')}`,
      name,
      rate,
      comment,
      at: Date.now(),
    };
    const nextReviews = [newReview, ...existingReviews].slice(0, 200);
    await applyChanges({ put: { [`restaurants/${rid}`]: { ...rest, reviews: nextReviews } } }, false);
    return res.json({ ok: true, reviews: nextReviews });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'تعذر إرسال التقييم.' });
  }
});

// Backward-compatible /api/session endpoints — strictly read-only or scoped RID switch only (NO privilege escalation)
app.get('/api/session', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  return res.json({
    sessionId: req.authSession?.sid || null,
    session: sanitizeAuthSessionForClient(req.authSession || null),
  });
});

app.post('/api/session', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const ses = req.authSession;
  if (!ses) {
    return res.status(401).json({ ok: false, error: 'يتطلب تسجيل الدخول عبر /api/auth/login.' });
  }
  const reqSes = (req.body as Record<string, unknown>)?.session as Record<string, unknown> | undefined;
  const targetRid = reqSes?.rid ? String(reqSes.rid).trim() : '';
  if (!targetRid || targetRid === ses.rid) {
    return res.json({ ok: true, sessionId: ses.sid });
  }
  if (ses.admin) {
    const updated = { ...ses, rid: targetRid, menuLoggedOut: false };
    await updateServerAuthSession(ses.sid, updated);
    req.authSession = updated;
    return res.json({ ok: true, sessionId: ses.sid });
  }
  // Partners can switch between any of their owned menus & branches
  const allData = await readAll(false);
  const owned = getOwnedPartnerRids(allData, ses.personalRid || ses.rid, ses);
  if (!owned.has(targetRid)) {
    return res.status(403).json({ ok: false, error: 'غير مصرح بالوصول إلى هذا المتجر.' });
  }
  const updated = { ...ses, rid: targetRid };
  await updateServerAuthSession(ses.sid, updated);
  req.authSession = updated;
  return res.json({ ok: true, sessionId: ses.sid });
});

app.delete('/api/session', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  await destroyServerAuthSession(req, res);
  return res.json({ ok: true });
});

// 2. Telegram Order Notifications Bot endpoints
app.get('/api/telegram-status', (_req, res) => {
  res.json(getTelegramBotStatus());
});

async function resolvePartnerTelegramAccess(req: Request, requestedRid: unknown): Promise<{ ok: true; rid: string } | { ok: false; status: number; error: string }> {
  const ses = req.authSession;
  if (!ses) {
    return { ok: false, status: 401, error: 'يرجى تسجيل الدخول للمتابعة.' };
  }
  const targetRid = String(requestedRid || ses.rid || '').trim();
  if (!targetRid) {
    return { ok: false, status: 400, error: 'معرّف المتجر مطلوب.' };
  }
  if (ses.admin) {
    return { ok: true, rid: targetRid };
  }
  const allData = await readAll(false);
  const owned = getOwnedPartnerRids(allData, ses.personalRid || ses.rid, ses);
  if (!owned.has(targetRid)) {
    return { ok: false, status: 403, error: 'غير مصرح بالوصول إلى هذا المتجر.' };
  }
  return { ok: true, rid: targetRid };
}

app.get('/api/dashboard/telegram/status', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const auth = await resolvePartnerTelegramAccess(req, req.query.rid);
    if (!auth.ok) return res.status(auth.status).json({ ok: false, error: auth.error });
    const status = await getTelegramOrderLinkStatus(auth.rid);
    return res.json(status);
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'تعذر تحميل حالة الربط.' });
  }
});

app.post('/api/dashboard/telegram/link', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const body = (req.body || {}) as Record<string, unknown>;
    const auth = await resolvePartnerTelegramAccess(req, body.rid);
    if (!auth.ok) return res.status(auth.status).json({ ok: false, error: auth.error });
    const result = await initTelegramOrderLink(auth.rid, String(body.phone || ''));
    return res.status(result.ok ? 200 : 400).json(result);
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'تعذر بدء ربط تيليجرام.' });
  }
});

app.post('/api/dashboard/telegram/toggle', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const body = (req.body || {}) as Record<string, unknown>;
    const auth = await resolvePartnerTelegramAccess(req, body.rid);
    if (!auth.ok) return res.status(auth.status).json({ ok: false, error: auth.error });
    const enabled = body.enabled !== false;
    const ok = await toggleTelegramForRestaurant(auth.rid, enabled);
    if (!ok) return res.status(404).json({ ok: false, error: 'المتجر غير موجود.' });
    return res.json({ ok: true, enabled });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'تعذر تحديث التفعيل.' });
  }
});

app.post('/api/dashboard/telegram/unlink', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const body = (req.body || {}) as Record<string, unknown>;
    const auth = await resolvePartnerTelegramAccess(req, body.rid);
    if (!auth.ok) return res.status(auth.status).json({ ok: false, error: auth.error });
    const ok = await unlinkTelegramForRestaurant(auth.rid);
    if (!ok) return res.status(404).json({ ok: false, error: 'المتجر غير موجود.' });
    return res.json({ ok: true });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'تعذر فك الربط.' });
  }
});

app.post('/api/dashboard/telegram/test', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const body = (req.body || {}) as Record<string, unknown>;
    const auth = await resolvePartnerTelegramAccess(req, body.rid);
    if (!auth.ok) return res.status(auth.status).json({ ok: false, error: auth.error });
    const result = await sendPartnerTestOrderNotification(auth.rid);
    return res.status(result.ok ? 200 : 400).json(result);
  } catch (err: any) {
    return res.status(500).json({ ok: false, message: err?.message || 'تعذر إرسال الطلب التجريبي.' });
  }
});

app.post('/api/dashboard/telegram/verify', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const body = (req.body || {}) as Record<string, unknown>;
    const auth = await resolvePartnerTelegramAccess(req, body.rid);
    if (!auth.ok) return res.status(auth.status).json({ ok: false, error: auth.error });
    const result = await verifyTelegramBotLive(auth.rid);
    return res.status(200).json(result);
  } catch (err: any) {
    return res.status(500).json({
      ok: false,
      diagnosticMessage: err?.message || 'تعذر فحص اتصال بوت تيليجرام.',
    });
  }
});

app.post('/api/telegram/webhook', async (req, res) => {
  try {
    const body = (req.body || {}) as { message?: Parameters<typeof handleIncomingTelegramMessage>[0] };
    if (body?.message && body.message.chat?.id) {
      await handleIncomingTelegramMessage(body.message);
    }
    return res.json({ ok: true });
  } catch (err: any) {
    console.warn('[Telegram Webhook] Error:', err?.message || err);
    return res.json({ ok: true });
  }
});

// 2.5. Cross-Menu Persistent Customer Profile (auto-fills across all menus & subdomains)
const CUST_PROFILE_COOKIE = 'mp_cust_id';
const CUST_PROFILE_KV_PREFIX = 'customer_profiles/';

function setCustomerProfileCookie(res: Response, req: Request, custId: string): void {
  const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';
  const reqHost = String(req.hostname || '').toLowerCase().trim();
  const sharesSubdomains =
    BASE_DOMAIN &&
    (reqHost === BASE_DOMAIN || reqHost.endsWith(`.${BASE_DOMAIN}`));
  const parts = [
    `${CUST_PROFILE_COOKIE}=${encodeURIComponent(custId)}`,
    'Path=/',
    'HttpOnly',
    isHttps ? 'SameSite=None' : 'SameSite=Lax',
    `Max-Age=${365 * 24 * 60 * 60}`,
  ];
  if (sharesSubdomains) parts.push(`Domain=.${BASE_DOMAIN}`);
  if (isHttps) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

app.get('/api/customer-profile', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const cookies = parseRequestCookies(req.headers.cookie);
    const custId = String(cookies[CUST_PROFILE_COOKIE] || req.headers['x-customer-profile-id'] || '').trim();
    if (!custId || !/^[a-zA-Z0-9_-]{8,64}$/.test(custId)) {
      return res.json({ ok: true, profile: null });
    }
    const profile = await getInternalStoreItem<{
      name?: string;
      phone?: string;
      address?: string;
      notes?: string;
      updatedAt?: number;
    }>(`${CUST_PROFILE_KV_PREFIX}${custId}`).catch(() => null);
    return res.json({ ok: true, custId, profile: profile || null });
  } catch {
    return res.json({ ok: true, profile: null });
  }
});

app.post('/api/customer-profile', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const cookies = parseRequestCookies(req.headers.cookie);
    let custId = String(cookies[CUST_PROFILE_COOKIE] || req.headers['x-customer-profile-id'] || '').trim();
    if (!custId || !/^[a-zA-Z0-9_-]{8,64}$/.test(custId)) {
      custId = `cust_${crypto.randomBytes(12).toString('hex')}`;
    }
    const body = (req.body || {}) as Record<string, unknown>;
    const existing = await getInternalStoreItem<{
      name?: string;
      phone?: string;
      address?: string;
      notes?: string;
      updatedAt?: number;
    }>(`${CUST_PROFILE_KV_PREFIX}${custId}`).catch(() => null);

    const nextProfile = {
      name: String(body.name ?? existing?.name ?? '').trim().slice(0, 120),
      phone: String(body.phone ?? existing?.phone ?? '').trim().slice(0, 40),
      address: String(body.address ?? existing?.address ?? '').trim().slice(0, 400),
      notes: String(body.notes ?? existing?.notes ?? '').trim().slice(0, 400),
      updatedAt: Date.now(),
    };
    await setInternalStoreItem(`${CUST_PROFILE_KV_PREFIX}${custId}`, nextProfile);
    setCustomerProfileCookie(res, req, custId);
    return res.json({ ok: true, custId, profile: nextProfile });
  } catch {
    return res.status(500).json({ ok: false });
  }
});

// 2.6. URL-Backed Media Image Upload, Serving & Cleanup (prevents Base64 bloat in menuplus_kv)
const MEDIA_DISK_DIR = path.resolve(process.cwd(), 'data/media');

function detectImageFormatAndMime(buf: Buffer): {
  ext: 'jpg' | 'png' | 'webp' | 'gif';
  mime: string;
} | null {
  if (buf.length < 12) return null;
  // JPEG: FF D8 FF
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    return { ext: 'jpg', mime: 'image/jpeg' };
  }
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    buf[0] === 0x89 &&
    buf[1] === 0x50 &&
    buf[2] === 0x4e &&
    buf[3] === 0x47 &&
    buf[4] === 0x0d &&
    buf[5] === 0x0a &&
    buf[6] === 0x1a &&
    buf[7] === 0x0a
  ) {
    return { ext: 'png', mime: 'image/png' };
  }
  // WebP: RIFF....WEBP
  if (
    buf.subarray(0, 4).toString('ascii') === 'RIFF' &&
    buf.subarray(8, 12).toString('ascii') === 'WEBP'
  ) {
    return { ext: 'webp', mime: 'image/webp' };
  }
  // GIF: GIF87a or GIF89a
  const gifSig = buf.subarray(0, 6).toString('ascii');
  if (gifSig === 'GIF87a' || gifSig === 'GIF89a') {
    return { ext: 'gif', mime: 'image/gif' };
  }
  return null;
}

app.post('/api/media/upload', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const ses = req.authSession;
    if (!ses) {
      return res.status(401).json({ ok: false, error: 'يرجى تسجيل الدخول لرفع الصور.' });
    }
    const { fileName, dataBase64 } = (req.body || {}) as {
      fileName?: string;
      dataBase64?: string;
    };
    const rawB64 = String(dataBase64 || '')
      .trim()
      .replace(/^data:image\/[a-zA-Z0-9.+-]+;base64,/i, '');
    if (!rawB64) {
      return res.status(400).json({ ok: false, error: 'بيانات الصورة غير صالحة.' });
    }
    const buf = Buffer.from(rawB64, 'base64');
    if (buf.length < 32 || buf.length > 4 * 1024 * 1024) {
      return res.status(400).json({ ok: false, error: 'حجم الصورة يجب أن يكون أقل من 4 ميغابايت.' });
    }
    const detected = detectImageFormatAndMime(buf);
    if (!detected) {
      return res.status(400).json({ ok: false, error: 'صيغة الصورة غير مدعومة (JPG/PNG/WebP/GIF فقط).' });
    }

    const fileId = `img_${Date.now().toString(36)}_${crypto.randomBytes(5).toString('hex')}`;
    if (!fs.existsSync(MEDIA_DISK_DIR)) {
      fs.mkdirSync(MEDIA_DISK_DIR, { recursive: true });
    }
    const diskPath = path.resolve(MEDIA_DISK_DIR, `${fileId}.${detected.ext}`);
    if (!diskPath.startsWith(MEDIA_DISK_DIR + path.sep)) {
      return res.status(400).json({ ok: false, error: 'مسار غير صالح.' });
    }
    fs.writeFileSync(diskPath, buf);

    // Lazy KV fallback (excluded from bulk sync/bootstrap; fetched only on cold cache miss)
    await setInternalStoreItem(`media_files/${fileId}`, {
      fileId,
      fileName: String(fileName || 'image').slice(0, 120),
      ext: detected.ext,
      mime: detected.mime,
      sizeBytes: buf.length,
      dataBase64: buf.toString('base64'),
      createdAt: new Date().toISOString(),
    });

    return res.json({
      ok: true,
      fileId,
      url: `/api/media/file/${fileId}.${detected.ext}`,
      ext: detected.ext,
      sizeBytes: buf.length,
    });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'فشل رفع الصورة.' });
  }
});

app.get('/api/media/file/:fileParam', async (req, res) => {
  try {
    const rawParam = String(req.params.fileParam || '').trim();
    const match = /^([a-zA-Z0-9_-]+)(?:\.(jpg|jpeg|png|webp|gif))?$/i.exec(rawParam);
    if (!match) {
      return res.status(400).send('Invalid media id');
    }
    const fileId = match[1];
    const mimeByExt: Record<string, string> = {
      jpg: 'image/jpeg',
      jpeg: 'image/jpeg',
      png: 'image/png',
      webp: 'image/webp',
      gif: 'image/gif',
    };

    for (const ext of ['jpg', 'png', 'webp', 'gif'] as const) {
      const candidate = path.resolve(MEDIA_DISK_DIR, `${fileId}.${ext}`);
      if (candidate.startsWith(MEDIA_DISK_DIR + path.sep) && fs.existsSync(candidate)) {
        res.setHeader('Content-Type', mimeByExt[ext]);
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        return res.sendFile(candidate);
      }
    }

    const stored = (await getInternalStoreItem(`media_files/${fileId}`)) as
      | { ext?: string; mime?: string; dataBase64?: string }
      | undefined;
    if (!stored || !stored.dataBase64) {
      return res.status(404).send('Image not found');
    }
    const buf = Buffer.from(stored.dataBase64, 'base64');
    const ext = stored.ext === 'png' || stored.ext === 'webp' || stored.ext === 'gif' ? stored.ext : 'jpg';
    const mime = stored.mime || mimeByExt[ext];
    try {
      if (!fs.existsSync(MEDIA_DISK_DIR)) fs.mkdirSync(MEDIA_DISK_DIR, { recursive: true });
      const diskPath = path.resolve(MEDIA_DISK_DIR, `${fileId}.${ext}`);
      if (diskPath.startsWith(MEDIA_DISK_DIR + path.sep)) {
        fs.writeFileSync(diskPath, buf);
      }
    } catch {
      // ignore disk cache write failure
    }
    res.setHeader('Content-Type', mime);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    return res.send(buf);
  } catch {
    return res.status(500).send('Failed to load image');
  }
});

app.post('/api/dashboard/media/delete-file', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const ses = req.authSession;
    if (!ses) {
      return res.status(401).json({ ok: false, error: 'يرجى تسجيل الدخول.' });
    }
    const url = String((req.body || {}).url || '').trim();
    if (!url || (!url.startsWith('/uploads/') && !url.startsWith('/api/media/file/'))) {
      return res.json({ ok: true, deletedFile: false });
    }

    // Check only relevant collections from in-memory snapshot without triggering a DB sync
    const snapshot = getMemoryStoreSnapshot(false);
    let stillReferenced = false;
    for (const [k, v] of Object.entries(snapshot)) {
      if (
        !k.startsWith('restaurants/') &&
        !k.startsWith('cats/') &&
        !k.startsWith('items/') &&
        !k.startsWith('reports/')
      ) {
        continue;
      }
      if (v && JSON.stringify(v).includes(url)) {
        stillReferenced = true;
        break;
      }
    }
    if (stillReferenced) {
      return res.json({ ok: true, deletedFile: false });
    }

    if (url.startsWith('/api/media/file/')) {
      const rawParam = url.slice('/api/media/file/'.length);
      const m = /^([a-zA-Z0-9_-]+)(?:\.(jpg|jpeg|png|webp|gif))?$/i.exec(rawParam);
      if (!m) return res.json({ ok: true, deletedFile: false });
      const fileId = m[1];
      let deletedDisk = false;
      for (const ext of ['jpg', 'jpeg', 'png', 'webp', 'gif']) {
        const target = path.resolve(MEDIA_DISK_DIR, `${fileId}.${ext}`);
        if (target.startsWith(MEDIA_DISK_DIR + path.sep) && fs.existsSync(target)) {
          fs.unlinkSync(target);
          deletedDisk = true;
        }
      }
      await deleteInternalStoreItem(`media_files/${fileId}`).catch(() => {});
      return res.json({ ok: true, deletedFile: deletedDisk || true });
    }

    const uploadsRoot = path.resolve(process.cwd(), 'public', 'uploads');
    const relPath = url.replace(/^\/uploads\//, '');
    const resolvedTarget = path.resolve(uploadsRoot, relPath);
    if (
      resolvedTarget.startsWith(uploadsRoot + path.sep) &&
      fs.existsSync(resolvedTarget) &&
      fs.statSync(resolvedTarget).isFile()
    ) {
      fs.unlinkSync(resolvedTarget);
      return res.json({ ok: true, deletedFile: true });
    }
    return res.json({ ok: true, deletedFile: false });
  } catch {
    return res.json({ ok: true, deletedFile: false });
  }
});


// 3. Notes endpoints (strictly protected with canUseNotes permission)
app.all('/api/notes', requireAdminOrStaff('canUseNotes'), async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const db = await readAll().catch(() => ({} as Record<string, unknown>));
    const seedNotes: StoredNote[] = Object.entries(db)
      .filter(([k]) => k.startsWith('notes/'))
      .map(([, v]) => v as StoredNote)
      .filter((v) => v && typeof v === 'object' && v.id);

    if (req.method === 'GET') {
      const result = readNotesDocument(seedNotes);
      if (seedNotes.length > 0 && isSupabaseConfigured()) {
        return res.json({ ...result, notes: seedNotes });
      }
      return res.json(result);
    }

    if (req.method === 'POST') {
      const body = req.body || {};
      if (body.action === 'delete' && body.id) {
        const noteId = String(body.id);
        const result = deleteNoteFromFile(noteId, seedNotes);
        await applyChanges({ del: [`notes/${noteId}`] }, false);
        return res.json({ ok: true, ...result });
      }
      if (body.action === 'replaceAll' && Array.isArray(body.notes)) {
        const result = replaceAllNotesInFile(body.notes);
        const oldNoteKeys = Object.keys(db).filter((k) => k.startsWith('notes/'));
        const putMap: Record<string, unknown> = {};
        for (const n of result.notes) {
          putMap[`notes/${n.id}`] = n;
        }
        const delKeys = oldNoteKeys.filter((k) => !Object.prototype.hasOwnProperty.call(putMap, k));
        await applyChanges({ put: putMap, del: delKeys }, false);
        return res.json({ ok: true, ...result });
      }
      if (body.note && typeof body.note === 'object' && body.note.id) {
        const result = saveNoteToFile(body.note as StoredNote, seedNotes);
        await applyChanges({ put: { [`notes/${result.savedNote.id}`]: result.savedNote } }, false);
        return res.json({ ok: true, ...result });
      }
      return res.status(400).json({ error: 'Invalid notes payload' });
    }

    return res.status(405).json({ error: 'Method not allowed' });
  } catch (err: any) {
    return res.status(500).json({ error: err?.message || 'Notes error' });
  }
});

// 4. Image search & proxy
app.get('/api/search-images', async (req, res) => {
  const q = String(req.query.q || '').slice(0, 120);
  const limit = Math.min(24, Math.max(4, Number(req.query.limit || '16') || 16));
  const offset = Math.max(0, Math.min(80, Number(req.query.offset || '0') || 0));
  const seed = Math.max(0, Math.min(50, Number(req.query.seed || '0') || 0));
  const excludeRaw = String(req.query.exclude || '');
  const exclude = excludeRaw ? excludeRaw.split(',').map((s) => s.trim()).filter(Boolean).slice(0, 48) : [];
  const images = await searchWebImages(q, limit, offset, seed, exclude);
  res.json({ query: q, images });
});

app.get('/api/proxy-image', async (req, res) => {
  const target = String(req.query.url || '');
  const result = await proxyExternalImage(target);
  res.status(result.status);
  res.setHeader('Content-Type', result.contentType);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (result.status === 200 && result.buffer) {
    res.setHeader('Content-Security-Policy', "default-src 'none'");
    res.setHeader('Cache-Control', 'public, max-age=86400');
    return res.send(result.buffer);
  }
  return res.json({ error: result.error || 'Proxy error' });
});

// 4.5. Admin persistent Staff CRUD & Accounts management endpoints
app.use(createAdminRouter());

// 4.6. Dynamic subdomain resolution, availability check & admin listing endpoints
app.use(createSubdomainRouter());

// 4.7. Platform Custom Font (.otf/.ttf/.woff/.woff2) Upload & Serving Endpoints
const FONTS_DISK_DIR = path.resolve(process.cwd(), 'data/fonts');

function detectFontFormatAndMime(fileName: string, buf: Buffer): {
  ext: 'otf' | 'ttf' | 'woff' | 'woff2';
  format: 'opentype' | 'truetype' | 'woff' | 'woff2';
  mime: string;
} | null {
  const lower = String(fileName || '').toLowerCase();
  const magic4 = buf.subarray(0, 4);
  const magicStr = magic4.toString('ascii');

  const isOtfMagic = magicStr === 'OTTO';
  const isTtfMagic =
    (magic4[0] === 0x00 && magic4[1] === 0x01 && magic4[2] === 0x00 && magic4[3] === 0x00) ||
    magicStr === 'true' ||
    magicStr === 'typ1';
  const isWoffMagic = magicStr === 'wOFF';
  const isWoff2Magic = magicStr === 'wOF2';

  if (lower.endsWith('.otf') && (isOtfMagic || isTtfMagic)) {
    return { ext: 'otf', format: 'opentype', mime: 'font/otf' };
  }
  if (lower.endsWith('.ttf') && (isTtfMagic || isOtfMagic)) {
    return { ext: 'ttf', format: 'truetype', mime: 'font/ttf' };
  }
  if (lower.endsWith('.woff2') && isWoff2Magic) {
    return { ext: 'woff2', format: 'woff2', mime: 'font/woff2' };
  }
  if (lower.endsWith('.woff') && isWoffMagic) {
    return { ext: 'woff', format: 'woff', mime: 'font/woff' };
  }

  // Fallback by magic bytes if filename had unusual casing or omitted ext
  if (isOtfMagic) return { ext: 'otf', format: 'opentype', mime: 'font/otf' };
  if (isWoff2Magic) return { ext: 'woff2', format: 'woff2', mime: 'font/woff2' };
  if (isWoffMagic) return { ext: 'woff', format: 'woff', mime: 'font/woff' };
  if (isTtfMagic) return { ext: 'ttf', format: 'truetype', mime: 'font/ttf' };
  return null;
}

app.post('/api/admin/fonts/upload', requireAdminOrStaff(), async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const ses = req.authSession!;
    const perms =
      ses.role === 'owner' || !ses.staffId
        ? FULL_OWNER_PERMISSIONS
        : { ...FULL_OWNER_PERMISSIONS, ...req.authPermissions };
    if (!perms.canManageSettings && !perms.canManageThemeMode && !perms.canEditHomePage) {
      return res.status(403).json({ ok: false, error: 'ليست لديك صلاحية رفع وتعديل خطوط المنصة' });
    }

    const { fileName, dataBase64, weight } = (req.body || {}) as {
      fileName?: string;
      dataBase64?: string;
      weight?: number;
    };

    const rawName = String(fileName || 'custom-font.otf').trim();
    const rawB64 = String(dataBase64 || '')
      .trim()
      .replace(/^data:[^;]+;base64,/i, '');

    if (!rawB64) {
      return res.status(400).json({ ok: false, error: 'ملف الخط فارغ أو غير صالح' });
    }

    const buf = Buffer.from(rawB64, 'base64');
    if (buf.length < 32 || buf.length > 8 * 1024 * 1024) {
      return res.status(400).json({ ok: false, error: 'حجم ملف الخط يجب أن يكون بين 32 بايت و 8 ميغابايت' });
    }

    const detected = detectFontFormatAndMime(rawName, buf);
    if (!detected) {
      return res.status(400).json({
        ok: false,
        error: 'صيغة ملف الخط غير مدعومة. يرجى رفع ملف خط بصيغة .otf أو .ttf أو .woff2 أو .woff',
      });
    }

    const fileId = `font_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`;
    const numericWeight = Number(weight) === 0 ? 0 : Math.min(900, Math.max(100, Number(weight) || 400));

    if (!fs.existsSync(FONTS_DISK_DIR)) {
      fs.mkdirSync(FONTS_DISK_DIR, { recursive: true });
    }
    const diskPath = path.join(FONTS_DISK_DIR, `${fileId}.${detected.ext}`);
    fs.writeFileSync(diskPath, buf);

    await applyChanges(
      {
        put: {
          [`custom_font_files/${fileId}`]: {
            fileId,
            fileName: rawName.slice(0, 140),
            ext: detected.ext,
            format: detected.format,
            mime: detected.mime,
            weight: numericWeight,
            sizeBytes: buf.length,
            dataBase64: buf.toString('base64'),
            createdAt: new Date().toISOString(),
          },
        },
      },
      false
    );

    return res.json({
      ok: true,
      fileId,
      url: `/api/fonts/file/${fileId}.${detected.ext}`,
      format: detected.format,
      ext: detected.ext,
      sizeBytes: buf.length,
    });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'فشل رفع ملف الخط' });
  }
});

app.get('/api/fonts/file/:fileParam', async (req, res) => {
  try {
    const rawParam = String(req.params.fileParam || '').trim();
    const match = /^([a-zA-Z0-9_-]+)(?:\.(otf|ttf|woff2|woff))?$/i.exec(rawParam);
    if (!match) {
      return res.status(400).send('Invalid font id');
    }
    const fileId = match[1];

    // 1. Check disk cache first
    for (const ext of ['otf', 'ttf', 'woff2', 'woff'] as const) {
      const candidate = path.join(FONTS_DISK_DIR, `${fileId}.${ext}`);
      if (fs.existsSync(candidate)) {
        const mime =
          ext === 'otf'
            ? 'font/otf'
            : ext === 'ttf'
            ? 'font/ttf'
            : ext === 'woff2'
            ? 'font/woff2'
            : 'font/woff';
        res.setHeader('Content-Type', mime);
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        return res.sendFile(candidate);
      }
    }

    // 2. Fallback to persistent store (e.g. Supabase or data/db-store.json)
    const stored = (await getInternalStoreItem(`custom_font_files/${fileId}`)) as
      | { ext?: string; mime?: string; dataBase64?: string }
      | undefined;
    if (!stored || !stored.dataBase64) {
      return res.status(404).send('Font not found');
    }
    const buf = Buffer.from(stored.dataBase64, 'base64');
    const ext = stored.ext || 'otf';
    const mime = stored.mime || 'font/otf';
    try {
      if (!fs.existsSync(FONTS_DISK_DIR)) fs.mkdirSync(FONTS_DISK_DIR, { recursive: true });
      fs.writeFileSync(path.join(FONTS_DISK_DIR, `${fileId}.${ext}`), buf);
    } catch {
      // ignore disk cache write failure
    }
    res.setHeader('Content-Type', mime);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    return res.send(buf);
  } catch {
    return res.status(500).send('Failed to load font');
  }
});

app.delete('/api/admin/fonts/:fileId', requireAdminOrStaff(), async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const ses = req.authSession!;
    const perms =
      ses.role === 'owner' || !ses.staffId
        ? FULL_OWNER_PERMISSIONS
        : { ...FULL_OWNER_PERMISSIONS, ...req.authPermissions };
    if (!perms.canManageSettings && !perms.canManageThemeMode && !perms.canEditHomePage) {
      return res.status(403).json({ ok: false, error: 'ليست لديك صلاحية حذف خطوط المنصة' });
    }
    const fileId = String(req.params.fileId || '').trim();
    if (!/^[a-zA-Z0-9_-]+$/.test(fileId)) {
      return res.status(400).json({ ok: false, error: 'معرف الخط غير صالح' });
    }
    for (const ext of ['otf', 'ttf', 'woff2', 'woff']) {
      const p = path.join(FONTS_DISK_DIR, `${fileId}.${ext}`);
      if (fs.existsSync(p)) {
        fs.unlinkSync(p);
      }
    }
    await applyChanges({ del: [`custom_font_files/${fileId}`] }, false);
    return res.json({ ok: true });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'فشل حذف ملف الخط' });
  }
});

function resolvePwaTargetFromQuery(
  allData: Record<string, unknown>,
  req: Request
): { targetRid: string; resolvedSlug: string; safeBranchId: string } {
  const rawRid = typeof req.query.rid === 'string' ? req.query.rid.trim() : '';
  const rawBranchId = typeof req.query.branchId === 'string' ? req.query.branchId.trim() : '';
  const rawSlug = typeof req.query.slug === 'string' ? req.query.slug.trim() : '';
  const safeQueryRid = /^[a-zA-Z0-9_-]{1,64}$/.test(rawRid) ? rawRid : '';
  const safeBranchId = /^[a-zA-Z0-9_-]{1,64}$/.test(rawBranchId) ? rawBranchId : '';
  const safeSlug = sanitizeSubdomainValue(rawSlug);
  const sessionRid = typeof req.authSession?.rid === 'string' ? req.authSession.rid.trim() : '';

  let targetRid = safeBranchId || safeQueryRid || '';
  if (!targetRid && safeSlug) {
    const matched = resolveRestaurantEntryByIdOrSlug(allData, safeSlug);
    if (matched) targetRid = matched.rid;
  }
  if (!targetRid) {
    targetRid = sessionRid;
  }

  let resolvedSlug = safeSlug;
  if (targetRid) {
    const restRec = allData[`restaurants/${targetRid}`] as Record<string, unknown> | undefined;
    const dbSlug = sanitizeSubdomainValue(String(restRec?.slug || restRec?.subdomain || ''));
    if (dbSlug) {
      resolvedSlug = dbSlug;
    } else if (targetRid === 'demo' && !resolvedSlug) {
      resolvedSlug = 'cap-burger';
    }
  }

  return { targetRid, resolvedSlug, safeBranchId };
}

app.get('/api/pwa/dashboard-icon', async (req, res) => {
  try {
    const allData = await readAll(false);
    const { targetRid } = resolvePwaTargetFromQuery(allData, req);
    const iconInfo = await resolveRestaurantPwaIcon(allData, targetRid);
    res
      .status(200)
      .setHeader('Content-Type', iconInfo.mimeType)
      .setHeader('Cache-Control', 'public, max-age=3600')
      .setHeader('X-Content-Type-Options', 'nosniff')
      .send(iconInfo.buffer);
  } catch {
    const fallback = getFallbackPwaIcon();
    res
      .status(200)
      .setHeader('Content-Type', fallback.mimeType)
      .setHeader('Cache-Control', 'no-cache')
      .send(fallback.buffer);
  }
});

app.get('/api/pwa/dashboard-manifest.webmanifest', async (req, res) => {
  const rawName = typeof req.query.name === 'string' ? req.query.name.trim() : '';
  const cleanQueryName = rawName.replace(/[\r\n\t<>]/g, '').slice(0, 60);

  let allData: Record<string, unknown> = {};
  try {
    allData = await readAll(false);
  } catch {
    allData = {};
  }

  const { targetRid, resolvedSlug, safeBranchId } = resolvePwaTargetFromQuery(allData, req);
  const { logo, name: dbName } = getRestaurantRecordForPwa(allData, targetRid);
  const cleanName = cleanQueryName || dbName.replace(/[\r\n\t<>]/g, '').slice(0, 60);

  const manifestId = resolvedSlug
    ? `/${resolvedSlug}/dashboard/`
    : safeBranchId
    ? `/dashboard/b/${safeBranchId}/`
    : '/dashboard/';
  const startUrl = resolvedSlug
    ? `/${encodeURIComponent(resolvedSlug)}/dashboard/home?source=pwa`
    : safeBranchId
    ? `/dashboard/b/${encodeURIComponent(safeBranchId)}/home?source=pwa`
    : '/dashboard/home?source=pwa';
  const fullName = cleanName ? `لوحة تحكم ${cleanName}` : 'لوحة تحكم Menu Plus';
  const shortNameSource = cleanName || 'لوحة التحكم';
  const shortName = shortNameSource.length <= 14 ? shortNameSource : `${shortNameSource.slice(0, 13)}…`;

  let icons: Array<{ src: string; sizes: string; type: string; purpose: string }> = [
    {
      src: '/pwa-192x192.png',
      sizes: '192x192',
      type: 'image/png',
      purpose: 'any',
    },
    {
      src: '/pwa-512x512.png',
      sizes: '512x512',
      type: 'image/png',
      purpose: 'any',
    },
    {
      src: '/pwa-maskable-512x512.png',
      sizes: '512x512',
      type: 'image/png',
      purpose: 'maskable',
    },
  ];

  if (targetRid && logo) {
    try {
      const iconInfo = await resolveRestaurantPwaIcon(allData, targetRid);
      if (iconInfo.isCustom && iconInfo.buffer.length > 0) {
        const ver = computePwaLogoVersion(logo);
        const iconSrc = `/api/pwa/dashboard-icon?rid=${encodeURIComponent(targetRid)}&v=${encodeURIComponent(ver)}`;
        const hasLargeDimensions = iconInfo.width >= 144 && iconInfo.height >= 144;
        if (hasLargeDimensions) {
          icons = [
            {
              src: iconSrc,
              sizes: `${iconInfo.width}x${iconInfo.height}`,
              type: iconInfo.mimeType,
              purpose: 'any',
            },
          ];
        } else {
          icons = [
            {
              src: iconSrc,
              sizes: iconInfo.width > 0 && iconInfo.height > 0 ? `${iconInfo.width}x${iconInfo.height}` : '192x192',
              type: iconInfo.mimeType,
              purpose: 'any',
            },
            {
              src: '/pwa-512x512.png',
              sizes: '512x512',
              type: 'image/png',
              purpose: 'any',
            },
          ];
        }
      }
    } catch {
      // keep default platform icons
    }
  }

  res
    .status(200)
    .setHeader('Content-Type', 'application/manifest+json; charset=utf-8')
    .setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0')
    .json({
      id: manifestId,
      name: fullName,
      short_name: shortName,
      description: 'لوحة تحكم Menu Plus لإدارة المنيو والفروع والطلبات مباشرة.',
      start_url: startUrl,
      scope: '/',
      display: 'standalone',
      orientation: 'portrait-primary',
      dir: 'rtl',
      lang: 'ar',
      theme_color: '#061c15',
      background_color: '#061c15',
      icons,
    });
});

// ============================================================================
// PUBLIC UNIQUE VISITOR TRACKING & ADMIN VISITOR STATS
// ============================================================================
const visitRateWindowMs = 60_000;
const visitRateMaxRequests = 60;
const visitRateBuckets = new Map<string, number[]>();

app.post('/api/analytics/visit', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const rawScope = typeof req.body?.scope === 'string' ? req.body.scope.trim() : '';
    const scope = rawScope === 'menu' ? 'menu' : rawScope === 'site' ? 'site' : '';
    if (!scope) {
      return res.status(400).json({ ok: false, error: 'Invalid visit scope' });
    }

    const clientIp = req.ip || req.socket.remoteAddress || '';
    const now = Date.now();
    const cutoff = now - visitRateWindowMs;
    const recent = (visitRateBuckets.get(clientIp) || []).filter((ts) => ts > cutoff);
    if (recent.length >= visitRateMaxRequests) {
      return res.status(200).json({ ok: true, throttled: true });
    }
    recent.push(now);
    visitRateBuckets.set(clientIp, recent);
    if (visitRateBuckets.size > 5000) {
      for (const [ip, tsList] of visitRateBuckets.entries()) {
        if (!tsList.some((ts) => ts > cutoff)) visitRateBuckets.delete(ip);
      }
    }

    const visitorId = typeof req.body?.visitorId === 'string' ? req.body.visitorId.trim() : '';
    const userAgent = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : '';

    await recordSiteOrMenuVisit({
      ip: clientIp,
      visitorId,
      userAgent,
      scope,
    });
    return res.json({ ok: true });
  } catch {
    return res.status(200).json({ ok: false });
  }
});

app.get('/api/admin/visitor-stats', requireAdminOrStaff(), async (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const stats = await getVisitorAnalyticsStats();
    return res.json({ ok: true, ...stats });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'تعذر جلب إحصائيات الزوار' });
  }
});

// ============================================================================
// PWA WEB PUSH SUBSCRIPTIONS & PUBLIC LOYALTY WALLET ENDPOINTS
// ============================================================================
app.get('/api/pwa/push-public-key', async (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const publicKey = await getWebPushPublicKey();
    return res.json({ ok: true, publicKey });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'Push key unavailable' });
  }
});

app.post('/api/pwa/push-subscribe', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const ses = req.authSession;
    if (!ses) {
      return res.status(401).json({ ok: false, error: 'يرجى تسجيل الدخول لتفعيل الإشعارات.' });
    }
    const allData = await readAll(false);
    let ownedRids: string[] = [];
    if (ses.admin) {
      for (const k of Object.keys(allData)) {
        if (k.startsWith('restaurants/') && !k.slice('restaurants/'.length).includes('/')) {
          ownedRids.push(k.slice('restaurants/'.length));
        }
      }
    } else {
      const ownerRid = ses.personalRid || ses.rid;
      ownedRids = Array.from(getOwnedPartnerRids(allData, ownerRid, ses));
    }

    const sub = req.body?.subscription || {};
    const result = await upsertPushSubscription({
      subscription: sub,
      ownedRids,
      accountId: ses.accountId,
      userAgent: typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : '',
    });

    if (!result.ok) {
      return res.status(400).json({ ok: false, error: result.error || 'بيانات الاشتراك غير صالحة' });
    }
    return res.json({ ok: true, id: result.id, ownedCount: ownedRids.length });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'Push subscribe failed' });
  }
});

app.post('/api/pwa/push-unsubscribe', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const endpoint = String(req.body?.endpoint || '').trim();
    if (endpoint) {
      await removePushSubscription(endpoint);
    }
    return res.json({ ok: true });
  } catch {
    return res.json({ ok: false });
  }
});

function normalizeCustomerLoyaltyPhone(raw: unknown): string {
  const digits = String(raw || '').replace(/[\s\-()+]/g, '').replace(/[^\d]/g, '');
  if (digits.startsWith('964') && digits.length >= 12) {
    return `0${digits.slice(3)}`;
  }
  return digits;
}

app.get('/api/loyalty/wallet', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const rid = String(req.query.rid || '').trim();
    const phone = normalizeCustomerLoyaltyPhone(req.query.phone);
    if (!rid || phone.length < 7) {
      return res.status(400).json({ ok: false, error: 'رقم الهاتف أو المعرف غير صالح.' });
    }
    const allData = await readAll(false);
    const key = `loyalty/${rid}__${phone}`;
    const existing = allData[key] as Record<string, unknown> | undefined;
    if (!existing) {
      return res.json({ ok: true, found: false, phone, points: 0, name: '' });
    }
    return res.json({
      ok: true,
      found: true,
      customer: {
        id: existing.id || `${rid}__${phone}`,
        rid,
        phone: String(existing.phone || phone),
        name: String(existing.name || ''),
        points: Math.max(0, Number(existing.points || 0)),
        totalOrders: Math.max(0, Number(existing.totalOrders || 0)),
        totalSpent: Math.max(0, Number(existing.totalSpent || 0)),
        updatedAt: Number(existing.updatedAt || Date.now()),
      },
    });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'Loyalty lookup failed' });
  }
});

app.post('/api/loyalty/register', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const rid = String(req.body?.rid || '').trim();
    const name = String(req.body?.name || '').trim().slice(0, 80);
    const phone = normalizeCustomerLoyaltyPhone(req.body?.phone);
    if (!rid || !name || phone.length < 7) {
      return res.status(400).json({ ok: false, error: 'يرجى كتابة الاسم ورقم الهاتف الصحيح.' });
    }
    const allData = await readAll(false);
    if (!allData[`restaurants/${rid}`]) {
      return res.status(404).json({ ok: false, error: 'المنيو غير موجود.' });
    }
    const key = `loyalty/${rid}__${phone}`;
    const existing = allData[key] as Record<string, unknown> | undefined;
    const now = Date.now();
    const customer = {
      id: `${rid}__${phone}`,
      rid,
      phone,
      name,
      points: Math.max(0, Number(existing?.points || 0)),
      totalOrders: Math.max(0, Number(existing?.totalOrders || 0)),
      totalSpent: Math.max(0, Number(existing?.totalSpent || 0)),
      createdAt: Number(existing?.createdAt || now),
      updatedAt: now,
    };
    await applyChanges({ put: { [key]: customer } }, false);
    return res.json({ ok: true, customer });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err?.message || 'Loyalty registration failed' });
  }
});

const MCP_TOOLS_CATALOG = [
  {
    name: 'search_menus',
    description: 'Search public restaurants, cafés, and digital QR menus hosted on Menu Plus by name or keyword.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Optional search keyword to filter stores.' },
        limit: { type: 'number', description: 'Maximum results to return (1-25, default 10).' },
      },
    },
  },
  {
    name: 'get_menu_details',
    description: 'Retrieve categories, menu items, descriptions, and prices for a Menu Plus store by slug.',
    inputSchema: {
      type: 'object',
      properties: {
        slug: { type: 'string', description: 'Store slug, e.g. cap-burger.' },
      },
      required: ['slug'],
    },
  },
  {
    name: 'get_pricing_plans',
    description: 'List Menu Plus subscription plans, monthly/annual prices, and included features (0% sales commission).',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'get_platform_info',
    description: 'Return Menu Plus overview, machine-readable contact details, and key documentation URLs.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
];

app.options('/api/mcp', (_req, res) => {
  res
    .status(204)
    .setHeader('Access-Control-Allow-Origin', '*')
    .setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
    .setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept')
    .end();
});

app.post('/api/mcp', async (req, res) => {
  res
    .setHeader('Access-Control-Allow-Origin', '*')
    .setHeader('Content-Type', 'application/json; charset=utf-8');

  const body = (req.body && typeof req.body === 'object' ? req.body : {}) as {
    jsonrpc?: string;
    id?: string | number | null;
    method?: string;
    params?: { name?: string; arguments?: Record<string, unknown> };
  };
  const id = body.id ?? null;
  const method = String(body.method || '').trim();
  const origin = resolveRequestOrigin(req);

  if (method === 'initialize') {
    return res.json({
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2025-03-26',
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'menu-plus', title: 'Menu Plus', version: '1.0.0' },
      },
    });
  }

  if (method === 'ping') {
    return res.json({ jsonrpc: '2.0', id, result: {} });
  }

  if (method === 'tools/list') {
    return res.json({ jsonrpc: '2.0', id, result: { tools: MCP_TOOLS_CATALOG } });
  }

  if (method === 'tools/call') {
    const toolName = String(body.params?.name || '').trim();
    const args = (body.params?.arguments && typeof body.params.arguments === 'object'
      ? body.params.arguments
      : {}) as Record<string, unknown>;
    const allData = await readAll(false).catch(() => ({} as Record<string, unknown>));

    if (toolName === 'search_menus') {
      const q = String(args.query || '').trim().toLowerCase();
      const limit = Math.min(25, Math.max(1, Number(args.limit || 10)));
      const stores = Object.entries(allData)
        .filter(([k, v]) => k.startsWith('restaurants/') && v && typeof v === 'object')
        .map(([k, v]) => {
          const r = v as Record<string, unknown>;
          const rid = String(r.id || k.slice('restaurants/'.length));
          const slug =
            sanitizeSubdomainValue(String(r.slug || r.subdomain || '')) ||
            (rid === 'demo' ? 'cap-burger' : rid);
          return {
            id: rid,
            name: String(r.n || slug),
            slug,
            url: `${origin}/${encodeURIComponent(slug)}`,
            type: String(r.projectType || 'restaurant'),
            active: r.a !== 0,
            isBranch: Boolean(r.isBranch),
          };
        })
        .filter(
          (st) =>
            st.active &&
            !st.isBranch &&
            (!q || st.name.toLowerCase().includes(q) || st.slug.toLowerCase().includes(q))
        )
        .slice(0, limit)
        .map(({ name, slug, url, type }) => ({ name, slug, url, type }));

      const payload = { stores };
      return res.json({
        jsonrpc: '2.0',
        id,
        result: {
          ...payload,
          structuredContent: payload,
          content: [{ type: 'text', text: JSON.stringify(payload) }],
        },
      });
    }

    if (toolName === 'get_menu_details') {
      const slugArg = String(args.slug || 'cap-burger').trim();
      const family = resolvePublicMenuFamily(allData, slugArg);
      if (!family) {
        return res.json({
          jsonrpc: '2.0',
          id,
          error: { code: -32602, message: `Menu not found: ${slugArg}` },
        });
      }
      const cats = Object.entries(family.bootstrapRecords)
        .filter(([k, v]) => k.startsWith('cats/') && v && typeof v === 'object')
        .map(([, v]) => ({ id: (v as Record<string, unknown>).id, name: (v as Record<string, unknown>).n }));
      const items = Object.entries(family.bootstrapRecords)
        .filter(([k, v]) => k.startsWith('items/') && v && typeof v === 'object')
        .map(([, v]) => {
          const it = v as Record<string, unknown>;
          return {
            id: it.id,
            categoryId: it.cat,
            name: it.n,
            description: it.d || '',
            price: Number(it.pr || 0),
          };
        });
      const payload = {
        name: String(family.rest.n || family.slug),
        slug: family.slug,
        url: `${origin}/${encodeURIComponent(family.slug)}`,
        currency: String(family.rest.currency || 'د.ع'),
        categories: cats,
        items,
      };
      return res.json({
        jsonrpc: '2.0',
        id,
        result: {
          ...payload,
          structuredContent: payload,
          content: [{ type: 'text', text: JSON.stringify(payload) }],
        },
      });
    }

    if (toolName === 'get_pricing_plans') {
      const plansDoc = allData['settings/plans'] as
        | { list?: Array<Record<string, unknown>> }
        | Array<Record<string, unknown>>
        | undefined;
      const rawPlans = Array.isArray(plansDoc) ? plansDoc : Array.isArray(plansDoc?.list) ? plansDoc.list : [];
      const activePlans = rawPlans
        .filter((p) => String(p.id || '') !== 'free' && Number(p.pr || 0) > 0)
        .map((p) => ({
          id: p.id,
          name: p.n,
          monthlyPrice: Number(p.pr || 0),
          annualPrice: Number(p.annualPrice || 0) || Number(p.pr || 0) * 10,
          features: Array.isArray(p.fs) ? p.fs : [],
        }));
      const payload = { currency: 'IQD', commissionRate: '0%', plans: activePlans };
      return res.json({
        jsonrpc: '2.0',
        id,
        result: {
          ...payload,
          structuredContent: payload,
          content: [{ type: 'text', text: JSON.stringify(payload) }],
        },
      });
    }

    if (toolName === 'get_platform_info') {
      const siteCfg = (allData['settings/site'] || {}) as Record<string, unknown>;
      const waRaw = String(siteCfg.supportWhatsapp || siteCfg.wa || '9647724799679').replace(/\D/g, '');
      const phone = waRaw.startsWith('0') ? `+964${waRaw.slice(1)}` : `+${waRaw || '9647724799679'}`;
      const email = String(siteCfg.em || 'support@menuplus.io').trim();
      const payload = {
        name: 'Menu Plus',
        description:
          'Smart QR digital menu and WhatsApp catalog platform for restaurants, cafés, and online stores with 0% sales commission.',
        url: `${origin}/`,
        contact: { email, telephone: phone, whatsapp: `https://wa.me/${phone.replace(/^\+/, '')}` },
        pages: {
          about: `${origin}/about`,
          contact: `${origin}/contact`,
          terms: `${origin}/terms`,
          privacy: `${origin}/privacy`,
          pricing: `${origin}/pricing`,
          faq: `${origin}/faq`,
          llms: `${origin}/llms.txt`,
        },
      };
      return res.json({
        jsonrpc: '2.0',
        id,
        result: {
          ...payload,
          structuredContent: payload,
          content: [{ type: 'text', text: JSON.stringify(payload) }],
        },
      });
    }

    return res.json({
      jsonrpc: '2.0',
      id,
      error: { code: -32601, message: `Unknown tool: ${toolName}` },
    });
  }

  return res.json({
    jsonrpc: '2.0',
    id,
    error: { code: -32601, message: `Method not found: ${method}` },
  });
});

// 5. Handle OPTIONS preflight and unmatched API routes with JSON 404 instead of index.html
app.options('/api/*', (_req, res) => {
  res.status(204).end();
});

app.all('/api/*', (_req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

// Global error handler for malformed JSON or unhandled middleware errors
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  if (err?.type === 'entity.parse.failed' || err instanceof SyntaxError) {
    return res.status(400).json({ error: 'Invalid JSON request body' });
  }
  console.error('[Server Error]', err?.message || err);
  return res.status(500).json({ error: 'Internal server error' });
});

const ASSET_EXTENSION_RE = /\.(?:js|mjs|css|map|png|jpe?g|webp|gif|svg|ico|woff2?|ttf|otf|eot|json|txt|xml)$/i;

const SEO_RESERVED_SEGMENTS = new Set([
  'login', 'signup', 'forgot', 'onboard', 'dashboard', 'admin', 'menu', 'explore', 'services', 'steps', 'pricing', 'faq', 'demo', 'menu-demo', 'about', 'contact', 'terms', 'privacy', 'api', 'assets', 'uploads',
]);

const VALID_STATIC_PLATFORM_ROUTES = new Set([
  'home',
  'explore',
  'services',
  'steps',
  'pricing',
  'faq',
  'about',
  'contact',
  'terms',
  'privacy',
  'login',
  'signup',
  'forgot',
  'onboard',
  'demo',
  'menu-demo',
]);

const VALID_DASHBOARD_TABS_SERVER = new Set([
  'home',
  'overview',
  'stats',
  'analytics',
  'cats',
  'categories',
  'items',
  'menu',
  'orders',
  'appearance',
  'lay',
  'theme',
  'branches',
  'qr',
  'addons',
  'telegram',
  'settings',
  'set',
]);

const VALID_ADMIN_TABS_SERVER = new Set([
  'home',
  'partners',
  'accounts',
  'notes',
  'reports',
  'staff',
  'home_editor',
  'home-editor',
  'plans',
  'settings',
  'account',
]);

function safeDecodeUriSegment(raw: string): string | null {
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

function doesRouteExistOnServer(
  cleanPath: string,
  allData: Record<string, unknown>,
  subdomainResolved?: ResolvedSubdomainResult
): boolean {
  const rawSegs = cleanPath.replace(/^\/+/, '').split('/').filter(Boolean);

  if (subdomainResolved?.found) {
    if (rawSegs.length === 0) return true;
    const s0 = rawSegs[0].toLowerCase();
    if (rawSegs.length === 1 && (s0 === 'login' || s0 === 'onboard' || s0 === 'forgot' || s0 === 'dashboard')) {
      return true;
    }
    if (s0 === 'dashboard') {
      if (rawSegs.length === 2) {
        return VALID_DASHBOARD_TABS_SERVER.has(rawSegs[1].toLowerCase());
      }
      if ((rawSegs.length === 3 || rawSegs.length === 4) && rawSegs[1].toLowerCase() === 'b') {
        const branchId = safeDecodeUriSegment(rawSegs[2]);
        if (!branchId) return false;
        const branchExists = branchId === 'demo' || Boolean(allData[`restaurants/${branchId}`]);
        if (!branchExists) return false;
        return rawSegs.length === 3 || VALID_DASHBOARD_TABS_SERVER.has(rawSegs[3].toLowerCase());
      }
    }
    return false;
  }

  if (rawSegs.length === 0) return true;

  const seg0Lower = rawSegs[0].toLowerCase();

  if (rawSegs.length === 1) {
    if (VALID_STATIC_PLATFORM_ROUTES.has(seg0Lower)) return true;
    if (seg0Lower === 'admin' || seg0Lower === 'dashboard') return true;
    const legacyMenuMatch = /^menu-([a-zA-Z0-9_-]+)$/.exec(rawSegs[0]);
    if (legacyMenuMatch) {
      const fam = resolvePublicMenuFamily(allData, legacyMenuMatch[1]);
      return Boolean(fam && fam.rest.deleted !== true);
    }
    if (SEO_RESERVED_SEGMENTS.has(seg0Lower)) {
      return false;
    }
    const decodedSlug = safeDecodeUriSegment(rawSegs[0]);
    if (!decodedSlug) return false;
    const fam = resolvePublicMenuFamily(allData, decodedSlug);
    return Boolean(fam && fam.rest.deleted !== true);
  }

  if (seg0Lower === 'admin') {
    return rawSegs.length === 2 && VALID_ADMIN_TABS_SERVER.has(rawSegs[1].toLowerCase());
  }

  if (seg0Lower === 'dashboard') {
    if (rawSegs.length === 2) {
      return VALID_DASHBOARD_TABS_SERVER.has(rawSegs[1].toLowerCase());
    }
    if ((rawSegs.length === 3 || rawSegs.length === 4) && rawSegs[1].toLowerCase() === 'b') {
      const branchId = safeDecodeUriSegment(rawSegs[2]);
      if (!branchId) return false;
      const branchExists = branchId === 'demo' || Boolean(allData[`restaurants/${branchId}`]);
      if (!branchExists) return false;
      return rawSegs.length === 3 || VALID_DASHBOARD_TABS_SERVER.has(rawSegs[3].toLowerCase());
    }
    return false;
  }

  if (
    (rawSegs.length === 2 || rawSegs.length === 3) &&
    rawSegs[1].toLowerCase() === 'dashboard' &&
    !SEO_RESERVED_SEGMENTS.has(seg0Lower)
  ) {
    const decodedSlug = safeDecodeUriSegment(rawSegs[0]);
    if (!decodedSlug) return false;
    const matched = resolveRestaurantEntryByIdOrSlug(allData, decodedSlug);
    if (!matched || matched.rest.deleted === true) return false;
    return rawSegs.length === 2 || VALID_DASHBOARD_TABS_SERVER.has(rawSegs[2].toLowerCase());
  }

  if (seg0Lower === 'menu' && rawSegs.length === 2) {
    const decodedTarget = safeDecodeUriSegment(rawSegs[1]);
    if (!decodedTarget) return false;
    const fam = resolvePublicMenuFamily(allData, decodedTarget);
    return Boolean(fam && fam.rest.deleted !== true);
  }

  return false;
}

function buildNotFoundMarkdown(req: Request): string {
  const origin = resolveRequestOrigin(req);
  const cleanPath = req.path === '/' ? '/' : req.path.replace(/\/+$/, '');
  return [
    '# 404 — Page Not Found | Menu Plus',
    '',
    `> The requested page (${cleanPath}) does not exist on Menu Plus.`,
    '',
    '## Available Pages',
    `- [Home](${origin}/)`,
    `- [Explore Menus](${origin}/explore)`,
    `- [Pricing](${origin}/pricing)`,
    `- [FAQ](${origin}/faq)`,
    `- [About](${origin}/about)`,
    `- [Contact](${origin}/contact)`,
  ].join('\n');
}

function injectNotFoundIntoHtml(html: string, req: Request, res?: Response): string {
  const origin = resolveRequestOrigin(req);
  const titleText = '404 — الصفحة غير موجودة | Menu Plus';
  const descText = 'عذراً، الصفحة المطلوبة غير موجودة أو تم نقلها | Menu Plus';
  const safeTitle = escapeSeoAttr(titleText);
  const safeDesc = escapeSeoAttr(descText);
  const safeOrigin = escapeSeoAttr(origin);

  if (res && !res.headersSent) {
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  }

  let out = html
    .replace(/<script[^>]*type="application\/ld\+json"[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<meta\s+name="robots"[^>]*\/?>/gi, '')
    .replace(/<link\s+rel="canonical"[^>]*\/?>/gi, '')
    .replace(/<link\s+rel="alternate"[^>]*type="text\/(?:markdown|plain)"[^>]*\/?>/gi, '');

  out = out.replace(/<title>[\s\S]*?<\/title>/i, () => `<title>${safeTitle}</title>`);
  out = out.replace(/<meta\s+name="description"\s+content="[^"]*"\s*\/?>/i, () => `<meta name="description" content="${safeDesc}" />`);
  out = out.replace(/<meta\s+property="og:title"\s+content="[^"]*"\s*\/?>/i, () => `<meta property="og:title" content="${safeTitle}" />`);
  out = out.replace(/<meta\s+property="og:description"\s+content="[^"]*"\s*\/?>/i, () => `<meta property="og:description" content="${safeDesc}" />`);

  const headInject = [
    `<meta name="robots" content="noindex, nofollow" />`,
    `<script>window.__MENUPLUS_NOT_FOUND__=true;</script>`,
  ].join('\n  ');
  if (out.includes('</head>')) {
    out = out.replace('</head>', () => `  ${headInject}\n  </head>`);
  }

  const ssr404Root = [
    `<header><nav aria-label="التنقل الرئيسي">`,
    `<a href="${safeOrigin}/">Menu Plus</a> `,
    `<a href="${safeOrigin}/explore">استكشف</a> `,
    `<a href="${safeOrigin}/pricing">الأسعار</a> `,
    `<a href="${safeOrigin}/contact">تواصل معنا</a>`,
    `</nav></header>`,
    `<main><h1>404 — الصفحة غير موجودة</h1><p>${safeDesc}</p><p><a href="${safeOrigin}/">العودة إلى الرئيسية</a></p></main>`,
  ].join('');

  out = out.replace(
    /<div\s+id="root">[\s\S]*?(?:<\/footer>\s*)?<\/div>/i,
    () => `<div id="root">${ssr404Root}</div>`
  );
  return out;
}

function resolveRequestOrigin(req: Request): string {
  const proto = String(req.headers['x-forwarded-proto'] || req.protocol || 'https').split(',')[0].trim();
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || BASE_DOMAIN).split(',')[0].trim();
  return `${proto}://${host}`;
}

function escapeSeoAttr(str: string): string {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function xmlEscape(str: string): string {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function normalizeTelUri(rawPhone: string): string {
  let clean = String(rawPhone || '').replace(/\D/g, '');
  if (!clean) clean = '9647724799679';
  else if (clean.startsWith('00')) clean = clean.slice(2);
  else if (clean.startsWith('0')) clean = `964${clean.slice(1)}`;
  else if (!clean.startsWith('964') && /^(77|78|75|79)/.test(clean)) clean = `964${clean}`;
  return `+${clean}`;
}

function applyAgentLinkHeaders(res: Response, origin: string, cleanPath: string): void {
  if (res.headersSent) return;
  const mdHref = `${origin}${cleanPath === '/' ? '/' : cleanPath}`;
  res.setHeader(
    'Link',
    [
      `<${origin}/llms.txt>; rel="alternate"; type="text/plain"; title="LLMs Guide"`,
      `<${mdHref}>; rel="alternate"; type="text/markdown"; title="Markdown"`,
      `<${origin}/.well-known/mcp/server-card.json>; rel="describedby"; type="application/json"; title="MCP Server Card"`,
    ].join(', ')
  );
  res.setHeader('Vary', 'Accept, Accept-Encoding');
}

function wantsMarkdownResponse(req: Request): boolean {
  const accept = String(req.headers.accept || '').toLowerCase();
  if (!accept.includes('text/markdown')) return false;
  return req.accepts(['text/markdown', 'text/html']) === 'text/markdown';
}

const DEFAULT_SEO_FAQS = [
  {
    q: 'ما هو المنيو والكتالوج الإلكتروني الذكي؟',
    a: 'هو رابط خاص وباركود QR باسم مشروعك يفتحه الزبون فوراً من متصفح هاتفه دون الحاجة لتحميل أي تطبيق؛ يتصفح الأقسام والوجبات أو المنتجات بالصور والأسعار، يضيفها إلى السلة، ويرسل لك الطلب مرتباً بالكامل على واتساب.',
  },
  {
    q: 'هل منصة Menu Plus مناسبة لمطعمي أو متجري؟',
    a: 'نعم، المنصة مصممة بمرونة كاملة لتناسب المطاعم، الكافيهات، محلات الحلويات والعصائر، وكذلك المتاجر الإلكترونية ومحلات العطور والملابس والإكسسوارات.',
  },
  {
    q: 'هل يمكنني استخدام اسمي وشعاري وتغيير الألوان والمظهر؟',
    a: 'بالتأكيد! يمكنك رفع شعار مشروعك وصورة الغلاف، والاختيار بين المظهر النهاري الفاتح والمظهر الليلي الداكن مع قوالب ألوان احترافية ورابط مخصص باسم مشروعك.',
  },
  {
    q: 'هل توجد نسبة أو عمولة على المبيعات والطلبات؟',
    a: 'لا، 0% عمولة على مبيعاتك للأبد. كل أرباح طلبات التوصيل والاستلام والطاولات تبقى لك بالكامل وتستلمها مباشرة على رقم الواتساب الخاص بك.',
  },
  {
    q: 'كيف يتم تفعيل الاشتراك وما هي الباقات المتوفرة؟',
    a: 'نوفر 3 باقات مرنة (الاقتصادية، الاحترافية، وباقة الأعمال الشاملة) باشتراك شهري أو سنوي بدون أي عمولات على مبيعاتك، ويمكنك الترقية بين الباقات في أي وقت.',
  },
  {
    q: 'هل يمكنني تفعيل مشروعي وتعديل الأسعار فوراً؟',
    a: 'نعم، خلال دقائق معدودة تسجّل برقم هاتفك، تضيف أقسامك ومنتجاتك، وتطبع رمز الـ QR لتبدأ باستقبال الطلبات فوراً.',
  },
];

const publicHtmlInjectionCache = new Map<
  string,
  { version: number; familyRids: string[] | null; html: string }
>();
const MAX_PUBLIC_HTML_CACHE = 200;

function resolvePublicAssetUrl(origin: string, rawUrl: unknown, fallbackPath = '/assets/logo.png'): string {
  const s = String(rawUrl || '').trim();
  if (!s || s.startsWith('data:')) return `${origin}${fallbackPath}`;
  if (/^https?:\/\//i.test(s)) return s;
  return `${origin}${s.startsWith('/') ? s : `/${s}`}`;
}

function buildSsrRootHtml(opts: {
  heading: string;
  description: string;
  origin: string;
  siteEmail: string;
  siteTel: string;
  sectionKey: string;
  plans?: Array<{ name: string; price: string }>;
  faqs?: Array<{ q: string; a: string }>;
  items?: Array<{ title: string; detail?: string }>;
  stores?: Array<{ name: string; href: string }>;
}): string {
  const { heading, description, origin, siteEmail, siteTel, sectionKey, plans = [], faqs = [], items = [], stores = [] } = opts;

  let bodyExtra = '';
  if (sectionKey === 'about') {
    bodyExtra =
      `<section><h2>عن منصة Menu Plus</h2><p>تساعد منصة Menu Plus أصحاب المطاعم والكافيهات والمتاجر في العراق والعالم العربي على إطلاق قائمة طعام إلكترونية تفاعلية عبر باركود QR واستقبال طلبات التوصيل والطاولات مباشرة على واتساب بدون أي عمولات على المبيعات.</p>` +
      `<ul><li>تشغيل فوري من المتصفح دون تحميل تطبيق</li><li>دعم العربية والكردية والإنجليزية</li><li>لوحة تحكم سحابية لإدارة الأصناف والأفرع</li></ul></section>`;
  } else if (sectionKey === 'contact') {
    bodyExtra =
      `<section><h2>قنوات التواصل المباشر</h2><ul>` +
      `<li>البريد الإلكتروني: <a href="mailto:${escapeSeoAttr(siteEmail)}">${escapeSeoAttr(siteEmail)}</a></li>` +
      `<li>الهاتف: <a href="tel:${escapeSeoAttr(siteTel)}">${escapeSeoAttr(siteTel)}</a></li>` +
      `<li>واتساب: <a href="https://wa.me/${escapeSeoAttr(siteTel.replace(/^\+/, ''))}">تواصل عبر واتساب</a></li>` +
      `<li>إنستقرام: <a href="https://instagram.com/iq.menu">@iq.menu</a></li>` +
      `</ul></section>`;
  } else if (sectionKey === 'terms' || sectionKey === 'privacy') {
    bodyExtra =
      `<section><h2>${sectionKey === 'privacy' ? 'حماية البيانات والخصوصية' : 'بنود الاستخدام والاشتراكات'}</h2>` +
      `<p>تلتزم منصة Menu Plus بحماية خصوصية بيانات الشركاء والزبائن وعدم بيع أو مشاركة أرقام الهواتف مع أي أطراف ثالثة. تُستخدم بيانات الطلبات حصراً لإيصال الطلب مباشرة إلى واتساب المتجر.</p>` +
      `<p>الاشتراكات مرنة شهرية أو سنوية بـ 0% عمولة على المبيعات، ويتحمل كل متجر مسؤولية دقة أسعاره وتوافر منتجاته.</p></section>`;
  } else {
    if (items.length > 0) {
      bodyExtra += `<section><h2>الأصناف والمنتجات</h2><ul>${items
        .slice(0, 24)
        .map((it) => `<li><strong>${escapeSeoAttr(it.title)}</strong>${it.detail ? ` — ${escapeSeoAttr(it.detail)}` : ''}</li>`)
        .join('')}</ul></section>`;
    } else {
      bodyExtra +=
        `<section><h2>لماذا Menu Plus؟</h2><ul>` +
        `<li>منيو إلكتروني QR سريع يفتح مباشرة من متصفح الهاتف</li>` +
        `<li>استقبال طلبات التوصيل والطاولات مرتبة على واتساب بـ 0% عمولة</li>` +
        `<li>إدارة الأقسام، الأسعار، العروض، والطاولات والأفرع من لوحة تحكم واحدة</li>` +
        `</ul></section>`;
    }
    if (plans.length > 0) {
      bodyExtra += `<section><h2>الباقات والأسعار</h2><ul>${plans
        .map((p) => `<li><strong>${escapeSeoAttr(p.name)}</strong>: ${escapeSeoAttr(p.price)} د.ع</li>`)
        .join('')}</ul></section>`;
    }
    if (stores.length > 0) {
      bodyExtra += `<section><h2>قوائم ومطاعم مباشرة</h2><ul>${stores
        .slice(0, 8)
        .map((s) => `<li><a href="${escapeSeoAttr(s.href)}">${escapeSeoAttr(s.name)}</a></li>`)
        .join('')}</ul></section>`;
    }
    if (faqs.length > 0) {
      bodyExtra += `<section><h2>الأسئلة الشائعة</h2>${faqs
        .slice(0, 6)
        .map((f) => `<article><h3>${escapeSeoAttr(f.q)}</h3><p>${escapeSeoAttr(f.a)}</p></article>`)
        .join('')}</section>`;
    }
  }

  return [
    `<header><nav aria-label="التنقل الرئيسي">`,
    `<a href="${escapeSeoAttr(`${origin}/`)}">Menu Plus</a> `,
    `<a href="${escapeSeoAttr(`${origin}/explore`)}">استكشف</a> `,
    `<a href="${escapeSeoAttr(`${origin}/services`)}">المميزات</a> `,
    `<a href="${escapeSeoAttr(`${origin}/pricing`)}">الأسعار</a> `,
    `<a href="${escapeSeoAttr(`${origin}/faq`)}">الأسئلة الشائعة</a> `,
    `<a href="${escapeSeoAttr(`${origin}/about`)}">عن المنصة</a> `,
    `<a href="${escapeSeoAttr(`${origin}/contact`)}">تواصل معنا</a>`,
    `</nav></header>`,
    `<main><h1>${escapeSeoAttr(heading)}</h1><p>${escapeSeoAttr(description)}</p>${bodyExtra}</main>`,
    `<footer>`,
    `<p>تواصل: <a href="mailto:${escapeSeoAttr(siteEmail)}">${escapeSeoAttr(siteEmail)}</a> | <a href="tel:${escapeSeoAttr(siteTel)}">${escapeSeoAttr(siteTel)}</a></p>`,
    `<nav aria-label="روابط قانونية ومعلوماتية">`,
    `<a href="${escapeSeoAttr(`${origin}/about`)}">عن Menu Plus</a> `,
    `<a href="${escapeSeoAttr(`${origin}/contact`)}">اتصل بنا</a> `,
    `<a href="${escapeSeoAttr(`${origin}/terms`)}">الشروط والأحكام</a> `,
    `<a href="${escapeSeoAttr(`${origin}/privacy`)}">سياسة الخصوصية</a> `,
    `<a href="${escapeSeoAttr(`${origin}/llms.txt`)}">llms.txt</a>`,
    `</nav>`,
    `</footer>`,
  ].join('');
}

function buildMarkdownDocument(req: Request, allData: Record<string, unknown>): string {
  const origin = resolveRequestOrigin(req);
  const cleanPath = req.path === '/' ? '/' : req.path.replace(/\/+$/, '');
  const segs = cleanPath.replace(/^\/+/, '').split('/').filter(Boolean);
  const siteSettings = (allData['settings/site'] || {}) as Record<string, unknown>;
  const siteEmail = String(siteSettings.em || 'support@menuplus.io').trim();
  const siteTel = normalizeTelUri(String(siteSettings.supportWhatsapp || siteSettings.wa || ''));

  let targetSlugOrId = '';
  if (segs[0]?.toLowerCase() === 'menu' && segs[1]) {
    targetSlugOrId = safeDecodeUriSegment(segs[1]) || '';
  } else if (segs.length === 1 && !SEO_RESERVED_SEGMENTS.has(segs[0].toLowerCase())) {
    targetSlugOrId = safeDecodeUriSegment(segs[0]) || '';
  }

  if (targetSlugOrId) {
    const family = resolvePublicMenuFamily(allData, targetSlugOrId);
    if (family) {
      const restName = String(family.rest.n || family.slug);
      const currency = String(family.rest.currency || 'د.ع');
      const cats = Object.entries(family.bootstrapRecords)
        .filter(([k]) => k.startsWith('cats/'))
        .map(([, v]) => v as Record<string, unknown>);
      const items = Object.entries(family.bootstrapRecords)
        .filter(([k]) => k.startsWith('items/'))
        .map(([, v]) => v as Record<string, unknown>);
      const lines = [
        `# ${restName} — Menu Plus`,
        '',
        `> Digital QR menu for ${restName} hosted on Menu Plus.`,
        '',
        `- URL: ${origin}/${encodeURIComponent(family.slug)}`,
        `- Currency: ${currency}`,
        '',
        '## Menu Items',
        '',
      ];
      for (const cat of cats) {
        const catItems = items.filter((it) => it.cat === cat.id);
        if (catItems.length === 0) continue;
        lines.push(`### ${String(cat.n || '')}`);
        for (const it of catItems) {
          lines.push(`- **${String(it.n || '')}**: ${Number(it.pr || 0).toLocaleString('en-US')} ${currency}${it.d ? ` — ${String(it.d)}` : ''}`);
        }
        lines.push('');
      }
      return lines.join('\n');
    }
  }

  const section = segs[0]?.toLowerCase() || '';
  const plansDoc = allData['settings/plans'] as
    | { list?: Array<Record<string, unknown>> }
    | Array<Record<string, unknown>>
    | undefined;
  const rawPlans = Array.isArray(plansDoc) ? plansDoc : Array.isArray(plansDoc?.list) ? plansDoc.list : [];
  const activePlans = rawPlans.filter((p) => String(p.id || '') !== 'free' && Number(p.pr || 0) > 0);
  const publicStores = Object.entries(allData)
    .filter(([k, v]) => k.startsWith('restaurants/') && v && typeof v === 'object')
    .map(([, v]) => v as Record<string, unknown>)
    .filter((r) => r.a !== 0 && !r.isBranch && String(r.n || '').trim())
    .slice(0, 8);

  const lines: string[] = [
    section === 'about'
      ? '# About Menu Plus'
      : section === 'contact'
      ? '# Contact Menu Plus'
      : section === 'terms'
      ? '# Terms of Service — Menu Plus'
      : section === 'privacy'
      ? '# Privacy Policy — Menu Plus'
      : section === 'pricing'
      ? '# Pricing & Plans — Menu Plus'
      : '# Menu Plus — Smart QR Digital Menu & WhatsApp Ordering Platform',
    '',
    '> Create an interactive QR digital menu and WhatsApp ordering catalog for your restaurant, café, or online store in minutes with 0% sales commission.',
    '',
    `Canonical: ${origin}${cleanPath}`,
    '',
    '## Key Capabilities',
    '- Fast browser-based QR digital menu (no mobile app required)',
    '- Structured WhatsApp order delivery & dine-in table checkout with GPS location',
    '- Cloud dashboard for categories, variants, branches, themes, and 50+ marketing add-ons',
    '- Multi-language support: Arabic, Kurdish, and English',
    '- 0% commission on all customer orders',
    '',
  ];

  if (activePlans.length > 0) {
    lines.push('## Pricing Plans (IQD)');
    for (const pl of activePlans) {
      lines.push(`- **${String(pl.n || '')}**: ${Number(pl.pr || 0).toLocaleString('en-US')} IQD / month`);
    }
    lines.push('');
  }

  if (publicStores.length > 0) {
    lines.push('## Live Menus');
    for (const r of publicStores) {
      const slug = sanitizeSubdomainValue(String(r.slug || r.subdomain || '')) || (r.id === 'demo' ? 'cap-burger' : String(r.id || ''));
      lines.push(`- [${String(r.n || slug)}](${origin}/${encodeURIComponent(slug)})`);
    }
    lines.push('');
  }

  lines.push(
    '## FAQ',
    ...DEFAULT_SEO_FAQS.map((f) => `- **${f.q}**: ${f.a}`),
    '',
    '## Contact',
    `- Email: mailto:${siteEmail}`,
    `- Telephone: tel:${siteTel}`,
    `- WhatsApp: https://wa.me/${siteTel.replace(/^\+/, '')}`,
    `- Instagram: https://instagram.com/iq.menu`,
    '',
    '## Pages',
    `- [Home](${origin}/)`,
    `- [About](${origin}/about)`,
    `- [Contact](${origin}/contact)`,
    `- [Terms of Service](${origin}/terms)`,
    `- [Privacy Policy](${origin}/privacy)`,
    `- [Pricing](${origin}/pricing)`,
    `- [FAQ](${origin}/faq)`,
    `- [llms.txt](${origin}/llms.txt)`,
    `- [MCP Server Card](${origin}/.well-known/mcp/server-card.json)`
  );

  return lines.join('\n');
}

async function injectSeoMetaIntoHtml(
  html: string,
  req: Request,
  res?: Response,
  preloadedAllData?: Record<string, unknown>
): Promise<string> {
  try {
    const origin = resolveRequestOrigin(req);
    const cleanPath = req.path === '/' ? '/' : req.path.replace(/\/+$/, '');
    const canonicalUrl = `${origin}${cleanPath === '/' ? '/' : cleanPath}`;

    let pageTitle = 'Menu Plus — المنيو الإلكتروني الذكي QR وكتالوج واتساب للمطاعم والمتاجر';
    let pageDesc =
      'أنشئ منيو إلكتروني QR احترافي وكتالوج مبيعات ذكي لمطعمك أو متجرك مع Menu Plus. استقبل طلبات التوصيل والطاولات مباشرة على واتساب بدون أي عمولة.';
    let noIndex = false;
    let embedImageUrl = `${origin}/assets/logo.png`;
    let embedImageAlt = 'Menu Plus — المنيو الإلكتروني الذكي للمطاعم والمتاجر';
    const ogType = 'website';
    let ssrRootHtml = '';
    const graphNodes: Record<string, unknown>[] = [];

    const segs = cleanPath.replace(/^\/+/, '').split('/').filter(Boolean);
    const isSlugDashRoute =
      segs.length >= 2 &&
      segs[1].toLowerCase() === 'dashboard' &&
      !SEO_RESERVED_SEGMENTS.has(segs[0].toLowerCase());
    const isAnyDashRoute = cleanPath.startsWith('/dashboard') || isSlugDashRoute;

    if (
      cleanPath.startsWith('/admin') ||
      isAnyDashRoute ||
      cleanPath === '/login' ||
      cleanPath === '/signup' ||
      cleanPath === '/forgot' ||
      cleanPath === '/onboard'
    ) {
      noIndex = true;
    }

    if (res && !res.headersSent) {
      res.setHeader(
        'X-Robots-Tag',
        noIndex
          ? 'noindex, nofollow'
          : 'index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1'
      );
      if (!noIndex) {
        applyAgentLinkHeaders(res, origin, cleanPath);
      }
    }

    const isCacheablePublicHtml = !isAnyDashRoute && !cleanPath.startsWith('/admin') && !cleanPath.startsWith('/onboard');
    if (isCacheablePublicHtml && isProduction) {
      const cacheKey = `${origin}|${cleanPath}`;
      const cached = publicHtmlInjectionCache.get(cacheKey);
      if (cached && cached.version === getRealtimeVersion('menu', cached.familyRids)) {
        return cached.html;
      }
    }

    // Remove static fallback JSON-LD, robots meta, canonical & alternate tags so server outputs one authoritative SEO block
    const stripStaticSeoTags = (input: string) =>
      input
        .replace(/<script[^>]*type="application\/ld\+json"[^>]*>[\s\S]*?<\/script>/gi, '')
        .replace(/<meta\s+name="robots"[^>]*\/?>/gi, '')
        .replace(/<link\s+rel="canonical"[^>]*\/?>/gi, '')
        .replace(/<link\s+rel="alternate"[^>]*type="text\/(?:markdown|plain)"[^>]*\/?>/gi, '');

    // Admin and onboard pages don't need full DB hydration in initial HTML
    if (cleanPath.startsWith('/admin') || cleanPath.startsWith('/onboard')) {
      const safeTitle = escapeSeoAttr(pageTitle);
      const safeDesc = escapeSeoAttr(pageDesc);
      const safeCanonical = escapeSeoAttr(canonicalUrl);
      const safeEmbedImage = escapeSeoAttr(embedImageUrl);
      let out = stripStaticSeoTags(html).replace(/<title>[\s\S]*?<\/title>/i, () => `<title>${safeTitle}</title>`);
      out = out.replace(/<meta\s+name="description"\s+content="[^"]*"\s*\/?>/i, () => `<meta name="description" content="${safeDesc}" />`);
      out = out.replace(/<meta\s+property="og:title"\s+content="[^"]*"\s*\/?>/i, () => `<meta property="og:title" content="${safeTitle}" />`);
      out = out.replace(/<meta\s+property="og:description"\s+content="[^"]*"\s*\/?>/i, () => `<meta property="og:description" content="${safeDesc}" />`);
      out = out.replace(/<meta\s+property="og:image"\s+content="[^"]*"\s*\/?>/i, () => `<meta property="og:image" content="${safeEmbedImage}" />`);
      out = out.replace(/<meta\s+name="twitter:image"\s+content="[^"]*"\s*\/?>/i, () => `<meta name="twitter:image" content="${safeEmbedImage}" />`);
      const seoTags = [
        `<link rel="canonical" href="${safeCanonical}" />`,
        `<meta property="og:url" content="${safeCanonical}" />`,
        `<meta name="robots" content="noindex, nofollow" />`,
      ];
      if (out.includes('</head>')) {
        out = out.replace('</head>', () => `  ${seoTags.join('\n  ')}\n  </head>`);
      }
      return out;
    }

    const allData = preloadedAllData ?? (await readAll(false).catch(() => ({} as Record<string, unknown>)));
    const siteSettings = (allData['settings/site'] || {}) as Record<string, unknown>;
    const siteTel = normalizeTelUri(String(siteSettings.supportWhatsapp || siteSettings.wa || ''));
    const siteEmail = String(siteSettings.em || 'support@menuplus.io').trim();

    // Check if route is /menu/:idOrSlug or /:slug (not dashboard!)
    let targetSlugOrId = '';
    if (segs[0]?.toLowerCase() === 'menu' && segs[1]) {
      targetSlugOrId = safeDecodeUriSegment(segs[1]) || '';
    } else if (segs.length === 1 && !SEO_RESERVED_SEGMENTS.has(segs[0].toLowerCase())) {
      targetSlugOrId = safeDecodeUriSegment(segs[0]) || '';
    }

    let matchedFamily: ReturnType<typeof resolvePublicMenuFamily> = null;
    if (targetSlugOrId) {
      matchedFamily = resolvePublicMenuFamily(allData, targetSlugOrId);
      const matchedRest = matchedFamily?.rest;
      if (matchedRest && matchedFamily) {
        const restName =
          matchedRest.isBranch && String(matchedRest.branchName || '').trim()
            ? String(matchedRest.branchName).trim()
            : String(matchedRest.n || 'المنيو الإلكتروني');
        const rawTagline = String(matchedRest.tagline || '').trim();
        const isMatchedStore = String(matchedRest.projectType || '').toLowerCase().trim() === 'store';
        const cleanTagline =
          isMatchedStore && rawTagline === 'أشهى الأطباق المحضرة يومياً طازجة بجودة عالية'
            ? ''
            : rawTagline;
        const restAbout = String(cleanTagline || matchedRest.aboutText || '').trim();
        const storeSlug = sanitizeSubdomainValue(String(matchedRest.slug || matchedRest.subdomain || '')) || String(matchedRest.id || targetSlugOrId);
        const storeCanonical = `${origin}/${encodeURIComponent(storeSlug)}`;
        pageTitle = `${restName} — المنيو الإلكتروني وطلبات الواتساب | Menu Plus`;
        pageDesc = restAbout
          ? `${restName}: ${restAbout.slice(0, 125)} — تصفح القائمة والأسعار واطلب مباشرة عبر واتساب على Menu Plus.`
          : `تصفح قائمة الطعام والمنتجات والأسعار في ${restName} واطلب مباشرة عبر واتساب بسهولة عبر منصة Menu Plus.`;
        embedImageUrl = resolvePublicAssetUrl(
          origin,
          (Array.isArray(matchedRest.coverImages) && matchedRest.coverImages[0]) || matchedRest.logo,
          '/assets/logo.png'
        );
        embedImageAlt = `${restName} — Menu Plus`;

        const menuCats = Object.entries(matchedFamily.bootstrapRecords)
          .filter(([k, v]) => k.startsWith('cats/') && v && typeof v === 'object')
          .map(([, v]) => v as Record<string, unknown>);
        const menuItems = Object.entries(matchedFamily.bootstrapRecords)
          .filter(([k, v]) => k.startsWith('items/') && v && typeof v === 'object')
          .map(([, v]) => v as Record<string, unknown>);

        graphNodes.push(
          {
            '@type': 'WebSite',
            '@id': `${origin}/#website`,
            name: 'Menu Plus',
            alternateName: ['Menu Plus', 'منيو بلس'],
            url: `${origin}/`,
          },
          {
            '@type': 'BreadcrumbList',
            itemListElement: [
              { '@type': 'ListItem', position: 1, name: 'Menu Plus', item: `${origin}/` },
              { '@type': 'ListItem', position: 2, name: 'تصفح المنيوهات', item: `${origin}/explore` },
              { '@type': 'ListItem', position: 3, name: restName, item: storeCanonical },
            ],
          },
          {
            '@type': isMatchedStore ? 'Store' : 'Restaurant',
            name: restName,
            description: pageDesc,
            url: storeCanonical,
            ...(matchedRest.ph ? { telephone: String(matchedRest.ph) } : {}),
            image: embedImageUrl,
            hasMenu: {
              '@type': 'Menu',
              name: `قائمة ${restName}`,
              url: storeCanonical,
              hasMenuSection: menuCats.slice(0, 8).map((cat) => ({
                '@type': 'MenuSection',
                name: String(cat.n || ''),
                hasMenuItem: menuItems
                  .filter((it) => it.cat === cat.id)
                  .slice(0, 10)
                  .map((it) => ({
                    '@type': 'MenuItem',
                    name: String(it.n || ''),
                    ...(it.d ? { description: String(it.d) } : {}),
                    offers: {
                      '@type': 'Offer',
                      price: String(Number(it.pr) || 0),
                      priceCurrency: 'IQD',
                    },
                  })),
              })),
            },
          }
        );

        ssrRootHtml = buildSsrRootHtml({
          heading: `${restName} — المنيو الإلكتروني | Menu Plus`,
          description: pageDesc,
          origin,
          siteEmail,
          siteTel,
          sectionKey: 'menu',
          items: menuItems.slice(0, 24).map((it) => ({
            title: String(it.n || ''),
            detail: it.pr ? `${Number(it.pr).toLocaleString('en-US')} ${String(matchedRest.currency || 'د.ع')}` : String(it.d || ''),
          })),
        });
      }
    } else if (!noIndex) {
      const routeSection = segs[0]?.toLowerCase() || '';
      const routeSectionNames: Record<string, { title: string; h1: string; desc: string; crumb: string }> = {
        explore: {
          title: 'تصفح المنيوهات والمتاجر المباشرة | Menu Plus',
          h1: 'استكشف لوحة تحكم وقوائم Menu Plus المباشرة',
          desc: 'اكتشف مطاعم وكافيهات ومتاجر تستخدم Menu Plus في العراق والوطن العربي، وتصفح القوائم التفاعلية المباشرة عبر باركود QR.',
          crumb: 'تصفح المنيوهات',
        },
        services: {
          title: 'مميزات المنيو الإلكتروني ونظام طلبات الواتساب | Menu Plus',
          h1: 'مميزات المنيو الإلكتروني الذكي وطلبات الواتساب',
          desc: 'باركود QR سريع، استقبال طلبات التوصيل والطاولات على واتساب، لوحة تحكم سحابية، فروع متعددة، وثيمات احترافية بـ 0% عمولة.',
          crumb: 'المميزات والخدمات',
        },
        steps: {
          title: 'خطوات إنشاء منيو إلكتروني QR لمطعمك في دقائق | Menu Plus',
          h1: 'خطوات إنشاء منيو إلكتروني QR في دقائق',
          desc: 'سجّل مشروعك، أضف الأقسام والأصناف بالصور والأسعار، واطبع كود QR لتستقبل طلبات زبائنك مباشرة على واتساب.',
          crumb: 'خطوات التشغيل',
        },
        pricing: {
          title: 'أسعار وباقات Menu Plus (0% عمولة على المبيعات)',
          h1: 'أسعار وباقات الاشتراك في Menu Plus',
          desc: 'اختر الباقة المناسبة لمطعمك أو متجرك باشتراك شهري أو سنوي مرن بدون أي عمولة على الطلبات والمبيعات في Menu Plus.',
          crumb: 'الأسعار والباقات',
        },
        faq: {
          title: 'الأسئلة الشائعة حول المنيو الإلكتروني QR | Menu Plus',
          h1: 'الأسئلة الشائعة حول المنيو الإلكتروني وطلبات الواتساب',
          desc: 'إجابات كاملة عن كيفية إنشاء المنيو الإلكتروني، كود QR للطاولات، ربط طلبات واتساب، الباقات، وتخصيص الهوية في Menu Plus.',
          crumb: 'الأسئلة الشائعة',
        },
        about: {
          title: 'عن منصة Menu Plus — نظام المنيو الإلكتروني وطلبات الواتساب',
          h1: 'عن منصة Menu Plus',
          desc: 'منصة عربية سحابية متخصصة في إنشاء المنيو الإلكتروني الذكي QR واستقبال طلبات المطاعم والكافيهات والمتاجر مباشرة على واتساب بـ 0% عمولة.',
          crumb: 'عن المنصة',
        },
        contact: {
          title: 'تواصل معنا — فريق دعم Menu Plus',
          h1: 'تواصل مع فريق Menu Plus',
          desc: 'تواصل مع فريق دعم ومبيعات Menu Plus عبر البريد الإلكتروني أو الهاتف أو واتساب للاستفسار عن الباقات وإعداد منيو مشروعك.',
          crumb: 'تواصل معنا',
        },
        terms: {
          title: 'الشروط والأحكام | Menu Plus',
          h1: 'الشروط والأحكام — Menu Plus',
          desc: 'الشروط والأحكام الخاصة باستخدام منصة Menu Plus لإنشاء القوائم الرقمية والكتالوجات وطلبات الواتساب.',
          crumb: 'الشروط والأحكام',
        },
        privacy: {
          title: 'سياسة الخصوصية وأمان البيانات | Menu Plus',
          h1: 'سياسة الخصوصية — Menu Plus',
          desc: 'التزام منصة Menu Plus الكامل بحماية بيانات المتاجر والزبائن وعدم مشاركتها مع أي أطراف ثالثة.',
          crumb: 'سياسة الخصوصية',
        },
      };

      const routeMeta = routeSectionNames[routeSection];
      if (routeMeta) {
        pageTitle = routeMeta.title;
        pageDesc = routeMeta.desc;
      }

      const homeDoc = allData['settings/home'] as { faq?: { enabled?: boolean; items?: Array<{ q?: string; a?: string; visible?: boolean }> }; footerConfig?: { instagramUrl?: string; authorUrl?: string } } | undefined;
      const faqList =
        homeDoc?.faq?.items && homeDoc.faq.items.length > 0
          ? homeDoc.faq.items.filter((f) => f.visible !== false && f.q && f.a).map((f) => ({ q: String(f.q), a: String(f.a) }))
          : DEFAULT_SEO_FAQS;
      const faqItems = faqList.map((f) => ({
        '@type': 'Question',
        name: f.q,
        acceptedAnswer: { '@type': 'Answer', text: f.a },
      }));

      const plansDoc = allData['settings/plans'] as { list?: Array<{ id?: string; n?: string; pr?: number }> } | Array<{ id?: string; n?: string; pr?: number }> | undefined;
      const plansList = (Array.isArray(plansDoc) ? plansDoc : Array.isArray(plansDoc?.list) ? plansDoc.list : []).filter(
        (p) => String(p.id || '') !== 'free' && Number(p.pr || 0) > 0
      );
      const planPrices = plansList.map((p) => Number(p.pr || 0)).filter((p) => p > 0);
      const lowPrice = planPrices.length > 0 ? String(Math.min(...planPrices)) : '9000';
      const highPrice = planPrices.length > 0 ? String(Math.max(...planPrices)) : '29000';

      const publicStores = Object.entries(allData)
        .filter(([k, v]) => k.startsWith('restaurants/') && v && typeof v === 'object')
        .map(([, v]) => v as Record<string, unknown>)
        .filter((r) => r.a !== 0 && !r.isBranch && String(r.n || '').trim())
        .slice(0, 12);

      const sameAsLinks = Array.from(
        new Set(
          [
            homeDoc?.footerConfig?.instagramUrl,
            'https://instagram.com/iq.menu',
            homeDoc?.footerConfig?.authorUrl || 'https://instagram.com/weel',
          ]
            .map((s) => String(s || '').trim())
            .filter((s) => /^https?:\/\//i.test(s))
        )
      );

      graphNodes.push(
        {
          '@type': 'WebSite',
          '@id': `${origin}/#website`,
          name: 'Menu Plus',
          alternateName: ['Menu Plus', 'منيو بلس'],
          url: `${origin}/`,
          inLanguage: ['ar', 'en', 'ku'],
          potentialAction: {
            '@type': 'SearchAction',
            target: `${origin}/explore?q={search_term_string}`,
            'query-input': 'required name=search_term_string',
          },
        },
        {
          '@type': 'Organization',
          '@id': `${origin}/#organization`,
          name: 'Menu Plus',
          alternateName: ['Menu Plus', 'منيو بلس'],
          url: `${origin}/`,
          logo: {
            '@type': 'ImageObject',
            url: `${origin}/pwa-512x512.png`,
            width: 512,
            height: 512,
          },
          image: `${origin}/assets/logo.png`,
          description: 'منصة عربية متخصصة في إنشاء المنيو الإلكتروني الذكي بباركود QR والكتالوج التفاعلي وطلبات الواتساب للمطاعم والكافيهات والمتاجر بدون عمولة.',
          email: siteEmail,
          telephone: siteTel,
          areaServed: ['IQ', 'SA', 'AE', 'KW', 'QA', 'JO', 'OM', 'EG'],
          sameAs: sameAsLinks,
          address: {
            '@type': 'PostalAddress',
            addressCountry: 'IQ',
            addressLocality: 'Baghdad',
          },
          contactPoint: {
            '@type': 'ContactPoint',
            contactType: 'customer support',
            telephone: siteTel,
            email: siteEmail,
            availableLanguage: ['Arabic', 'Kurdish', 'English'],
          },
        },
        {
          '@type': 'SoftwareApplication',
          '@id': `${origin}/#software`,
          name: 'Menu Plus',
          alternateName: ['Menu Plus', 'منيو بلس'],
          applicationCategory: 'BusinessApplication',
          operatingSystem: 'Web, iOS, Android',
          inLanguage: ['ar', 'en', 'ku'],
          url: `${origin}/`,
          image: `${origin}/assets/logo.png`,
          description: pageDesc,
          publisher: { '@id': `${origin}/#organization` },
          featureList: [
            'منيو إلكتروني سريع برمز QR',
            'استقبال طلبات التوصيل والطاولات مباشرة على واتساب بدون عمولة',
            'لوحة تحكم سحابية متكاملة لإدارة الأقسام والأسعار والعروض',
            'دعم الفروع المتعددة وتخصيص الهوية والألوان',
          ],
          offers: {
            '@type': 'AggregateOffer',
            priceCurrency: 'IQD',
            lowPrice,
            highPrice,
            offerCount: String(Math.max(1, plansList.length || 3)),
          },
        },
        {
          '@type':
            routeSection === 'about'
              ? 'AboutPage'
              : routeSection === 'contact'
              ? 'ContactPage'
              : 'WebPage',
          '@id': `${canonicalUrl}#webpage`,
          url: canonicalUrl,
          name: pageTitle,
          description: pageDesc,
          isPartOf: { '@id': `${origin}/#website` },
          about: { '@id': `${origin}/#organization` },
        }
      );

      if (routeMeta) {
        graphNodes.push({
          '@type': 'BreadcrumbList',
          itemListElement: [
            { '@type': 'ListItem', position: 1, name: 'Menu Plus', item: `${origin}/` },
            { '@type': 'ListItem', position: 2, name: routeMeta.crumb, item: canonicalUrl },
          ],
        });
      }

      if (faqItems.length > 0 && homeDoc?.faq?.enabled !== false && (!routeSection || routeSection === 'faq' || routeSection === 'pricing')) {
        graphNodes.push({
          '@type': 'FAQPage',
          mainEntity: faqItems,
        });
      }

      if (publicStores.length > 0 && (!routeSection || routeSection === 'explore')) {
        graphNodes.push({
          '@type': 'ItemList',
          name: 'متاجر ومطاعم تستخدم Menu Plus',
          itemListElement: publicStores.map((r, idx) => {
            const slug = sanitizeSubdomainValue(String(r.slug || r.subdomain || '')) || (r.id === 'demo' ? 'cap-burger' : String(r.id || ''));
            return {
              '@type': 'ListItem',
              position: idx + 1,
              name: String(r.n || slug),
              url: `${origin}/${encodeURIComponent(slug)}`,
            };
          }),
        });
      }

      ssrRootHtml = buildSsrRootHtml({
        heading: routeMeta?.h1 || 'Menu Plus — المنيو الإلكتروني الذكي QR وطلبات الواتساب',
        description: pageDesc,
        origin,
        siteEmail,
        siteTel,
        sectionKey: routeSection || 'home',
        plans: plansList.map((p) => ({
          name: String(p.n || ''),
          price: Number(p.pr || 0).toLocaleString('en-US'),
        })),
        faqs: faqList,
        stores: publicStores.map((r) => {
          const slug = sanitizeSubdomainValue(String(r.slug || r.subdomain || '')) || (r.id === 'demo' ? 'cap-burger' : String(r.id || ''));
          return {
            name: String(r.n || slug),
            href: `${origin}/${encodeURIComponent(slug)}`,
          };
        }),
      });
    }

    const safeTitle = escapeSeoAttr(pageTitle);
    const safeDesc = escapeSeoAttr(pageDesc);
    const safeCanonical = escapeSeoAttr(canonicalUrl);
    const safeEmbedImage = escapeSeoAttr(embedImageUrl);
    const safeEmbedAlt = escapeSeoAttr(embedImageAlt);

    let out = stripStaticSeoTags(html).replace(/<title>[\s\S]*?<\/title>/i, () => `<title>${safeTitle}</title>`);
    out = out.replace(/<meta\s+name="description"\s+content="[^"]*"\s*\/?>/i, () => `<meta name="description" content="${safeDesc}" />`);
    out = out.replace(/<meta\s+property="og:type"\s+content="[^"]*"\s*\/?>/i, () => `<meta property="og:type" content="${ogType}" />`);
    out = out.replace(/<meta\s+property="og:site_name"\s+content="[^"]*"\s*\/?>/i, () => `<meta property="og:site_name" content="Menu Plus" />`);
    out = out.replace(/<meta\s+property="og:title"\s+content="[^"]*"\s*\/?>/i, () => `<meta property="og:title" content="${safeTitle}" />`);
    out = out.replace(/<meta\s+property="og:description"\s+content="[^"]*"\s*\/?>/i, () => `<meta property="og:description" content="${safeDesc}" />`);
    out = out.replace(/<meta\s+property="og:image"\s+content="[^"]*"\s*\/?>/i, () => `<meta property="og:image" content="${safeEmbedImage}" />`);
    out = out.replace(/<meta\s+property="og:image:alt"\s+content="[^"]*"\s*\/?>/i, () => `<meta property="og:image:alt" content="${safeEmbedAlt}" />`);
    out = out.replace(/<meta\s+name="twitter:title"\s+content="[^"]*"\s*\/?>/i, () => `<meta name="twitter:title" content="${safeTitle}" />`);
    out = out.replace(/<meta\s+name="twitter:description"\s+content="[^"]*"\s*\/?>/i, () => `<meta name="twitter:description" content="${safeDesc}" />`);
    out = out.replace(/<meta\s+name="twitter:image"\s+content="[^"]*"\s*\/?>/i, () => `<meta name="twitter:image" content="${safeEmbedImage}" />`);
    out = out.replace(/<meta\s+name="twitter:image:alt"\s+content="[^"]*"\s*\/?>/i, () => `<meta name="twitter:image:alt" content="${safeEmbedAlt}" />`);

    const seoTags: string[] = [
      `<link rel="canonical" href="${safeCanonical}" />`,
      `<link rel="alternate" type="text/markdown" href="${safeCanonical}" title="Markdown" />`,
      `<link rel="alternate" type="text/plain" href="${escapeSeoAttr(`${origin}/llms.txt`)}" title="llms.txt" />`,
      `<link rel="alternate" hreflang="ar" href="${safeCanonical}" />`,
      `<link rel="alternate" hreflang="ar-IQ" href="${safeCanonical}" />`,
      `<link rel="alternate" hreflang="x-default" href="${safeCanonical}" />`,
      `<meta property="og:url" content="${safeCanonical}" />`,
      `<meta name="twitter:url" content="${safeCanonical}" />`,
      `<meta name="robots" content="${noIndex ? 'noindex, nofollow' : 'index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1'}" />`,
    ];
    if (graphNodes.length > 0) {
      const unifiedGraph = { '@context': 'https://schema.org', '@graph': graphNodes };
      seoTags.push(
        `<script id="mp-ssr-jsonld" type="application/ld+json">${JSON.stringify(unifiedGraph).replace(/</g, '\\u003c')}</script>`
      );
    }

    if (out.includes('</head>')) {
      out = out.replace('</head>', () => `  ${seoTags.join('\n  ')}\n  </head>`);
    }
    if (ssrRootHtml && !noIndex) {
      out = out.replace(
        /<div\s+id="root">[\s\S]*?(?:<\/footer>\s*)?<\/div>/i,
        () => `<div id="root">${ssrRootHtml}</div>`
      );
    }
    if (matchedFamily) {
      out = injectInitialMenuBootstrapIntoHtml(out, matchedFamily);
    } else if (!isAnyDashRoute && !cleanPath.startsWith('/admin') && !cleanPath.startsWith('/onboard')) {
      out = injectInitialHomeBootstrapIntoHtml(out, allData);
    }

    if (isAnyDashRoute) {
      const branchMatch = /^\/dashboard\/b\/([a-zA-Z0-9_-]+)/.exec(req.path);
      const slugDashMatch = isSlugDashRoute ? decodeURIComponent(segs[0]) : '';
      const sessionRid = typeof req.authSession?.rid === 'string' ? req.authSession.rid.trim() : '';
      let targetRid = branchMatch ? branchMatch[1] : '';
      let resolvedSlug = slugDashMatch ? sanitizeSubdomainValue(slugDashMatch) : '';

      if (!targetRid && resolvedSlug) {
        const matched = resolveRestaurantEntryByIdOrSlug(allData, resolvedSlug);
        if (matched) targetRid = matched.rid;
      }
      if (!targetRid) {
        targetRid = sessionRid;
      }

      if (targetRid) {
        const restRec = allData[`restaurants/${targetRid}`] as Record<string, unknown> | undefined;
        const dbSlug = sanitizeSubdomainValue(String(restRec?.slug || restRec?.subdomain || ''));
        if (dbSlug) resolvedSlug = dbSlug;
        else if (targetRid === 'demo' && !resolvedSlug) resolvedSlug = 'cap-burger';
      }

      const { logo, name } = getRestaurantRecordForPwa(allData, targetRid);
      const ver = computePwaLogoVersion(logo);

      if (name) {
        const dashTitle = escapeSeoAttr(`لوحة تحكم ${name} | Menu Plus`);
        out = out.replace(/<title>[\s\S]*?<\/title>/i, () => `<title>${dashTitle}</title>`);
      }

      const manifestParams = new URLSearchParams();
      if (targetRid) manifestParams.set('rid', targetRid);
      if (resolvedSlug) manifestParams.set('slug', resolvedSlug);
      if (branchMatch) manifestParams.set('branchId', branchMatch[1]);
      if (name) manifestParams.set('name', name);
      if (logo) manifestParams.set('v', ver);
      const manifestQs = manifestParams.toString();
      const manifestHref = manifestQs
        ? `/api/pwa/dashboard-manifest.webmanifest?${manifestQs}`
        : '/api/pwa/dashboard-manifest.webmanifest';

      out = out.replace(
        /<link\s+rel="manifest"\s+href="[^"]*"\s*\/?>/i,
        () => `<link rel="manifest" href="${escapeSeoAttr(manifestHref)}" />`
      );

      if (targetRid && logo) {
        const iconHref = escapeSeoAttr(
          `/api/pwa/dashboard-icon?rid=${encodeURIComponent(targetRid)}&v=${encodeURIComponent(ver)}`
        );
        out = out.replace(
          /<link\s+rel="apple-touch-icon"[^>]*\/?>/gi,
          () => `<link rel="apple-touch-icon" href="${iconHref}" />`
        );
        out = out.replace(
          /<link\s+rel="icon"[^>]*\/?>/gi,
          () => `<link rel="icon" href="${iconHref}" />`
        );
      }

      if (name) {
        const shortTitle = name.length <= 14 ? name : `${name.slice(0, 13)}…`;
        out = out.replace(
          /<meta\s+name="apple-mobile-web-app-title"\s+content="[^"]*"\s*\/?>/i,
          () => `<meta name="apple-mobile-web-app-title" content="${escapeSeoAttr(shortTitle)}" />`
        );
      }
    }

    if (isCacheablePublicHtml && isProduction) {
      const famRids = matchedFamily ? Array.from(matchedFamily.familyRids) : null;
      const cacheVer = getRealtimeVersion('menu', famRids);
      if (publicHtmlInjectionCache.size >= MAX_PUBLIC_HTML_CACHE) {
        const firstKey = publicHtmlInjectionCache.keys().next().value;
        if (firstKey) publicHtmlInjectionCache.delete(firstKey);
      }
      publicHtmlInjectionCache.set(`${origin}|${cleanPath}`, {
        version: cacheVer,
        familyRids: famRids,
        html: out,
      });
    }

    return out;
  } catch {
    return html;
  }
}

app.get('/robots.txt', (req, res) => {
  const origin = resolveRequestOrigin(req);
  res
    .status(200)
    .setHeader('Content-Type', 'text/plain; charset=utf-8')
    .setHeader('Cache-Control', 'public, max-age=3600')
    .send(
      [
        'User-agent: *',
        'Content-Signal: search=yes, ai-train=no',
        'Allow: /',
        'Allow: /about',
        'Allow: /contact',
        'Allow: /terms',
        'Allow: /privacy',
        'Allow: /explore',
        'Allow: /services',
        'Allow: /steps',
        'Allow: /pricing',
        'Allow: /faq',
        'Allow: /llms.txt',
        'Allow: /.well-known/mcp/server-card.json',
        'Disallow: /admin',
        'Disallow: /admin/',
        'Disallow: /dashboard',
        'Disallow: /dashboard/',
        'Disallow: /*/dashboard',
        'Disallow: /*/dashboard/',
        'Disallow: /login',
        'Disallow: /signup',
        'Disallow: /forgot',
        'Disallow: /onboard',
        'Disallow: /api/',
        `Sitemap: ${origin}/sitemap.xml`,
      ].join('\n')
    );
});

app.get('/llms.txt', async (req, res) => {
  try {
    const origin = resolveRequestOrigin(req);
    const allData = await readAll(false).catch(() => ({} as Record<string, unknown>));
    const siteCfg = (allData['settings/site'] || {}) as Record<string, unknown>;
    const siteEmail = String(siteCfg.em || 'support@menuplus.io').trim();
    const siteTel = normalizeTelUri(String(siteCfg.supportWhatsapp || siteCfg.wa || ''));

    const plansDoc = allData['settings/plans'] as
      | { list?: Array<Record<string, unknown>> }
      | Array<Record<string, unknown>>
      | undefined;
    const rawPlans = Array.isArray(plansDoc) ? plansDoc : Array.isArray(plansDoc?.list) ? plansDoc.list : [];
    const activePlans = rawPlans.filter((p) => String(p.id || '') !== 'free' && Number(p.pr || 0) > 0);
    const publicStores = Object.entries(allData)
      .filter(([k, v]) => k.startsWith('restaurants/') && v && typeof v === 'object')
      .map(([, v]) => v as Record<string, unknown>)
      .filter((r) => r.a !== 0 && !r.isBranch && String(r.n || '').trim())
      .slice(0, 12);

    const content = [
      '# Menu Plus',
      '',
      '> Smart QR digital menu and WhatsApp ordering storefront platform for restaurants, cafés, bakeries, and online stores with 0% sales commission.',
      '',
      '## Core Pages',
      `- [Homepage](${origin}/): Platform overview, interactive dashboard preview, plans, and FAQ.`,
      `- [About Menu Plus](${origin}/about): Mission, platform capabilities, and regional coverage.`,
      `- [Contact](${origin}/contact): Customer support channels, email, telephone, and WhatsApp.`,
      `- [Explore](${origin}/explore): Dashboard preview and live menu search.`,
      `- [Features](${origin}/services): QR menus, WhatsApp ordering, branches, and themes.`,
      `- [Pricing](${origin}/pricing): Monthly and annual subscription tiers (0% commission).`,
      `- [FAQ](${origin}/faq): Answers on QR codes, setup, and customization.`,
      `- [Terms of Service](${origin}/terms): Service terms and billing policies.`,
      `- [Privacy Policy](${origin}/privacy): Data protection and privacy commitments.`,
      '',
      ...(activePlans.length > 0
        ? [
            '## Subscription Plans (IQD)',
            ...activePlans.map(
              (p) => `- **${String(p.n || '')}**: ${Number(p.pr || 0).toLocaleString('en-US')} IQD / month`
            ),
            '',
          ]
        : []),
      ...(publicStores.length > 0
        ? [
            '## Public Storefronts',
            ...publicStores.map((r) => {
              const slug = sanitizeSubdomainValue(String(r.slug || r.subdomain || '')) || (r.id === 'demo' ? 'cap-burger' : String(r.id || ''));
              return `- [${String(r.n || slug)}](${origin}/${encodeURIComponent(slug)})`;
            }),
            '',
          ]
        : []),
      '## Agent & Machine-Readable Endpoints',
      `- [Sitemap](${origin}/sitemap.xml)`,
      `- [Robots Policy](${origin}/robots.txt)`,
      `- [MCP Server Card](${origin}/.well-known/mcp/server-card.json)`,
      `- MCP Streamable HTTP Endpoint: ${origin}/api/mcp`,
      `- Markdown Representation: Send \`Accept: text/markdown\` to ${origin}/ or any public route.`,
      '',
      '## Contact',
      `- Email: mailto:${siteEmail}`,
      `- Telephone: tel:${siteTel}`,
      `- Instagram: https://instagram.com/iq.menu`,
    ].join('\n');

    return res
      .status(200)
      .setHeader('Content-Type', 'text/plain; charset=utf-8')
      .setHeader('Access-Control-Allow-Origin', '*')
      .setHeader('Cache-Control', 'public, max-age=1800')
      .send(content);
  } catch {
    return res.status(500).setHeader('Content-Type', 'text/plain').send('Failed to generate llms.txt');
  }
});

app.get('/.well-known/mcp/server-card.json', (req, res) => {
  const origin = resolveRequestOrigin(req);
  const endpoint = `${origin}/api/mcp`;
  return res
    .status(200)
    .setHeader('Content-Type', 'application/json; charset=utf-8')
    .setHeader('Access-Control-Allow-Origin', '*')
    .setHeader('Cache-Control', 'public, max-age=3600')
    .json({
      $schema: 'https://static.modelcontextprotocol.io/schemas/mcp-server-card/v1.json',
      version: '1.0.0',
      protocolVersion: '2025-03-26',
      name: 'menu-plus',
      title: 'Menu Plus',
      description:
        'Smart QR Digital Menu and WhatsApp Ordering Platform for restaurants, cafés, and retail stores.',
      serverInfo: {
        name: 'menu-plus',
        title: 'Menu Plus',
        version: '1.0.0',
        description:
          'Smart QR Digital Menu and WhatsApp Ordering Platform for restaurants, cafés, and retail stores.',
      },
      endpoint,
      transport: {
        type: 'streamable-http',
        endpoint,
      },
      capabilities: {
        tools: { listChanged: false },
        resources: { listChanged: false },
        prompts: { listChanged: false },
      },
      tools: MCP_TOOLS_CATALOG,
    });
});

app.get('/sitemap.xml', async (req, res) => {
  try {
    const origin = resolveRequestOrigin(req);
    const allData = await readAll(false).catch(() => ({} as Record<string, unknown>));
    const nowIso = new Date().toISOString().slice(0, 10);

    const demoRest = allData['restaurants/demo'] as Record<string, unknown> | undefined;
    const demoSlug = sanitizeSubdomainValue(String(demoRest?.slug || '')) || 'cap-burger';
    const entries: Array<{ loc: string; lastmod: string; priority: string; changefreq: string; image?: string; imageTitle?: string }> = [
      { loc: `${origin}/`, lastmod: nowIso, priority: '1.0', changefreq: 'daily', image: `${origin}/assets/logo.png`, imageTitle: 'Menu Plus' },
      { loc: `${origin}/explore`, lastmod: nowIso, priority: '0.95', changefreq: 'daily', image: `${origin}/assets/logo.png`, imageTitle: 'تصفح المنيوهات المباشرة — Menu Plus' },
      { loc: `${origin}/services`, lastmod: nowIso, priority: '0.9', changefreq: 'weekly' },
      { loc: `${origin}/steps`, lastmod: nowIso, priority: '0.8', changefreq: 'weekly' },
      { loc: `${origin}/pricing`, lastmod: nowIso, priority: '0.9', changefreq: 'weekly' },
      { loc: `${origin}/faq`, lastmod: nowIso, priority: '0.8', changefreq: 'weekly' },
      { loc: `${origin}/about`, lastmod: nowIso, priority: '0.75', changefreq: 'monthly' },
      { loc: `${origin}/contact`, lastmod: nowIso, priority: '0.75', changefreq: 'monthly' },
      { loc: `${origin}/terms`, lastmod: nowIso, priority: '0.6', changefreq: 'monthly' },
      { loc: `${origin}/privacy`, lastmod: nowIso, priority: '0.6', changefreq: 'monthly' },
      {
        loc: `${origin}/${encodeURIComponent(demoSlug)}`,
        lastmod: nowIso,
        priority: '0.85',
        changefreq: 'daily',
        image: resolvePublicAssetUrl(origin, (Array.isArray(demoRest?.coverImages) && demoRest?.coverImages[0]) || demoRest?.logo, '/assets/logo.png'),
        imageTitle: String(demoRest?.n || 'المنيو التجريبي — Menu Plus'),
      },
    ];

    const seen = new Set(entries.map((e) => e.loc));
    for (const [k, v] of Object.entries(allData)) {
      if (!k.startsWith('restaurants/') || !v || typeof v !== 'object') continue;
      const r = v as Record<string, unknown>;
      const id = String(r.id || k.slice('restaurants/'.length));
      if (!id || id === 'demo' || r.a === 0 || r.isBranch) continue;
      const slug = sanitizeSubdomainValue(String(r.slug || r.subdomain || '')) || id;
      const loc = `${origin}/${encodeURIComponent(slug)}`;
      if (!seen.has(loc)) {
        seen.add(loc);
        const rawUpdated = typeof r.updatedAt === 'number' && Number.isFinite(r.updatedAt) ? new Date(r.updatedAt).toISOString().slice(0, 10) : nowIso;
        const imgUrl = resolvePublicAssetUrl(
          origin,
          (Array.isArray(r.coverImages) && r.coverImages[0]) || r.logo,
          '/assets/logo.png'
        );
        entries.push({
          loc,
          lastmod: rawUpdated,
          priority: '0.8',
          changefreq: 'daily',
          image: imgUrl,
          imageTitle: String(r.n || slug),
        });
      }
    }

    const xml =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">\n` +
      entries
        .map(
          (e) =>
            `  <url>\n` +
            `    <loc>${xmlEscape(e.loc)}</loc>\n` +
            `    <lastmod>${e.lastmod}</lastmod>\n` +
            `    <changefreq>${e.changefreq}</changefreq>\n` +
            `    <priority>${e.priority}</priority>\n` +
            (e.image
              ? `    <image:image>\n      <image:loc>${xmlEscape(e.image)}</image:loc>\n${e.imageTitle ? `      <image:title>${xmlEscape(e.imageTitle)}</image:title>\n` : ''}    </image:image>\n`
              : '') +
            `  </url>`
        )
        .join('\n') +
      `\n</urlset>`;

    return res
      .status(200)
      .setHeader('Content-Type', 'application/xml; charset=utf-8')
      .setHeader('Cache-Control', 'public, max-age=1800')
      .send(xml);
  } catch {
    return res.status(500).setHeader('Content-Type', 'text/plain').send('Failed to generate sitemap');
  }
});

// 6. Subdomain interception + Vite middleware (dev) or static dist/ + SPA fallback (prod)
app.use(subdomainMiddleware());

async function runStartupMigrations() {
  const allData = await readAll(false).catch(() => ({} as Record<string, unknown>));
  const putData: Record<string, unknown> = {};
  const delKeys: string[] = [];

  if (!allData['migrations/purged_7833239944_v3']) {
    const targetKeys = new Set(normalizePhoneKeys('07833239944'));
    const matchesTarget = (val: unknown): boolean =>
      typeof val === 'string' && val.trim() !== '' && normalizePhoneKeys(val).some((k) => targetKeys.has(k));

    for (const [k, v] of Object.entries(allData)) {
      if (!v || typeof v !== 'object') continue;
      const rec = v as Record<string, any>;
      if (k.startsWith('accounts/')) {
        const isProtectedAdmin =
          k === 'accounts/acc_admin_owner' || rec.admin === true || rec.r === 'admin';
        if (
          !isProtectedAdmin &&
          (matchesTarget(rec.phone) ||
            matchesTarget(rec.projectPhone) ||
            matchesTarget(rec.em) ||
            matchesTarget(rec.username) ||
            matchesTarget(rec.e) ||
            matchesTarget(rec.u))
        ) {
          delKeys.push(k);
          if (rec.rid && rec.rid !== 'demo') {
            await clearAuthSessionsByTarget(String(rec.rid), k.slice('accounts/'.length)).catch(() => {});
          }
        }
      } else if (k.startsWith('staff/')) {
        if (matchesTarget(rec.phone) || matchesTarget(rec.email)) {
          delKeys.push(k);
        }
      } else if (k.startsWith('restaurants/') && !k.slice('restaurants/'.length).includes('/')) {
        if (matchesTarget(rec.ph) || matchesTarget(rec.ow)) {
          putData[k] = {
            ...rec,
            ...(matchesTarget(rec.ph) ? { ph: '' } : {}),
            ...(matchesTarget(rec.ow) ? { ow: '' } : {}),
          };
        }
      }
    }

    await deleteTelegramUserByPhone('07833239944').catch(() => {});
    await deleteTelegramUserByPhone('9647833239944').catch(() => {});
    putData['migrations/purged_7833239944_v3'] = true;
  }

  if (!allData['migrations/default_light_platform_v1']) {
    const existingSite =
      allData['settings/site'] && typeof allData['settings/site'] === 'object'
        ? (allData['settings/site'] as Record<string, any>)
        : {};
    const existingTheme =
      allData['settings/theme'] && typeof allData['settings/theme'] === 'object'
        ? (allData['settings/theme'] as Record<string, any>)
        : {};

    putData['settings/site'] = {
      ...existingSite,
      homeThemeMode: 'light',
    };
    putData['settings/theme'] = {
      c1: '#0F766E',
      c2: '#FFFFFF',
      c3: '#059669',
      bg: '#F8FAFC',
      mode: 'light',
      c4: '#F1F5F9',
      c5: '#0F766E',
      font: existingTheme.font && !String(existingTheme.font).toLowerCase().startsWith('thmanyah') ? existingTheme.font : 'tajawal',
      ...(existingTheme.typography ? { typography: existingTheme.typography } : {}),
      preset: 'clean_light',
    };
    putData['migrations/default_light_platform_v1'] = true;
  }

  if (!allData['migrations/hero_iraq_copy_v1']) {
    const existingHome =
      allData['settings/home'] && typeof allData['settings/home'] === 'object'
        ? (allData['settings/home'] as Record<string, any>)
        : {};
    const existingHero =
      existingHome.hero && typeof existingHome.hero === 'object' ? existingHome.hero : {};
    putData['settings/home'] = {
      ...existingHome,
      hero: {
        ...existingHero,
        titleLine1: 'المنيو الأذكى بالعراق',
        titleLine2: 'لمتجرك أو مطعمك',
        title: 'المنيو الأذكى بالعراق — لمتجرك أو مطعمك',
        lead: 'أطلق متجرك الآن واستقبل الطلبات',
      },
    };
    putData['migrations/hero_iraq_copy_v1'] = true;
  }

  if (!allData['migrations/root_codes_and_disable_google_subdomain_v1']) {
    const existingSite =
      putData['settings/site'] && typeof putData['settings/site'] === 'object'
        ? (putData['settings/site'] as Record<string, any>)
        : allData['settings/site'] && typeof allData['settings/site'] === 'object'
        ? (allData['settings/site'] as Record<string, any>)
        : {};
    const normalizedSubRules = normalizeSubdomainRules(existingSite);
    putData['settings/site'] = {
      ...existingSite,
      googleAuthEnabled: false,
      subdomainRules: {
        ...normalizedSubRules,
        enabled: false,
      },
    };

    const existingHome =
      putData['settings/home'] && typeof putData['settings/home'] === 'object'
        ? (putData['settings/home'] as Record<string, any>)
        : allData['settings/home'] && typeof allData['settings/home'] === 'object'
        ? (allData['settings/home'] as Record<string, any>)
        : null;
    if (existingHome) {
      const existingHero = existingHome.hero && typeof existingHome.hero === 'object' ? existingHome.hero : {};
      const curCta1 = String(existingHero.cta1Link || '').trim();
      if (!curCta1 || curCta1 === '/menu/demo') {
        putData['settings/home'] = {
          ...existingHome,
          hero: {
            ...existingHero,
            cta1Link: '/cap-burger',
          },
        };
      }
    }

    const plansList = extractPlansList(allData['settings/plans']);
    if (allData['settings/plans'] && typeof allData['settings/plans'] === 'object') {
      const rawPlansDoc = allData['settings/plans'] as Record<string, any>;
      if (Array.isArray(rawPlansDoc.list)) {
        putData['settings/plans'] = {
          ...rawPlansDoc,
          list: rawPlansDoc.list.map((pl: any) => ({
            ...pl,
            featuresMap: {
              ...(pl.featuresMap || {}),
              customSlug: !(pl.id === 'free' && Number(pl.pr || 0) <= 0),
            },
          })),
        };
      }
    }

    const takenSlugs = new Set<string>();
    const restEntries: Array<[string, Record<string, any>]> = [];
    for (const [k, v] of Object.entries(allData)) {
      if (!k.startsWith('restaurants/') || k.slice('restaurants/'.length).includes('/') || !v || typeof v !== 'object') {
        continue;
      }
      const rec = (putData[k] as Record<string, any> | undefined) || (v as Record<string, any>);
      restEntries.push([k, rec]);
    }

    // Reserve valid slugs of paid plans first
    for (const [k, rec] of restEntries) {
      const rid = k.slice('restaurants/'.length);
      if (rid === 'demo') {
        takenSlugs.add('cap-burger');
        continue;
      }
      const { isPaid } = isPaidPlanForRestaurant(rec as StoreRecord, plansList);
      if (isPaid) {
        const curSlug = sanitizeSubdomainValue(String(rec.slug || rec.subdomain || ''));
        if (curSlug && curSlug.length >= 3 && !SYSTEM_RESERVED_SUBDOMAINS.has(curSlug) && !takenSlugs.has(curSlug)) {
          takenSlugs.add(curSlug);
        }
      }
    }

    // Migrate every restaurant to root-level handle (custom for paid, 6-char random code for free/missing)
    for (const [k, rec] of restEntries) {
      const rid = k.slice('restaurants/'.length);
      if (rid === 'demo') {
        const demoSlug = sanitizeSubdomainValue(String(rec.slug || '')) || 'cap-burger';
        putData[k] = {
          ...rec,
          slug: demoSlug,
          subdomain: '',
          isPaid: true,
        };
        continue;
      }

      const { isPaid } = isPaidPlanForRestaurant(rec as StoreRecord, plansList);
      const curSlug = sanitizeSubdomainValue(String(rec.slug || rec.subdomain || ''));

      let nextSlug: string;
      if (isPaid) {
        if (curSlug && curSlug.length >= 3 && !SYSTEM_RESERVED_SUBDOMAINS.has(curSlug)) {
          nextSlug = curSlug;
          takenSlugs.add(curSlug);
        } else {
          nextSlug = generateUniqueMenuCode(takenSlugs);
        }
      } else {
        // Free tier MUST have a 6-char random alphanumeric code
        if (isValidSixCharCode(curSlug) && !SYSTEM_RESERVED_SUBDOMAINS.has(curSlug) && !takenSlugs.has(curSlug)) {
          nextSlug = curSlug;
          takenSlugs.add(curSlug);
        } else {
          nextSlug = generateUniqueMenuCode(takenSlugs);
        }
      }

      putData[k] = {
        ...rec,
        isPaid,
        slug: nextSlug,
        subdomain: '',
      };
    }

    putData['migrations/root_codes_and_disable_google_subdomain_v1'] = true;
  }

  if (!allData['migrations/branches_and_links_v2']) {
    const existingSite =
      putData['settings/site'] && typeof putData['settings/site'] === 'object'
        ? (putData['settings/site'] as Record<string, any>)
        : allData['settings/site'] && typeof allData['settings/site'] === 'object'
        ? (allData['settings/site'] as Record<string, any>)
        : {};
    const subRules = normalizeSubdomainRules(existingSite);
    const plansList = extractPlansList(allData['settings/plans']);

    const curHome =
      putData['settings/home'] && typeof putData['settings/home'] === 'object'
        ? (putData['settings/home'] as Record<string, any>)
        : allData['settings/home'] && typeof allData['settings/home'] === 'object'
        ? (allData['settings/home'] as Record<string, any>)
        : null;
    if (curHome?.hero && (String(curHome.hero.cta1Link || '').includes('/menu/') || !curHome.hero.cta1Link)) {
      putData['settings/home'] = {
        ...curHome,
        hero: {
          ...curHome.hero,
          cta1Link: '/cap-burger',
        },
      };
    }

    const takenSlugs = new Set<string>(['cap-burger']);
    const restItems: Array<[string, Record<string, any>]> = [];
    for (const [k, v] of Object.entries(allData)) {
      if (!k.startsWith('restaurants/') || k.slice('restaurants/'.length).includes('/') || !v || typeof v !== 'object') {
        continue;
      }
      const rec = (putData[k] as Record<string, any> | undefined) || (v as Record<string, any>);
      restItems.push([k, rec]);
      const rid = k.slice('restaurants/'.length);
      if (rid === 'demo') continue;
      const parentRec = rec.parentRid ? (allData[`restaurants/${rec.parentRid}`] as Record<string, any> | undefined) : undefined;
      const { isPaid } = isPaidPlanForRestaurant((parentRec || rec) as StoreRecord, plansList);
      const curSlug = sanitizeSubdomainValue(String(rec.slug || rec.subdomain || ''));
      if (isPaid && curSlug && curSlug.length >= 3 && !SYSTEM_RESERVED_SUBDOMAINS.has(curSlug)) {
        takenSlugs.add(curSlug);
      } else if (!isPaid && isValidSixCharCode(curSlug) && !SYSTEM_RESERVED_SUBDOMAINS.has(curSlug)) {
        takenSlugs.add(curSlug);
      }
    }

    for (const [k, rec] of restItems) {
      const rid = k.slice('restaurants/'.length);
      if (rid === 'demo') continue;
      const parentRec = rec.parentRid ? (allData[`restaurants/${rec.parentRid}`] as Record<string, any> | undefined) : undefined;
      const { isPaid } = isPaidPlanForRestaurant((parentRec || rec) as StoreRecord, plansList);
      const curSlug = sanitizeSubdomainValue(String(rec.slug || rec.subdomain || ''));

      let nextSlug = curSlug;
      if (isPaid) {
        if (!curSlug || curSlug.length < 3 || SYSTEM_RESERVED_SUBDOMAINS.has(curSlug)) {
          nextSlug = generateUniqueMenuCode(takenSlugs);
        }
      } else {
        if (!isValidSixCharCode(curSlug) || SYSTEM_RESERVED_SUBDOMAINS.has(curSlug)) {
          nextSlug = generateUniqueMenuCode(takenSlugs);
        }
      }

      const nextSubdomain = subRules.enabled && isPaid ? nextSlug : '';
      if (rec.slug !== nextSlug || (rec.subdomain || '') !== nextSubdomain || Boolean(rec.isPaid) !== isPaid) {
        putData[k] = {
          ...rec,
          isPaid,
          slug: nextSlug,
          subdomain: nextSubdomain,
        };
      }
    }

    putData['migrations/branches_and_links_v2'] = true;
  }

  // Idempotent migration v3: clean up legacy phoneDemo data from settings/home
  if (!allData['migrations/home_phone_demo_off_v1']) {
    const curHome =
      putData['settings/home'] && typeof putData['settings/home'] === 'object'
        ? (putData['settings/home'] as Record<string, any>)
        : allData['settings/home'] && typeof allData['settings/home'] === 'object'
        ? (allData['settings/home'] as Record<string, any>)
        : {};
    const curSections =
      curHome.sections && typeof curHome.sections === 'object'
        ? (curHome.sections as Record<string, any>)
        : {};
    const { phoneDemo: _legacyPhoneDemo, ...restHome } = curHome;
    putData['settings/home'] = {
      ...restHome,
      sections: {
        hero: curSections.hero !== false,
        services: curSections.services !== false,
        faq: curSections.faq !== false,
        pricing: curSections.pricing !== false,
        footer: curSections.footer !== false,
      },
    };
    putData['migrations/home_phone_demo_off_v1'] = true;
  }

  // Idempotent migration v4: update Cap Burger demo restaurant phone to 07724799679 (leaving Owner Admin 07711448594 intact)
  if (!allData['migrations/cap_burger_phone_07833239944_v1']) {
    const curDemo =
      putData['restaurants/demo'] && typeof putData['restaurants/demo'] === 'object'
        ? (putData['restaurants/demo'] as Record<string, any>)
        : allData['restaurants/demo'] && typeof allData['restaurants/demo'] === 'object'
        ? (allData['restaurants/demo'] as Record<string, any>)
        : null;
    if (curDemo) {
      putData['restaurants/demo'] = {
        ...curDemo,
        ph: '07724799679',
      };
    }
    putData['migrations/cap_burger_phone_07833239944_v1'] = true;
  }

  // Idempotent migration v5: switch platform support & demo phone to 07724799679 everywhere
  if (!allData['migrations/platform_phone_07724799679_v1']) {
    const curSite =
      putData['settings/site'] && typeof putData['settings/site'] === 'object'
        ? (putData['settings/site'] as Record<string, any>)
        : allData['settings/site'] && typeof allData['settings/site'] === 'object'
        ? (allData['settings/site'] as Record<string, any>)
        : {};
    const oldPlaceholders = new Set(['', '07833239944', '9647833239944', '+9647833239944', '07701234567']);
    const curWa = String(curSite.wa || '').trim();
    const curSupportWa = String(curSite.supportWhatsapp || '').trim();
    if (oldPlaceholders.has(curWa) || oldPlaceholders.has(curSupportWa)) {
      putData['settings/site'] = {
        ...curSite,
        wa: oldPlaceholders.has(curWa) ? '07724799679' : curWa,
        supportWhatsapp: oldPlaceholders.has(curSupportWa) ? '07724799679' : curSupportWa,
      };
    }

    const curDemo =
      putData['restaurants/demo'] && typeof putData['restaurants/demo'] === 'object'
        ? (putData['restaurants/demo'] as Record<string, any>)
        : allData['restaurants/demo'] && typeof allData['restaurants/demo'] === 'object'
        ? (allData['restaurants/demo'] as Record<string, any>)
        : null;
    if (curDemo) {
      const curSocial = curDemo.social && typeof curDemo.social === 'object' ? curDemo.social : {};
      const curDemoSocialWa = String(curSocial.whatsapp || '').trim();
      putData['restaurants/demo'] = {
        ...curDemo,
        ph: '07724799679',
        social: {
          ...curSocial,
          whatsapp:
            !curDemoSocialWa || curDemoSocialWa === '9647711448594' || curDemoSocialWa.includes('7833239944')
              ? '9647724799679'
              : curDemoSocialWa,
        },
      };
    }
    putData['migrations/platform_phone_07724799679_v1'] = true;
  }

  // Idempotent migration v6: disable self-registration by default (login only)
  if (!allData['migrations/disable_signup_default_v1']) {
    const curSite =
      putData['settings/site'] && typeof putData['settings/site'] === 'object'
        ? (putData['settings/site'] as Record<string, any>)
        : allData['settings/site'] && typeof allData['settings/site'] === 'object'
        ? (allData['settings/site'] as Record<string, any>)
        : {};
    putData['settings/site'] = {
      ...curSite,
      signupEnabled: false,
      su: 0,
    };
    putData['migrations/disable_signup_default_v1'] = true;
  }

  // Idempotent migration v7: remove Thmanyah font completely and set Tajawal as default platform font
  if (!allData['migrations/remove_thmanyah_default_tajawal_v1']) {
    const curTheme =
      putData['settings/theme'] && typeof putData['settings/theme'] === 'object'
        ? (putData['settings/theme'] as Record<string, any>)
        : allData['settings/theme'] && typeof allData['settings/theme'] === 'object'
        ? (allData['settings/theme'] as Record<string, any>)
        : {};
    const curTypo =
      curTheme.typography && typeof curTheme.typography === 'object'
        ? { ...(curTheme.typography as Record<string, any>) }
        : {};
    delete curTypo.thmanyahFamily;
    const rawKey = String(curTypo.fontKey || curTheme.font || '').trim().toLowerCase();
    const normalizedKey =
      rawKey === 'firjar'
        ? 'firjar'
        : rawKey === 'alan_sans' || rawKey === 'alansans' || rawKey === 'alan sans'
        ? 'alan_sans'
        : 'tajawal';
    putData['settings/theme'] = {
      ...curTheme,
      font: normalizedKey,
      typography: {
        ...curTypo,
        fontKey: normalizedKey,
        separateHeadingFont: false,
        headingFontKey: normalizedKey,
        bodyFontKey: normalizedKey,
        headingScale: curTypo.headingScale ?? 100,
        bodySize: curTypo.bodySize ?? 15,
        descSize: curTypo.descSize ?? 13.5,
        headingWeight: curTypo.headingWeight ?? 800,
        subHeadingWeight: curTypo.subHeadingWeight ?? 700,
        bodyWeight: curTypo.bodyWeight ?? 400,
        descWeight: curTypo.descWeight ?? 400,
        headingLineHeight: curTypo.headingLineHeight ?? 1.28,
        bodyLineHeight: curTypo.bodyLineHeight ?? 1.7,
        letterSpacing: curTypo.letterSpacing ?? 0,
        fontStretch: curTypo.fontStretch ?? 100,
      },
    };
    putData['migrations/curated_google_fonts_cleanup_v1'] = true;
    putData['migrations/remove_thmanyah_default_tajawal_v1'] = true;
  }
  if (allData['migrations/thmanyah_serif_display_headings_v1']) {
    delKeys.push('migrations/thmanyah_serif_display_headings_v1');
  }

  // Idempotent migration v8: ensure demo platform admin account (07711448594 / 11111111) exists internally
  if (!allData['migrations/demo_platform_admin_07711448594_v1'] || !allData['accounts/acc_admin_demo']) {
    putData['accounts/acc_admin_demo'] = {
      id: 'acc_admin_demo',
      n: 'مدير منصة تجريبي',
      roleTitle: 'مدير منصة تجريبي',
      em: '07711448594',
      username: '07711448594',
      phone: '+9647711448594',
      pw: '29a217776b53a000d9a17f20587c7983ab7749f3d03a566b0aac9684cec5cbd4',
      rid: 'demo',
      admin: true,
      active: true,
      at: new Date().toISOString().slice(0, 10),
    };
    putData['migrations/demo_platform_admin_07711448594_v1'] = true;
  }

  if (allData['migrations/telegram_otp_off_v1']) {
    const curSite =
      putData['settings/site'] && typeof putData['settings/site'] === 'object'
        ? { ...(putData['settings/site'] as Record<string, any>) }
        : allData['settings/site'] && typeof allData['settings/site'] === 'object'
        ? { ...(allData['settings/site'] as Record<string, any>) }
        : null;
    if (curSite && 'telegramAuthEnabled' in curSite) {
      delete curSite.telegramAuthEnabled;
      putData['settings/site'] = curSite;
    }
    await updateAdminTelegramConfig({ enabled: true }).catch(() => {});
    delKeys.push('migrations/telegram_otp_off_v1');
  }

  if (!allData['migrations/remove_free_plan_v1']) {
    const existingPlans =
      allData['settings/plans'] && typeof allData['settings/plans'] === 'object'
        ? (allData['settings/plans'] as { list?: Array<Record<string, any>>; [k: string]: any })
        : null;
    if (existingPlans && Array.isArray(existingPlans.list)) {
      const nextList = existingPlans.list.filter(
        (pl) => pl && pl.id !== 'free' && Number(pl.pr) > 0
      );
      putData['settings/plans'] = {
        ...existingPlans,
        list: nextList,
        planNoFreeV8: true,
      };
    }

    const existingHome =
      allData['settings/home'] && typeof allData['settings/home'] === 'object'
        ? { ...(allData['settings/home'] as Record<string, any>) }
        : null;
    if (existingHome) {
      if (existingHome.nav && typeof existingHome.nav === 'object') {
        existingHome.nav = { ...existingHome.nav };
        if (existingHome.nav.modalSignup === 'إنشاء حساب مجاني') {
          existingHome.nav.modalSignup = 'إنشاء حساب';
        }
      }
      if (existingHome.hero && typeof existingHome.hero === 'object') {
        existingHome.hero = { ...existingHome.hero };
        if (typeof existingHome.hero.cta1 === 'string' && /مجانا|مجاناً/i.test(existingHome.hero.cta1)) {
          existingHome.hero.cta1 = 'جرّب المنيو الآن';
        }
      }
      if (existingHome.pricing && typeof existingHome.pricing === 'object') {
        const nextPricing = { ...existingHome.pricing };
        delete nextPricing.freeBadge;
        delete nextPricing.freeCta;
        if (typeof nextPricing.sub !== 'string' || /مجان|مجانية|تجريبية/i.test(nextPricing.sub)) {
          nextPricing.sub = 'اشترك بالباقة المناسبة لمشروعك بدون أي عمولة على مبيعاتك، وطوّر باقتك في أي وقت مع نمو طلباتك.';
        }
        existingHome.pricing = nextPricing;
      }
      if (existingHome.faq && Array.isArray(existingHome.faq.items)) {
        existingHome.faq = {
          ...existingHome.faq,
          items: existingHome.faq.items.map((item: Record<string, any>) =>
            item?.id === 'faq_5' || /الباقة المجانية|أبدأ مجاناً/i.test(`${item?.q || ''} ${item?.a || ''}`)
              ? {
                  ...item,
                  q: 'كيف يتم تفعيل الاشتراك وما هي الباقات المتوفرة؟',
                  a: 'نوفر 3 باقات مرنة (الاقتصادية، الاحترافية، وباقة الأعمال الشاملة) باشتراك شهري أو سنوي بدون أي عمولات على مبيعاتك، ويمكنك الترقية بين الباقات في أي وقت.',
                }
              : item
          ),
        };
      }
      putData['settings/home'] = existingHome;
    }

    for (const [k, v] of Object.entries(allData)) {
      if (!k.startsWith('restaurants/') || k.slice('restaurants/'.length).includes('/') || !v || typeof v !== 'object') {
        continue;
      }
      const r = v as Record<string, any>;
      const planStr = String(r.p || '').trim();
      if (r.planId === 'free' || planStr === 'الباقة المجانية' || planStr === 'البداية المجانية') {
        putData[k] = {
          ...r,
          planId: 'starter',
          p: 'الباقة الاقتصادية',
          isPaid: true,
        };
      }
    }

    putData['migrations/remove_free_plan_v1'] = true;
  }

  for (const k of Object.keys(allData)) {
    if (k.startsWith('promo_codes/')) {
      delKeys.push(k);
    } else if (k.startsWith('items/')) {
      const itemRec = allData[k] as Record<string, any> | undefined;
      if (itemRec && typeof itemRec.img === 'string' && itemRec.img.includes('1576107232684-1279f3908594')) {
        putData[k] = {
          ...itemRec,
          img: '/uploads/hmo/item_046.jpg',
        };
      }
    }
  }

  // Ensure sub-branches whose parent restaurant is active do not stay stuck with stale a: 0
  for (const [k, v] of Object.entries(allData)) {
    if (!k.startsWith('restaurants/') || k.slice('restaurants/'.length).includes('/') || !v || typeof v !== 'object') {
      continue;
    }
    const rec = (putData[k] as Record<string, any> | undefined) || (v as Record<string, any>);
    const parentRid = String(rec.parentRid || '').trim();
    if (!parentRid || rec.deleted === true || rec.a !== 0) continue;
    const parentRec =
      (putData[`restaurants/${parentRid}`] as Record<string, any> | undefined) ||
      (allData[`restaurants/${parentRid}`] as Record<string, any> | undefined);
    if (parentRec && parentRec.a !== 0) {
      putData[k] = {
        ...rec,
        a: parentRec.a ?? 1,
      };
    }
  }

  if (!allData['migrations/brand_menu_plus_v1']) {
    const replaceBrandStr = (s: unknown) =>
      typeof s === 'string'
        ? s
            .replace(/منيو\s*بلس\s*\|\s*Menu\+|Menu\+\s*\|\s*منيو\s*بلس|منيو\s*بلس\s*\(Menu\+\)|منيو\s*بلس/g, 'Menu Plus')
            .replace(/مینیۆ\s*پڵەس/g, 'Menu Plus')
            .replace(/Menu\+(?![a-zA-Z0-9_])/gi, 'Menu Plus')
        : s;

    const curSite =
      putData['settings/site'] && typeof putData['settings/site'] === 'object'
        ? { ...(putData['settings/site'] as Record<string, any>) }
        : allData['settings/site'] && typeof allData['settings/site'] === 'object'
        ? { ...(allData['settings/site'] as Record<string, any>) }
        : null;
    if (curSite) {
      curSite.name = 'Menu Plus';
      curSite.logoText = 'Menu Plus';
      putData['settings/site'] = curSite;
    }

    const curHome =
      putData['settings/home'] && typeof putData['settings/home'] === 'object'
        ? { ...(putData['settings/home'] as Record<string, any>) }
        : allData['settings/home'] && typeof allData['settings/home'] === 'object'
        ? { ...(allData['settings/home'] as Record<string, any>) }
        : null;
    if (curHome) {
      if (curHome.hero && typeof curHome.hero === 'object') {
        curHome.hero = { ...curHome.hero };
        if (curHome.hero.cta1 === 'جرب المنيو الان') {
          curHome.hero.cta1 = 'جرّب المنيو الآن';
        }
      }
      if (curHome.steps && typeof curHome.steps === 'object') {
        curHome.steps = { ...curHome.steps, title: replaceBrandStr(curHome.steps.title) };
      }
      if (curHome.demo && typeof curHome.demo === 'object') {
        curHome.demo = { ...curHome.demo, title: replaceBrandStr(curHome.demo.title) };
      }
      if (curHome.faq && typeof curHome.faq === 'object') {
        curHome.faq = {
          ...curHome.faq,
          title: curHome.faq.title === 'أسئلة ممكن تجي في بالك' ? 'الأسئلة الشائعة' : replaceBrandStr(curHome.faq.title),
        };
      }
      if (typeof curHome.footer === 'string') {
        curHome.footer = replaceBrandStr(curHome.footer);
      }
      putData['settings/home'] = curHome;
    }
    putData['migrations/brand_menu_plus_v1'] = true;
  }

  if (!allData['migrations/default_tabs_order_labels_v1']) {
    const curSite =
      putData['settings/site'] && typeof putData['settings/site'] === 'object'
        ? { ...(putData['settings/site'] as Record<string, any>) }
        : allData['settings/site'] && typeof allData['settings/site'] === 'object'
        ? { ...(allData['settings/site'] as Record<string, any>) }
        : {};
    curSite.adminTabOrder = ['home', 'notes', 'partners', 'staff', 'home_editor', 'reports', 'settings'];
    curSite.adminTabLabels = {
      home: 'الصفحة الرئيسية',
      notes: 'الملاحظات',
      partners: 'الحسابات',
      staff: 'الادارة',
      home_editor: 'تعديل الرئيسية',
      reports: 'البلاغات',
      settings: 'الإعدادات',
    };
    curSite.dashboardTabOrder = ['home', 'stats', 'cats', 'menu', 'orders', 'appearance', 'branches', 'addons', 'qr', 'set'];
    curSite.dashboardTabLabels = {
      home: 'الصفحة الرئيسية',
      stats: 'احصائيات احترافية',
      cats: 'الأقسام',
      menu: 'العناصر',
      orders: 'الطلبات',
      appearance: 'المظهر',
      branches: 'عدة أفرع',
      addons: 'الإضافات',
      qr: 'كود QR',
      set: 'الإعدادات',
    };
    putData['settings/site'] = curSite;
    putData['migrations/default_tabs_order_labels_v1'] = true;
  }

  if (Object.keys(putData).length > 0 || delKeys.length > 0) {
    await applyChanges({ put: putData, del: delKeys }, false);
  }
}

const DEV_BOOT_BUILD_ID = Date.now().toString(36);
let cachedProdBuildId = '';

function resolveServerBuildId(indexHtmlContent?: string): string {
  if (!isProduction) return DEV_BOOT_BUILD_ID;
  if (cachedProdBuildId) return cachedProdBuildId;
  if (indexHtmlContent) {
    const hash = crypto.createHash('sha1').update(indexHtmlContent).digest('hex').slice(0, 12);
    cachedProdBuildId = hash;
    return hash;
  }
  return DEV_BOOT_BUILD_ID;
}

let SERVER_BUILD_ID = resolveServerBuildId();

function injectBuildFingerprint(html: string, buildId: string): string {
  if (!buildId) return html;
  const tag = `<script>window.__MENUPLUS_BUILD__=${JSON.stringify(buildId)};</script>`;
  if (html.includes('</head>')) {
    return html.replace('</head>', () => `  ${tag}\n  </head>`);
  }
  return `${tag}${html}`;
}

async function startServer() {
  await runStartupMigrations().catch((err) => {
    console.warn('[Startup Migration] Failed:', err);
  });
  const setNoStoreHtmlHeaders = (res: Response) => {
    res.removeHeader('ETag');
    res.setHeader('Cache-Control', 'private, no-store, no-cache, must-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Vary', 'User-Agent, Accept-Encoding');
    res.setHeader('CDN-Cache-Control', 'no-store');
    res.setHeader('Cloudflare-CDN-Cache-Control', 'no-store');
    res.setHeader('Surrogate-Control', 'no-store');
  };

  if (isProduction) {
    const localDist = path.resolve(__dirname, 'dist');
    const cwdDist = path.resolve(process.cwd(), 'dist');
    const distDir = fs.existsSync(path.join(localDist, 'index.html')) ? localDist : cwdDist;
    const distAssetsDir = path.join(distDir, 'assets');
    const distUploadsDir = path.join(distDir, 'uploads');
    const publicUploadsDir = path.resolve(process.cwd(), 'public/uploads');
    const uploadsDir = fs.existsSync(distUploadsDir) ? distUploadsDir : publicUploadsDir;
    const indexHtmlPath = path.join(distDir, 'index.html');

    // Long immutable cache for hashed Vite JS/CSS bundles
    app.use(
      '/assets',
      express.static(distAssetsDir, {
        maxAge: '1y',
        immutable: true,
        index: false,
      })
    );

    if (fs.existsSync(uploadsDir)) {
      app.use(
        '/uploads',
        express.static(uploadsDir, {
          maxAge: '30d',
          index: false,
        })
      );
    }

    // Static serving for public assets (e.g. favicon, icons) while keeping SW & manifest uncached
    app.use(
      express.static(distDir, {
        cacheControl: false,
        index: false,
        setHeaders: (res, filePath) => {
          const base = path.basename(filePath).toLowerCase();
          if (base === 'sw.js' || base === 'manifest.webmanifest' || base === 'index.html') {
            setNoStoreHtmlHeaders(res);
          } else {
            res.setHeader('Cache-Control', 'public, max-age=604800');
          }
        },
      })
    );

    // Cache dist/index.html keyed by file mtime so live rebuilds never serve stale CSS/JS hashes
    let cachedProdHtml: string | null = null;
    let cachedProdHtmlMtime = -1;
    const readFreshProdHtml = (): string | null => {
      try {
        const st = fs.statSync(indexHtmlPath);
        if (!cachedProdHtml || st.mtimeMs !== cachedProdHtmlMtime) {
          cachedProdHtml = fs.readFileSync(indexHtmlPath, 'utf-8');
          cachedProdHtmlMtime = st.mtimeMs;
        }
        return cachedProdHtml;
      } catch {
        return cachedProdHtml;
      }
    };

    const bootProdHtml = readFreshProdHtml();
    if (bootProdHtml) {
      SERVER_BUILD_ID = resolveServerBuildId(bootProdHtml);
    }

    app.get('*', async (req, res, next) => {
      if (req.path.startsWith('/assets/') || req.path.startsWith('/uploads/') || ASSET_EXTENSION_RE.test(req.path)) {
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('CDN-Cache-Control', 'no-store');
        res.setHeader('Cloudflare-CDN-Cache-Control', 'no-store');
        return res.status(404).end();
      }
      const cleanPath = req.path === '/' ? '/' : req.path.replace(/\/+$/, '') || '/';
      const subdomainResolved = res.locals.subdomainResolved as ResolvedSubdomainResult | undefined;
      try {
        const allData = await readAll(false).catch(() => ({} as Record<string, unknown>));
        const routeExists = doesRouteExistOnServer(cleanPath, allData, subdomainResolved);
        if (!routeExists) {
          res.setHeader('X-Robots-Tag', 'noindex, nofollow');
          if (wantsMarkdownResponse(req)) {
            res.setHeader('Cache-Control', 'no-store');
            return res
              .status(404)
              .setHeader('Content-Type', 'text/markdown; charset=utf-8')
              .send(buildNotFoundMarkdown(req));
          }
          const rawHtml404 = readFreshProdHtml();
          setNoStoreHtmlHeaders(res);
          if (!rawHtml404) {
            return res.status(404).setHeader('Content-Type', 'text/plain; charset=utf-8').send('404 Not Found');
          }
          SERVER_BUILD_ID = resolveServerBuildId(rawHtml404);
          const notFoundHtml = injectBuildFingerprint(injectNotFoundIntoHtml(rawHtml404, req, res), SERVER_BUILD_ID);
          return res.status(404).setHeader('Content-Type', 'text/html; charset=utf-8').send(notFoundHtml);
        }

        if (wantsMarkdownResponse(req)) {
          const origin = resolveRequestOrigin(req);
          applyAgentLinkHeaders(res, origin, cleanPath);
          return res.status(200).setHeader('Content-Type', 'text/markdown; charset=utf-8').send(buildMarkdownDocument(req, allData));
        }
        const rawHtml = readFreshProdHtml();
        if (!rawHtml) {
          return res.status(500).send('Build output not found. Run npm run build first.');
        }
        setNoStoreHtmlHeaders(res);
        SERVER_BUILD_ID = resolveServerBuildId(rawHtml);
        if (subdomainResolved?.found) {
          let subHtml = injectSubdomainHtmlMeta(rawHtml, subdomainResolved);
          if (subdomainResolved.restaurant?.id) {
            const subFamily = resolvePublicMenuFamily(allData, subdomainResolved.restaurant.id);
            subHtml = injectInitialMenuBootstrapIntoHtml(subHtml, subFamily);
          }
          const injected = injectBuildFingerprint(subHtml, SERVER_BUILD_ID);
          applyAgentLinkHeaders(res, resolveRequestOrigin(req), cleanPath);
          return res.status(200).setHeader('Content-Type', 'text/html; charset=utf-8').send(injected);
        }
        const seoInjected = injectBuildFingerprint(
          await injectSeoMetaIntoHtml(rawHtml, req, res, allData),
          SERVER_BUILD_ID
        );
        return res.status(200).setHeader('Content-Type', 'text/html; charset=utf-8').send(seoInjected);
      } catch (err) {
        return next(err);
      }
    });
  } else {
    const publicUploadsDir = path.resolve(process.cwd(), 'public/uploads');
    if (fs.existsSync(publicUploadsDir)) {
      app.use(
        '/uploads',
        express.static(publicUploadsDir, {
          maxAge: '30d',
          index: false,
        })
      );
    }

    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: process.env.DISABLE_HMR !== 'true' },
      appType: 'custom',
    });

    app.get('*', async (req, res, next) => {
      if (
        req.path.startsWith('/@') ||
        req.path.startsWith('/src/') ||
        req.path.startsWith('/node_modules/') ||
        req.path.startsWith('/assets/') ||
        req.path.startsWith('/uploads/') ||
        ASSET_EXTENSION_RE.test(req.path)
      ) {
        return next();
      }
      const cleanPath = req.path === '/' ? '/' : req.path.replace(/\/+$/, '') || '/';
      const subdomainResolved = res.locals.subdomainResolved as ResolvedSubdomainResult | undefined;
      try {
        const allData = await readAll(false).catch(() => ({} as Record<string, unknown>));
        const routeExists = doesRouteExistOnServer(cleanPath, allData, subdomainResolved);
        if (!routeExists) {
          res.setHeader('X-Robots-Tag', 'noindex, nofollow');
          if (wantsMarkdownResponse(req)) {
            res.setHeader('Cache-Control', 'no-store');
            return res
              .status(404)
              .setHeader('Content-Type', 'text/markdown; charset=utf-8')
              .send(buildNotFoundMarkdown(req));
          }
          setNoStoreHtmlHeaders(res);
          const rawTemplate = fs.readFileSync(path.resolve(process.cwd(), 'index.html'), 'utf-8');
          const transformed = await vite.transformIndexHtml(req.originalUrl, rawTemplate);
          const notFoundHtml = injectBuildFingerprint(injectNotFoundIntoHtml(transformed, req, res), SERVER_BUILD_ID);
          return res.status(404).setHeader('Content-Type', 'text/html; charset=utf-8').send(notFoundHtml);
        }

        if (wantsMarkdownResponse(req)) {
          const origin = resolveRequestOrigin(req);
          applyAgentLinkHeaders(res, origin, cleanPath);
          return res.status(200).setHeader('Content-Type', 'text/markdown; charset=utf-8').send(buildMarkdownDocument(req, allData));
        }
        setNoStoreHtmlHeaders(res);
        const rawTemplate = fs.readFileSync(path.resolve(process.cwd(), 'index.html'), 'utf-8');
        const transformed = await vite.transformIndexHtml(req.originalUrl, rawTemplate);
        if (subdomainResolved?.found) {
          let subHtml = injectSubdomainHtmlMeta(transformed, subdomainResolved);
          if (subdomainResolved.restaurant?.id) {
            const subFamily = resolvePublicMenuFamily(allData, subdomainResolved.restaurant.id);
            subHtml = injectInitialMenuBootstrapIntoHtml(subHtml, subFamily);
          }
          const injected = injectBuildFingerprint(subHtml, SERVER_BUILD_ID);
          applyAgentLinkHeaders(res, resolveRequestOrigin(req), cleanPath);
          return res.status(200).setHeader('Content-Type', 'text/html; charset=utf-8').send(injected);
        }
        const seoInjected = injectBuildFingerprint(
          await injectSeoMetaIntoHtml(transformed, req, res, allData),
          SERVER_BUILD_ID
        );
        return res.status(200).setHeader('Content-Type', 'text/html; charset=utf-8').send(seoInjected);
      } catch (err) {
        return next(err);
      }
    });
    app.use(vite.middlewares);
    app.use((_req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('X-Robots-Tag', 'noindex, nofollow');
      return res.status(404).end();
    });
  }

  const onListening = () => {
    const addr = typeof PORT === 'number' ? `http://0.0.0.0:${PORT}` : String(PORT);
    console.log(`Menu Plus server running on ${addr} (${isProduction ? 'production' : 'development'})`);
    const dbInfo = getDatabaseUrlInfo();
    if (dbInfo.configured && dbInfo.valid) {
      console.log(`[Database] DATABASE_URL configured (${dbInfo.host}:${dbInfo.port}/${dbInfo.database})`);
    } else if (dbInfo.configured && !dbInfo.valid) {
      console.warn(`[Database] DATABASE_URL invalid: ${dbInfo.error}`);
    } else {
      console.warn('[Database] DATABASE_URL is not set.');
    }
    void readAll(false).catch(() => {});
    startTelegramBotPolling().catch((err) => {
      console.warn('[Telegram Bot] Failed to start polling:', err);
    });
    ensureWebPushVapidKeys().catch((err) => {
      console.warn('[WebPush] Failed to initialize VAPID keys:', err);
    });
  };

  const server =
    typeof PORT === 'number'
      ? app.listen(PORT, '0.0.0.0', onListening)
      : app.listen(PORT, onListening);

  server.keepAliveTimeout = 65_000;
  server.headersTimeout = 66_000;
  server.requestTimeout = 30_000;

  const shutdown = (signal: string) => {
    console.log(`[Server] Received ${signal}, shutting down gracefully...`);
    stopTelegramBotPolling();
    clearInterval(otpCleanupTimer);
    void flushVisitorAnalytics();
    server.close(() => {
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 5000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

startServer();
