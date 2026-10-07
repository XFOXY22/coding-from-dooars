'use strict';

/*
===========================================================
 CODING FROM DOOARS
 FINAL HARD CUSTOMER PHOTO DOWNLOAD SERVER
===========================================================

 FIX:
 - .htm / .html download বন্ধ
 - Customer photo সরাসরি Backblaze B2 থেকে stream
 - Firestore order থেকে REAL B2 key resolve
 - Image MIME validate
 - Firebase Auth validate
 - Admin / Super Admin access
 - Website localhost:3000 থেকেও serve করবে
 - .env support
===========================================================
*/

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const zlib = require('zlib');
const crypto = require('crypto');

const admin = require('firebase-admin');

const {
  S3Client,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  ListObjectsV2Command
} = require('@aws-sdk/client-s3');


/* =========================================================
   CONFIG
========================================================= */

const PORT = Number(process.env.PORT || 3000);

const B2_ENDPOINT = String(
  process.env.B2_ENDPOINT ||
  'https://s3.eu-central-003.backblazeb2.com'
).replace(/\/+$/, '');

const B2_KEY_ID =
  process.env.B2_KEY_ID ||
  '';

const B2_APPLICATION_KEY =
  process.env.B2_APPLICATION_KEY ||
  '';

const B2_BUCKET_NAME =
  process.env.B2_BUCKET_NAME ||
  process.env.B2_BUCKET ||
  'cooding-from-dooars';



/* =========================================================
   FIREBASE INITIALIZATION
========================================================= */

if (!admin.apps.length) {

  let serviceAccount = null;

  /*
    Option 1:
    FIREBASE_SERVICE_ACCOUNT_JSON

    Option 2:
    GOOGLE_APPLICATION_CREDENTIALS
  */

  const rawJson =
    process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

  const credentialsPath =
    process.env.GOOGLE_APPLICATION_CREDENTIALS;


  if (rawJson && rawJson.trim()) {

    try {

      serviceAccount = JSON.parse(rawJson);

    } catch (err) {

      console.error(
        'FIREBASE_SERVICE_ACCOUNT_JSON invalid JSON.'
      );

      process.exit(1);
    }

  } else if (
    credentialsPath &&
    fs.existsSync(credentialsPath)
  ) {

    try {

      serviceAccount =
        JSON.parse(
          fs.readFileSync(
            credentialsPath,
            'utf8'
          )
        );

    } catch (err) {

      console.error(
        'Could not read Firebase service account file.'
      );

      console.error(err.message);

      process.exit(1);
    }

  } else {

    console.error('');
    console.error(
      'Firebase credentials not found.'
    );
    console.error(
      'Set GOOGLE_APPLICATION_CREDENTIALS in .env'
    );
    console.error('');

    process.exit(1);
  }


  admin.initializeApp({
    credential:
      admin.credential.cert(serviceAccount)
  });
}


const db = admin.firestore();


/* =========================================================
   BACKBLAZE B2 CLIENT
========================================================= */

if (
  !B2_KEY_ID ||
  !B2_APPLICATION_KEY ||
  !B2_BUCKET_NAME
) {

  console.error('');
  console.error(
    'Backblaze B2 credentials are missing.'
  );
  console.error('');
  process.exit(1);
}


const b2Region =
  process.env.B2_REGION ||
  'eu-central-003';


const s3 = new S3Client({

  region: b2Region,

  endpoint: B2_ENDPOINT,

  forcePathStyle: true,

  credentials: {

    accessKeyId:
      B2_KEY_ID,

    secretAccessKey:
      B2_APPLICATION_KEY

  }

});


/* =========================================================
   EXPRESS
========================================================= */

const app = express();

app.disable('x-powered-by');


app.use(
  cors({

    origin: true,

    methods: [
      'GET',
      'POST',
      'PATCH',
      'DELETE',
      'OPTIONS'
    ],

    allowedHeaders: [
      'Authorization',
      'Content-Type'
    ]

  })
);


app.use(
  express.json({
    limit: '20mb'
  })
);

app.use(express.urlencoded({ extended: false, limit: '64kb' }));


/* =========================================================
   BASIC HEALTH
========================================================= */

app.get(
  '/api/health',
  (_req, res) => {

    res.json({

      ok: true,

      server: true,

      firebase:
        admin.apps.length > 0,

      b2:
        Boolean(
          B2_KEY_ID &&
          B2_APPLICATION_KEY &&
          B2_BUCKET_NAME
        ),

      bucket:
        B2_BUCKET_NAME,

      time:
        new Date().toISOString()

    });

  }
);


/*
   Also support /health
*/

app.get(
  '/health',
  (_req, res) => {

    res.json({

      ok: true,

      server: true,

      firebase: true,

      b2: true,

      bucket:
        B2_BUCKET_NAME,

      time:
        new Date().toISOString()

    });

  }
);


/* =========================================================
   HELPERS
========================================================= */

function cleanKey(value) {

  let key =
    String(value || '')
      .trim()
      .replace(/^\/+/, '');

  if (!key) {
    return '';
  }

  if (key.includes('\0')) {
    return '';
  }

  /*
     Block traversal.
  */

  const parts =
    key.split('/');

  if (
    parts.some(
      part => part === '..'
    )
  ) {

    return '';
  }

  return key;
}


/* ---------------------------------------------------------
   SAFE FILENAME
--------------------------------------------------------- */

function safeFilename(value) {

  let name =
    String(
      value ||
      'customer-photo'
    ).trim();


  name =
    name.replace(
      /[^\w.\- ()[\]]+/g,
      '_'
    );


  name =
    name.slice(
      0,
      180
    );


  return (
    name ||
    'customer-photo'
  );
}


/* ---------------------------------------------------------
   AUTH
--------------------------------------------------------- */

async function requireUser(req) {

  const header = String(req.headers.authorization || '');
  const queryToken = String(req.query?.access_token || '').trim();
  const bodyToken = String(req.body?.access_token || '').trim();
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : (bodyToken || queryToken);

  if (!token) {
    const err = new Error('Authentication required.');
    err.status = 401;
    throw err;
  }


  if (!token) {

    const err =
      new Error(
        'Authentication token missing.'
      );

    err.status = 401;

    throw err;
  }


  // V18: verify the Firebase ID token without a forced revocation lookup.
  // verifyIdToken(token) still validates the signed token; the second `true`
  // parameter triggers an extra network-dependent revocation check on every
  // request, which was causing local API requests to stall when Firebase
  // networking was slow/unreachable. Firebase tokens are short-lived and
  // the client refreshes them automatically when needed.
  return admin.auth().verifyIdToken(token);
}


/* ---------------------------------------------------------
   FIRESTORE ORDER
--------------------------------------------------------- */

async function getOrder(orderId) {

  const id =
    String(orderId || '')
      .trim();


  if (!id) {
    return null;
  }


  const snap =
    await db
      .collection('orders')
      .doc(id)
      .get();


  if (!snap.exists) {
    return null;
  }


  return {

    id:
      snap.id,

    ...snap.data()

  };
}


/* ---------------------------------------------------------
   ADMIN CHECK
--------------------------------------------------------- */

async function isPrivilegedUser(user) {

  const claimRole =
    String(
      user?.role ||
      user?.claims?.role ||
      ''
    ).toLowerCase();


  if (
    claimRole === 'admin' ||
    claimRole === 'super_admin'
  ) {

    return true;
  }


  try {

    const snap =
      await db
        .collection('profiles')
        .doc(
          String(user.uid)
        )
        .get();


    if (snap.exists) {

      const role =
        String(
          snap.data()?.role ||
          ''
        ).toLowerCase();


      if (
        role === 'admin' ||
        role === 'super_admin'
      ) {

        return true;
      }
    }

  } catch (err) {

    console.warn(
      'Profile role lookup failed:',
      err.message
    );

  }


  return false;
}


/* =========================================================
   B2 URL → REAL OBJECT KEY
========================================================= */

function extractB2KeyFromUrl(value) {

  const valueString =
    String(value || '')
      .trim();


  if (!valueString) {
    return '';
  }


  /*
     If already a B2 object key.
  */

  if (
    !/^https?:\/\//i.test(
      valueString
    )
  ) {

    return cleanKey(
      valueString
    );
  }


  try {

    const url =
      new URL(
        valueString
      );


    let pathname =
      decodeURIComponent(
        url.pathname
      ).replace(
        /^\/+/,
        ''
      );


    /*
       Remove bucket name if URL contains it.
    */

    if (
      pathname.startsWith(
        B2_BUCKET_NAME + '/'
      )
    ) {

      pathname =
        pathname.slice(
          B2_BUCKET_NAME.length + 1
        );

    }


    return cleanKey(
      pathname
    );

  } catch {

    return '';
  }
}


/* =========================================================
   FIND CUSTOMER PHOTO INSIDE ORDER
========================================================= */

function collectCustomerPhotoCandidates(order) {

  const roots = [

    order?.customerPhoto,

    order?.customerPhotoUrl,

    order?.photo,

    order?.photoUrl,

    order?.custom?.Photo,

    order?.custom?.photo,

    order?.customerFiles,

    order?.files

  ];


  const output = [];

  const seen =
    new Set();


  function walk(
    value,
    hint = ''
  ) {

    if (
      value === null ||
      value === undefined
    ) {

      return;
    }


    /*
       String value
    */

    if (
      typeof value ===
      'string'
    ) {

      const key =
        extractB2KeyFromUrl(
          value
        );


      if (key) {

        if (
          !seen.has(key)
        ) {

          seen.add(key);

          output.push({

            key,

            name:
              hint ||
              key.split('/').pop() ||
              'customer-photo'

          });

        }

      }

      return;
    }


    /*
       Array
    */

    if (
      Array.isArray(value)
    ) {

      value.forEach(
        item =>
          walk(
            item,
            hint
          )
      );

      return;
    }


    /*
       Object
    */

    if (
      typeof value !==
      'object'
    ) {

      return;
    }


    const name =
      String(
        value.name ||
        value.fileName ||
        value.filename ||
        hint ||
        ''
      ).trim();


    const type =
      String(
        value.type ||
        value.contentType ||
        value.mimeType ||
        ''
      ).trim();


    const possibleKeys = [

      value.path,

      value.storagePath,

      value.key,

      value.b2Key,

      value.fileId,

      value.objectKey,

      value.downloadPath,

      value.url,

      value.downloadURL,

      value.downloadUrl,

      value.src

    ];


    for (
      const raw of possibleKeys
    ) {

      const key =
        extractB2KeyFromUrl(
          raw
        );


      if (
        key &&
        !seen.has(key)
      ) {

        seen.add(key);

        output.push({

          key,

          name:
            name ||
            key.split('/').pop() ||
            'customer-photo',

          type

        });

      }

    }


    /*
       Recursive scan.
       Payment proof excluded.
    */

    for (
      const [field, child]
      of Object.entries(value)
    ) {

      if (
        [
          'paymentScreenshot',
          'paymentProof',
          'paymentScreenshotUrl',
          'paymentProofUrl'
        ].includes(field)
      ) {

        continue;
      }


      if (
        child &&
        typeof child ===
        'object'
      ) {

        walk(
          child,
          name || hint
        );

      }

    }

  }


  roots.forEach(
    root =>
      walk(root)
  );


  return output;
}


/* =========================================================
   IMAGE CHECK
========================================================= */

function looksLikeImage(
  name,
  type
) {

  const mime =
    String(
      type || ''
    )
      .toLowerCase()
      .split(';')[0];


  if (
    mime.startsWith(
      'image/'
    )
  ) {

    return true;
  }


  return /\.(jpe?g|png|webp|gif|bmp|avif|svg)$/i
    .test(
      String(name || '')
    );
}


/* =========================================================
   RESOLVE CUSTOMER PHOTO
========================================================= */

app.get(
  '/api/b2/resolve-customer-photo',
  async (req, res) => {

    try {

      const user =
        await requireUser(
          req
        );


      const orderId =
        String(
          req.query.orderId ||
          ''
        ).trim();


      const index =
        Math.max(
          0,
          Number(
            req.query.index || 0
          ) || 0
        );


      if (!orderId) {

        return res
          .status(400)
          .json({

            ok: false,

            error:
              'Order ID is missing.'

          });

      }


      const order =
        await getOrder(
          orderId
        );


      if (!order) {

        return res
          .status(404)
          .json({

            ok: false,

            error:
              'Order not found.'

          });

      }


      const privileged =
        await isPrivilegedUser(
          user
        );

      if (privileged) order.__cfdAllowGlobalRecovery = true;


      const owner =
        String(
          order.userId ||
          order.customerId ||
          ''
        ) ===
        String(
          user.uid
        );


      if (
        !owner &&
        !privileged
      ) {

        return res
          .status(403)
          .json({

            ok: false,

            error:
              'You are not allowed to access this order.'

          });

      }


      // IMPORTANT: Firestore may store only the bare filename (for example
      // cropped_circle_image.png), while the real B2 object may be stored as
      // customer_files/<uid>/<orderId>_<timestamp>_<filename>. Never reject
      // the request just because Firestore does not contain a full B2 key.
      // The hardened resolver scans the customer's B2 namespace and verifies
      // the real object with HeadObject.
      const requestedPath = String(req.query.path || '').trim();
      const requestedName = String(req.query.name || '').trim();
      const chosen = await resolveB2CustomerFile(order, requestedPath, requestedName);

      if (!chosen) {
        return res.status(404).json({
          ok: false,
          error: 'Customer image was not found in Backblaze B2.',
          orderId,
          storageProvider: 'backblaze-b2'
        });
      }

      let head;
      try {
        head = await s3.send(new HeadObjectCommand({
          Bucket: B2_BUCKET_NAME,
          Key: chosen.key
        }));
      } catch (err) {
        console.error('[CFD PHOTO] resolved B2 HEAD failed:', chosen.key, err.message);
        return res.status(404).json({
          ok: false,
          error: 'Customer image was not found in Backblaze B2.',
          orderId,
          storageProvider: 'backblaze-b2'
        });
      }

      const contentType = String(head.ContentType || chosen.type || '').toLowerCase().split(';')[0];
      if (!contentType.startsWith('image/')) {
        return res.status(415).json({
          ok: false,
          error: 'Stored customer object is not an image.',
          type: contentType || 'unknown'
        });
      }

      return res.json({

        ok: true,

        key:
          chosen.key,

        name:
          chosen.name ||
          chosen.key
            .split('/')
            .pop() ||
          'customer-photo',

        type:
          contentType,

        size:
          head.ContentLength ??
          null

      });


    } catch (err) {

      console.error(
        'resolve-customer-photo:',
        err
      );


      const status =
        Number(
          err?.status
        ) || 500;


      return res
        .status(status)
        .json({

          ok: false,

          error:
            status === 500
              ? 'Photo resolver server error.'
              : String(
                  err.message ||
                  'Photo resolver failed.'
                )

        });

    }

  }
);



/* =========================================================
   ABSOLUTE B2 CUSTOMER PHOTO RECOVERY
   This route is intentionally independent of the normal resolver.
   It scans B2 directly and streams the first verified image belonging to
   the order/customer namespace. It exists to recover legacy/mismatched
   Firestore photo metadata without falling back to Firebase Storage.
========================================================= */
async function absoluteRecoverB2CustomerPhoto(order, requestedName = '') {
  const uid = String(order?.userId || order?.customerId || order?.uid || '').trim().toLowerCase();
  const oid = String(order?.id || '').trim().toLowerCase();
  const wanted = isGenericCustomerPhotoLabel(requestedName) ? '' : String(requestedName || '').trim().toLowerCase();
  const seen = new Set();
  const candidates = [];

  const push = (obj, sourceScore = 0) => {
    const key = cleanKey(obj?.Key);
    if (!key || seen.has(key)) return;
    const low = key.toLowerCase();
    const leaf = low.split('/').pop() || '';
    if (/^(payment_screenshots|payments|transactions)\//i.test(key) || /payment|transaction|receipt|utr/.test(leaf)) return;
    const parts = low.split('/');
    const uidMatch = !!uid && parts.includes(uid);
    const orderMatch = !!oid && (leaf.startsWith(oid + '_') || parts.includes(oid) || low.includes('/' + oid + '_'));
    const nameMatch = !!wanted && (leaf === wanted || leaf.endsWith('_' + wanted));
    const customerRoot = /^customer_files\//i.test(key);
    if (!customerRoot) return;
    // HARD ORDER LOCK: recovery may never return a photo unless the object key
    // itself contains the current order ID. This eliminates previous-order reuse.
    const exactOrder = cfdPhotoKeyIsExactOrder(key, oid);
    const createdRaw = order?.createdAt || order?.created_at || order?.orderCreatedAt || null;
    const createdMs = createdRaw?.toMillis ? createdRaw.toMillis() : (createdRaw?._seconds ? Number(createdRaw._seconds)*1000 : (typeof createdRaw === 'number' ? createdRaw : (Date.parse(createdRaw)||0)));
    const freshForOrder = !!createdMs && !!obj?.LastModified && new Date(obj.LastModified).getTime() >= (createdMs - 120000);
    // Exact order is always preferred. Legacy objects are accepted only when
    // they are under this customer's UID and were uploaded after this order.
    if (!exactOrder && !(uidMatch && freshForOrder && (!wanted || nameMatch))) return;
    // Do not reject octet-stream metadata here; byte-level detection below
    // determines whether the object is really an image.
    seen.add(key);
    candidates.push({
      key, name: leaf, type: String(obj?.ContentType || ''),
      lastModified: obj?.LastModified || null,
      score: sourceScore + (orderMatch ? 100000 : 0) + (nameMatch ? 50000 : 0) + (uidMatch ? 25000 : 0) + (customerRoot ? 1000 : 0)
    });
  };

  async function scan(prefix) {
    let token;
    do {
      const r = await s3.send(new ListObjectsV2Command({Bucket:B2_BUCKET_NAME, Prefix:prefix, ContinuationToken:token, MaxKeys:1000}));
      for (const obj of (r.Contents || [])) push(obj, prefix ? 1000 : 0);
      token = r.IsTruncated ? r.NextContinuationToken : undefined;
    } while (token);
  }

  // First scan the canonical customer area, then the complete bucket as a
  // legacy recovery path. This is deliberately independent from Firestore.
  await scan('customer_files/');
  if (!candidates.length) await scan('');

  candidates.sort((a,b) => b.score - a.score || (new Date(b.lastModified || 0) - new Date(a.lastModified || 0)));

  for (const c of candidates) {
    // Owner boundary: regular customers can only receive objects containing
    // their UID. Privileged admins may recover legacy objects across customer_files.
    if (!order.__cfdAllowGlobalRecovery && uid && !c.key.toLowerCase().split('/').includes(uid)) continue;
    try {
      const obj = await s3.send(new GetObjectCommand({Bucket:B2_BUCKET_NAME, Key:c.key}));
      const buf = obj.Body?.transformToByteArray ? Buffer.from(await obj.Body.transformToByteArray()) : Buffer.from(await streamToBuffer(obj.Body));
      if (!buf.length) continue;
      const mime = detectImageMime(buf, c.type, c.name);
      if (!mime || !isImageMime(mime)) continue;
      return {key:c.key, name:c.name, type:mime, size:buf.length, buffer:buf};
    } catch (e) {
      console.warn('[CFD PHOTO ABSOLUTE] B2 object failed:', c.key, e.message);
    }
  }
  console.error('[CFD PHOTO ABSOLUTE] NO IMAGE', {orderId:order?.id || '', uid, requestedName, candidates:candidates.slice(0,20).map(x=>x.key)});
  return null;
}

app.get('/api/b2/photo-fix-status', (req, res) => {
  res.json({ok:true, route:'absolute', bucket:B2_BUCKET_NAME, version:'PHOTO_FINAL_2026_09_10_V10_ORDER_BOUND_UPLOAD_DIAGNOSTIC'});
});

/* ---------------------------------------------------------
   CUSTOMER PHOTO DIAGNOSTIC (ADMIN ONLY)
   This route never changes files. It reports exactly what Firestore
   references and what B2 actually contains for one order.
--------------------------------------------------------- */
app.get('/api/b2/customer-photo-debug', async (req, res) => {
  try {
    const user = await requireUser(req);
    const privileged = await isPrivilegedUser(user);
    if (!privileged) return res.status(403).json({ok:false,error:'Admin access required.'});

    const orderId = String(req.query.orderId || '').trim();
    if (!orderId) return res.status(400).json({ok:false,error:'Order ID is missing.'});

    const order = await getOrder(orderId);
    if (!order) return res.status(404).json({ok:false,error:'Order not found.',orderId});

    const uid = String(order.userId || order.customerId || order.uid || '').trim();
    const stored = (collectCustomerPhotoCandidates(order) || []).map(x => ({
      key: cleanKey(x.key || ''),
      name: x.name || '',
      type: x.type || '',
      field: x.field || ''
    })).filter(x => x.key || x.name);

    const prefix = uid ? `customer_files/${uid}/` : 'customer_files/';
    const objects = [];
    let token;
    do {
      const listed = await s3.send(new ListObjectsV2Command({
        Bucket:B2_BUCKET_NAME, Prefix:'customer_files/', ContinuationToken:token, MaxKeys:1000
      }));
      for (const obj of (listed.Contents || [])) {
        const key = cleanKey(obj?.Key);
        if (!key) continue;
        const low = key.toLowerCase();
        const leaf = key.split('/').pop() || '';
        const parts = low.split('/');
        const exactOrder = cfdPhotoKeyIsExactOrder(key, orderId);
        const sameUid = !!uid && parts.includes(uid.toLowerCase());
        const image = isImageMime(String(obj?.ContentType || '')) || looksLikeImage(leaf, obj?.ContentType || '');
        const relevant = exactOrder || (sameUid && image);
        if (relevant) {
          objects.push({
            key, size:obj?.Size ?? null, lastModified:obj?.LastModified || null,
            contentType:obj?.ContentType || '', exactOrder, sameUid, image,
            underExpectedUidPrefix:key.toLowerCase().startsWith(prefix.toLowerCase())
          });
        }
      }
      token = listed.IsTruncated ? listed.NextContinuationToken : undefined;
    } while (token);

    const heads = [];
    for (const x of objects.filter(x => x.exactOrder).slice(0, 20)) {
      try {
        const h = await s3.send(new HeadObjectCommand({Bucket:B2_BUCKET_NAME, Key:x.key}));
        heads.push({key:x.key,ok:true,contentType:h.ContentType || '',size:h.ContentLength ?? null});
      } catch (e) {
        heads.push({key:x.key,ok:false,error:String(e?.message || e)});
      }
    }

    let diagnosis = 'NO_EXACT_ORDER_OBJECT';
    if (heads.some(x => x.ok && (isImageMime(x.contentType) || looksLikeImage(x.key, x.contentType)))) diagnosis = 'EXACT_ORDER_IMAGE_FOUND';
    else if (stored.some(x => x.key)) diagnosis = 'FIRESTORE_HAS_PHOTO_KEY_BUT_B2_MATCH_FAILED';
    else if (objects.some(x => x.sameUid && x.image)) diagnosis = 'ONLY_UID_PHOTOS_FOUND_NO_EXACT_ORDER';

    return res.json({
      ok:true, serverVersion:'PHOTO_FINAL_2026_09_10_V10_ORDER_BOUND_UPLOAD_DIAGNOSTIC',
      bucket:B2_BUCKET_NAME, orderId, uid, customerName:customerDisplayName(order),
      orderCreatedAt:order.createdAt || order.created_at || null,
      storedPhotoCandidates:stored.slice(0, 30),
      expectedUploadPrefix:prefix,
      b2CustomerFileObjects:objects.slice(0, 200),
      headChecks:heads, diagnosis
    });
  } catch (err) {
    console.error('[CFD PHOTO DEBUG] error:', err);
    return res.status(Number(err?.status)||500).json({ok:false,error:String(err?.message || 'Photo diagnostic failed.')});
  }
});

app.get('/api/b2/customer-photo-recovery', async (req, res) => {
  try {
    const user = await requireUser(req);
    const orderId = String(req.query.orderId || '').trim();
    if (!orderId) return res.status(400).json({ok:false,error:'Order ID is missing.'});
    const order = await getOrder(orderId);
    if (!order) return res.status(404).json({ok:false,error:'Order not found.'});
    const privileged = await isPrivilegedUser(user);
    const owner = String(order.userId || order.customerId || order.uid || '') === String(user.uid);
    if (!owner && !privileged) return res.status(403).json({ok:false,error:'You are not allowed to access this order.'});
    order.__cfdAllowGlobalRecovery = privileged;
    const recovered = await absoluteRecoverB2CustomerPhoto(order, String(req.query.name || ''));
    if (!recovered) return res.status(404).json({ok:false,error:'Customer image was not found anywhere in Backblaze B2.',orderId,storageProvider:'backblaze-b2'});
    res.setHeader('Content-Type', recovered.type);
    res.setHeader('Content-Length', String(recovered.size));
    res.setHeader('Content-Disposition', `inline; filename="${previewFilename(recovered.name, recovered.type).replace(/"/g,'')}"`);
    res.setHeader('Cache-Control','private, no-store, max-age=0');
    res.setHeader('X-CFD-Recovered-B2-Key', recovered.key);
    return res.end(recovered.buffer);
  } catch (err) {
    console.error('[CFD PHOTO ABSOLUTE] route error:', err);
    if (!res.headersSent) return res.status(Number(err?.status)||500).json({ok:false,error:String(err?.message || 'B2 recovery failed.')});
    res.destroy(err);
  }
});

/* =========================================================
   FIREBASE STORAGE CUSTOMER PHOTO PREVIEW
   REAL IMAGE RESPONSE ONLY — NEVER HTML / NEVER attachment
========================================================= */

function isImageMime(type) {
  return /^image\//i.test(String(type || '').split(';')[0].trim());
}

function safeStoragePath(value) {
  const p = String(value || '').trim().replace(/^\/+/, '');
  if (!p || p.includes('\0') || p.split('/').some(x => x === '..')) return '';
  if (!/^customer_files\//i.test(p)) return '';
  return p;
}

function customerPhotoRoots(order) {
  const roots = [];
  const uid = String(order?.userId || order?.customerId || order?.uid || '').trim();
  const id = String(order?.id || '').trim();
  if (uid && id) {
    roots.push(`customer_files/${uid}/${id}/`);
    roots.push(`customer_files/${uid}/${id}_`);
  }
  if (uid) roots.push(`customer_files/${uid}/`);
  return roots;
}

function extractFirebaseStoragePath(value) {
  const s = String(value || '').trim();
  if (!/^https?:\/\//i.test(s)) return '';
  try {
    const u = new URL(s);
    const m = u.pathname.match(/\/o\/(.+)$/);
    if (m) return safeStoragePath(decodeURIComponent(m[1]));
  } catch (_) {}
  return '';
}

function collectFirebasePhotoPaths(value, out = [], seen = new Set()) {
  if (value === null || value === undefined) return out;
  if (typeof value === 'string') {
    const p = safeStoragePath(value) || extractFirebaseStoragePath(value);
    if (p && !seen.has(p)) { seen.add(p); out.push(p); }
    return out;
  }
  if (Array.isArray(value)) {
    for (const v of value) collectFirebasePhotoPaths(v, out, seen);
    return out;
  }
  if (typeof value !== 'object') return out;

  for (const key of ['storagePath','path','fullPath']) {
    const p = safeStoragePath(value[key]);
    if (p && !seen.has(p)) { seen.add(p); out.push(p); }
  }
  for (const key of ['url','downloadURL','downloadUrl','src']) {
    const p = extractFirebaseStoragePath(value[key]);
    if (p && !seen.has(p)) { seen.add(p); out.push(p); }
  }
  for (const key of ['customerPhoto','customerPhotoUrl','customerFiles','files','photo','photoUrl','custom']) {
    if (value[key]) collectFirebasePhotoPaths(value[key], out, seen);
  }
  return out;
}

function detectImageMime(buffer, declaredType, filename) {
  const b = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer || []);
  const declared = String(declaredType || '').toLowerCase().split(';')[0].trim();

  // Magic bytes first: never trust a bad text/html metadata value.
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  if (b.length >= 8 && b.subarray(0,8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]))) return 'image/png';
  if (b.length >= 12 && b.toString('ascii',0,4) === 'RIFF' && b.toString('ascii',8,12) === 'WEBP') return 'image/webp';
  if (b.length >= 6 && (b.toString('ascii',0,6) === 'GIF87a' || b.toString('ascii',0,6) === 'GIF89a')) return 'image/gif';
  if (b.length >= 2 && b[0] === 0x42 && b[1] === 0x4d) return 'image/bmp';
  if (b.length >= 12 && (b.toString('ascii',4,8) === 'ftyp') && /^(avif|avis)$/i.test(b.toString('ascii',8,12))) return 'image/avif';

  // SVG is text, so inspect only the beginning after BOM/whitespace.
  const head = b.subarray(0,4096).toString('utf8').replace(/^\uFEFF/, '').trimStart().toLowerCase();
  if (head.startsWith('<svg') || (head.startsWith('<?xml') && head.includes('<svg'))) return 'image/svg+xml';

  // Declared image MIME is acceptable only when it is already an image type.
  if (isImageMime(declared)) return declared;

  // Extension is only a last resort, never the primary detection method.
  const ext = String(filename || '').toLowerCase().match(/\.([a-z0-9]+)$/)?.[1] || '';
  const byExt = {
    jpg:'image/jpeg', jpeg:'image/jpeg', png:'image/png', webp:'image/webp',
    gif:'image/gif', bmp:'image/bmp', avif:'image/avif', svg:'image/svg+xml'
  };
  return byExt[ext] || '';
}

function imageExtension(mime) {
  return ({
    'image/jpeg':'.jpg', 'image/jpg':'.jpg', 'image/png':'.png',
    'image/webp':'.webp', 'image/gif':'.gif', 'image/bmp':'.bmp',
    'image/avif':'.avif', 'image/svg+xml':'.svg'
  })[String(mime || '').toLowerCase()] || '.jpg';
}

function previewFilename(name, mime) {
  let n = safeFilename(name || 'customer-photo');
  n = n.replace(/\.(html?|xhtml)$/i, '');
  n = n.replace(/\.(jpe?g|png|webp|gif|bmp|avif|svg)$/i, '');
  return n + imageExtension(mime);
}

function isGenericCustomerPhotoLabel(value) {
  const v = String(value || '').trim().toLowerCase().replace(/[_-]+/g, ' ');
  return !v || /^(customer\s+customi[sz]ation|customer\s+photo|customer\s+file|customer\s+image|customi[sz]ation|photo|image|file|upload|attachment|customer\s+attachment)$/i.test(v);
}

function cfdPhotoKeyIsExactOrder(key, orderId) {
  const k = cleanKey(key).toLowerCase();
  const oid = String(orderId || '').trim().toLowerCase();
  if (!k || !oid) return false;
  const parts = k.split('/');
  const leaf = parts[parts.length - 1] || '';
  // New customer uploads are always order-bound: <orderId>_..._<filename>
  // or a dedicated <orderId>/ directory. Never select another order's photo.
  return leaf.startsWith(oid + '_') || parts.includes(oid) || k.includes('/' + oid + '_');
}

async function resolveB2CustomerFile(order, requestedPath, requestedName) {
  const candidates=[]; const seen=new Set();
  const uid=String(order?.userId||order?.customerId||order?.uid||'').trim().toLowerCase();
  const oid=String(order?.id||'').trim().toLowerCase();
  const requested=cleanKey(requestedPath);
  const wanted=isGenericCustomerPhotoLabel(requestedName)?'':String(requestedName||'').trim().toLowerCase();

  const orderCreatedRaw = order?.createdAt || order?.created_at || order?.orderCreatedAt || null;
  const orderCreatedMs = orderCreatedRaw?.toMillis ? orderCreatedRaw.toMillis() :
    (orderCreatedRaw?._seconds ? Number(orderCreatedRaw._seconds)*1000 :
    (typeof orderCreatedRaw === 'number' ? orderCreatedRaw : (Date.parse(orderCreatedRaw)||0)));

  // Only exact current-order keys are accepted normally. A legacy object may
  // be accepted only when it is inside THIS customer's UID namespace and was
  // actually uploaded at/after this order was created. This prevents an older
  // order photo from being reused merely because the filename is identical.
  const add=(key,name,type,lastModified,score=0,legacyCurrent=false,authoritative=false)=>{
    key=cleanKey(key); if(!key||seen.has(key))return;
    const leaf=key.split('/').pop()||'';
    const low=leaf.toLowerCase();
    if(/payment|transaction|receipt|utr/.test(low) || /^(payment_screenshots|payments|transactions)\//i.test(key)) return;
    const lowKey=key.toLowerCase();
    const parts=lowKey.split('/');
    const sameUid=!!uid && parts.includes(uid);
    const exactOrder=cfdPhotoKeyIsExactOrder(key, oid);
    const lm=lastModified ? new Date(lastModified).getTime() : 0;
    const freshForOrder=!!orderCreatedMs && !!lm && lm >= (orderCreatedMs - 120000);

    if(!exactOrder){
      // Non-order-bound legacy objects remain restricted to customer_files.
      if(!/^customer_files\//i.test(key)) return;
      // A Firestore key/path that belongs to THIS order is authoritative even
      // when the legacy B2 key does not contain the orderId/UID in its path.
      // Only listing-based legacy candidates remain subject to the UID +
      // upload-time guard below.
      if(!legacyCurrent) return;
      if(authoritative) {
        // Explicit key persisted on the current order: accept it and verify
        // the object with HeadObject below.
      } else if(!sameUid || !freshForOrder) return;
    }
    seen.add(key);
    candidates.push({
      key,name:name||leaf,type:type||'',lastModified:lastModified||null,
      score:score + (exactOrder?1000000:0) + (sameUid?100000:0) + (freshForOrder?75000:0)
    });
  };

  // 1) Firestore's current-order B2 key, but only if it is really bound to
  // this order. Never blindly trust a stale key from an older order.
  if(requested) add(requested, requested.split('/').pop(), '', null, 1000000, true, true);
  for(const item of (collectCustomerPhotoCandidates(order)||[])){
    const k=cleanKey(item?.key);
    if(k) {
      // Firestore fields stored on the current order are the strongest link
      // we have. Do not require the current customer's UID to be encoded in
      // the legacy B2 key; customers can and do have different UIDs.
      add(k,item.name||k.split('/').pop(),item.type||'',null,900000,true,true);
    }
  }

  async function listPrefix(prefix){
    const out=[]; let token;
    do{
      const listed=await s3.send(new ListObjectsV2Command({Bucket:B2_BUCKET_NAME,Prefix:prefix,ContinuationToken:token,MaxKeys:1000}));
      for(const obj of (listed.Contents||[])){
        const k=cleanKey(obj?.Key); if(!k)continue;
        const leaf=k.split('/').pop()||'', low=leaf.toLowerCase(), kl=k.toLowerCase(), parts=kl.split('/');
        if(/payment|transaction|receipt|utr/.test(low) || /^(payment_screenshots|payments|transactions)\//i.test(k)) continue;
        const sameUid=!!uid && parts.includes(uid);
        const exactOrder=!!oid && cfdPhotoKeyIsExactOrder(k,oid);
        const exactName=!!wanted && (low===wanted || low.endsWith('_'+wanted));
        const lm=obj?.LastModified || null;
        const freshForOrder=!!orderCreatedMs && !!lm && new Date(lm).getTime() >= (orderCreatedMs - 120000);
        const underCustomerFiles=/^customer_files\//i.test(k);
        const score=(exactOrder?300000:0)+(exactName?200000:0)+(sameUid?100000:0)+(freshForOrder?75000:0)+(underCustomerFiles?10000:0);
        out.push({key:k,name:leaf,type:obj?.ContentType||'',lastModified:lm,score,sameUid,exactOrder,exactName,freshForOrder,underCustomerFiles});
      }
      token=listed.IsTruncated?listed.NextContinuationToken:undefined;
    }while(token);
    return out;
  }

  let listed=await listPrefix('customer_files/');
  listed.sort((a,b)=>b.score-a.score || (new Date(b.lastModified||0)-new Date(a.lastModified||0)));
  for(const x of listed){
    add(x.key,x.name,x.type,x.lastModified,x.score,!!x.freshForOrder && !!x.sameUid && (!wanted || x.exactName));
  }

  // Search the whole bucket as a final path-layout fallback. Exact order-ID
  // matches are safe even when the object is outside customer_files; legacy
  // non-exact objects still require the customer's UID + fresh-upload guard.
  if(order){
    const existing=new Set(candidates.map(x=>x.key));
    let global=[];
    try{global=await listPrefix('');}catch(e){console.warn('[CFD PHOTO] global B2 listing failed:',e.message);}
    global.sort((a,b)=>b.score-a.score || (new Date(b.lastModified||0)-new Date(a.lastModified||0)));
    for(const x of global){
      if(!existing.has(x.key)) add(x.key,x.name,x.type,x.lastModified,x.score,!!x.freshForOrder && !!x.sameUid && (!wanted || x.exactName));
    }
  }

  candidates.sort((a,b)=>b.score-a.score || (new Date(b.lastModified||0)-new Date(a.lastModified||0)));

  for(const item of candidates){
    try{
      const head=await s3.send(new HeadObjectCommand({Bucket:B2_BUCKET_NAME,Key:item.key}));
      const type=String(head.ContentType||item.type||'').toLowerCase().split(';')[0];
      const imageByMime=isImageMime(type);
      const imageByName=looksLikeImage(item.name,type);
      if(imageByMime || imageByName){
        return {...item,type:type||item.type||'',size:head.ContentLength??null,head};
      }
    }catch(e){ console.warn('[CFD PHOTO] HEAD failed:',item.key,e.message); }
  }

  console.error('[CFD PHOTO RESOLVE] NO IMAGE FOUND',{orderId:order?.id||'',uid:order?.userId||order?.customerId||order?.uid||'',requestedPath:requestedPath||'',requestedName:requestedName||'',orderCreatedMs,candidateCount:candidates.length,sample:candidates.slice(0,20).map(x=>({key:x.key,lastModified:x.lastModified,score:x.score}))});
  return null;
}

// Short-lived, one-use preview tickets allow window.open() without putting a
// Firebase ID token in the image URL. Ticket is bound to the authenticated
// admin, order and selected Backblaze B2 object.
const customerPhotoPreviewTickets = new Map();
const PREVIEW_TICKET_TTL = 60 * 1000;

function issuePreviewTicket(payload) {
  const crypto = require('crypto');
  const token = crypto.randomBytes(32).toString('hex');
  customerPhotoPreviewTickets.set(token, { ...payload, expiresAt:Date.now()+PREVIEW_TICKET_TTL });
  return token;
}

function takePreviewTicket(token) {
  const t = customerPhotoPreviewTickets.get(String(token || ''));
  if (!t) return null;
  customerPhotoPreviewTickets.delete(String(token));
  if (t.expiresAt < Date.now()) return null;
  return t;
}

setInterval(() => {
  const now = Date.now();
  for (const [token, item] of customerPhotoPreviewTickets) {
    if (item.expiresAt < now) customerPhotoPreviewTickets.delete(token);
  }
}, 30 * 1000).unref();

app.get('/api/firebase/customer-photo/preview-token', async (req, res) => {
  try {
    const user = await requireUser(req);
    if (!await isPrivilegedUser(user)) {
      return res.status(403).json({ok:false,error:'Admin or Super Admin access required.'});
    }
    const orderId = String(req.query.orderId || '').trim();
    const requestedPath = cleanKey(req.query.path);
    const requestedName = String(req.query.name || '').trim();
    if (!orderId) return res.status(400).json({ok:false,error:'Order ID is missing.'});

    const order = await getOrder(orderId);
    if (!order) return res.status(404).json({ok:false,error:'Order not found.'});
    if (await isPrivilegedUser(user)) order.__cfdAllowGlobalRecovery = true;

    const resolved = await resolveB2CustomerFile(order, requestedPath, requestedName);
    if (!resolved) return res.status(404).json({ok:false,error:'Customer photo was not found in Backblaze B2.'});

    const ticket = issuePreviewTicket({
      uid:user.uid,
      orderId,
      path:resolved.key,
      name:String(resolved.name || requestedName || resolved.key.split('/').pop() || 'customer-photo')
    });
    const base = `${req.protocol}://${req.get('host')}`;
    return res.json({ok:true,url:`${base}/api/firebase/customer-photo/preview?ticket=${encodeURIComponent(ticket)}`});
  } catch (err) {
    console.error('[CFD PHOTO] preview-token error:', err);
    const status = Number(err?.status) || 500;
    return res.status(status).json({ok:false,error:String(err?.message || 'Photo preview could not be prepared.')});
  }
});

app.get('/api/firebase/customer-photo/preview', async (req, res) => {
  let ticket = null;
  try {
    ticket = takePreviewTicket(req.query.ticket);
    if (!ticket) return res.status(401).json({ok:false,error:'Photo preview ticket expired or is invalid.'});
    const order = await getOrder(ticket.orderId);
    if (!order) return res.status(404).json({ok:false,error:'Order not found.'});

    const resolved = await resolveB2CustomerFile(order, ticket.path, ticket.name);
    if (!resolved) return res.status(404).json({ok:false,error:'Photo unavailable'});

    const object = await s3.send(new GetObjectCommand({Bucket:B2_BUCKET_NAME, Key:resolved.key}));
    const buffer = object.Body?.transformToByteArray ? Buffer.from(await object.Body.transformToByteArray()) : Buffer.from(await streamToBuffer(object.Body));
    if (!buffer.length) return res.status(404).json({ok:false,error:'Photo unavailable'});

    const mime = detectImageMime(buffer, resolved.type, ticket.name || resolved.key);
    if (!mime || !isImageMime(mime)) return res.status(415).json({ok:false,error:'Photo unavailable'});
    const filename = previewFilename(ticket.name || resolved.key.split('/').pop(), mime);
    res.status(200);
    res.setHeader('Content-Type', mime);
    res.setHeader('Content-Length', String(buffer.length));
    res.setHeader('Content-Disposition', `inline; filename="${filename.replace(/"/g,'')}"`);
    res.setHeader('Cache-Control', 'private, no-store, max-age=0');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-CFD-Image-Preview', '1');
    return res.end(buffer);
  } catch (err) {
    console.error('[CFD PHOTO] B2 preview error:', err);
    if (!res.headersSent) return res.status(Number(err?.status)||500).json({ok:false,error:'Photo unavailable'});
    res.destroy(err);
  }
});

// Backward-compatible path. Despite the historical URL name, this endpoint
// ALWAYS reads the image from Backblaze B2. Firebase Storage is never used.
app.get('/api/firebase/customer-photo', async (req, res) => {
  try {
    const user = await requireUser(req);
    const orderId = String(req.query.orderId || '').trim();
    if (!orderId) return res.status(400).json({ok:false,error:'Order ID is missing.'});
    const order = await getOrder(orderId);
    if (!order) return res.status(404).json({ok:false,error:'Order not found.'});

    const resolved = await resolveB2CustomerFile(order, cleanKey(req.query.path), String(req.query.name || '').trim());
    if (!resolved) return res.status(404).json({ok:false,error:'Photo unavailable'});
    const object = await s3.send(new GetObjectCommand({Bucket:B2_BUCKET_NAME, Key:resolved.key}));
    const buffer = object.Body?.transformToByteArray ? Buffer.from(await object.Body.transformToByteArray()) : Buffer.from(await streamToBuffer(object.Body));
    if (!buffer.length) return res.status(404).json({ok:false,error:'Photo unavailable'});
    const mime = detectImageMime(buffer, resolved.type, req.query.name || resolved.key);
    if (!mime || !isImageMime(mime)) return res.status(415).json({ok:false,error:'Photo unavailable'});
    const filename = previewFilename(req.query.name || resolved.name || resolved.key.split('/').pop(), mime);
    res.status(200);
    res.setHeader('Content-Type', mime);
    res.setHeader('Content-Length', String(buffer.length));
    res.setHeader('Content-Disposition', `inline; filename="${filename.replace(/"/g,'')}"`);
    res.setHeader('Cache-Control', 'private, no-store, max-age=0');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-CFD-Image-Preview', '1');
    return res.end(buffer);
  } catch (err) {
    console.error('[CFD PHOTO] B2 customer-photo error:', err);
    if (!res.headersSent) return res.status(Number(err?.status)||500).json({ok:false,error:'Photo unavailable'});
    res.destroy(err);
  }
});

/* =========================================================
   B2 CUSTOMER PHOTO UPLOAD
========================================================= */
/* =========================================================
   CUSTOMER B2 FOLDER DISPLAY NAME
   Structure for new customer photos:
   customer_files/<Customer Name>/<UID>/<orderId>_..._<filename>
   This keeps the customer's readable name visible in B2 Browse Files,
   while the UID remains the ownership boundary.
========================================================= */
function customerDisplayName(order) {
  const candidates = [
    order?.customerName,
    order?.name,
    order?.customer?.name,
    order?.customerDetails?.name,
    order?.custom?.Name,
    order?.custom?.name,
    order?.custom?.CustomerName,
    order?.billing?.name,
    order?.details?.name
  ];
  for (const value of candidates) {
    const v = String(value || '').trim();
    if (v && !isGenericCustomerPhotoLabel(v)) return v;
  }
  return 'Customer';
}

function safeFolderName(value) {
  return safeFilename(value).replace(/[\\/]+/g, '_').replace(/\s+/g, ' ').trim().slice(0, 120) || 'Customer';
}

function customerB2Prefix(order) {
  const uid = String(order?.userId || order?.customerId || order?.uid || '').trim();
  if (!uid) return '';
  return `customer_files/${safeFolderName(customerDisplayName(order))}/${uid}/`;
}

function customerB2KeyBelongsToOrder(key, order) {
  const k = cleanKey(key);
  const uid = String(order?.userId || order?.customerId || order?.uid || '').trim().toLowerCase();
  const oid = String(order?.id || '').trim().toLowerCase();
  if (!k || !uid || !oid || !/^customer_files\//i.test(k)) return false;
  const parts = k.split('/');
  const lowerParts = parts.map(x => String(x).toLowerCase());
  const uidIndex = lowerParts.indexOf(uid);
  if (uidIndex < 1) return false;
  const leaf = lowerParts[lowerParts.length - 1] || '';
  // A customer's B2 namespace is the ownership boundary. Older uploads may
  // exist as customer_files/<uid>/<filename> without the current order ID.
  // They are still valid for that same authenticated customer.
  return leaf.startsWith(`${oid}_`) ||
         lowerParts.some((p, i) => i > uidIndex && p === oid);
}

app.post('/api/b2/upload', async (req, res) => {
  try {
    const user = await requireUser(req);
    const orderId = String(req.body?.orderId || '').trim();
    const kind = String(req.body?.kind || 'customer-file').trim().toLowerCase();
    const name = safeFilename(req.body?.name || 'customer-photo');
    const type = String(req.body?.type || '').toLowerCase().split(';')[0].trim();
    const data = String(req.body?.data || '').trim();
    if (!orderId || !data) return res.status(400).json({ok:false,error:'Order ID and image data are required.'});
    if (kind !== 'customer-file' && kind !== 'payment') return res.status(400).json({ok:false,error:'Invalid upload type.'});
    if (!isImageMime(type)) return res.status(415).json({ok:false,error:'Only image files are allowed.'});

    const order = await getOrder(orderId);
    if (!order) return res.status(404).json({ok:false,error:'Order not found.'});
    const privileged = await isPrivilegedUser(user);
    if (!privileged && String(order.userId || order.customerId || '') !== String(user.uid)) return res.status(403).json({ok:false,error:'You are not allowed to upload to this order.'});

    const raw = data.replace(/^data:[^;]+;base64,/i, '');
    let buffer;
    try { buffer = Buffer.from(raw, 'base64'); } catch { return res.status(400).json({ok:false,error:'Invalid image data.'}); }
    const max = kind === 'payment' ? 3 * 1024 * 1024 : 10 * 1024 * 1024;
    if (!buffer.length || buffer.length > max) return res.status(413).json({ok:false,error:`Image is too large. Maximum is ${Math.floor(max/1024/1024)}MB.`});

    const crypto = require('crypto');
    const uid = String(order.userId || order.customerId || order.uid || user.uid).trim();
    const folder = kind === 'payment' ? 'payment_screenshots' : 'customer_files';
    const canonicalOrderId = String(order.id || orderId).trim();
    // V10: customer photos are stored in a deterministic UID namespace and
    // the filename starts with the canonical order ID. This makes the B2
    // object independently recoverable even if Firestore photo metadata is
    // missing or stale. Existing objects are not moved or deleted.
    const key = kind === 'customer-file'
      ? `${folder}/${uid}/${canonicalOrderId}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}_${name}`
      : `${folder}/${uid}/${canonicalOrderId}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}_${name}`;
    console.log('[CFD B2 UPLOAD V10] starting', {orderId:canonicalOrderId, uid, kind, key, name, type, size:buffer.length});
    await s3.send(new PutObjectCommand({Bucket:B2_BUCKET_NAME, Key:key, Body:buffer, ContentType:type, ContentLength:buffer.length}));
    console.log('[CFD B2 UPLOAD V10] B2 PUT OK', {orderId:canonicalOrderId, key, size:buffer.length});

    // Persist the REAL B2 key on the same order. This makes the photo permanently
    // linked to exactly one customer UID + one order ID; UI labels are irrelevant.
    if (kind === 'customer-file') {
      const photo = {name, type, size:buffer.length, b2Key:key, key, path:key, storagePath:key, storageProvider:'backblaze-b2'};
      await db.collection('orders').doc(orderId).set({
        customerPhotoKey:key,
        customerPhotoPath:key,
        customerPhoto:photo,
        customerPhotoUrl:'',
        customerFiles:admin.firestore.FieldValue.arrayUnion(photo),
        files:admin.firestore.FieldValue.arrayUnion(photo),
        updatedAt:admin.firestore.FieldValue.serverTimestamp()
      }, {merge:true});
    }

    console.log('[CFD B2 UPLOAD V10] completed', {orderId:canonicalOrderId, key, firestoreSaved:kind === 'customer-file'});
    return res.status(201).json({ok:true,key,path:key,name,type,size:buffer.length,storageProvider:'backblaze-b2',orderId:canonicalOrderId});
  } catch (err) {
    console.error('[CFD B2] upload error:', err);
    return res.status(Number(err?.status)||500).json({ok:false,error:String(err?.message||'Backblaze B2 upload failed.')});
  }
});

/* =========================================================
   REAL B2 CUSTOMER PHOTO DOWNLOAD
========================================================= */

app.get(
  '/api/b2/download',
  async (req, res) => {
    try {
      const user = await requireUser(req);
      const key = cleanKey(req.query.key);
      const requestedOrderId = String(req.query.orderId || '').trim();
      const requestedName = String(req.query.name || '').trim();

      if (!key && !requestedOrderId) return res.status(400).json({error:'File key or order ID is missing.'});

      let order = requestedOrderId ? await getOrder(requestedOrderId) : null;
      if (requestedOrderId && !order) return res.status(404).json({error:'Order not found.'});
      const privileged = await isPrivilegedUser(user);

      if (order && !privileged && String(order.userId || order.customerId || '') !== String(user.uid)) {
        return res.status(403).json({error:'You are not allowed to download this file.'});
      }
      if (!order && !privileged) return res.status(403).json({error:'Order access could not be verified.'});

      let resolvedKey = key;
      let resolvedName = requestedName;
      let resolvedType = '';

      // Bare filename/path values from legacy Firestore are resolved against B2.
      if (!order || !cfdPhotoKeyIsExactOrder(resolvedKey, order.id)) {
        if (!order) return res.status(400).json({error:'Invalid customer file key.'});
        const resolved = await resolveB2CustomerFile(order, resolvedKey, requestedName || resolvedKey);
        if (!resolved) return res.status(404).json({error:'Customer file was not found in Backblaze B2.'});
        resolvedKey = resolved.key;
        resolvedName = resolved.name;
        resolvedType = resolved.type;
      }

      if (!resolvedKey || !order || !cfdPhotoKeyIsExactOrder(resolvedKey, order.id)) {
        return res.status(400).json({error:'Invalid customer file key.'});
      }

      // Always bind a customer photo to the CURRENT order, including for admins.
      // Never stream a stale key merely because it came from an old card/cache.
      if (order) {
        const oid = String(order.id || '').trim().toLowerCase();
        const lowKey = String(resolvedKey || '').toLowerCase();
        const exact = cfdPhotoKeyIsExactOrder(resolvedKey, oid);
        if (!exact) {
          const resolved = await resolveB2CustomerFile(order, resolvedKey, requestedName || (resolvedKey.split('/').pop() || ''));
          if (!resolved) return res.status(403).json({error:'Customer file does not belong to this order.'});
          resolvedKey = resolved.key;
          resolvedName = resolved.name;
          resolvedType = resolved.type;
        }
      }

      /*
         FIRST:
         HEAD B2 object.
      */

      let head;


      try {

        head =
          await s3.send(
            new HeadObjectCommand({

              Bucket:
                B2_BUCKET_NAME,

              Key:
                resolvedKey

            })
          );

      } catch (err) {

        console.error(
          'B2 HEAD failed:',
          err.message
        );


        return res
          .status(404)
          .json({

            error:
              'Customer file was not found in Backblaze B2.'

          });

      }


      /*
         NEVER return HTML.
      */

      let contentType =
        String(
          head.ContentType ||
          ''
        )
          .toLowerCase()
          .split(';')[0];


      const extension =
        (
          resolvedKey
            .split('.')
            .pop() ||
          ''
        ).toLowerCase();


      const mimeByExtension = {

        jpg:
          'image/jpeg',

        jpeg:
          'image/jpeg',

        png:
          'image/png',

        webp:
          'image/webp',

        gif:
          'image/gif',

        bmp:
          'image/bmp',

        avif:
          'image/avif',

        svg:
          'image/svg+xml'

      };


      /*
         If B2 metadata is bad,
         recover MIME from real file extension.
      */

      if (
        !contentType ||
        contentType ===
          'application/octet-stream' ||
        contentType ===
          'text/html' ||
        contentType ===
          'text/xhtml'
      ) {

        contentType =
          mimeByExtension[
            extension
          ] ||
          '';

      }


      /*
         FINAL HARD BLOCK:
         HTML/XHTML can NEVER be sent.
      */

      if (
        !contentType ||
        !contentType.startsWith(
          'image/'
        )
      ) {

        return res
          .status(415)
          .json({

            error:
              'Blocked: Backblaze B2 object is not an image.',

            type:
              contentType ||
              'unknown',

            key:
              resolvedKey

          });

      }


      /*
         GET REAL B2 OBJECT
      */

      const object =
        await s3.send(
          new GetObjectCommand({

            Bucket:
              B2_BUCKET_NAME,

            Key:
              resolvedKey

          })
        );


      /*
         Filename
      */

      let filename =
        safeFilename(
          req.query.name ||
          resolvedKey.split('/').pop() ||
          'customer-photo'
        );


      /*
         REMOVE HTML EXTENSIONS
      */

      filename =
        filename.replace(
          /\.(html?|xhtml)$/i,
          ''
        );


      /*
         If filename has no image extension,
         add correct extension.
      */

      if (
        !/\.(jpe?g|png|webp|gif|bmp|avif|svg)$/i
          .test(filename)
      ) {

        const extensionMap = {

          'image/jpeg':
            '.jpg',

          'image/png':
            '.png',

          'image/webp':
            '.webp',

          'image/gif':
            '.gif',

          'image/bmp':
            '.bmp',

          'image/avif':
            '.avif',

          'image/svg+xml':
            '.svg'

        };


        filename +=
          extensionMap[
            contentType
          ] ||
          '.jpg';

      }


      /*
         RESPONSE HEADERS
      */

      res.status(200);


      res.setHeader(
        'Content-Type',
        contentType
      );


      if (
        head.ContentLength !=
        null
      ) {

        res.setHeader(
          'Content-Length',
          String(
            head.ContentLength
          )
        );

      }


      res.setHeader(
        'Content-Disposition',
        `inline; filename="${filename.replace(/"/g, '')}"`
      );

      // Mobile/Desktop browser must receive the REAL image inline.
      // This lets Chrome/Safari use their native Save/Download Image action.
      res.setHeader(
        'Accept-Ranges',
        'bytes'
      );

      res.setHeader(
        'X-CFD-Real-Image',
        '1'
      );


      res.setHeader(
        'Cache-Control',
        'private, no-store, max-age=0'
      );


      res.setHeader(
        'X-Content-Type-Options',
        'nosniff'
      );


      /*
         STREAM B2 → BROWSER
         NO index.html
         NO redirect
         NO webpage
      */

      if (
        object.Body &&
        typeof object.Body.pipe ===
          'function'
      ) {

        object.Body.pipe(
          res
        );

      } else {

        const bytes =
          await object.Body
            .transformToByteArray();


        res.end(
          Buffer.from(
            bytes
          )
        );

      }


    } catch (err) {

      console.error(
        'CUSTOMER PHOTO DOWNLOAD ERROR:',
        err
      );


      const status =
        Number(
          err?.status
        ) || 500;


      if (
        !res.headersSent
      ) {

        return res
          .status(status)
          .json({

            error:
              status === 500
                ? 'Server download error.'
                : String(
                    err.message ||
                    'Download failed.'
                  )

          });

      }


      res.destroy(
        err
      );

    }

  }
);


/* =========================================================
   PAYMENT SCREENSHOT DOWNLOAD
========================================================= */

async function resolveB2PaymentKey(order) {
  const existing = extractPaymentKey(order);
  if (existing) {
    try {
      await s3.send(new HeadObjectCommand({Bucket:B2_BUCKET_NAME, Key:existing}));
      return existing;
    } catch (_) {}
  }
  const uid = String(order?.userId || order?.customerId || order?.uid || '').trim();
  const orderId = String(order?.id || '').trim();
  if (!uid || !orderId) return '';
  const prefix = `payment_screenshots/${uid}/`;
  const matches = [];
  let continuationToken;
  do {
    const listed = await s3.send(new ListObjectsV2Command({
      Bucket:B2_BUCKET_NAME, Prefix:prefix, ContinuationToken:continuationToken, MaxKeys:1000
    }));
    for (const obj of (listed.Contents || [])) {
      const key = cleanKey(obj?.Key);
      const base = key.split('/').pop() || '';
      if (!key || !base) continue;
      if (base.toLowerCase().startsWith(orderId.toLowerCase() + '_') || base.toLowerCase().includes(orderId.toLowerCase())) {
        matches.push({key, time:Number(obj?.LastModified ? new Date(obj.LastModified).getTime() : 0)});
      }
    }
    continuationToken = listed.IsTruncated ? listed.NextContinuationToken : undefined;
  } while (continuationToken);
  matches.sort((a,b)=>b.time-a.time);
  for (const m of matches) {
    try { await s3.send(new HeadObjectCommand({Bucket:B2_BUCKET_NAME, Key:m.key})); return m.key; } catch (_) {}
  }
  return '';
}

function extractPaymentKey(order) {

  const candidates = [

    order?.paymentScreenshotPath,

    order?.paymentScreenshotKey,

    order?.paymentScreenshot?.key,

    order?.paymentScreenshot?.path,

    order?.paymentScreenshot?.storagePath

  ];


  for (
    const candidate of candidates
  ) {

    const key =
      cleanKey(
        candidate
      );


    if (key) {
      return key;
    }

  }


  return '';
}


app.get(
  '/api/b2/payment-screenshot-download',
  async (req, res) => {

    try {

      const user =
        await requireUser(
          req
        );


      const orderId =
        String(
          req.query.orderId ||
          ''
        ).trim();


      if (!orderId) {

        return res
          .status(400)
          .json({

            error:
              'Order ID is missing.'

          });

      }


      const order =
        await getOrder(
          orderId
        );


      if (!order) {

        return res
          .status(404)
          .json({

            error:
              'Order not found.'

          });

      }


      const privileged =
        await isPrivilegedUser(
          user
        );


      const owner =
        String(
          order.userId || ''
        ) ===
        String(
          user.uid
        );


      if (
        !owner &&
        !privileged
      ) {

        return res
          .status(403)
          .json({

            error:
              'You are not allowed to download this file.'

          });

      }


      const key =
        await resolveB2PaymentKey(
          order
        );


      if (!key) {

        return res
          .status(404)
          .json({

            error:
              'Payment screenshot key not found.'

          });

      }


      const head =
        await s3.send(
          new HeadObjectCommand({

            Bucket:
              B2_BUCKET_NAME,

            Key:
              key

          })
        );


      const object =
        await s3.send(
          new GetObjectCommand({

            Bucket:
              B2_BUCKET_NAME,

            Key:
              key

          })
        );


      let filename =
        safeFilename(
          order.paymentScreenshotName ||
          order.paymentScreenshot?.name ||
          key.split('/').pop() ||
          'payment-screenshot'
        );


      filename =
        filename.replace(
          /\.(html?|xhtml)$/i,
          ''
        );


      res.status(200);


      res.setHeader(
        'Content-Type',
        head.ContentType ||
          'application/octet-stream'
      );


      if (
        head.ContentLength !=
        null
      ) {

        res.setHeader(
          'Content-Length',
          String(
            head.ContentLength
          )
        );

      }


      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${filename.replace(/"/g, '')}"`
      );


      res.setHeader(
        'Cache-Control',
        'private, no-store, max-age=0'
      );


      res.setHeader(
        'X-Content-Type-Options',
        'nosniff'
      );


      if (
        object.Body &&
        typeof object.Body.pipe ===
          'function'
      ) {

        object.Body.pipe(
          res
        );

      } else {

        const bytes =
          await object.Body
            .transformToByteArray();


        res.end(
          Buffer.from(
            bytes
          )
        );

      }


    } catch (err) {

      console.error(
        'PAYMENT DOWNLOAD ERROR:',
        err
      );


      const status =
        Number(
          err?.status
        ) || 500;


      if (
        !res.headersSent
      ) {

        return res
          .status(status)
          .json({

            error:
              status === 500
                ? 'Server download error.'
                : String(
                    err.message ||
                    'Download failed.'
                  )

          });

      }

      res.destroy(
        err
      );

    }

  }
);



/* =========================================================
   CODING FROM DOOARS - MANAGEMENT API
   Required by Admin / Super Admin Manage UI
========================================================= */

function normalizeRole(value) {
  const r = String(value || '').trim().toLowerCase();
  return r === 'super_admin' || r === 'super-admin' ? 'super_admin'
       : r === 'admin' ? 'admin'
       : 'user';
}

async function getUserProfile(uid) {
  const id = String(uid || '').trim();
  if (!id) return null;
  const snap = await db.collection('profiles').doc(id).get();
  return snap.exists ? { uid: snap.id, ...snap.data() } : null;
}

async function getVerifiedRole(user) {
  const email = String(user?.email || '').trim().toLowerCase();
  if (email === 'argha889944@gmail.com') return 'super_admin';
  const claim = normalizeRole(user?.role || user?.claims?.role);
  if (claim !== 'user') return claim;
  const profile = await getUserProfile(user?.uid);
  return normalizeRole(profile?.role);
}

async function requirePrivileged(req) {
  const user = await requireUser(req);
  const role = await getVerifiedRole(user);
  if (role !== 'admin' && role !== 'super_admin') {
    const err = new Error('Admin or Super Admin access required.');
    err.status = 403;
    throw err;
  }
  return { user, role };
}

function makeSecureAccessCode() {
  const crypto = require('crypto');
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(25);
  let raw = '';
  for (let i = 0; i < 25; i++) raw += chars[bytes[i] % chars.length];
  return raw.match(/.{1,5}/g).join('-');
}

async function ensureAccessCode(uid) {
  const id = String(uid || '').trim();
  if (!id) throw new Error('User ID is required.');
  const ref = db.collection('profiles').doc(id);
  const snap = await ref.get();
  const profile = snap.exists ? snap.data() || {} : {};
  let code = String(profile.access_code || '').trim();
  if (!/^[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}$/.test(code)) {
    code = makeSecureAccessCode();
    await ref.set({
      access_code: code,
      access_code_status: 'ACTIVE',
      access_code_updated_at: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
  }
  return code;
}

/* Backend role verification used by the Admin/User toggle. */
app.get('/api/auth/role-check', async (req, res) => {
  try {
    const user = await requireUser(req);
    const role = await getVerifiedRole(user);
    return res.json({ ok: true, role, uid: user.uid });
  } catch (err) {
    return res.status(Number(err?.status) || 500).json({ ok: false, error: String(err?.message || 'Role verification failed.') });
  }
});

/* Server-side session metadata sync. Never returns credentials. */
app.post('/api/auth/session-sync', async (req, res) => {
  try {
    const user = await requireUser(req);
    const role = await getVerifiedRole(user);
    const ref = db.collection('profiles').doc(String(user.uid));
    const snap = await ref.get();
    const existing = snap.exists ? snap.data() || {} : {};
    const patch = {
      email: user.email || existing.email || '',
      last_login_at: admin.firestore.FieldValue.serverTimestamp(),
      updated_at: admin.firestore.FieldValue.serverTimestamp()
    };
    if (!existing.created_at) patch.created_at = admin.firestore.FieldValue.serverTimestamp();
    if (!existing.role || role === 'super_admin') patch.role = role;
    await ref.set(patch, { merge: true });
    const fresh = await ref.get();
    const p = fresh.exists ? fresh.data() || {} : {};
    return res.json({
      ok: true,
      profile: {
        uid: user.uid,
        email: user.email || p.email || '',
        full_name: p.full_name || p.name || user.name || '',
        role,
        customer_code: p.customer_code || '',
        access_code_status: p.access_code_status || 'ACTIVE'
      }
    });
  } catch (err) {
    return res.status(Number(err?.status) || 500).json({ ok: false, error: String(err?.message || 'Session sync failed.') });
  }
});

/* Current user's private management/access-code metadata. */
app.get('/api/access-code/me', async (req, res) => {
  try {
    const user = await requireUser(req);
    const profile = await getUserProfile(user.uid) || {};
    const role = await getVerifiedRole(user);
    await ensureAccessCode(user.uid);
    return res.json({ ok: true, uid: user.uid, role, status: profile.access_code_status || 'ACTIVE' });
  } catch (err) {
    return res.status(Number(err?.status) || 500).json({ ok: false, error: String(err?.message || 'Access code unavailable.') });
  }
});

/* Reveal is deliberately server-authorized and never included in list responses. */
app.post('/api/access-code/reveal', async (req, res) => {
  try {
    const user = await requireUser(req);
    const targetUid = String(req.body?.uid || user.uid).trim();
    const actorRole = await getVerifiedRole(user);
    const target = await getUserProfile(targetUid);
    if (!target) return res.status(404).json({ ok: false, error: 'Account not found.' });

    const targetRole = normalizeRole(target.role);
    if (targetUid !== user.uid) {
      if (actorRole !== 'admin' && actorRole !== 'super_admin') return res.status(403).json({ ok:false, error:'Management access required.' });
      if (targetRole === 'super_admin' && actorRole !== 'super_admin') return res.status(403).json({ ok:false, error:'Only Super Admin can manage a Super Admin code.' });
    }

    const code = await ensureAccessCode(targetUid);
    return res.json({ ok: true, code, uid: targetUid });
  } catch (err) {
    return res.status(Number(err?.status) || 500).json({ ok: false, error: String(err?.message || 'Access code reveal failed.') });
  }
});

app.get('/api/access-codes', async (req, res) => {
  try {
    const { user, role } = await requirePrivileged(req);
    const snap = await db.collection('profiles').limit(200).get();
    const rows = [];
    snap.forEach(doc => {
      const p = doc.data() || {};
      const targetRole = normalizeRole(p.role);
      if (targetRole === 'user' || targetRole === 'admin' || targetRole === 'super_admin') {
        if (targetRole === 'super_admin' && role !== 'super_admin') return;
        rows.push({
          uid: doc.id,
          name: String(p.full_name || p.name || p.displayName || p.email || 'Account'),
          email: String(p.email || ''),
          role: targetRole.toUpperCase(),
          status: String(p.access_code_status || 'ACTIVE').toUpperCase()
        });
      }
    });
    rows.sort((a,b) => (a.role + a.name).localeCompare(b.role + b.name));
    return res.json({ ok:true, rows, actorUid:user.uid });
  } catch (err) {
    return res.status(Number(err?.status) || 500).json({ ok:false, error:String(err?.message || 'Access-code list failed.') });
  }
});

app.post('/api/access-codes/:uid/regenerate', async (req, res) => {
  try {
    const { role } = await requirePrivileged(req);
    const uid = String(req.params.uid || '').trim();
    const target = await getUserProfile(uid);
    if (!target) return res.status(404).json({ ok:false, error:'Account not found.' });
    const targetRole = normalizeRole(target.role);
    if (targetRole === 'super_admin' && role !== 'super_admin') return res.status(403).json({ ok:false, error:'Only Super Admin can regenerate a Super Admin code.' });
    const code = makeSecureAccessCode();
    await db.collection('profiles').doc(uid).set({
      access_code: code,
      access_code_status: 'ACTIVE',
      access_code_updated_at: admin.firestore.FieldValue.serverTimestamp()
    }, { merge:true });
    return res.json({ ok:true, uid, status:'ACTIVE' });
  } catch (err) {
    return res.status(Number(err?.status) || 500).json({ ok:false, error:String(err?.message || 'Access-code regeneration failed.') });
  }
});

/* Private 20-character customer code endpoint. */
app.get('/api/customer-code/me', async (req, res) => {
  try {
    const user = await requireUser(req);
    const ref = db.collection('profiles').doc(String(user.uid));
    const snap = await ref.get();
    const p = snap.exists ? snap.data() || {} : {};
    let code = String(p.customer_code || '').trim();
    if (!/^[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}$/.test(code)) {
      const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
      const crypto = require('crypto');
      const bytes = crypto.randomBytes(25);
      let raw = '';
      for (let i=0;i<25;i++) raw += chars[bytes[i] % chars.length];
      code = raw.match(/.{1,5}/g).join('-');
      await ref.set({ customer_code:code, updated_at:admin.firestore.FieldValue.serverTimestamp() }, { merge:true });
    }
    return res.json({ ok:true, code });
  } catch (err) {
    return res.status(Number(err?.status) || 500).json({ ok:false, error:String(err?.message || 'Customer code unavailable.') });
  }
});

/* Backend menu-block API. The frontend also uses Firestore realtime, so these
   routes are deliberately thin and compatible with the existing collection. */
app.get('/api/menu-blocks', async (req, res) => {
  try {
    await requireUser(req);
    const snap = await db.collection('menu_blocks').orderBy('order','asc').limit(100).get();
    const blocks = snap.docs.map(d => ({ id:d.id, ...d.data() })).filter(b => b.enabled !== false && b.active !== false && b.showInUserMenu !== false && b.deletedAt == null);
    return res.json({ ok:true, blocks });
  } catch (err) {
    return res.status(Number(err?.status) || 500).json({ ok:false, error:String(err?.message || 'Menu blocks unavailable.') });
  }
});

app.get('/api/menu-blocks/manage', async (req, res) => {
  try {
    await requirePrivileged(req);
    const snap = await db.collection('menu_blocks').orderBy('order','asc').limit(100).get();
    return res.json({ ok:true, blocks:snap.docs.map(d => ({ id:d.id, ...d.data() })) });
  } catch (err) {
    return res.status(Number(err?.status) || 500).json({ ok:false, error:String(err?.message || 'Menu block management unavailable.') });
  }
});

app.post('/api/menu-blocks', async (req, res) => {
  try {
    const { user } = await requirePrivileged(req);
    const title = String(req.body?.title || '').trim();
    const action = String(req.body?.action || '').trim();
    if (!title || !action) return res.status(400).json({ok:false,error:'Block title and link/action are required.'});
    const data = {
      title,
      name:title,
      icon:String(req.body?.icon || '✦').trim(),
      description:String(req.body?.description || '').trim(),
      action,
      target:action,
      order:Number.isFinite(Number(req.body?.displayOrder)) ? Number(req.body.displayOrder) : 0,
      displayOrder:Number.isFinite(Number(req.body?.displayOrder)) ? Number(req.body.displayOrder) : 0,
      enabled:req.body?.enabled !== false,
      active:req.body?.enabled !== false,
      showInUserMenu:req.body?.showInUserMenu !== false,
      createdBy:user.uid,
      createdAt:admin.firestore.FieldValue.serverTimestamp(),
      updatedAt:admin.firestore.FieldValue.serverTimestamp(),
      updatedBy:user.uid
    };
    const ref = await db.collection('menu_blocks').add(data);
    return res.status(201).json({ok:true,id:ref.id,block:{id:ref.id,...data}});
  } catch (err) {
    return res.status(Number(err?.status) || 500).json({ok:false,error:String(err?.message || 'Could not create menu block.')});
  }
});

app.patch('/api/menu-blocks/:id', async (req, res) => {
  try {
    const { user } = await requirePrivileged(req);
    const id = String(req.params.id || '').trim();
    if (!id) return res.status(400).json({ok:false,error:'Block ID is required.'});
    const allowed = ['title','name','icon','description','action','target','order','displayOrder','enabled','active','showInUserMenu'];
    const patch = {};
    for (const key of allowed) if (Object.prototype.hasOwnProperty.call(req.body || {}, key)) patch[key] = req.body[key];
    if (patch.title != null) patch.name = String(patch.title);
    if (patch.action != null) patch.target = String(patch.action);
    if (patch.order != null) patch.displayOrder = Number(patch.order) || 0;
    if (patch.displayOrder != null) patch.order = Number(patch.displayOrder) || 0;
    patch.updatedAt = admin.firestore.FieldValue.serverTimestamp();
    patch.updatedBy = user.uid;
    await db.collection('menu_blocks').doc(id).set(patch,{merge:true});
    return res.json({ok:true,id});
  } catch (err) {
    return res.status(Number(err?.status) || 500).json({ok:false,error:String(err?.message || 'Could not update menu block.')});
  }
});

app.delete('/api/menu-blocks/:id', async (req, res) => {
  try {
    const { user } = await requirePrivileged(req);
    const id = String(req.params.id || '').trim();
    if (!id) return res.status(400).json({ok:false,error:'Block ID is required.'});
    await db.collection('menu_blocks').doc(id).set({enabled:false,active:false,deletedAt:admin.firestore.FieldValue.serverTimestamp(),updatedAt:admin.firestore.FieldValue.serverTimestamp(),updatedBy:user.uid},{merge:true});
    return res.json({ok:true,id});
  } catch (err) {
    return res.status(Number(err?.status) || 500).json({ok:false,error:String(err?.message || 'Could not delete menu block.')});
  }
});


/* =========================================================
   CAP HUMAN VERIFICATION — PHOTO DOWNLOAD SECURITY
========================================================= */
const CAP_API_ENDPOINT = String(process.env.CAP_API_ENDPOINT || '').trim().replace(/\/+$/,'/');
const CAP_SECRET_KEY = String(process.env.CAP_SECRET_KEY || '').trim();
const CAP_REQUIRED = String(process.env.CAP_REQUIRED ?? 'true').toLowerCase() !== 'false';

app.get('/api/security/cap-config', (_req,res)=>{
  return res.json({ok:true,enabled:!!(CAP_API_ENDPOINT&&CAP_SECRET_KEY),required:CAP_REQUIRED,apiEndpoint:CAP_API_ENDPOINT});
});

async function cfdVerifyCap(req){
  if(!CAP_REQUIRED){
    console.log('[CFD CAP VERIFY] disabled');
    return {ok:true,success:true,disabled:true};
  }

  if(!CAP_API_ENDPOINT || !CAP_SECRET_KEY){
    console.error('[CFD CAP VERIFY] configuration missing', {
      endpointConfigured: !!CAP_API_ENDPOINT,
      secretConfigured: !!CAP_SECRET_KEY,
      endpoint: CAP_API_ENDPOINT || ''
    });
    const e=new Error('Human verification is not configured.');
    e.status=503;
    throw e;
  }

  // Cap supports the normal cap-token form field. We also accept our
  // existing capToken field and the custom header for compatibility.
  const token=String(
    req.headers['x-cfd-cap-token'] ||
    req.body?.['cap-token'] ||
    req.body?.capToken ||
    req.query?.['cap-token'] ||
    ''
  ).trim();

  if(!token){
    console.warn('[CFD CAP VERIFY] token missing');
    const e=new Error('Human verification required.');
    e.status=403;
    throw e;
  }

  const endpoint=CAP_API_ENDPOINT.replace(/\/+$/,'')+'/siteverify';
  const ac=new AbortController();
  const timer=setTimeout(()=>ac.abort(),10000);

  try{
    console.log('[CFD CAP VERIFY] request', {
      endpoint,
      tokenReceived:true
    });

    const r=await fetch(endpoint,{
      method:'POST',
      headers:{
        'content-type':'application/json',
        'accept':'application/json'
      },
      body:JSON.stringify({
        secret:CAP_SECRET_KEY,
        response:token
      }),
      signal:ac.signal
    });

    const raw=await r.text();
    let j={};
    try{ j=raw ? JSON.parse(raw) : {}; }catch(_){
      j={raw:raw.slice(0,500)};
    }

    // NEVER log the secret or token. Only log Cap's safe response fields.
    console.log('[CFD CAP VERIFY RESULT]', {
      status:r.status,
      ok:r.ok,
      success:j.success,
      error:j.error || '',
      message:j.message || ''
    });

    if(!r.ok || j.success!==true){
      const reason=j.error || j.message || `HTTP ${r.status}`;
      console.error('[CFD CAP VERIFY FAILED]', reason);
      const e=new Error('Human verification failed: '+reason);
      e.status=403;
      throw e;
    }

    return {ok:true,success:true};

  }catch(err){
    if(err?.status) throw err;

    console.error('[CFD CAP VERIFY ERROR]',{
      name:err?.name || '',
      message:err?.message || ''
    });

    const e=new Error('Human verification service is unavailable. Please try again.');
    e.status=503;
    throw e;
  }finally{
    clearTimeout(timer);
  }
}

/* =========================================================
   CUSTOMER PHOTOS ZIP DOWNLOAD — FINAL
   Always a real ZIP response. Never 204 / HTML.
========================================================= */
function cfdZipCrc32(buf) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j++) crc = (crc >>> 1) ^ (0xEDB88320 & -(crc & 1));
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}
function cfdZipDate(date = new Date()) {
  const y = Math.max(1980, date.getFullYear());
  return {
    time: ((date.getHours() & 31) << 11) | ((date.getMinutes() & 63) << 5) | ((Math.floor(date.getSeconds()/2)) & 31),
    date: (((y-1980) & 127) << 9) | (((date.getMonth()+1) & 15) << 5) | (date.getDate() & 31)
  };
}
function cfdZipName(name, fallback='customer-photo.jpg') {
  let n = safeFilename(name || fallback).replace(/[\\/]/g,'_').replace(/[\u0000-\u001F]/g,'_').trim();
  return n || fallback;
}
function cfdMakeZip(entries) {
  const locals=[], centrals=[]; let offset=0;
  for (const e of entries) {
    const raw=Buffer.isBuffer(e.buffer)?e.buffer:Buffer.from(e.buffer||[]);
    const comp=raw;
    const crc=cfdZipCrc32(raw), dt=cfdZipDate(e.date||new Date());
    const name=Buffer.from(cfdZipName(e.name),'utf8');
    const local=Buffer.alloc(30+name.length);
    local.writeUInt32LE(0x04034b50,0); local.writeUInt16LE(20,4); local.writeUInt16LE(0,6); local.writeUInt16LE(0,8);
    local.writeUInt16LE(dt.time,10); local.writeUInt16LE(dt.date,12); local.writeUInt32LE(crc,14);
    local.writeUInt32LE(comp.length>>>0,18); local.writeUInt32LE(raw.length>>>0,22); local.writeUInt16LE(name.length,26); name.copy(local,30);
    const block=Buffer.concat([local,comp]); locals.push(block);
    const central=Buffer.alloc(46+name.length);
    central.writeUInt32LE(0x02014b50,0); central.writeUInt16LE(20,4); central.writeUInt16LE(20,6); central.writeUInt16LE(0,8); central.writeUInt16LE(0,10);
    central.writeUInt16LE(dt.time,12); central.writeUInt16LE(dt.date,14); central.writeUInt32LE(crc,16); central.writeUInt32LE(comp.length>>>0,20); central.writeUInt32LE(raw.length>>>0,24);
    central.writeUInt16LE(name.length,28); central.writeUInt32LE(offset>>>0,42); name.copy(central,46); centrals.push(central);
    offset += block.length;
  }
  const localData=Buffer.concat(locals), centralDir=Buffer.concat(centrals), end=Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50,0); end.writeUInt16LE(entries.length,8); end.writeUInt16LE(entries.length,10);
  end.writeUInt32LE(centralDir.length>>>0,12); end.writeUInt32LE(localData.length>>>0,16);
  return Buffer.concat([localData,centralDir,end]);
}

function cfdIsPhotoObject(key, type, name) {
  const low=String(key||'').toLowerCase();
  if (/payment|transaction|receipt|utr/.test(low)) return false;
  return isImageMime(type) || looksLikeImage(name || key, type);
}

app.use('/api/b2/customer-photos-download-zip',(req,res,next)=>{
  const started=Date.now();
  console.log(`[CFD ZIP REQUEST] ${req.method} ${req.path} order=${String(req.query?.orderId||req.body?.orderId||'')} origin=${String(req.headers.origin||'-')}`);
  res.on('finish',()=>console.log(`[CFD ZIP RESPONSE] ${req.method} status=${res.statusCode} bytes=${String(res.getHeader('Content-Length')||'-')} ms=${Date.now()-started}`));
  next();
});

const cfdPhotoZipInflight = new Map();

// Short-lived download tickets let browser/IDM retry the final ZIP GET
// without replaying the Cap token or Firebase POST. Tickets are random,
// order-bound, expire quickly, and allow a small number of GETs so IDM can
// take over a browser download without receiving the protected POST again.
const cfdPhotoZipTickets = new Map();
function cfdCreatePhotoZipTicket(orderId, uid, zip, filename) {
  const ticket = crypto.randomBytes(32).toString("hex");
  cfdPhotoZipTickets.set(ticket, {
    orderId: String(orderId),
    uid: String(uid || ""),
    zip,
    filename: String(filename),
    createdAt: Date.now(),
    expiresAt: Date.now() + 5 * 60 * 1000,
    uses: 0,
    maxUses: 20
  });
  return ticket;
}
function cfdTakePhotoZipTicket(ticket, consume = true) {
  const key = String(ticket || "").trim();
  const item = cfdPhotoZipTickets.get(key);
  if (!item) return null;
  if (Date.now() > item.expiresAt || item.uses >= item.maxUses) {
    cfdPhotoZipTickets.delete(key);
    return null;
  }
  if (consume) item.uses += 1;
  return item;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of cfdPhotoZipTickets) {
    if (!v || now > Number(v.expiresAt || 0)) cfdPhotoZipTickets.delete(k);
  }
}, 30 * 1000).unref();

async function cfdGetB2PhotoBuffer(key, timeoutMs = 30000) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    console.log('[CFD PHOTO ZIP V23] B2 GetObject start key=' + String(key));
    const obj = await s3.send(
      new GetObjectCommand({
        Bucket: B2_BUCKET_NAME,
        Key: key,
      }),
      { abortSignal: ac.signal }
    );

    console.log('[CFD PHOTO ZIP V21] B2 GetObject headers received key=' + String(key));

    const body = obj.Body;
    if (!body) throw new Error('B2 returned an empty response body.');

    const chunks = [];
    let total = 0;

    if (typeof body[Symbol.asyncIterator] === 'function') {
      for await (const chunk of body) {
        if (ac.signal.aborted) throw new Error('B2 photo download timed out.');
        const b = Buffer.from(chunk);
        if (!b.length) continue;
        chunks.push(b);
        total += b.length;
        if (total > 50 * 1024 * 1024) {
          throw new Error('Customer photo is too large for ZIP download.');
        }
      }
    } else if (typeof body.transformToByteArray === 'function') {
      const arr = await body.transformToByteArray();
      const b = Buffer.from(arr);
      chunks.push(b);
      total = b.length;
    } else {
      throw new Error('Unsupported B2 response body.');
    }

    const bytes = Buffer.concat(chunks, total);
    console.log('[CFD PHOTO ZIP V21] B2 GetObject complete key=' + String(key) + ' bytes=' + String(bytes.length));
    return { bytes, contentType: obj.ContentType || '' };
  } catch (err) {
    if (ac.signal.aborted || err?.name === 'AbortError') {
      const e = new Error('B2 photo download timed out.');
      e.status = 504;
      throw e;
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

const cfdWithTimeout = async (promise, ms, label) => {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          const e = new Error(label + ' timed out.');
          e.status = 504;
          reject(e);
        }, ms);
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
};

const cfdCustomerPhotosZipHandler = async (req,res)=>{
  let inflightKey='';
  try {
    console.log('[CFD PHOTO ZIP V21] Cap passed; starting auth/order processing');
    await cfdVerifyCap(req);
    console.log('[CFD PHOTO ZIP V21] Cap verified; starting Firebase auth');
    const user=await cfdWithTimeout(requireUser(req),15000,'Firebase authentication');
    console.log('[CFD PHOTO ZIP V21] Firebase auth passed uid=' + String(user?.uid||''));
    const orderId=String(req.query.orderId||req.body?.orderId||'').trim();
    if(!orderId) return res.status(400).json({ok:false,error:'Order ID is required.'});
    inflightKey=String(orderId).toLowerCase();
    if(cfdPhotoZipInflight.has(inflightKey)){
      console.warn('[CFD PHOTO ZIP V18] duplicate in-flight request blocked order=' + orderId);
      return res.status(409).json({ok:false,error:'Customer photo ZIP is already being prepared. Please wait a moment.'});
    }
    cfdPhotoZipInflight.set(inflightKey,Date.now());
    console.log('[CFD PHOTO ZIP V21] loading order=' + orderId);
    const order=await cfdWithTimeout(getOrder(orderId),15000,'Order lookup');
    if(!order) return res.status(404).json({ok:false,error:'Order not found.'});
    console.log('[CFD PHOTO ZIP V21] order loaded; checking privilege');
    const privileged=await cfdWithTimeout(isPrivilegedUser(user),15000,'Privilege check');
    const ownerUid=String(order.userId||order.customerId||order.uid||'').trim();
    console.log('[CFD PHOTO ZIP V21] privilege check complete privileged=' + String(privileged));
    if(!privileged && ownerUid !== String(user.uid)) return res.status(403).json({ok:false,error:'You are not allowed to download this order.'});

    const candidates=[]; const seen=new Set();
    const add=(key,name,type,score=0)=>{
      key=cleanKey(key); if(!key||seen.has(key)) return;
      if(!cfdIsPhotoObject(key,type,name)) return;
      seen.add(key); candidates.push({key,name:name||key.split('/').pop(),type:type||'',score});
    };

    // A) Every real B2 key already saved in the current order document.
    const stored=collectCustomerPhotoCandidates(order)||[];
    for(const x of stored) add(x?.key,x?.name,x?.type,100000);

    const uid=ownerUid.toLowerCase();
    const oid=orderId.toLowerCase();
    const wantedNames=new Set(stored.map(x=>String(x?.name||'').trim().toLowerCase()).filter(Boolean));

    // B) Only scan B2 when the order document did NOT already give us real
    // customer-photo keys.  The order document is authoritative here.
    // Scanning the entire customer_files namespace on every ZIP click can
    // take a long time (or appear hung) on a large bucket, even though the
    // exact two stored objects are already known.
    const listed=[];
    if(!candidates.length){
      console.log('[CFD PHOTO ZIP V20] no stored photo keys; scanning B2 customer_files');
      let token;
      do{
        const page=await cfdWithTimeout(s3.send(new ListObjectsV2Command({
          Bucket:B2_BUCKET_NAME, Prefix:'customer_files/',
          ContinuationToken:token, MaxKeys:1000
        })),20000,'B2 customer_files listing');
        for(const o of (page.Contents||[])){
          const key=cleanKey(o?.Key); if(!key) continue;
          const leaf=(key.split('/').pop()||'');
          const low=key.toLowerCase();
          if(/payment|transaction|receipt|utr/.test(low)) continue;
          const image=isImageMime(o?.ContentType||'') || looksLikeImage(leaf,o?.ContentType||'');
          if(!image) continue;
          const exactOrder=cfdPhotoKeyIsExactOrder(key,orderId) || low.includes('/'+oid+'/') || low.includes('/'+oid+'_');
          const sameUid=!!uid && low.split('/').includes(uid);
          const nameMatch=wantedNames.has(leaf.toLowerCase());
          listed.push({key,name:leaf,type:o?.ContentType||'',lastModified:o?.LastModified||null,exactOrder,sameUid,nameMatch});
        }
        token=page.IsTruncated?page.NextContinuationToken:undefined;
      }while(token);
      console.log('[CFD PHOTO ZIP V20] B2 listing complete objects=' + String(listed.length));
    } else {
      console.log('[CFD PHOTO ZIP V21] stored photo keys found count=' + String(candidates.length) + '; skipping full B2 listing');
    }

    // Strict order-bound files first.
    for(const x of listed.filter(x=>x.exactOrder)) add(x.key,x.name,x.type,300000);
    // Firestore filename matches next, even for legacy keys.
    for(const x of listed.filter(x=>x.nameMatch)) add(x.key,x.name,x.type,250000);

    // C) Legacy fallback: if the order has no order-bound objects, use images
    // inside THIS customer's UID namespace. This is what makes old uploads
    // downloadable when their B2 path was customer_files/<name>/<uid>/<file>.
    if(!candidates.length && uid){
      for(const x of listed.filter(x=>x.sameUid)) add(x.key,x.name,x.type,100000);
    }

    // D) Last resolver fallback for Firestore paths that point to one legacy
    // object whose key cannot be inferred from the current order shape.
    if(!candidates.length){
      try{
        const resolved=await resolveB2CustomerFile(order,'','');
        if(resolved) add(resolved.key,resolved.name,resolved.type,500000);
      }catch(e){console.warn('[CFD PHOTO ZIP V6] resolver fallback:',e?.message||e);}
    }

    if(!candidates.length){
      return res.status(404).json({ok:false,error:'No customer photos were found for this order.',orderId,uid,storedKeys:stored.map(x=>x?.key||'').filter(Boolean)});
    }

    console.log('[CFD PHOTO ZIP V21] candidates ready count=' + String(candidates.length));
    const entries=[], used=new Set();
    for(const item of candidates.sort((a,b)=>b.score-a.score)){
      try{
        console.log('[CFD PHOTO ZIP V21] downloading candidate key=' + String(item.key));
        const got=await cfdGetB2PhotoBuffer(item.key,30000);
        const bytes=got.bytes;
        if(!bytes || !bytes.length) continue;
        const mime=detectImageMime(bytes,got.contentType||item.type,item.name||item.key);
        if(!isImageMime(mime)) continue;
        let name=cfdZipName(item.name || item.key.split('/').pop() || 'customer-photo');
        if(!/\.[A-Za-z0-9]{2,5}$/.test(name)) name += ({'image/jpeg':'.jpg','image/png':'.png','image/webp':'.webp','image/gif':'.gif','image/bmp':'.bmp','image/avif':'.avif','image/svg+xml':'.svg'}[mime]||'.jpg');
        let final=name,n=2; while(used.has(final.toLowerCase())) final=name.replace(/(\.[^.]+)$/,'-'+n+++'$1');
        used.add(final.toLowerCase()); entries.push({name:final,buffer:bytes,date:new Date()});
      }catch(e){console.warn('[CFD PHOTO ZIP V6] skipped',item.key,e?.message||e);}
    }

    if(!entries.length){
      return res.status(404).json({ok:false,error:'Customer photo objects were found, but none could be downloaded.',orderId,candidateCount:candidates.length,candidates:candidates.slice(0,30).map(x=>x.key)});
    }
    const zip=cfdMakeZip(entries);
    const filename=`${safeFilename(orderId)}-customer-photos.zip`;
    const ticket=cfdCreatePhotoZipTicket(orderId,user?.uid||ownerUid,zip,filename);
    console.log('[CFD PHOTO ZIP V23] ZIP prepared bytes=' + String(zip.length) + ' entries=' + String(entries.length) + '; issuing download ticket');
    const ticketUrl=`/api/b2/customer-photos-download-zip?ticket=${encodeURIComponent(ticket)}`;
    // 303 makes the native POST become a GET. The GET is protected by a
    // short-lived random ticket, so IDM can request the same final URL without
    // replaying the single-use Cap token.
    return res.redirect(303,ticketUrl);
  }catch(err){
    console.error('[CFD PHOTO ZIP V21] route error:',err?.stack||err);
    if(!res.headersSent) return res.status(Number(err?.status)||500).json({ok:false,error:String(err?.message||'Customer photos ZIP download failed.')});
    res.destroy(err);
  } finally {
    if(inflightKey) cfdPhotoZipInflight.delete(inflightKey);
  }
};

app.get('/api/b2/customer-photos-download-zip', (req,res,next)=>{
  const ticket=String(req.query?.ticket||'').trim();
  if(!ticket) return cfdCustomerPhotosZipHandler(req,res,next);

  // IDM and browser download managers may use HEAD and/or HTTP Range requests.
  // HEAD must not consume a ticket, and every valid byte-range GET must be
  // allowed during the short ticket lifetime.
  const isHead=req.method === 'HEAD';
  const range=String(req.headers.range||'').trim();
  const item=cfdTakePhotoZipTicket(ticket,!isHead);
  if(!item) return res.status(410).json({ok:false,error:'This ZIP download link has expired. Please start the download again.'});

  const zip=Buffer.isBuffer(item.zip) ? item.zip : Buffer.from(item.zip||'');
  const total=zip.length;
  const filename=String(item.filename||'customer-photos.zip').replace(/[\"\r\n]/g,'');
  res.setHeader('Accept-Ranges','bytes');
  res.setHeader('Content-Type','application/zip');
  res.setHeader('Content-Disposition',`attachment; filename="${filename}"`);
  res.setHeader('Cache-Control','private, no-store, max-age=0');
  res.setHeader('Pragma','no-cache');
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-CFD-Photo-Zip-Version','V23-IDM-RANGE');

  if(isHead){
    res.setHeader('Content-Length',String(total));
    console.log('[CFD PHOTO ZIP V23] HEAD ticket check order=' + item.orderId);
    return res.status(200).end();
  }

  let start=0; let end=total-1;
  if(range){
    const m=/^bytes=(\d*)-(\d*)$/i.exec(range);
    if(m){
      if(m[1]==='' && m[2]===''){
        return res.status(416).setHeader('Content-Range',`bytes */${total}`).end();
      }
      if(m[1]===''){
        const suffix=Math.max(0,Number(m[2]));
        if(!Number.isFinite(suffix) || suffix<=0) return res.status(416).setHeader('Content-Range',`bytes */${total}`).end();
        start=Math.max(0,total-suffix);
      } else {
        start=Number(m[1]);
        if(!Number.isFinite(start) || start<0 || start>=total) return res.status(416).setHeader('Content-Range',`bytes */${total}`).end();
        if(m[2] !== '') end=Number(m[2]);
      }
      if(!Number.isFinite(end) || end<start) return res.status(416).setHeader('Content-Range',`bytes */${total}`).end();
      end=Math.min(end,total-1);
      const chunk=zip.subarray(start,end+1);
      res.status(206);
      res.setHeader('Content-Range',`bytes ${start}-${end}/${total}`);
      res.setHeader('Content-Length',String(chunk.length));
      console.log('[CFD PHOTO ZIP V23] RANGE served order=' + item.orderId + ' bytes=' + start + '-' + end + '/' + total + ' use=' + item.uses + '/' + item.maxUses);
      return res.end(chunk);
    }
  }

  res.status(200).setHeader('Content-Length',String(total));
  console.log('[CFD PHOTO ZIP V23] full GET served order=' + item.orderId + ' bytes=' + total + ' use=' + item.uses + '/' + item.maxUses);
  return res.end(zip);
});
app.post('/api/b2/customer-photos-download-zip', cfdCustomerPhotosZipHandler);

/* =========================================================
   WEBSITE STATIC FILES
========================================================= */

const PUBLIC_DIR =
  __dirname;


/*
   IMPORTANT:
   API routes are already defined above.
   Static website comes after them.
*/

app.use(
  express.static(
    PUBLIC_DIR,
    {
      index:
        'index.html'
    }
  )
);


app.get(
  '/',
  (_req, res) => {

    res.sendFile(
      path.join(
        PUBLIC_DIR,
        'index.html'
      )
    );

  }
);


/*
   Express 5 SPA fallback.
*/

app.get(
  '/{*splat}',
  (req, res, next) => {

    if (
      req.path.startsWith(
        '/api/'
      )
    ) {

      return next();

    }


    res.sendFile(
      path.join(
        PUBLIC_DIR,
        'index.html'
      ),
      err => {

        if (err) {
          next(err);
        }

      }
    );

  }
);


/* =========================================================
   API 404
========================================================= */

app.use(
  (req, res) => {

    res
      .status(404)
      .json({

        error:
          'API endpoint not found.'

      });

  }
);


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (
    err,
    _req,
    res,
    _next
  ) => {

    console.error(
      'EXPRESS ERROR:',
      err
    );


    if (
      res.headersSent
    ) {

      return;
    }


    res
      .status(
        Number(
          err?.status
        ) || 500
      )
      .json({

        error:
          String(
            err?.message ||
            'Internal server error.'
          )

      });

  }
);

// ============================================================
// FINAL API FALLBACK
// IMPORTANT: API request must NEVER receive index.html
// ============================================================

app.use((req, res, next) => {

  if (req.path.startsWith('/api/')) {
    return res.status(404).json({
      ok: false,
      error: 'API endpoint not found.'
    });
  }

  next();
});


/* =========================================================
   START
========================================================= */

console.log('CUSTOMER PHOTO ABSOLUTE RECOVERY: ENABLED');
console.log('CUSTOMER PHOTO STATUS ROUTE: /api/b2/photo-fix-status (V10)');

app.listen(
  PORT,
  () => {

    console.log('');
    console.log(
      '=========================================='
    );
    console.log(
      ' CODING FROM DOOARS SERVER'
    );
    console.log(
      '=========================================='
    );

    console.log(
      ` http://localhost:${PORT}`
    );

    console.log(
      ` Firebase: ${
        admin.apps.length
          ? 'true'
          : 'false'
      }`
    );

    console.log(
      ` B2: ${
        B2_KEY_ID &&
        B2_APPLICATION_KEY
          ? 'true'
          : 'false'
      }`
    );

    console.log(
      ` Bucket: ${B2_BUCKET_NAME}`
    );

    console.log(
      ' REAL B2 IMAGE DOWNLOAD: ENABLED'
    );

    console.log(
      ' CUSTOMER PHOTO RESOLVER: ENABLED'
    );

    console.log(
      ' HTML DOWNLOAD BLOCK: ENABLED'
    );

    console.log(
      ' WEBSITE STATIC SERVING: ENABLED'
    );

    console.log(
      '=========================================='
    );

    console.log('');

  }
);