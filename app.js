/* ==========================================================================
   Maktab 49 — Ta'lim Platformasi (v4)
   - Barcha qurilmalarda ishlaydigan Pure-JS + WebCrypto PBKDF2-HMAC-SHA256 login
   - 4 ta xato urinishdan keyin 120 soniyalik jonli sanaydigan taymer (countdown)
   - GitHub Cloud Sync (data.json + uploads/): Admin yuklagan video/rasm va barcha
     o'zgarishlar boshqa barcha telefon va kompyuterlarda ham ko'rinadi!
   - Parol o'zgartirish faqat Admin uchun, Tadbirlar bo'limida rasm/video yuklash
   ========================================================================== */

(() => {
  "use strict";

  const GH_OWNER = "malsapayevbekzod-jpg";
  const GH_REPO = "maktab-49";
  const GH_BRANCH = "main";
  const GH_RAW_BASE = `https://raw.githubusercontent.com/${GH_OWNER}/${GH_REPO}/${GH_BRANCH}`;
  const GH_API_BASE = `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}`;
  const GH_TOKEN_KEY = "maktab49_gh_token_v1";

  // ==================== 1. PURE-JS + WEBCRYPTO PBKDF2-HMAC-SHA256 ====================
  function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }

  function getRandomBytes(len) {
    const out = new Uint8Array(len);
    if (window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(out);
    } else {
      for (let i = 0; i < len; i++) out[i] = Math.floor(Math.random() * 256);
    }
    return out;
  }

  // Pure-JS SHA-256 (har qanday eski telefon yoki Telegram WebView uchun 100% ishlaydi)
  const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  function sha256Bytes(msg) {
    const len = msg.length;
    const bitLen = len * 8;
    const paddedLen = Math.ceil((len + 9) / 64) * 64;
    const buf = new Uint8Array(paddedLen);
    buf.set(msg);
    buf[len] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(paddedLen - 8, Math.floor(bitLen / 0x100000000), false);
    dv.setUint32(paddedLen - 4, bitLen >>> 0, false);

    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const w = new Uint32Array(64);

    for (let off = 0; off < paddedLen; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
      for (let i = 16; i < 64; i++) {
        const s0 = ((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >>> 3);
        const s1 = ((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (let i = 0; i < 64; i++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }

    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    odv.setUint32(0, h0, false); odv.setUint32(4, h1, false); odv.setUint32(8, h2, false); odv.setUint32(12, h3, false);
    odv.setUint32(16, h4, false); odv.setUint32(20, h5, false); odv.setUint32(24, h6, false); odv.setUint32(28, h7, false);
    return out;
  }

  function hmacSha256(keyBytes, dataBytes) {
    let key = keyBytes.length > 64 ? sha256Bytes(keyBytes) : keyBytes;
    const ipad = new Uint8Array(64 + dataBytes.length);
    const opad = new Uint8Array(64 + 32);
    for (let i = 0; i < 64; i++) {
      const kb = i < key.length ? key[i] : 0;
      ipad[i] = kb ^ 0x36;
      opad[i] = kb ^ 0x5c;
    }
    ipad.set(dataBytes, 64);
    opad.set(sha256Bytes(ipad), 64);
    return sha256Bytes(opad);
  }

  function utf8Bytes(str) {
    if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(str);
    const encoded = unescape(encodeURIComponent(str));
    const arr = new Uint8Array(encoded.length);
    for (let i = 0; i < encoded.length; i++) arr[i] = encoded.charCodeAt(i);
    return arr;
  }

  async function pbkdf2Sha256Bytes(password, saltBytes, iterations) {
    // 1) Avval tezkor WebCrypto API (HTTPS / zamonaviy brauzerlar)
    if (window.crypto && window.crypto.subtle) {
      try {
        const key = await window.crypto.subtle.importKey("raw", utf8Bytes(password), "PBKDF2", false, ["deriveBits"]);
        const bits = await window.crypto.subtle.deriveBits(
          { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations },
          key,
          256
        );
        return new Uint8Array(bits);
      } catch {
        // Fallback pastda
      }
    }
    // 2) Pure-JS fallback (HTTP, eski telefonlar, Telegram/Instagram WebView)
    const pwBytes = utf8Bytes(password);
    const saltBlock = new Uint8Array(saltBytes.length + 4);
    saltBlock.set(saltBytes);
    saltBlock[saltBytes.length + 3] = 1;
    let u = hmacSha256(pwBytes, saltBlock);
    const out = new Uint8Array(u);
    for (let i = 1; i < iterations; i++) {
      u = hmacSha256(pwBytes, u);
      for (let j = 0; j < 32; j++) out[j] ^= u[j];
    }
    return out;
  }

  async function hashPasswordWeb(password) {
    const salt = getRandomBytes(32);
    const derived = await pbkdf2Sha256Bytes(password, salt, 260000);
    return `pbkdf2_sha256$260000$${bytesToHex(salt)}$${bytesToHex(derived)}`;
  }

  async function verifyPasswordWeb(password, storedHash) {
    try {
      const [algo, iterStr, saltHex, hashHex] = String(storedHash || "").split("$");
      if (algo !== "pbkdf2_sha256") return false;
      const iterations = parseInt(iterStr, 10);
      const salt = hexToBytes(saltHex);
      const derived = await pbkdf2Sha256Bytes(password, salt, iterations);
      return constantTimeEqual(bytesToHex(derived), hashHex);
    } catch {
      return false;
    }
  }

  function validatePasswordStrength(pw) {
    if (!pw || pw.length < 8) return "Parol kamida 8 ta belgidan iborat bo'lishi kerak.";
    if (!/[A-Z]/.test(pw)) return "Parolda kamida bitta katta harf (A-Z) bo'lishi kerak.";
    if (!/[a-z]/.test(pw)) return "Parolda kamida bitta kichik harf (a-z) bo'lishi kerak.";
    if (!/[0-9]/.test(pw)) return "Parolda kamida bitta raqam (0-9) bo'lishi kerak.";
    return null;
  }

  // ==================== 2. INDEXEDDB + GITHUB CLOUD SYNC ====================
  const IDB_NAME = "maktab49_media_db";
  const IDB_STORE = "media_blobs";
  const blobUrlCache = new Map();

  function openMediaDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(IDB_NAME, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(IDB_STORE)) db.createObjectStore(IDB_STORE);
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function saveBlobToIDB(key, blob) {
    const db = await openMediaDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, "readwrite");
      tx.objectStore(IDB_STORE).put(blob, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async function getRawBlobFromIDB(key) {
    const db = await openMediaDB();
    return new Promise((resolve) => {
      const tx = db.transaction(IDB_STORE, "readonly");
      const req = tx.objectStore(IDB_STORE).get(key);
      req.onsuccess = () => resolve(req.result instanceof Blob ? req.result : null);
      req.onerror = () => resolve(null);
    });
  }

  async function getBlobUrlFromIDB(key) {
    if (blobUrlCache.has(key)) return blobUrlCache.get(key);
    const blob = await getRawBlobFromIDB(key);
    if (!blob) return "";
    const u = URL.createObjectURL(blob);
    blobUrlCache.set(key, u);
    return u;
  }

  async function deleteBlobFromIDB(key) {
    try {
      const db = await openMediaDB();
      const tx = db.transaction(IDB_STORE, "readwrite");
      tx.objectStore(IDB_STORE).delete(key);
      if (blobUrlCache.has(key)) {
        URL.revokeObjectURL(blobUrlCache.get(key));
        blobUrlCache.delete(key);
      }
    } catch { /* ignore */ }
  }

  async function resolveMediaPath(path) {
    if (!path || typeof path !== "string") return "";
    if (path.startsWith("idb://")) return await getBlobUrlFromIDB(path.slice(6));
    if (path.startsWith("uploads/") && useStaticMode) {
      return `${GH_RAW_BASE}/${path}`;
    }
    return path;
  }

  function fileToDataUrl(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(new Error("Faylni o'qib bo'lmadi."));
      reader.readAsDataURL(file);
    });
  }

  function fileToBase64Content(file) {
    return fileToDataUrl(file).then((du) => String(du).split(",")[1] || "");
  }

  function utf8ToBase64(str) {
    const bytes = utf8Bytes(str);
    let bin = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(bin);
  }

  function getGitHubToken() {
    return (localStorage.getItem(GH_TOKEN_KEY) || "").trim();
  }

  function formatGhError(status, apiMsg) {
    if (status === 401) return "GitHub token noto'g'ri yoki muddati tugagan. Yangi token yarating.";
    if (status === 403 || status === 404) {
      return "Tokenda maktab-49 ga yozish (repo) ruxsati yo'q! 'Tayyor GitHub Token yaratish' havolasini bosib, 'repo' katagi belgilangan yangi token yarating.";
    }
    if (status === 413 || status === 422) {
      return `Fayl juda katta yoki GitHub rad etdi (${apiMsg || status}). Video 50 MB dan kichik bo'lsin.`;
    }
    if (status === 409) return "Bir vaqtda ikkita o'zgarish to'qnashdi. Iltimos, 2 soniyadan keyin qayta bosing.";
    return `GitHub xatosi (${status}): ${apiMsg || "Internet ulanishini tekshiring."}`;
  }

  // Bir yoki bir nechta faylni (50 MB gacha video + data.json) BITTA atomar GitHub commit bilan yuklash!
  async function ghCommitFiles(filesMap, commitMsg) {
    const token = getGitHubToken();
    if (!token) return false;
    const headers = {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
    };

    // 1. Joriy main branch HEAD SHA ni keshsiz olish
    const refRes = await fetch(`${GH_API_BASE}/git/ref/heads/${GH_BRANCH}?_t=${Date.now()}`, {
      headers,
      cache: "no-store",
    });
    if (!refRes.ok) {
      const e = await refRes.json().catch(() => ({}));
      throw new Error(formatGhError(refRes.status, e.message));
    }
    const refData = await refRes.json();
    const headCommitSha = refData.object.sha;

    // 2. Asosiy daraxt (base_tree) SHA ni olish
    const commitRes = await fetch(`${GH_API_BASE}/git/commits/${headCommitSha}`, {
      headers,
      cache: "no-store",
    });
    if (!commitRes.ok) {
      const e = await commitRes.json().catch(() => ({}));
      throw new Error(formatGhError(commitRes.status, e.message));
    }
    const baseTreeSha = (await commitRes.json()).tree.sha;

    // 3. Har bir fayl uchun Git Blob yaratish (50 MB gacha video muammosiz yuklanadi!)
    const treeEntries = [];
    for (const [repoPath, base64Content] of Object.entries(filesMap)) {
      const blobRes = await fetch(`${GH_API_BASE}/git/blobs`, {
        method: "POST",
        headers,
        body: JSON.stringify({ content: base64Content, encoding: "base64" }),
      });
      if (!blobRes.ok) {
        const e = await blobRes.json().catch(() => ({}));
        throw new Error(formatGhError(blobRes.status, e.message));
      }
      const blobData = await blobRes.json();
      treeEntries.push({
        path: repoPath,
        mode: "100644",
        type: "blob",
        sha: blobData.sha,
      });
    }

    // 4. Yangi tree yaratish
    const treeRes = await fetch(`${GH_API_BASE}/git/trees`, {
      method: "POST",
      headers,
      body: JSON.stringify({ base_tree: baseTreeSha, tree: treeEntries }),
    });
    if (!treeRes.ok) {
      const e = await treeRes.json().catch(() => ({}));
      throw new Error(formatGhError(treeRes.status, e.message));
    }
    const newTreeSha = (await treeRes.json()).sha;

    // 5. Yangi commit yaratish
    const newCommitRes = await fetch(`${GH_API_BASE}/git/commits`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        message: commitMsg,
        tree: newTreeSha,
        parents: [headCommitSha],
      }),
    });
    if (!newCommitRes.ok) {
      const e = await newCommitRes.json().catch(() => ({}));
      throw new Error(formatGhError(newCommitRes.status, e.message));
    }
    const newCommitSha = (await newCommitRes.json()).sha;

    // 6. main branch ni yangi commitga yo'naltirish
    const patchRes = await fetch(`${GH_API_BASE}/git/refs/heads/${GH_BRANCH}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ sha: newCommitSha, force: false }),
    });
    if (!patchRes.ok) {
      const e = await patchRes.json().catch(() => ({}));
      throw new Error(formatGhError(patchRes.status, e.message));
    }
    return true;
  }

  async function syncStoreToGitHub(store, commitMsg = "Update Maktab 49 site data", extraFiles = {}) {
    if (!useStaticMode) return false;
    const token = getGitHubToken();
    if (!token) return false;
    store.updated_at = Math.floor(Date.now() / 1000);
    saveLocalStore(store);
    const jsonStr = JSON.stringify(store, null, 2);
    const filesMap = Object.assign({}, extraFiles, { "data.json": utf8ToBase64(jsonStr) });
    await ghCommitFiles(filesMap, commitMsg);
    showToast("Barcha qurilmalarga saqlandi ✓", "success");
    return true;
  }

  async function fetchCloudDataOnLoad() {
    const urls = [
      `${GH_RAW_BASE}/data.json?t=${Date.now()}`,
      `data.json?t=${Date.now()}`,
    ];
    for (const u of urls) {
      try {
        const res = await fetch(u, { cache: "no-store" });
        if (!res.ok) continue;
        const remote = await res.json();
        if (remote && remote.school && Array.isArray(remote.users)) {
          const local = loadLocalStoreRaw();
          // Agar bulutdagi data yangiroq bo'lsa yoki lokalda hali yo'q bo'lsa -> yangilash!
          if (!local || (remote.updated_at || 0) >= (local.updated_at || 0)) {
            saveLocalStore(remote);
          } else {
            // Har doim eng so'nggi remote users / events / gallery bilan birlashtirish
            local.users = remote.users;
            saveLocalStore(local);
          }
          return true;
        }
      } catch { /* keyingi manzilga o'tish */ }
    }
    return false;
  }

  // ==================== 3. STATIK STORE VA 4-URINISH / 120s BLOKLASH ====================
  const STORE_KEY = "maktab49_secure_store_v4";
  const SESSION_KEY = "maktab49_active_session_v4";
  const LOCKOUT_KEY = "maktab49_lockout_v4";
  const MAX_ATTEMPTS = 4;
  const LOCKOUT_SECONDS = 120;
  const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

  let toastTimer = null;
  function showToast(msg, type = "info") {
    const el = document.getElementById("global-toast");
    if (!el) return;
    el.textContent = msg;
    el.className = `global-toast ${type === "success" ? "toast-success" : type === "error" ? "toast-error" : ""}`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.add("hidden"), 3800);
  }

  function getSeedData() {
    const now = Math.floor(Date.now() / 1000);
    return {
      version: 4,
      updated_at: 1795667400,
      users: [
        {
          id: 1,
          username: "admin49",
          password_hash: "pbkdf2_sha256$260000$a0db61dddd4078117d094889f529494c775b9fc8dd3f81c19f9bc7b0bac0c192$acbfca0048c8476a6c6542b2b3735e31c9ccdc5d1e053c4ae7f8eae467b6d497",
          full_name: "Matsapayev Bekzod Dilshod o'g'li",
          role: "admin",
          position: "Tizim administratori",
          is_active: 1,
          created_at: now,
        },
        {
          id: 2,
          username: "direktor49",
          password_hash: "pbkdf2_sha256$260000$ec227df2fc878c30c74fe418ffb4152cc8505bad16a6136915b6cb3d0140c3b3$55703d3178f9eabdb52378cbdd079e5cae9a59cbbdc7ad04c397a51d785999dc",
          full_name: "Alimov Elyor Kuriyaz o'g'li",
          role: "director",
          position: "Maktab direktori",
          is_active: 1,
          created_at: now,
        },
      ],
      school: {
        school_number: "49",
        school_name: "49-sonli umumiy o'rta ta'lim maktabi",
        platform_name: "Maktab 49 Ta'lim Platformasi",
        region: "Qoraqalpog'iston Respublikasi",
        district: "Ellikqal'a tumani",
        community: "Soribiy OFY",
        full_address: "Qoraqalpog'iston Respublikasi, Ellikqal'a tumani, Soribiy OFY",
        location_detail: "Qoraqalpog'iston Respublikasi, Ellikqal'a tumani, Soribiy OFY (Barhayot MFY, Xabarchi ko'chasi, 305-uy)",
        location_lat: "41.572770",
        location_lng: "60.890981",
        founded_date: "01/09/1988",
        total_teachers: "43",
        deputy_directors: "2",
        total_students: "473",
        phone_1: "+998 88 654 30 06",
        phone_2: "+998 77 312 84 85",
        admin_name: "Matsapayev Bekzod Dilshod o'g'li",
      },
      leadership: [
        { id: 1, full_name: "Alimov Elyor Kuriyaz o'g'li", position: "Maktab direktori", category: "Direktor", phone: "+998 88 654 30 06", bio: "49-sonli umumiy o'rta ta'lim maktabining umumiy boshqaruvi, ta'lim sifati va rivojlanish strategiyasiga mas'ul." },
        { id: 2, full_name: "Matniyazov Muzaffar Ayitovich", position: "Direktor o'rinbosari", category: "Direktor o'rinbosari", phone: "+998 88 654 30 06", bio: "O'quv-tarbiya jarayonini tashkil etish, dars jadvali va pedagogik faoliyatni muvofiqlashtirish bo'yicha mas'ul." },
        { id: 3, full_name: "Abduraimov G'ayrat Tajiboy o'g'li", position: "Direktor o'rinbosari", category: "Direktor o'rinbosari", phone: "+998 77 312 84 85", bio: "Ma'naviy-ma'rifiy ishlar, o'quvchilar intizomi va maktab jamoasini qo'llab-quvvatlash bo'yicha mas'ul." },
        { id: 4, full_name: "Atadjanov Ikram Xakimovich", position: "Boshqaruv xodimi", category: "Boshqaruv xodimi", phone: "+998 77 312 84 85", bio: "Maktabning ma'muriy-xo'jalik va tashkiliy boshqaruv jarayonlariga mas'ul xodim." },
        { id: 5, full_name: "Matsapayev Bekzod Dilshod o'g'li", position: "Tizim administratori", category: "Axborot xavfsizligi va IT", phone: "+998 88 654 30 06 / +998 77 312 84 85", bio: "Maktab 49 ta'lim platformasining texnik barqarorligi, ma'lumotlar xavfsizligi va foydalanuvchi murojaatlariga mas'ul." },
      ],
      teachers: [
        { id: 1, full_name: "Allabergenova Nasiba Ismoilovna", subject: "O'qituvchi", category: "Pedagog xodim", phone: "", experience_years: 0 },
        { id: 2, full_name: "Amatov Jamoladdin Mirza o'g'li", subject: "O'qituvchi", category: "Pedagog xodim", phone: "", experience_years: 0 },
        { id: 3, full_name: "Ayitbayeva Fazilat Reyimbayevna", subject: "O'qituvchi", category: "Pedagog xodim", phone: "", experience_years: 0 },
        { id: 4, full_name: "Ayitov Javlonbek Muzaffar o'g'li", subject: "O'qituvchi", category: "Pedagog xodim", phone: "", experience_years: 0 },
        { id: 5, full_name: "Bobadjanova Olmaxon Ruslanbek qizi", subject: "O'qituvchi", category: "Pedagog xodim", phone: "", experience_years: 0 },
        { id: 6, full_name: "Doshanov Nurgali Muratovich", subject: "O'qituvchi", category: "Pedagog xodim", phone: "", experience_years: 0 },
        { id: 7, full_name: "Guzenbayeva Miyirxon Kamoladdin qizi", subject: "O'qituvchi", category: "Pedagog xodim", phone: "", experience_years: 0 },
        { id: 8, full_name: "Halillayeva Hosiyat Baxtiyorovna", subject: "O'qituvchi", category: "Pedagog xodim", phone: "", experience_years: 0 },
      ],
      gallery: [
        { id: 1, title: "Maktab old tomon ko'rinishi", category: "Old ko'rinish", description: "49-sonli umumiy o'rta ta'lim maktabining asosiy kirish qismi — o'zbek, qoraqalpoq va ingliz tillarida qutlov peshtaxtasi.", image_path: "entrance.jpg" },
        { id: 2, title: "Maktab binosi va hovlisi", category: "Old ko'rinish", description: "Soribiy OFY hududida joylashgan 49-maktabning old fasadi, ko'kalamzorlashtirilgan hovlisi va yorug' derazalari.", image_path: "yard.jpg" },
        { id: 3, title: "Zamonaviy o'quv sinf xonasi", category: "Sinf xonalari", description: "Yangi parta va stullar, o'quv ko'rgazmali qurollari hamda keng doska bilan jihozlangan yorug' sinf xonasi.", image_path: "classroom.jpg" },
        { id: 4, title: "Maktab axborot-kutubxona markazi", category: "Kutubxona", description: "\"Eng yaxshi kitobxon\" va \"Uchinchi Renessansga mening hissam\" burchaklariga ega boy kitob fondli o'quv zali.", image_path: "library.jpg" },
        { id: 5, title: "Maktab asosiy foyesi", category: "Ichki ko'rinish", description: "\"Yangi O'zbekiston — maktab ostonasidan boshlanadi\" shiori, dars jadvali va axborot ekraniga ega markaziy foye.", image_path: "hall_main.jpg" },
        { id: 6, title: "Davlat ramzlari va e'lonlar burchagi", category: "Ichki ko'rinish", description: "O'zbekiston va Qoraqalpog'iston davlat ramzlari, buyruqlar, e'lonlar va yurist maslahati stendlari.", image_path: "hall_board.jpg" },
        { id: 7, title: "O'quv binosi yo'lagi", category: "Ichki ko'rinish", description: "Milliy uyg'onish davri ma'rifatparvarlari portretlari bilan bezatilgan toza va keng maktab yo'lagi.", image_path: "corridor.jpg" },
      ],
      events: [
        {
          id: 1,
          title: "O'quvchilar tadbiri",
          media_type: "video",
          event_date: "2026-11-25",
          description: "49-sonli umumiy o'rta ta'lim maktabi o'quvchilari hayotidan videolavha.",
          media_path: "oquvchilar.mp4",
          poster_path: "entrance.jpg",
          created_at: now,
        },
      ],
      schedule: [
        { id: 1, class_name: "10-A", day_of_week: 1, lesson_number: 1, time_range: "08:30 - 09:15", subject: "Kelajak soati" },
        { id: 2, class_name: "10-A", day_of_week: 1, lesson_number: 2, time_range: "09:20 - 10:05", subject: "Adabiyot" },
        { id: 3, class_name: "10-A", day_of_week: 1, lesson_number: 3, time_range: "10:10 - 10:55", subject: "Rus tili" },
        { id: 4, class_name: "10-A", day_of_week: 1, lesson_number: 4, time_range: "11:00 - 11:45", subject: "Algebra" },
        { id: 5, class_name: "10-A", day_of_week: 1, lesson_number: 5, time_range: "11:50 - 12:35", subject: "Geografiya" },
        { id: 6, class_name: "10-A", day_of_week: 2, lesson_number: 1, time_range: "08:30 - 09:15", subject: "O'zbekiston tarixi" },
        { id: 7, class_name: "10-A", day_of_week: 2, lesson_number: 2, time_range: "09:20 - 10:05", subject: "Fizika" },
        { id: 8, class_name: "10-A", day_of_week: 2, lesson_number: 3, time_range: "10:10 - 10:55", subject: "Huquq" },
        { id: 9, class_name: "10-A", day_of_week: 2, lesson_number: 4, time_range: "11:00 - 11:45", subject: "Biologiya" },
        { id: 10, class_name: "10-A", day_of_week: 2, lesson_number: 5, time_range: "11:50 - 12:35", subject: "Jismoniy tarbiya" },
        { id: 11, class_name: "10-A", day_of_week: 2, lesson_number: 6, time_range: "12:40 - 13:25", subject: "Algebra" },
        { id: 12, class_name: "10-A", day_of_week: 3, lesson_number: 1, time_range: "08:30 - 09:15", subject: "Ingliz tili" },
        { id: 13, class_name: "10-A", day_of_week: 3, lesson_number: 2, time_range: "09:20 - 10:05", subject: "Tarbiya" },
        { id: 14, class_name: "10-A", day_of_week: 3, lesson_number: 3, time_range: "10:10 - 10:55", subject: "Informatika" },
        { id: 15, class_name: "10-A", day_of_week: 3, lesson_number: 4, time_range: "11:00 - 11:45", subject: "Ona tili" },
        { id: 16, class_name: "10-A", day_of_week: 3, lesson_number: 5, time_range: "11:50 - 12:35", subject: "ChQBT" },
        { id: 17, class_name: "10-A", day_of_week: 4, lesson_number: 1, time_range: "08:30 - 09:15", subject: "Adabiyot" },
        { id: 18, class_name: "10-A", day_of_week: 4, lesson_number: 2, time_range: "09:20 - 10:05", subject: "Geografiya" },
        { id: 19, class_name: "10-A", day_of_week: 4, lesson_number: 3, time_range: "10:10 - 10:55", subject: "Qoraqalpoq tili" },
        { id: 20, class_name: "10-A", day_of_week: 4, lesson_number: 4, time_range: "11:00 - 11:45", subject: "ChQBT" },
        { id: 21, class_name: "10-A", day_of_week: 4, lesson_number: 5, time_range: "11:50 - 12:35", subject: "Kimyo" },
        { id: 22, class_name: "10-A", day_of_week: 4, lesson_number: 6, time_range: "12:40 - 13:25", subject: "Fizika" },
        { id: 23, class_name: "10-A", day_of_week: 5, lesson_number: 1, time_range: "08:30 - 09:15", subject: "Jismoniy tarbiya" },
        { id: 24, class_name: "10-A", day_of_week: 5, lesson_number: 2, time_range: "09:20 - 10:05", subject: "Algebra" },
        { id: 25, class_name: "10-A", day_of_week: 5, lesson_number: 3, time_range: "10:10 - 10:55", subject: "Informatika" },
        { id: 26, class_name: "10-A", day_of_week: 5, lesson_number: 4, time_range: "11:00 - 11:45", subject: "Kimyo" },
        { id: 27, class_name: "10-A", day_of_week: 5, lesson_number: 5, time_range: "11:50 - 12:35", subject: "Geometriya" },
        { id: 28, class_name: "10-A", day_of_week: 6, lesson_number: 1, time_range: "08:30 - 09:15", subject: "Qoraqalpoq tarixi" },
        { id: 29, class_name: "10-A", day_of_week: 6, lesson_number: 2, time_range: "09:20 - 10:05", subject: "Rus tili" },
        { id: 30, class_name: "10-A", day_of_week: 6, lesson_number: 3, time_range: "10:10 - 10:55", subject: "Geometriya" },
        { id: 31, class_name: "10-A", day_of_week: 6, lesson_number: 4, time_range: "11:00 - 11:45", subject: "Ingliz tili" },
        { id: 32, class_name: "10-A", day_of_week: 6, lesson_number: 5, time_range: "11:50 - 12:35", subject: "Biologiya" },
      ],
      appeals: [],
      audit_logs: [
        {
          id: 1,
          event_type: "SYSTEM_INIT",
          username: "system",
          ip_address: "github-cloud",
          details: "Maktab 49 himoyalangan ta'lim platformasi ishga tushirildi.",
          severity: "info",
          created_at: now,
        },
      ],
    };
  }

  function loadLocalStoreRaw() {
    try {
      const raw = localStorage.getItem(STORE_KEY);
      if (raw) return JSON.parse(raw);
      // Oldingi v2 xotirasidan video/tadbirlarni ko'chirib olish
      const oldRaw = localStorage.getItem("maktab49_secure_store_v2");
      if (oldRaw) {
        const old = JSON.parse(oldRaw);
        localStorage.setItem(STORE_KEY, JSON.stringify(old));
        return old;
      }
    } catch { /* ignore */ }
    return null;
  }

  function loadLocalStore() {
    const existing = loadLocalStoreRaw();
    if (existing) {
      if (!Array.isArray(existing.events)) existing.events = getSeedData().events;
      return existing;
    }
    const seed = getSeedData();
    localStorage.setItem(STORE_KEY, JSON.stringify(seed));
    return seed;
  }

  function saveLocalStore(store) {
    localStorage.setItem(STORE_KEY, JSON.stringify(store));
  }

  function addAudit(store, event_type, username, details, severity = "info") {
    store.audit_logs.unshift({
      id: Date.now(),
      event_type,
      username,
      ip_address: "https-client",
      details,
      severity,
      created_at: Math.floor(Date.now() / 1000),
    });
    store.audit_logs = store.audit_logs.slice(0, 80);
  }

  function getStaticSession() {
    try {
      const raw = sessionStorage.getItem(SESSION_KEY);
      if (!raw) return null;
      const sess = JSON.parse(raw);
      if (!sess || Date.now() > sess.expires_at) {
        sessionStorage.removeItem(SESSION_KEY);
        return null;
      }
      return sess;
    } catch {
      return null;
    }
  }

  // ---- 4 urinish / 120 soniyalik jonli taymer boshqaruvi ----
  function getLockoutState() {
    try {
      const raw = localStorage.getItem(LOCKOUT_KEY);
      if (!raw) return { count: 0, lockUntil: 0 };
      const st = JSON.parse(raw);
      if (st.lockUntil && Date.now() >= st.lockUntil) {
        localStorage.removeItem(LOCKOUT_KEY);
        return { count: 0, lockUntil: 0 };
      }
      return { count: Number(st.count || 0), lockUntil: Number(st.lockUntil || 0) };
    } catch {
      return { count: 0, lockUntil: 0 };
    }
  }

  function setLockoutState(st) {
    localStorage.setItem(LOCKOUT_KEY, JSON.stringify(st));
  }

  function clearLockoutState() {
    localStorage.removeItem(LOCKOUT_KEY);
  }

  let lockoutInterval = null;

  function formatCountdown(sec) {
    const s = Math.max(0, Math.ceil(sec));
    const mm = String(Math.floor(s / 60)).padStart(2, "0");
    const ss = String(s % 60).padStart(2, "0");
    return `${mm}:${ss} (${s} soniya)`;
  }

  function startLockoutCountdown(secondsOrUntilMs, isTimestamp = false) {
    const until = isTimestamp ? secondsOrUntilMs : Date.now() + secondsOrUntilMs * 1000;
    setLockoutState({ count: MAX_ATTEMPTS, lockUntil: until });

    const box = document.getElementById("login-lockout-box");
    const cd = document.getElementById("lockout-countdown");
    const errEl = document.getElementById("login-error");
    const uIn = document.getElementById("login-username");
    const pIn = document.getElementById("login-password");
    const btn = document.getElementById("login-submit-btn");

    if (lockoutInterval) clearInterval(lockoutInterval);

    function tick() {
      const remSec = Math.ceil((until - Date.now()) / 1000);
      if (remSec <= 0) {
        clearInterval(lockoutInterval);
        lockoutInterval = null;
        clearLockoutState();
        box?.classList.add("hidden");
        if (uIn) uIn.disabled = false;
        if (pIn) pIn.disabled = false;
        if (btn) btn.disabled = false;
        if (errEl) {
          errEl.textContent = "Bloklash vaqti tugadi. Endi qayta urinib ko'rishingiz mumkin.";
          errEl.className = "alert-box alert-success";
        }
        return;
      }
      errEl?.classList.add("hidden");
      box?.classList.remove("hidden");
      if (cd) cd.textContent = formatCountdown(remSec);
      if (uIn) uIn.disabled = true;
      if (pIn) pIn.disabled = true;
      if (btn) btn.disabled = true;
    }

    tick();
    lockoutInterval = setInterval(tick, 1000);
  }

  function restoreLockoutIfActive() {
    const st = getLockoutState();
    if (st.lockUntil && st.lockUntil > Date.now()) {
      startLockoutCountdown(st.lockUntil, true);
      return true;
    }
    return false;
  }

  async function staticApiDispatch(url, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    const body = options.body ? JSON.parse(options.body) : {};
    const store = loadLocalStore();

    if (url === "/api/auth/me" && method === "GET") {
      const sess = getStaticSession();
      if (!sess) return { authenticated: false };
      return { authenticated: true, csrf_token: sess.csrf_token, user: sess.user };
    }

    if (url === "/api/auth/login" && method === "POST") {
      const username = String(body.username || "").trim();
      const password = String(body.password || "");
      const lockSt = getLockoutState();
      if (lockSt.lockUntil && lockSt.lockUntil > Date.now()) {
        const rem = Math.ceil((lockSt.lockUntil - Date.now()) / 1000);
        const err = new Error(`4 marta noto'g'ri kiritildi. ${rem} soniya kuting.`);
        err.retryAfter = rem;
        throw err;
      }

      const user = store.users.find((u) => u.username.toLowerCase() === username.toLowerCase() && u.is_active);
      const valid = user ? await verifyPasswordWeb(password, user.password_hash) : false;

      if (!user || !valid) {
        const nextCount = lockSt.count + 1;
        const remaining = Math.max(MAX_ATTEMPTS - nextCount, 0);
        if (remaining === 0) {
          setLockoutState({ count: MAX_ATTEMPTS, lockUntil: Date.now() + LOCKOUT_SECONDS * 1000 });
          addAudit(store, "LOGIN_LOCKED", username || "noma'lum", `4 ta xato urinish tufayli ${LOCKOUT_SECONDS} soniyaga bloklandi.`, "danger");
          saveLocalStore(store);
          const err = new Error(`4 marta noto'g'ri kiritildi. ${LOCKOUT_SECONDS} soniya kuting.`);
          err.retryAfter = LOCKOUT_SECONDS;
          throw err;
        }
        setLockoutState({ count: nextCount, lockUntil: 0 });
        addAudit(store, "LOGIN_FAILED", username || "noma'lum", `Noto'g'ri login yoki parol (qolgan: ${remaining}).`, "warning");
        saveLocalStore(store);
        throw new Error(`Login yoki parol noto'g'ri. Qolgan urinishlar soni: ${remaining}.`);
      }

      if (user.role !== "admin" && user.role !== "director") {
        addAudit(store, "LOGIN_DENIED", user.username, "Faqat admin va direktor kirishi mumkin.", "warning");
        saveLocalStore(store);
        throw new Error("Tizimga kirish faqat Tizim administratori va Maktab direktori uchun!");
      }

      clearLockoutState();
      const pubUser = { id: user.id, username: user.username, full_name: user.full_name, role: user.role, position: user.position };
      const csrf = bytesToHex(getRandomBytes(16));
      sessionStorage.setItem(SESSION_KEY, JSON.stringify({ user: pubUser, csrf_token: csrf, expires_at: Date.now() + SESSION_TTL_MS }));
      addAudit(store, "LOGIN_SUCCESS", user.username, `Muvaffaqiyatli kirish (${user.role}).`, "info");
      saveLocalStore(store);
      return { ok: true, csrf_token: csrf, user: pubUser };
    }

    const sess = getStaticSession();
    const isManager = Boolean(sess && (sess.user.role === "admin" || sess.user.role === "director"));
    const isAdmin = Boolean(sess && sess.user.role === "admin");

    if (url === "/api/dashboard" && method === "GET") {
      return {
        school: store.school,
        leadership: store.leadership,
        teachers: store.teachers,
        gallery: store.gallery,
        events: store.events,
        schedule: store.schedule,
        appeals: isManager ? store.appeals : [],
      };
    }

    if (url === "/api/appeals" && method === "POST") {
      if (!body.sender_name || !body.phone || !body.message) throw new Error("Barcha majburiy maydonlarni to'ldiring.");
      const actor = sess ? sess.user.username : "mehmon";
      store.appeals.unshift({
        id: Date.now(),
        sender_name: body.sender_name,
        phone: body.phone,
        topic: body.topic || "Umumiy murojaat",
        message: body.message,
        status: "Yangi",
        created_by: actor,
        created_at: Math.floor(Date.now() / 1000),
      });
      addAudit(store, "APPEAL_SUBMIT", actor, `Yangi murojaat: ${body.topic || "Umumiy"}`, "info");
      saveLocalStore(store);
      if (getGitHubToken()) { try { await syncStoreToGitHub(store, "New appeal submitted"); } catch { /* ignore */ } }
      return { ok: true, message: "Murojaatingiz xavfsiz qabul qilindi!" };
    }

    if (!sess || !isManager) throw new Error("Bu amal faqat Tizim administratori va Maktab direktori uchun.");

    if (url === "/api/auth/logout" && method === "POST") {
      addAudit(store, "LOGOUT", sess.user.username, "Foydalanuvchi tizimdan chiqdi.", "info");
      saveLocalStore(store);
      sessionStorage.removeItem(SESSION_KEY);
      return { ok: true };
    }

    if (url === "/api/auth/change-password" && method === "POST") {
      if (!isAdmin) throw new Error("Parol o'zgartirish bo'limi faqat Tizim administratori uchun!");
      const u = store.users.find((x) => x.id === sess.user.id);
      if (!u || !(await verifyPasswordWeb(body.current_password || "", u.password_hash))) {
        throw new Error("Joriy parol noto'g'ri kiritildi.");
      }
      const pwErr = validatePasswordStrength(body.new_password);
      if (pwErr) throw new Error(pwErr);
      u.password_hash = await hashPasswordWeb(body.new_password);
      addAudit(store, "PASSWORD_CHANGE", u.username, "Administrator parolini yangiladi.", "info");
      saveLocalStore(store);
      await syncStoreToGitHub(store, "Admin password updated");
      return { ok: true, message: "Admin paroli muvaffaqiyatli va xavfsiz yangilandi!" };
    }

    if (url === "/api/admin/reset-password" && method === "POST") {
      if (!isAdmin) throw new Error("Faqat Tizim administratori parollarni o'zgartira oladi!");
      const target = store.users.find((x) => x.username.toLowerCase() === String(body.username || "").trim().toLowerCase());
      if (!target) throw new Error("Bunday loginli hisob topilmadi.");
      const pwErr = validatePasswordStrength(body.new_password);
      if (pwErr) throw new Error(pwErr);
      target.password_hash = await hashPasswordWeb(body.new_password);
      addAudit(store, "ADMIN_PASSWORD_RESET", sess.user.username, `${target.username} paroli yangilandi.`, "warning");
      saveLocalStore(store);
      await syncStoreToGitHub(store, `Password reset for ${target.username}`);
      return { ok: true, message: `"${target.username}" hisobining paroli yangilandi!` };
    }

    if (url === "/api/admin/users" && method === "POST") {
      if (!isAdmin) throw new Error("Faqat Tizim administratori yangi hisob yarata oladi.");
      if (store.users.some((u) => u.username.toLowerCase() === String(body.username || "").toLowerCase())) {
        throw new Error("Bunday login allaqachon mavjud.");
      }
      const pwErr = validatePasswordStrength(body.password);
      if (pwErr) throw new Error(pwErr);
      store.users.push({
        id: Date.now(),
        username: body.username,
        password_hash: await hashPasswordWeb(body.password),
        full_name: body.full_name,
        role: body.role === "admin" ? "admin" : "director",
        position: body.position || "Rahbariyat",
        is_active: 1,
        created_at: Math.floor(Date.now() / 1000),
      });
      addAudit(store, "USER_CREATE", sess.user.username, `Yangi hisob yaratildi: ${body.username}`, "info");
      saveLocalStore(store);
      await syncStoreToGitHub(store, `Create user ${body.username}`);
      return { ok: true };
    }

    if (url === "/api/school" && method === "PUT") {
      const allowed = ["total_students", "total_teachers", "deputy_directors", "founded_date", "phone_1", "phone_2"];
      for (const k of allowed) {
        if (body[k] !== undefined && String(body[k]).trim() !== "") store.school[k] = String(body[k]).trim();
      }
      addAudit(store, "SCHOOL_INFO_UPDATE", sess.user.username, "Maktab ko'rsatkichlari yangilandi.", "info");
      saveLocalStore(store);
      await syncStoreToGitHub(store, "Update school info");
      return { ok: true, school: store.school };
    }

    if (url === "/api/leadership" && method === "POST") {
      store.leadership.push({ id: Date.now(), full_name: body.full_name, position: body.position, category: body.position || "Rahbariyat", phone: body.phone || "", bio: body.bio || "" });
      addAudit(store, "LEADERSHIP_ADD", sess.user.username, `Rahbariyatga qo'shildi: ${body.full_name}`, "info");
      saveLocalStore(store);
      await syncStoreToGitHub(store, "Add leadership member");
      return { ok: true, leadership: store.leadership };
    }

    if (url.startsWith("/api/leadership/") && method === "PUT") {
      const id = Number(url.split("/").pop());
      const item = store.leadership.find((x) => x.id === id);
      if (!item) throw new Error("Topilmadi.");
      item.full_name = body.full_name; item.position = body.position; item.phone = body.phone || ""; item.bio = body.bio || "";
      addAudit(store, "LEADERSHIP_UPDATE", sess.user.username, `Rahbariyat tahrirlandi: ${body.full_name}`, "info");
      saveLocalStore(store);
      await syncStoreToGitHub(store, "Update leadership member");
      return { ok: true, leadership: store.leadership };
    }

    if (url.startsWith("/api/leadership/") && method === "DELETE") {
      const id = Number(url.split("/").pop());
      store.leadership = store.leadership.filter((x) => x.id !== id);
      addAudit(store, "LEADERSHIP_DELETE", sess.user.username, `Rahbariyat #${id} o'chirildi.`, "warning");
      saveLocalStore(store);
      await syncStoreToGitHub(store, "Delete leadership member");
      return { ok: true, leadership: store.leadership };
    }

    if (url === "/api/teachers" && method === "POST") {
      if (!body.full_name || body.full_name.length < 3) throw new Error("F.I.Sh. kamida 3 ta harf bo'lishi kerak.");
      store.teachers.push({ id: Date.now(), full_name: body.full_name, subject: body.subject || "O'qituvchi", category: body.category || "Pedagog xodim", phone: body.phone || "", experience_years: Number(body.experience_years || 0) });
      store.teachers.sort((a, b) => a.full_name.localeCompare(b.full_name));
      addAudit(store, "TEACHER_ADD", sess.user.username, `Yangi o'qituvchi qo'shildi: ${body.full_name}`, "info");
      saveLocalStore(store);
      await syncStoreToGitHub(store, "Add teacher");
      return { ok: true, teachers: store.teachers };
    }

    if (url.startsWith("/api/teachers/") && method === "PUT") {
      const id = Number(url.split("/").pop());
      const t = store.teachers.find((x) => x.id === id);
      if (!t) throw new Error("O'qituvchi topilmadi.");
      t.full_name = body.full_name; t.subject = body.subject || "O'qituvchi"; t.category = body.category || "Pedagog xodim"; t.phone = body.phone || ""; t.experience_years = Number(body.experience_years || 0);
      addAudit(store, "TEACHER_UPDATE", sess.user.username, `Tahrirlandi: ${body.full_name}`, "info");
      saveLocalStore(store);
      await syncStoreToGitHub(store, "Update teacher");
      return { ok: true, teachers: store.teachers };
    }

    if (url.startsWith("/api/teachers/") && method === "DELETE") {
      const id = Number(url.split("/").pop());
      store.teachers = store.teachers.filter((x) => x.id !== id);
      addAudit(store, "TEACHER_DELETE", sess.user.username, `O'qituvchi #${id} o'chirildi.`, "warning");
      saveLocalStore(store);
      await syncStoreToGitHub(store, "Delete teacher");
      return { ok: true, teachers: store.teachers };
    }

    if (url === "/api/schedule" && method === "PUT") {
      const cn = body.class_name || "10-A";
      const d = Number(body.day_of_week);
      const l = Number(body.lesson_number);
      const subj = String(body.subject || "").trim();
      const idx = store.schedule.findIndex((s) => s.class_name === cn && s.day_of_week === d && s.lesson_number === l);
      if (!subj) {
        if (idx >= 0) store.schedule.splice(idx, 1);
      } else if (idx >= 0) {
        store.schedule[idx].time_range = body.time_range;
        store.schedule[idx].subject = subj;
      } else {
        store.schedule.push({ id: Date.now(), class_name: cn, day_of_week: d, lesson_number: l, time_range: body.time_range, subject: subj });
      }
      addAudit(store, "SCHEDULE_UPDATE", sess.user.username, `Dars jadvali yangilandi: ${cn}, kun #${d}, ${l}-dars -> ${subj || "bo'sh"}`, "info");
      saveLocalStore(store);
      await syncStoreToGitHub(store, "Update class schedule");
      return { ok: true, schedule: store.schedule };
    }

    if (url.startsWith("/api/events/") && method === "DELETE") {
      const id = Number(url.split("/").pop());
      const ev = store.events.find((x) => x.id === id);
      if (ev && typeof ev.media_path === "string" && ev.media_path.startsWith("idb://")) {
        await deleteBlobFromIDB(ev.media_path.slice(6));
      }
      store.events = store.events.filter((x) => x.id !== id);
      addAudit(store, "EVENT_DELETE", sess.user.username, `Tadbir #${id} o'chirildi.`, "warning");
      saveLocalStore(store);
      await syncStoreToGitHub(store, "Delete event");
      return { ok: true, events: store.events };
    }

    if (url.startsWith("/api/gallery/") && method === "DELETE") {
      const id = Number(url.split("/").pop());
      const g = store.gallery.find((x) => x.id === id);
      if (g && typeof g.image_path === "string" && g.image_path.startsWith("idb://")) {
        await deleteBlobFromIDB(g.image_path.slice(6));
      }
      store.gallery = store.gallery.filter((x) => x.id !== id);
      addAudit(store, "GALLERY_DELETE", sess.user.username, `Sinf/maktab rasmi #${id} o'chirildi.`, "warning");
      saveLocalStore(store);
      await syncStoreToGitHub(store, "Delete gallery photo");
      return { ok: true, gallery: store.gallery };
    }

    if (url === "/api/appeals" && method === "GET") return { appeals: store.appeals };

    if (url.startsWith("/api/appeals/") && method === "PUT") {
      const id = Number(url.split("/").pop());
      const item = store.appeals.find((a) => a.id === id);
      if (item) item.status = body.status;
      saveLocalStore(store);
      await syncStoreToGitHub(store, "Update appeal status");
      return { ok: true, appeals: store.appeals };
    }

    if (url === "/api/admin/security" && method === "GET") return { audit_logs: store.audit_logs };

    throw new Error("So'rov manzili topilmadi.");
  }

  // ==================== 4. ASOSIY ILOVA HOLATI VA UI ====================
  let useStaticMode = false;

  const state = {
    user: null,
    csrfToken: "",
    school: {},
    leadership: [],
    teachers: [],
    gallery: [],
    events: [],
    schedule: [],
    appeals: [],
    auditLogs: [],
    currentPage: "home",
    scheduleView: "daily",
    selectedDay: getInitialSchoolDay(),
    selectedClass: "10-A",
    galleryFilter: "all",
    eventsFilter: "all",
    lightboxItems: [],
    lightboxIndex: 0,
  };

  const PAGE_TITLES = {
    home: "Bosh sahifa",
    schedule: "Dars jadvali (10-A sinf)",
    leadership: "Maktab rahbariyati",
    teachers: "O'qituvchilar tarkibi",
    students: "O'quvchilar va ta'lim",
    gallery: "Sinf xonalari va galereya",
    events: "Maktab tadbirlari",
    location: "Maktab lokatsiyasi",
    contact: "Murojaatlar va aloqa",
    security: "Boshqaruv va xavfsizlik",
  };

  const ROLE_LABELS = { admin: "Tizim administratori", director: "Maktab direktori" };

  const DAYS_META = [
    { day: 1, short: "Dush", full: "Dushanba" },
    { day: 2, short: "Sesh", full: "Seshanba" },
    { day: 3, short: "Chor", full: "Chorshanba" },
    { day: 4, short: "Pay", full: "Payshanba" },
    { day: 5, short: "Jum", full: "Juma" },
    { day: 6, short: "Shan", full: "Shanba" },
    { day: 7, short: "Yak", full: "Yakshanba" },
  ];

  const DEFAULT_BELL_TIMES = {
    1: "08:30 - 09:15", 2: "09:20 - 10:05", 3: "10:10 - 10:55",
    4: "11:00 - 11:45", 5: "11:50 - 12:35", 6: "12:40 - 13:25",
  };

  const UZ_MONTHS = ["yanvar", "fevral", "mart", "aprel", "may", "iyun", "iyul", "avgust", "sentabr", "oktabr", "noyabr", "dekabr"];

  function getInitialSchoolDay() {
    const jsDay = new Date().getDay();
    return jsDay === 0 ? 1 : jsDay;
  }

  function getCurrentWeekDates() {
    const now = new Date();
    const jsDay = now.getDay();
    const diffToMon = jsDay === 0 ? -6 : 1 - jsDay;
    const monday = new Date(now.getFullYear(), now.getMonth(), now.getDate() + diffToMon);
    return DAYS_META.map((d, idx) => {
      const dt = new Date(monday.getFullYear(), monday.getMonth(), monday.getDate() + idx);
      return { ...d, dateNum: dt.getDate(), monthName: UZ_MONTHS[dt.getMonth()] };
    });
  }

  function applyTheme(theme) {
    const normalized = theme === "dark" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", normalized);
    localStorage.setItem("maktab49_theme", normalized);
    const metaTheme = document.querySelector('meta[name="theme-color"]');
    if (metaTheme) metaTheme.setAttribute("content", normalized === "dark" ? "#0b1120" : "#ffffff");
    document.querySelectorAll("[data-theme-toggle]").forEach((btn) => {
      const isDark = normalized === "dark";
      btn.querySelector(".icon-moon")?.classList.toggle("hidden", isDark);
      btn.querySelector(".icon-sun")?.classList.toggle("hidden", !isDark);
      const label = btn.querySelector(".theme-toggle-label");
      if (label) label.textContent = isDark ? "Kunduzgi rejim" : "Tungi rejim";
    });
  }

  document.querySelectorAll("[data-theme-toggle]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const cur = document.documentElement.getAttribute("data-theme") || "light";
      applyTheme(cur === "dark" ? "light" : "dark");
    });
  });
  applyTheme(localStorage.getItem("maktab49_theme") || "light");

  function esc(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function getInitials(name) {
    const parts = String(name || "M4").trim().split(/\s+/);
    return ((parts[0]?.[0] || "") + (parts[1]?.[0] || "")).toUpperCase() || "M4";
  }

  function formatTimestamp(ts) {
    if (!ts) return "—";
    return new Date(ts * 1000).toLocaleString("uz-UZ", {
      year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
    });
  }

  async function apiFetch(url, options = {}) {
    if (useStaticMode) return staticApiDispatch(url, options);
    const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
    if (state.csrfToken && options.method && options.method !== "GET") headers["X-CSRF-Token"] = state.csrfToken;
    try {
      const res = await fetch(url, { credentials: "same-origin", ...options, headers });
      const contentType = res.headers.get("content-type") || "";
      if (!contentType.includes("application/json")) {
        useStaticMode = true;
        return staticApiDispatch(url, options);
      }
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const err = new Error(data.error || "Server xatoligi yuz berdi.");
        err.status = res.status;
        if (data.retry_after) err.retryAfter = data.retry_after;
        throw err;
      }
      return data;
    } catch (err) {
      if (err && err.status) throw err;
      useStaticMode = true;
      return staticApiDispatch(url, options);
    }
  }

  const loginView = document.getElementById("login-view");
  const appView = document.getElementById("app-view");
  const loginForm = document.getElementById("login-form");
  const loginUsername = document.getElementById("login-username");
  const loginPassword = document.getElementById("login-password");
  const loginError = document.getElementById("login-error");
  const loginSubmitBtn = document.getElementById("login-submit-btn");
  const hintUsername = document.getElementById("hint-username");
  const hintPassword = document.getElementById("hint-password");
  const sidebar = document.getElementById("sidebar");
  const sidebarBackdrop = document.getElementById("sidebar-backdrop");
  const sidebarToggleBtn = document.getElementById("sidebar-toggle-btn");

  function syncHints() {
    hintUsername.classList.toggle("is-filled", loginUsername.value.trim().length > 0);
    hintPassword.classList.toggle("is-filled", loginPassword.value.length > 0);
  }
  loginUsername.addEventListener("input", syncHints);
  loginPassword.addEventListener("input", syncHints);

  document.getElementById("toggle-pw-btn").addEventListener("click", () => {
    const isPw = loginPassword.type === "password";
    loginPassword.type = isPw ? "text" : "password";
    document.getElementById("eye-icon-open").classList.toggle("hidden", isPw);
    document.getElementById("eye-icon-closed").classList.toggle("hidden", !isPw);
  });

  function openModal(id) { document.getElementById(id)?.classList.remove("hidden"); }
  function closeModal(id) { document.getElementById(id)?.classList.add("hidden"); }
  document.querySelectorAll("[data-close-modal]").forEach((el) => el.addEventListener("click", () => closeModal(el.dataset.closeModal)));
  document.getElementById("open-help-btn").addEventListener("click", () => openModal("help-modal"));
  document.getElementById("open-help-btn-2").addEventListener("click", () => openModal("help-modal"));

  function updateCloudStatusUI() {
    const badge = document.getElementById("gh-sync-status-badge");
    const banner = document.getElementById("events-cloud-banner");
    const bannerText = document.getElementById("events-cloud-status-text");
    const token = getGitHubToken();

    if (!useStaticMode) {
      if (badge) badge.textContent = "Lokal SQLite serveri faol ✓";
      banner?.classList.add("hidden");
      return;
    }

    if (token) {
      if (badge) {
        badge.textContent = "GitHub Cloud ulangan ✓";
        badge.style.background = "rgba(22,163,74,0.14)";
        badge.style.color = "#15803d";
      }
      if (banner && bannerText) {
        banner.classList.add("is-connected");
        bannerText.textContent = "GitHub Cloud ulangan ✓ — Yuklagan barcha rasm va videolaringiz hamma qurilmalarda ko'rinadi!";
      }
    } else {
      if (badge) {
        badge.textContent = "Ulanmagan (faqat shu qurilma)";
        badge.style.background = "";
        badge.style.color = "";
      }
      if (banner && bannerText) {
        banner.classList.remove("is-connected");
        bannerText.textContent = "Yuklangan video/rasmlar barcha qurilmalarda ko'rinishi uchun Boshqaruv bo'limida GitHub kalitini bir marta ulang.";
      }
    }
  }

  // GitHub Cloud ulash / sinash / qo'lda yuklash
  document.getElementById("gh-token-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fb = document.getElementById("gh-token-feedback");
    const btn = document.getElementById("gh-connect-btn");
    const token = document.getElementById("gh-token-input").value.trim();
    fb.className = "alert-box hidden";
    if (!token) {
      fb.textContent = "Iltimos, GitHub Tokenni kiriting.";
      fb.className = "alert-box alert-error";
      return;
    }
    btn.disabled = true;
    btn.textContent = "Tekshirilmoqda...";
    try {
      const headers = { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" };
      const uRes = await fetch("https://api.github.com/user", { headers, cache: "no-store" });
      if (!uRes.ok) {
        throw new Error("Token noto'g'ri yoki muddati o'tgan. Yangi token yaratib qayta urinib ko'ring.");
      }
      // Classic token (ghp_...) uchun 'repo' yozish ruxsati borligini aniq tekshirish!
      const scopes = (uRes.headers.get("x-oauth-scopes") || "").toLowerCase();
      if (token.startsWith("ghp_") && !scopes.includes("repo")) {
        throw new Error("Bu Classic tokenda 'repo' katagi belgilanmagan! Yuqoridagi 'Tayyor GitHub Token yaratish' havolasidan 'repo' belgilangan yangi token yarating.");
      }
      const rRes = await fetch(`${GH_API_BASE}/contents/data.json?ref=${GH_BRANCH}&_t=${Date.now()}`, { headers, cache: "no-store" });
      if (!rRes.ok) {
        throw new Error("Tokenda maktab-49 repozitoriysiga ruxsat yo'q. Classic token (repo belgilangan) yarating.");
      }
      localStorage.setItem(GH_TOKEN_KEY, token);
      document.getElementById("gh-token-input").value = "";
      updateCloudStatusUI();
      fb.textContent = "GitHub muvaffaqiyatli ulandi! Endi barcha o'zgarishlar va videolar hamma qurilmalarga avtomatik saqlanadi.";
      fb.className = "alert-box alert-success";
      showToast("GitHub Cloud ulandi ✓", "success");
    } catch (err) {
      fb.textContent = err.message;
      fb.className = "alert-box alert-error";
    } finally {
      btn.disabled = false;
      btn.textContent = "Sinash va Ulash";
    }
  });

  document.getElementById("gh-disconnect-btn")?.addEventListener("click", () => {
    localStorage.removeItem(GH_TOKEN_KEY);
    updateCloudStatusUI();
    showToast("GitHub ulanishi uzildi.", "info");
  });

  document.getElementById("gh-push-now-btn")?.addEventListener("click", async () => {
    const fb = document.getElementById("gh-token-feedback");
    fb.className = "alert-box hidden";
    if (!getGitHubToken()) {
      fb.textContent = "Avval yuqorida GitHub Tokenni kiriting va 'Sinash va Ulash' tugmasini bosing.";
      fb.className = "alert-box alert-error";
      return;
    }
    const btn = document.getElementById("gh-push-now-btn");
    btn.disabled = true;
    btn.textContent = "Yuklanmoqda...";
    try {
      const store = loadLocalStore();
      const extraFiles = {};
      for (const ev of store.events) {
        if (typeof ev.media_path === "string" && ev.media_path.startsWith("idb://")) {
          const blob = await getRawBlobFromIDB(ev.media_path.slice(6));
          if (blob) {
            if (blob.size > 50 * 1024 * 1024) {
              throw new Error(`"${ev.title}" videosi 50 MB dan katta (${(blob.size / 1048576).toFixed(1)} MB). Kichikroq video yuklang.`);
            }
            const ext = ev.media_type === "video" ? "mp4" : "jpg";
            const repoPath = `uploads/ev_${ev.id}.${ext}`;
            extraFiles[repoPath] = await fileToBase64Content(blob);
            ev.media_path = repoPath;
          }
        }
      }
      for (const g of store.gallery) {
        if (typeof g.image_path === "string" && g.image_path.startsWith("idb://")) {
          const blob = await getRawBlobFromIDB(g.image_path.slice(6));
          if (blob) {
            const repoPath = `uploads/gal_${g.id}.jpg`;
            extraFiles[repoPath] = await fileToBase64Content(blob);
            g.image_path = repoPath;
          }
        }
      }
      await syncStoreToGitHub(store, "Sync all Maktab 49 changes and media to all devices", extraFiles);
      fb.textContent = "Barcha lokal o'zgarishlar, rasmlar va videolar GitHub'ga yuklandi! Endi hamma qurilmalarda ko'rinadi.";
      fb.className = "alert-box alert-success";
      await loadDashboardData();
    } catch (err) {
      fb.textContent = "Yuklashda xatolik: " + err.message;
      fb.className = "alert-box alert-error";
    } finally {
      btn.disabled = false;
      btn.textContent = "Hozir barcha o'zgarishlarni yuklash";
    }
  });

  // ---- Init / Session ----
  async function checkSession() {
    try {
      const res = await apiFetch("/api/auth/me");
      if (useStaticMode) {
        await fetchCloudDataOnLoad();
      }
      if (res.authenticated && (res.user.role === "admin" || res.user.role === "director")) {
        state.user = res.user;
        state.csrfToken = res.csrf_token;
      } else {
        state.user = null;
        state.csrfToken = "";
      }
    } catch {
      useStaticMode = true;
      await fetchCloudDataOnLoad();
      state.user = null;
      state.csrfToken = "";
    }
    await enterApp();
  }

  function openLoginScreen() {
    closeMobileSidebar();
    loginError.classList.add("hidden");
    loginError.className = "alert-box alert-error hidden";
    loginPassword.value = "";
    syncHints();
    appView.classList.add("hidden");
    loginView.classList.remove("hidden");
    if (!restoreLockoutIfActive()) {
      loginUsername.disabled = false;
      loginPassword.disabled = false;
      loginSubmitBtn.disabled = false;
      loginUsername.focus();
    }
  }

  function closeLoginScreen() {
    loginView.classList.add("hidden");
    appView.classList.remove("hidden");
  }

  document.querySelectorAll("[data-open-login]").forEach((btn) => btn.addEventListener("click", openLoginScreen));
  document.getElementById("back-to-site-btn")?.addEventListener("click", closeLoginScreen);

  function syncRoleVisibility() {
    const isManager = Boolean(state.user && (state.user.role === "admin" || state.user.role === "director"));
    const isSuperAdmin = Boolean(state.user && state.user.role === "admin");

    document.querySelectorAll(".admin-only").forEach((el) => el.classList.toggle("hidden", !isManager));
    document.querySelectorAll(".superadmin-only").forEach((el) => el.classList.toggle("hidden", !isSuperAdmin));
    document.querySelectorAll(".guest-only").forEach((el) => el.classList.toggle("hidden", isManager));

    if (isManager) {
      document.getElementById("user-avatar").textContent = getInitials(state.user.full_name);
      document.getElementById("user-fullname").textContent = state.user.full_name;
      document.getElementById("user-role-label").textContent = ROLE_LABELS[state.user.role] || state.user.role;
      updateCloudStatusUI();
    }
  }

  async function enterApp() {
    loginView.classList.add("hidden");
    appView.classList.remove("hidden");
    document.querySelectorAll("img[data-auth-src]").forEach((img) => {
      img.src = img.dataset.authSrc;
    });

    syncRoleVisibility();
    await loadDashboardData();
    if (state.currentPage === "security" && !state.user) {
      switchPage("home");
    } else {
      switchPage(state.currentPage || "home");
    }
  }

  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (restoreLockoutIfActive()) return;

    loginError.className = "alert-box alert-error hidden";
    const username = loginUsername.value.trim();
    const password = loginPassword.value;
    if (!username || !password) {
      loginError.textContent = "Iltimos, login va parolni kiriting.";
      loginError.classList.remove("hidden");
      return;
    }

    loginSubmitBtn.disabled = true;
    const origText = loginSubmitBtn.querySelector("span")?.textContent || "Tizimga kiring";
    if (loginSubmitBtn.querySelector("span")) loginSubmitBtn.querySelector("span").textContent = "Tekshirilmoqda...";

    try {
      const res = await apiFetch("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      state.user = res.user;
      state.csrfToken = res.csrf_token;
      loginPassword.value = "";
      await enterApp();
    } catch (err) {
      if (err && err.retryAfter) {
        startLockoutCountdown(err.retryAfter, false);
      } else {
        loginError.textContent = err.message;
        loginError.className = "alert-box alert-error";
      }
    } finally {
      if (loginSubmitBtn.querySelector("span")) loginSubmitBtn.querySelector("span").textContent = origText;
      if (!getLockoutState().lockUntil) {
        loginSubmitBtn.disabled = false;
      }
    }
  });

  document.getElementById("logout-btn").addEventListener("click", async () => {
    try { await apiFetch("/api/auth/logout", { method: "POST", body: JSON.stringify({}) }); } catch { /* ignore */ }
    state.user = null;
    state.csrfToken = "";
    state.appeals = [];
    state.auditLogs = [];
    closeMobileSidebar();
    syncRoleVisibility();
    await loadDashboardData();
    switchPage("home");
  });

  async function loadDashboardData() {
    const data = await apiFetch("/api/dashboard");
    state.school = data.school || {};
    state.leadership = data.leadership || [];
    state.teachers = data.teachers || [];
    state.gallery = data.gallery || [];
    state.events = data.events || [];
    state.schedule = data.schedule || [];
    state.appeals = data.appeals || [];

    await renderHome();
    renderSchedule();
    renderLeadership();
    renderTeachers();
    await renderGallery();
    await renderEvents();
    renderLocation();
    renderAppeals();
    fillSchoolEditForm();

    if (state.user && (state.user.role === "admin" || state.user.role === "director")) {
      loadSecurityAudit();
      updateCloudStatusUI();
    }
  }

  async function loadSecurityAudit() {
    try {
      const data = await apiFetch("/api/admin/security");
      state.auditLogs = data.audit_logs || [];
      renderAuditLogs();
    } catch { /* ignore */ }
  }

  function closeMobileSidebar() {
    sidebar.classList.remove("expanded");
    sidebarBackdrop.classList.add("hidden");
  }
  sidebarToggleBtn.addEventListener("click", () => {
    const willOpen = !sidebar.classList.contains("expanded");
    sidebar.classList.toggle("expanded", willOpen);
    sidebarBackdrop.classList.toggle("hidden", !willOpen);
  });
  sidebarBackdrop.addEventListener("click", closeMobileSidebar);

  function switchPage(pageKey) {
    if (state.currentPage === "events" && pageKey !== "events") {
      document.querySelectorAll("#events-grid video").forEach((v) => v.pause());
    }
    state.currentPage = pageKey;
    document.querySelectorAll(".nav-item").forEach((btn) => btn.classList.toggle("active", btn.dataset.page === pageKey));
    document.querySelectorAll(".page-section").forEach((sec) => sec.classList.toggle("active", sec.id === `page-${pageKey}`));
    document.getElementById("current-page-title").textContent = PAGE_TITLES[pageKey] || "Maktab 49";
    closeMobileSidebar();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  document.querySelectorAll(".nav-item").forEach((btn) => btn.addEventListener("click", () => switchPage(btn.dataset.page)));
  document.querySelectorAll("[data-goto]").forEach((btn) => btn.addEventListener("click", () => switchPage(btn.dataset.goto)));

  // ---- 1. Bosh sahifa ----
  async function renderHome() {
    document.getElementById("stat-students").textContent = state.school.total_students || "473";
    document.getElementById("students-page-total").textContent = state.school.total_students || "473";
    document.getElementById("stat-teachers").textContent = state.school.total_teachers || "43";
    document.getElementById("stat-deputies").textContent = state.school.deputy_directors || "2";
    const p1 = state.school.phone_1 || "+998 88 654 30 06";
    const p2 = state.school.phone_2 || "+998 77 312 84 85";
    const hp = document.getElementById("hero-phones");
    if (hp) {
      hp.innerHTML = `<a href="tel:${esc(p1.replace(/\s+/g, ""))}">${esc(p1.replace(/^\+998\s*/, ""))}</a> • <a href="tel:${esc(p2.replace(/\s+/g, ""))}">${esc(p2.replace(/^\+998\s*/, ""))}</a>`;
    }

    const mini = document.getElementById("home-mini-gallery");
    const previewItems = state.gallery.slice(1, 5);
    const resolved = await Promise.all(previewItems.map(async (item) => ({ ...item, _src: await resolveMediaPath(item.image_path) })));
    mini.innerHTML = resolved
      .map(
        (item, idx) => `
      <div class="mini-photo-card" data-preview-idx="${idx}">
        <img src="${esc(item._src)}" alt="${esc(item.title)}" loading="lazy" />
        <span>${esc(item.title)}</span>
      </div>`
      )
      .join("");
    mini.querySelectorAll(".mini-photo-card").forEach((el) => {
      el.addEventListener("click", () => openLightbox(resolved.map((x) => ({ image_path: x._src, title: x.title, description: x.description })), Number(el.dataset.previewIdx)));
    });
  }

  // ---- 2. Dars jadvali ----
  document.querySelectorAll("[data-sched-view]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.scheduleView = btn.dataset.schedView;
      document.querySelectorAll("[data-sched-view]").forEach((b) => {
        const active = b === btn;
        b.classList.toggle("active", active);
        b.setAttribute("aria-selected", String(active));
      });
      document.getElementById("schedule-daily-panel").classList.toggle("hidden", state.scheduleView !== "daily");
      document.getElementById("schedule-weekly-panel").classList.toggle("hidden", state.scheduleView !== "weekly");
    });
  });

  function getSlot(dayOfWeek, lessonNum) {
    return state.schedule.find((s) => s.class_name === state.selectedClass && s.day_of_week === dayOfWeek && s.lesson_number === lessonNum);
  }

  function renderSchedule() { renderDailySchedule(); renderWeeklySchedule(); }

  function renderDailySchedule() {
    const weekDates = getCurrentWeekDates();
    const strip = document.getElementById("daily-day-strip");
    strip.innerHTML = weekDates
      .map((d) => `<button type="button" class="day-card ${d.day === state.selectedDay ? "active" : ""} ${d.day === 7 ? "is-sunday" : ""}" data-select-day="${d.day}"><span class="day-short">${esc(d.short)}</span><span class="day-num">${d.dateNum}</span></button>`)
      .join("");
    strip.querySelectorAll("[data-select-day]").forEach((btn) => btn.addEventListener("click", () => { state.selectedDay = Number(btn.dataset.selectDay); renderDailySchedule(); }));

    const curDayInfo = weekDates.find((d) => d.day === state.selectedDay) || weekDates[0];
    document.getElementById("daily-board-caption").textContent = `${curDayInfo.dateNum} ${curDayInfo.monthName} (${curDayInfo.full}) — ${state.selectedClass} sinf kunlik dars jadvali`;

    const body = document.getElementById("daily-board-body");
    const isManager = Boolean(state.user && (state.user.role === "admin" || state.user.role === "director"));
    if (state.selectedDay === 7) {
      body.innerHTML = `<div class="sunday-notice">Yakshanba — dam olish kuni. Darslar mavjud emas.</div>`;
      return;
    }

    let cellsHtml = `<div class="daily-head-cell">Sinf</div>${[1, 2, 3, 4, 5, 6].map((n) => `<div class="daily-head-cell">${n}-dars</div>`).join("")}<div class="daily-class-cell">${esc(state.selectedClass)}</div>`;
    for (let n = 1; n <= 6; n++) {
      const slot = getSlot(state.selectedDay, n);
      const editableAttr = isManager ? `data-edit-slot="${state.selectedDay}:${n}"` : "";
      const editableCls = isManager ? "lesson-editable" : "";
      if (slot) {
        cellsHtml += `<div class="daily-lesson-cell ${editableCls}" data-lesson-label="${n}-dars" ${editableAttr}><div class="lesson-mobile-wrap"><div class="lesson-time">${esc(slot.time_range)}</div><div class="lesson-subject-pill">${esc(slot.subject)}</div></div></div>`;
      } else {
        cellsHtml += `<div class="daily-lesson-cell ${editableCls}" data-lesson-label="${n}-dars" ${editableAttr}><div class="lesson-mobile-wrap"><div class="lesson-empty-dash">—</div></div></div>`;
      }
    }
    body.innerHTML = `<div class="daily-grid-table">${cellsHtml}</div>`;
    if (isManager) {
      body.querySelectorAll("[data-edit-slot]").forEach((el) => el.addEventListener("click", () => { const [d, l] = el.dataset.editSlot.split(":").map(Number); openScheduleEditModal(d, l); }));
    }
  }

  function renderWeeklySchedule() {
    const isManager = Boolean(state.user && (state.user.role === "admin" || state.user.role === "director"));
    const schoolDays = DAYS_META.slice(0, 6);
    const desktopWrap = document.getElementById("weekly-board-desktop");
    let rowsHtml = "";
    for (let n = 1; n <= 6; n++) {
      let tds = `<td class="weekly-slot-num"><strong>${n}-dars</strong><span>${DEFAULT_BELL_TIMES[n]}</span></td>`;
      for (const d of schoolDays) {
        const slot = getSlot(d.day, n);
        const editableAttr = isManager ? `data-edit-slot="${d.day}:${n}"` : "";
        const editableCls = isManager ? "lesson-editable" : "";
        if (slot) {
          tds += `<td><div class="weekly-cell-box ${editableCls}" ${editableAttr}><div class="weekly-cell-subject">${esc(slot.subject)}</div><div class="weekly-cell-time">${esc(slot.time_range)}</div></div></td>`;
        } else {
          tds += `<td><div class="weekly-cell-box ${editableCls}" style="align-items:center;opacity:0.45;" ${editableAttr}><span class="lesson-empty-dash">—</span></div></td>`;
        }
      }
      rowsHtml += `<tr>${tds}</tr>`;
    }
    desktopWrap.innerHTML = `<table class="weekly-table"><thead><tr><th>Dars</th>${schoolDays.map((d) => `<th>${esc(d.full)}</th>`).join("")}</tr></thead><tbody>${rowsHtml}</tbody></table>`;

    const mobileWrap = document.getElementById("weekly-board-mobile");
    mobileWrap.innerHTML = schoolDays
      .map((d) => {
        const daySlots = [];
        for (let n = 1; n <= 6; n++) { const slot = getSlot(d.day, n); if (slot) daySlots.push(slot); }
        return `<div class="weekly-day-card"><div class="weekly-day-card-head">${esc(d.full)} (${daySlots.length} ta dars)</div>${daySlots.map((s) => `<div class="weekly-day-card-row ${isManager ? "lesson-editable" : ""}" ${isManager ? `data-edit-slot="${d.day}:${s.lesson_number}"` : ""}><div><strong style="color:var(--accent-indigo);margin-right:6px;">${s.lesson_number}.</strong><strong>${esc(s.subject)}</strong></div><span class="lesson-time">${esc(s.time_range)}</span></div>`).join("")}</div>`;
      })
      .join("");

    if (isManager) {
      document.querySelectorAll("#schedule-weekly-panel [data-edit-slot]").forEach((el) => el.addEventListener("click", () => { const [d, l] = el.dataset.editSlot.split(":").map(Number); openScheduleEditModal(d, l); }));
    }
  }

  function openScheduleEditModal(dayOfWeek, lessonNum) {
    const slot = getSlot(dayOfWeek, lessonNum);
    const dayMeta = DAYS_META.find((d) => d.day === dayOfWeek);
    document.getElementById("sched-modal-title").textContent = `${state.selectedClass} • ${dayMeta ? dayMeta.full : ""} • ${lessonNum}-dars`;
    document.getElementById("sf-class").value = state.selectedClass;
    document.getElementById("sf-day").value = String(dayOfWeek);
    document.getElementById("sf-lesson").value = String(lessonNum);
    document.getElementById("sf-time").value = slot ? slot.time_range : DEFAULT_BELL_TIMES[lessonNum];
    document.getElementById("sf-subject").value = slot ? slot.subject : "";
    document.getElementById("sf-error").classList.add("hidden");
    openModal("schedule-modal");
  }

  document.getElementById("schedule-edit-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const errEl = document.getElementById("sf-error");
    errEl.classList.add("hidden");
    const payload = {
      class_name: document.getElementById("sf-class").value,
      day_of_week: Number(document.getElementById("sf-day").value),
      lesson_number: Number(document.getElementById("sf-lesson").value),
      time_range: document.getElementById("sf-time").value.trim(),
      subject: document.getElementById("sf-subject").value.trim(),
    };
    try {
      const res = await apiFetch("/api/schedule", { method: "PUT", body: JSON.stringify(payload) });
      state.schedule = res.schedule || [];
      renderSchedule();
      closeModal("schedule-modal");
    } catch (err) { errEl.textContent = err.message; errEl.classList.remove("hidden"); }
  });

  // ---- 3. Rahbariyat ----
  function renderLeadership() {
    const isManager = Boolean(state.user && (state.user.role === "admin" || state.user.role === "director"));
    const grid = document.getElementById("leadership-grid");
    grid.innerHTML = state.leadership
      .map((p) => {
        const extraClass = p.category === "Direktor" ? "is-director" : p.position.toLowerCase().includes("administrator") ? "is-admin" : "";
        return `
        <article class="leader-card ${extraClass}">
          <div class="leader-top">
            <div class="leader-avatar">${esc(getInitials(p.full_name))}</div>
            <div><span class="leader-role-pill">${esc(p.position)}</span><h4 class="leader-name">${esc(p.full_name)}</h4></div>
          </div>
          <p class="leader-bio">${esc(p.bio)}</p>
          <div class="leader-phone">Aloqa: ${esc(p.phone || "+998 88 654 30 06")}</div>
          ${isManager ? `<div class="card-admin-bar"><button type="button" class="btn-outline-sm" data-edit-lead="${p.id}">Tahrirlash</button><button type="button" class="btn-danger-sm" data-del-lead="${p.id}">O'chirish</button></div>` : ""}
        </article>`;
      })
      .join("");
    if (isManager) {
      grid.querySelectorAll("[data-edit-lead]").forEach((btn) => btn.addEventListener("click", () => openEditLeadership(Number(btn.dataset.editLead))));
      grid.querySelectorAll("[data-del-lead]").forEach((btn) => btn.addEventListener("click", () => handleDeleteLeadership(Number(btn.dataset.delLead))));
    }
  }

  document.getElementById("open-add-leadership-btn")?.addEventListener("click", () => {
    document.getElementById("lead-modal-title").textContent = "Yangi rahbariyat a'zosi qo'shish";
    document.getElementById("lf-id").value = "";
    document.getElementById("lf-fullname").value = "";
    document.getElementById("lf-position").value = "";
    document.getElementById("lf-phone").value = "";
    document.getElementById("lf-bio").value = "";
    document.getElementById("lf-error").classList.add("hidden");
    openModal("leadership-modal");
  });

  function openEditLeadership(id) {
    const p = state.leadership.find((x) => x.id === id);
    if (!p) return;
    document.getElementById("lead-modal-title").textContent = "Rahbariyat ma'lumotini tahrirlash";
    document.getElementById("lf-id").value = String(p.id);
    document.getElementById("lf-fullname").value = p.full_name;
    document.getElementById("lf-position").value = p.position;
    document.getElementById("lf-phone").value = p.phone || "";
    document.getElementById("lf-bio").value = p.bio || "";
    document.getElementById("lf-error").classList.add("hidden");
    openModal("leadership-modal");
  }

  document.getElementById("leadership-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const errEl = document.getElementById("lf-error");
    errEl.classList.add("hidden");
    const id = document.getElementById("lf-id").value;
    const payload = {
      full_name: document.getElementById("lf-fullname").value.trim(),
      position: document.getElementById("lf-position").value.trim(),
      phone: document.getElementById("lf-phone").value.trim(),
      bio: document.getElementById("lf-bio").value.trim(),
    };
    try {
      const res = id ? await apiFetch(`/api/leadership/${id}`, { method: "PUT", body: JSON.stringify(payload) }) : await apiFetch("/api/leadership", { method: "POST", body: JSON.stringify(payload) });
      state.leadership = res.leadership || state.leadership;
      renderLeadership();
      closeModal("leadership-modal");
    } catch (err) { errEl.textContent = err.message; errEl.classList.remove("hidden"); }
  });

  async function handleDeleteLeadership(id) {
    if (!window.confirm("Ushbu rahbariyat a'zosini o'chirishni tasdiqlaysizmi?")) return;
    try { const res = await apiFetch(`/api/leadership/${id}`, { method: "DELETE" }); state.leadership = res.leadership || []; renderLeadership(); } catch (err) { window.alert(err.message); }
  }

  // ---- 4. O'qituvchilar ----
  const teacherSearchInput = document.getElementById("teacher-search");
  teacherSearchInput.addEventListener("input", renderTeachers);

  function renderTeachers() {
    const query = teacherSearchInput.value.trim().toLowerCase();
    const filtered = state.teachers.filter((t) => t.full_name.toLowerCase().includes(query) || t.subject.toLowerCase().includes(query) || t.category.toLowerCase().includes(query));
    document.getElementById("teachers-count-badge").textContent = `Jami: ${state.school.total_teachers || "43"} nafar • Tizimda: ${state.teachers.length} nafar`;
    const isManager = Boolean(state.user && (state.user.role === "admin" || state.user.role === "director"));
    const container = document.getElementById("teachers-list");
    if (!filtered.length) {
      container.innerHTML = `<div style="padding:20px;text-align:center;color:var(--text-soft);">Mos o'qituvchi topilmadi.</div>`;
      return;
    }
    container.innerHTML = filtered
      .map(
        (t, idx) => `
      <div class="teacher-row">
        <div class="teacher-main">
          <div class="teacher-num">${idx + 1}</div>
          <div>
            <div class="teacher-name">${esc(t.full_name)}</div>
            <div class="teacher-meta">${esc(t.subject)} • ${esc(t.category)}${t.experience_years ? ` • ${t.experience_years} yil staj` : ""}${t.phone ? ` • ${esc(t.phone)}` : ""}</div>
          </div>
        </div>
        ${isManager ? `<div class="teacher-actions"><button type="button" class="btn-outline-sm" data-edit-teacher="${t.id}">Tahrirlash</button><button type="button" class="btn-danger-sm" data-del-teacher="${t.id}">O'chirish</button></div>` : ""}
      </div>`
      )
      .join("");
    if (isManager) {
      container.querySelectorAll("[data-edit-teacher]").forEach((btn) => btn.addEventListener("click", () => openEditTeacher(Number(btn.dataset.editTeacher))));
      container.querySelectorAll("[data-del-teacher]").forEach((btn) => btn.addEventListener("click", () => handleDeleteTeacher(Number(btn.dataset.delTeacher))));
    }
  }

  document.getElementById("open-add-teacher-btn").addEventListener("click", () => {
    document.getElementById("teacher-modal-title").textContent = "Yangi o'qituvchi qo'shish";
    document.getElementById("tf-id").value = "";
    document.getElementById("tf-fullname").value = "";
    document.getElementById("tf-subject").value = "O'qituvchi";
    document.getElementById("tf-category").value = "Pedagog xodim";
    document.getElementById("tf-exp").value = "0";
    document.getElementById("tf-phone").value = "";
    document.getElementById("tf-error").classList.add("hidden");
    openModal("teacher-modal");
  });

  function openEditTeacher(id) {
    const t = state.teachers.find((x) => x.id === id);
    if (!t) return;
    document.getElementById("teacher-modal-title").textContent = "O'qituvchi ma'lumotini tahrirlash";
    document.getElementById("tf-id").value = String(t.id);
    document.getElementById("tf-fullname").value = t.full_name;
    document.getElementById("tf-subject").value = t.subject;
    document.getElementById("tf-category").value = t.category;
    document.getElementById("tf-exp").value = String(t.experience_years || 0);
    document.getElementById("tf-phone").value = t.phone || "";
    document.getElementById("tf-error").classList.add("hidden");
    openModal("teacher-modal");
  }

  document.getElementById("teacher-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const errEl = document.getElementById("tf-error");
    errEl.classList.add("hidden");
    const id = document.getElementById("tf-id").value;
    const payload = {
      full_name: document.getElementById("tf-fullname").value.trim(),
      subject: document.getElementById("tf-subject").value.trim(),
      category: document.getElementById("tf-category").value.trim(),
      experience_years: Number(document.getElementById("tf-exp").value || 0),
      phone: document.getElementById("tf-phone").value.trim(),
    };
    try {
      const res = id ? await apiFetch(`/api/teachers/${id}`, { method: "PUT", body: JSON.stringify(payload) }) : await apiFetch("/api/teachers", { method: "POST", body: JSON.stringify(payload) });
      state.teachers = res.teachers;
      renderTeachers();
      closeModal("teacher-modal");
    } catch (err) { errEl.textContent = err.message; errEl.classList.remove("hidden"); }
  });

  async function handleDeleteTeacher(id) {
    if (!window.confirm("Ushbu o'qituvchini ro'yxatdan o'chirishni tasdiqlaysizmi?")) return;
    try { const res = await apiFetch(`/api/teachers/${id}`, { method: "DELETE" }); state.teachers = res.teachers; renderTeachers(); } catch (err) { window.alert(err.message); }
  }

  // ---- 5. Sinf xonalari va Galereya ----
  document.getElementById("gallery-filters").addEventListener("click", (e) => {
    const btn = e.target.closest(".filter-chip");
    if (!btn) return;
    state.galleryFilter = btn.dataset.cat;
    document.querySelectorAll("#gallery-filters .filter-chip").forEach((c) => c.classList.toggle("active", c === btn));
    renderGallery();
  });

  async function renderGallery() {
    const isManager = Boolean(state.user && (state.user.role === "admin" || state.user.role === "director"));
    const items = state.galleryFilter === "all" ? state.gallery : state.gallery.filter((g) => g.category === state.galleryFilter);
    const resolved = await Promise.all(items.map(async (item) => ({ ...item, _src: await resolveMediaPath(item.image_path) })));
    const grid = document.getElementById("gallery-grid");
    grid.innerHTML = resolved
      .map(
        (item, idx) => `
      <article class="gallery-card">
        <div class="gallery-img-wrap" data-gal-idx="${idx}"><img src="${esc(item._src)}" alt="${esc(item.title)}" loading="lazy" /><span class="gallery-cat-badge">${esc(item.category)}</span></div>
        <div class="gallery-card-body">
          <h4>${esc(item.title)}</h4>
          <p>${esc(item.description)}</p>
          ${isManager ? `<div class="card-admin-bar"><button type="button" class="btn-danger-sm" data-del-gal="${item.id}">O'chirish</button></div>` : ""}
        </div>
      </article>`
      )
      .join("");
    grid.querySelectorAll("[data-gal-idx]").forEach((el) => el.addEventListener("click", () => openLightbox(resolved.map((x) => ({ image_path: x._src, title: x.title, description: x.description })), Number(el.dataset.galIdx))));
    if (isManager) {
      grid.querySelectorAll("[data-del-gal]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          if (!window.confirm("Ushbu rasmni o'chirishni tasdiqlaysizmi?")) return;
          const res = await apiFetch(`/api/gallery/${btn.dataset.delGal}`, { method: "DELETE" });
          state.gallery = res.gallery || [];
          await renderGallery();
          await renderHome();
        });
      });
    }
  }

  document.getElementById("open-upload-gallery-btn")?.addEventListener("click", () => {
    document.getElementById("gallery-upload-form").reset();
    document.getElementById("gal-error").classList.add("hidden");
    openModal("gallery-upload-modal");
  });

  document.getElementById("gallery-upload-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const errEl = document.getElementById("gal-error");
    const submitBtn = document.getElementById("gal-submit-btn");
    errEl.classList.add("hidden");
    const file = document.getElementById("gal-file").files[0];
    const title = document.getElementById("gal-title").value.trim();
    const category = document.getElementById("gal-cat").value;
    const description = document.getElementById("gal-desc").value.trim();
    if (!file || !file.type.startsWith("image/")) {
      errEl.textContent = "Iltimos, rasm faylini tanlang.";
      errEl.classList.remove("hidden");
      return;
    }
    submitBtn.disabled = true;
    submitBtn.textContent = "Yuklanmoqda...";
    try {
      if (useStaticMode) {
        const id = Date.now();
        let savedPath = "";
        const extraFiles = {};
        if (getGitHubToken()) {
          const ext = (file.name.split(".").pop() || "jpg").toLowerCase().replace(/[^a-z0-9]/g, "") || "jpg";
          const repoPath = `uploads/gal_${id}.${ext}`;
          extraFiles[repoPath] = await fileToBase64Content(file);
          savedPath = repoPath;
        } else {
          const key = `gal_${id}`;
          await saveBlobToIDB(key, file);
          savedPath = `idb://${key}`;
        }
        const store = loadLocalStore();
        store.gallery.push({ id, title, category, description, image_path: savedPath });
        addAudit(store, "GALLERY_ADD", state.user.username, `Yangi sinf/maktab rasmi: ${title}`, "info");
        if (getGitHubToken()) {
          await syncStoreToGitHub(store, `Add gallery photo: ${title}`, extraFiles);
        } else {
          saveLocalStore(store);
        }
        state.gallery = store.gallery;
      } else {
        const dataUrl = await fileToDataUrl(file);
        const res = await apiFetch("/api/gallery", { method: "POST", body: JSON.stringify({ title, category, description, media_data: dataUrl }) });
        state.gallery = res.gallery || [];
      }
      await renderGallery();
      await renderHome();
      closeModal("gallery-upload-modal");
    } catch (err) {
      errEl.textContent = err.message;
      errEl.classList.remove("hidden");
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = "Saqlash";
    }
  });

  // ---- 6. TADBIRLAR (Rasm + Video yuklash -> GitHub Cloud yoki Lokal) ----
  document.getElementById("events-filters")?.addEventListener("click", (e) => {
    const btn = e.target.closest(".filter-chip");
    if (!btn) return;
    state.eventsFilter = btn.dataset.evFilter;
    document.querySelectorAll("#events-filters .filter-chip").forEach((c) => c.classList.toggle("active", c === btn));
    renderEvents();
  });

  function openEventUploadModal(mediaType) {
    document.getElementById("event-upload-form").reset();
    document.getElementById("ev-error").classList.add("hidden");
    document.getElementById("ev-media-type").value = mediaType;
    document.getElementById("ev-date").value = new Date().toISOString().slice(0, 10);
    const fileInput = document.getElementById("ev-file");
    if (mediaType === "video") {
      document.getElementById("event-modal-title").textContent = "Tadbirga video yuklash";
      document.getElementById("ev-file-label").textContent = "Video faylini tanlang (MP4, WEBM — 24 MB gacha)";
      fileInput.accept = "video/mp4,video/webm,video/*";
    } else {
      document.getElementById("event-modal-title").textContent = "Tadbirga rasm yuklash";
      document.getElementById("ev-file-label").textContent = "Rasm faylini tanlang (JPG, PNG, WEBP)";
      fileInput.accept = "image/*";
    }
    openModal("event-upload-modal");
  }

  document.getElementById("open-upload-event-photo-btn")?.addEventListener("click", () => openEventUploadModal("photo"));
  document.getElementById("open-upload-event-video-btn")?.addEventListener("click", () => openEventUploadModal("video"));

  document.getElementById("event-upload-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const errEl = document.getElementById("ev-error");
    const submitBtn = document.getElementById("ev-submit-btn");
    errEl.classList.add("hidden");

    const mediaType = document.getElementById("ev-media-type").value;
    const title = document.getElementById("ev-title").value.trim();
    const eventDate = document.getElementById("ev-date").value;
    const description = document.getElementById("ev-desc").value.trim();
    const file = document.getElementById("ev-file").files[0];

    if (!file) { errEl.textContent = "Iltimos, faylni tanlang."; errEl.classList.remove("hidden"); return; }
    const lowerName = (file.name || "").toLowerCase();
    const isPhotoFile = file.type.startsWith("image/") || /\.(jpg|jpeg|png|webp|gif)$/.test(lowerName);
    const isVideoFile = file.type.startsWith("video/") || /\.(mp4|webm|mov|m4v)$/.test(lowerName);
    if (mediaType === "photo" && !isPhotoFile) { errEl.textContent = "Faqat rasm faylini (JPG, PNG, WEBP) yuklang."; errEl.classList.remove("hidden"); return; }
    if (mediaType === "video" && !isVideoFile) { errEl.textContent = "Faqat video faylini (MP4, WEBM, MOV) yuklang."; errEl.classList.remove("hidden"); return; }
    if (file.size > 50 * 1024 * 1024) {
      errEl.textContent = `Fayl hajmi juda katta (${(file.size / 1048576).toFixed(1)} MB). 50 MB dan kichik fayl yuklang.`;
      errEl.classList.remove("hidden");
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = getGitHubToken()
      ? `GitHub'ga yuklanmoqda (${(file.size / 1048576).toFixed(1)} MB)...`
      : "Saqlanmoqda...";
    try {
      if (useStaticMode) {
        const id = Date.now();
        let savedPath = "";
        const extraFiles = {};
        if (getGitHubToken()) {
          const defExt = mediaType === "video" ? "mp4" : "jpg";
          const ext = (lowerName.split(".").pop() || defExt).replace(/[^a-z0-9]/g, "") || defExt;
          const repoPath = `uploads/ev_${id}.${ext}`;
          extraFiles[repoPath] = await fileToBase64Content(file);
          savedPath = repoPath;
        } else {
          const key = `ev_${id}`;
          await saveBlobToIDB(key, file);
          savedPath = `idb://${key}`;
        }
        const store = loadLocalStore();
        store.events.unshift({
          id,
          title,
          media_type: mediaType,
          event_date: eventDate,
          description: description || "49-sonli maktab tadbiri.",
          media_path: savedPath,
          poster_path: mediaType === "video" ? "entrance.jpg" : "",
          created_at: Math.floor(Date.now() / 1000),
        });
        addAudit(store, "EVENT_ADD", state.user.username, `Yangi tadbir (${mediaType === "video" ? "video" : "rasm"}): ${title}`, "info");
        if (getGitHubToken()) {
          await syncStoreToGitHub(store, `Add event ${mediaType}: ${title}`, extraFiles);
        } else {
          saveLocalStore(store);
          showToast("Shu qurilmada saqlandi. Hammaga ko'rinishi uchun GitHub kalitini ulang.", "info");
        }
        state.events = store.events;
      } else {
        const dataUrl = await fileToDataUrl(file);
        const res = await apiFetch("/api/events", {
          method: "POST",
          body: JSON.stringify({ title, media_type: mediaType, event_date: eventDate, description, media_data: dataUrl }),
        });
        state.events = res.events || [];
      }
      await renderEvents();
      closeModal("event-upload-modal");
    } catch (err) {
      errEl.textContent = err.message;
      errEl.classList.remove("hidden");
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = "Yuklash va saqlash";
    }
  });

  async function renderEvents() {
    const grid = document.getElementById("events-grid");
    if (!grid) return;
    const isManager = Boolean(state.user && (state.user.role === "admin" || state.user.role === "director"));
    const items = state.eventsFilter === "all" ? state.events : state.events.filter((ev) => ev.media_type === state.eventsFilter);
    if (!items.length) {
      grid.innerHTML = `<div class="card" style="color:var(--text-soft);">Ushbu bo'limda hozircha tadbirlar yo'q.</div>`;
      return;
    }

    const resolved = await Promise.all(
      items.map(async (ev) => ({
        ...ev,
        _src: await resolveMediaPath(ev.media_path),
        _poster: ev.poster_path ? await resolveMediaPath(ev.poster_path) : "",
      }))
    );

    const photoItems = resolved.filter((x) => x.media_type === "photo");

    grid.innerHTML = resolved
      .map((ev) => {
        const typeLabel = ev.media_type === "video" ? "Video" : "Rasm";
        const mediaHtml =
          ev.media_type === "video"
            ? `<div class="video-player-wrap"><video controls playsinline preload="metadata" ${ev._poster ? `poster="${esc(ev._poster)}"` : ""}><source src="${esc(ev._src)}" type="video/mp4" />Brauzeringiz video ijrosini qo'llab-quvvatlamaydi.</video></div>`
            : `<div class="event-photo-wrap" data-ev-photo-id="${ev.id}"><img src="${esc(ev._src)}" alt="${esc(ev.title)}" loading="lazy" /><span class="gallery-cat-badge">Rasm</span></div>`;
        return `
        <article class="event-card">
          ${mediaHtml}
          <div class="video-card-body">
            <div class="video-card-head">
              <h4>${esc(ev.title)}</h4>
              <span class="count-badge">${typeLabel}${ev.event_date ? ` • ${esc(ev.event_date)}` : ""}</span>
            </div>
            <p>${esc(ev.description)}</p>
            ${isManager ? `<div class="card-admin-bar"><button type="button" class="btn-danger-sm" data-del-ev="${ev.id}">O'chirish</button></div>` : ""}
          </div>
        </article>`;
      })
      .join("");

    grid.querySelectorAll("[data-ev-photo-id]").forEach((el) => {
      el.addEventListener("click", () => {
        const idx = photoItems.findIndex((p) => String(p.id) === el.dataset.evPhotoId);
        openLightbox(photoItems.map((p) => ({ image_path: p._src, title: p.title, description: p.description })), Math.max(0, idx));
      });
    });

    if (isManager) {
      grid.querySelectorAll("[data-del-ev]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          if (!window.confirm("Ushbu tadbirni o'chirishni tasdiqlaysizmi?")) return;
          const res = await apiFetch(`/api/events/${btn.dataset.delEv}`, { method: "DELETE" });
          state.events = res.events || [];
          await renderEvents();
        });
      });
    }
  }

  // ---- Lightbox ----
  document.querySelectorAll("[data-lightbox]").forEach((el) => el.addEventListener("click", () => openLightbox([{ image_path: el.dataset.lightbox, title: el.dataset.caption || "" }], 0)));
  const lightbox = document.getElementById("lightbox");
  const lbImg = document.getElementById("lb-img");
  const lbCaption = document.getElementById("lb-caption");
  function openLightbox(items, index) { state.lightboxItems = items; state.lightboxIndex = index; updateLightbox(); lightbox.classList.remove("hidden"); }
  function updateLightbox() {
    const item = state.lightboxItems[state.lightboxIndex];
    if (!item) return;
    lbImg.src = item.image_path;
    lbImg.alt = item.title || "";
    lbCaption.textContent = `${item.title || ""}${item.description ? " — " + item.description : ""}`;
  }
  function closeLightbox() { lightbox.classList.add("hidden"); }
  document.getElementById("lb-close").addEventListener("click", closeLightbox);
  document.getElementById("lb-prev").addEventListener("click", () => { state.lightboxIndex = (state.lightboxIndex - 1 + state.lightboxItems.length) % state.lightboxItems.length; updateLightbox(); });
  document.getElementById("lb-next").addEventListener("click", () => { state.lightboxIndex = (state.lightboxIndex + 1) % state.lightboxItems.length; updateLightbox(); });
  lightbox.addEventListener("click", (e) => { if (e.target === lightbox) closeLightbox(); });
  document.addEventListener("keydown", (e) => {
    if (lightbox.classList.contains("hidden")) return;
    if (e.key === "Escape") closeLightbox();
    if (e.key === "ArrowLeft") document.getElementById("lb-prev").click();
    if (e.key === "ArrowRight") document.getElementById("lb-next").click();
  });

  // ---- 7. Lokatsiya ----
  function renderLocation() {
    const lat = state.school.location_lat || "41.572770";
    const lng = state.school.location_lng || "60.890981";
    document.getElementById("coords-text").textContent = `${lat}, ${lng}`;
    document.getElementById("google-maps-link").href = `https://www.google.com/maps/search/?api=1&query=${lat},${lng}`;
    document.getElementById("yandex-maps-link").href = `https://yandex.uz/maps/?pt=${lng},${lat}&z=17&l=sat,skl`;
  }

  document.getElementById("copy-coords-btn").addEventListener("click", async (e) => {
    const coords = document.getElementById("coords-text").textContent;
    try { await navigator.clipboard.writeText(coords); const orig = e.target.textContent; e.target.textContent = "Nusxalandi ✓"; setTimeout(() => (e.target.textContent = orig), 1800); }
    catch { window.prompt("Koordinatani nusxalang:", coords); }
  });

  // ---- 8. Murojaatlar ----
  document.getElementById("appeal-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fb = document.getElementById("appeal-feedback");
    fb.className = "alert-box hidden";
    const payload = {
      sender_name: document.getElementById("appeal-name").value.trim(),
      phone: document.getElementById("appeal-phone").value.trim(),
      topic: document.getElementById("appeal-topic").value.trim(),
      message: document.getElementById("appeal-message").value.trim(),
    };
    try {
      const res = await apiFetch("/api/appeals", { method: "POST", body: JSON.stringify(payload) });
      fb.textContent = res.message;
      fb.className = "alert-box alert-success";
      e.target.reset();
      if (state.user && (state.user.role === "admin" || state.user.role === "director")) {
        const listRes = await apiFetch("/api/appeals");
        state.appeals = listRes.appeals || [];
        renderAppeals();
      }
    } catch (err) { fb.textContent = err.message; fb.className = "alert-box alert-error"; }
  });

  function renderAppeals() {
    const container = document.getElementById("appeals-list");
    if (!container) return;
    if (!state.appeals.length) {
      container.innerHTML = `<div style="color:var(--text-soft);font-size:13.5px;">Hozircha murojaatlar yo'q.</div>`;
      return;
    }
    container.innerHTML = state.appeals
      .map(
        (a) => `
      <div class="appeal-row">
        <div>
          <strong>${esc(a.topic)}</strong> — ${esc(a.sender_name)} (${esc(a.phone)})
          <div style="font-size:13px;color:var(--text-muted);margin-top:4px;">${esc(a.message)}</div>
          <div style="font-size:11.5px;color:var(--text-soft);margin-top:4px;">${formatTimestamp(a.created_at)}</div>
        </div>
        <select class="btn-outline-sm" data-appeal-status="${a.id}">
          <option value="Yangi" ${a.status === "Yangi" ? "selected" : ""}>Yangi</option>
          <option value="Ko'rib chiqilmoqda" ${a.status === "Ko'rib chiqilmoqda" ? "selected" : ""}>Ko'rib chiqilmoqda</option>
          <option value="Hal qilindi" ${a.status === "Hal qilindi" ? "selected" : ""}>Hal qilindi</option>
        </select>
      </div>`
      )
      .join("");
    container.querySelectorAll("[data-appeal-status]").forEach((sel) => {
      sel.addEventListener("change", async () => { await apiFetch(`/api/appeals/${sel.dataset.appealStatus}`, { method: "PUT", body: JSON.stringify({ status: sel.value }) }); });
    });
  }

  // ---- 9. Boshqaruv: Faqat Admin parol o'zgartirishi + Maktab ko'rsatkichlari + Audit ----
  function fillSchoolEditForm() {
    const f1 = document.getElementById("si-students");
    if (!f1) return;
    f1.value = state.school.total_students || "473";
    document.getElementById("si-teachers").value = state.school.total_teachers || "43";
    document.getElementById("si-deputies").value = state.school.deputy_directors || "2";
    const sf = document.getElementById("si-founded");
    if (sf) sf.value = state.school.founded_date || "01/09/1988";
    document.getElementById("si-phone1").value = state.school.phone_1 || "+998 88 654 30 06";
    const sp2 = document.getElementById("si-phone2");
    if (sp2) sp2.value = state.school.phone_2 || "+998 77 312 84 85";
  }

  document.getElementById("school-info-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fb = document.getElementById("school-info-feedback");
    fb.className = "alert-box hidden";
    const payload = {
      total_students: document.getElementById("si-students").value.trim(),
      total_teachers: document.getElementById("si-teachers").value.trim(),
      deputy_directors: document.getElementById("si-deputies").value.trim(),
      founded_date: document.getElementById("si-founded")?.value.trim(),
      phone_1: document.getElementById("si-phone1").value.trim(),
      phone_2: document.getElementById("si-phone2")?.value.trim(),
    };
    try {
      const res = await apiFetch("/api/school", { method: "PUT", body: JSON.stringify(payload) });
      state.school = res.school || state.school;
      await renderHome();
      renderTeachers();
      fb.textContent = "Maktab ko'rsatkichlari muvaffaqiyatli saqlandi!";
      fb.className = "alert-box alert-success";
    } catch (err) { fb.textContent = err.message; fb.className = "alert-box alert-error"; }
  });

  document.getElementById("change-pw-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fb = document.getElementById("pw-feedback");
    fb.className = "alert-box hidden";
    const cur = document.getElementById("cur-pw").value;
    const nw = document.getElementById("new-pw").value;
    const cnf = document.getElementById("confirm-pw").value;
    if (nw !== cnf) { fb.textContent = "Yangi parol va tasdiqlash paroli bir xil emas."; fb.className = "alert-box alert-error"; return; }
    try {
      const res = await apiFetch("/api/auth/change-password", { method: "POST", body: JSON.stringify({ current_password: cur, new_password: nw }) });
      fb.textContent = res.message;
      fb.className = "alert-box alert-success";
      e.target.reset();
      loadSecurityAudit();
    } catch (err) { fb.textContent = err.message; fb.className = "alert-box alert-error"; }
  });

  document.getElementById("reset-other-pw-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fb = document.getElementById("reset-pw-feedback");
    fb.className = "alert-box hidden";
    const username = document.getElementById("rp-username").value.trim();
    const new_password = document.getElementById("rp-new-pw").value;
    try {
      const res = await apiFetch("/api/admin/reset-password", { method: "POST", body: JSON.stringify({ username, new_password }) });
      fb.textContent = res.message;
      fb.className = "alert-box alert-success";
      document.getElementById("rp-new-pw").value = "";
      loadSecurityAudit();
    } catch (err) { fb.textContent = err.message; fb.className = "alert-box alert-error"; }
  });

  document.getElementById("create-user-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fb = document.getElementById("user-create-feedback");
    fb.className = "alert-box hidden";
    const payload = {
      full_name: document.getElementById("nu-fullname").value.trim(),
      username: document.getElementById("nu-username").value.trim(),
      role: document.getElementById("nu-role").value,
      position: document.getElementById("nu-position").value.trim(),
      password: document.getElementById("nu-password").value,
    };
    try {
      await apiFetch("/api/admin/users", { method: "POST", body: JSON.stringify(payload) });
      fb.textContent = `"${payload.username}" hisobi xavfsiz yaratildi!`;
      fb.className = "alert-box alert-success";
      e.target.reset();
      loadSecurityAudit();
    } catch (err) { fb.textContent = err.message; fb.className = "alert-box alert-error"; }
  });

  document.getElementById("refresh-audit-btn")?.addEventListener("click", loadSecurityAudit);

  function renderAuditLogs() {
    const list = document.getElementById("audit-list");
    if (!list) return;
    if (!state.auditLogs.length) {
      list.innerHTML = `<div style="color:var(--text-soft);">Yozuvlar mavjud emas.</div>`;
      return;
    }
    list.innerHTML = state.auditLogs
      .map(
        (l) => `
      <div class="audit-row">
        <div>
          <span class="audit-badge sev-${esc(l.severity)}">${esc(l.event_type)}</span>
          <strong style="margin-left:8px;">${esc(l.username)}</strong>
          <span style="color:var(--text-muted);margin-left:6px;font-size:13.5px;">${esc(l.details)}</span>
        </div>
        <div style="font-size:12px;color:var(--text-soft);">${esc(l.ip_address)} • ${formatTimestamp(l.created_at)}</div>
      </div>`
      )
      .join("");
  }

  checkSession();
})();
