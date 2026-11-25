/* ==========================================================================
   Maktab 49 — Ta'lim Platformasi (GitHub Pages + Lokal Server Dual-Mode)
   PBKDF2-HMAC-SHA256 (260,000 iteratsiya, Web Crypto API), Brute-Force himoya,
   Kunlik & Haftalik 10-A dars jadvali, Videolar, Lokatsiya, Kunduzgi/Tungi rejim
   ========================================================================== */

(() => {
  "use strict";

  // ==================== 1. XAVFSIZ STATIK DARAJADAGI BACKEND (GitHub Pages) ====================
  const STORE_KEY = "maktab49_secure_store_v1";
  const SESSION_KEY = "maktab49_active_session_v1";
  const RATE_KEY = "maktab49_rate_limit_v1";
  const MAX_ATTEMPTS = 5;
  const LOCKOUT_MS = 15 * 60 * 1000;
  const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

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

  async function hashPasswordWeb(password) {
    const salt = new Uint8Array(32);
    crypto.getRandomValues(salt);
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 260000 }, key, 256);
    return `pbkdf2_sha256$260000$${bytesToHex(salt)}$${bytesToHex(new Uint8Array(bits))}`;
  }

  async function verifyPasswordWeb(password, storedHash) {
    try {
      const [algo, iterStr, saltHex, hashHex] = storedHash.split("$");
      if (algo !== "pbkdf2_sha256") return false;
      const iterations = parseInt(iterStr, 10);
      const salt = hexToBytes(saltHex);
      const enc = new TextEncoder();
      const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
      const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
      return constantTimeEqual(bytesToHex(new Uint8Array(bits)), hashHex);
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

  function getSeedData() {
    const now = Math.floor(Date.now() / 1000);
    return {
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
        {
          id: 3,
          username: "oqituvchi49",
          password_hash: "pbkdf2_sha256$260000$69112c2d14936f232b321d3718218e818585f043b4c292c2ca4ef7bc7cd07e83$a05dc19e11e56a3d15ee6b15be54c0e2561759f4a1ed4502c8d7dab8c77295bd",
          full_name: "49-maktab xodimi",
          role: "teacher",
          position: "O'qituvchi",
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
        {
          id: 1,
          full_name: "Alimov Elyor Kuriyaz o'g'li",
          position: "Maktab direktori",
          category: "Direktor",
          phone: "+998 88 654 30 06",
          bio: "49-sonli umumiy o'rta ta'lim maktabining umumiy boshqaruvi, ta'lim sifati va rivojlanish strategiyasiga mas'ul.",
        },
        {
          id: 2,
          full_name: "Matniyazov Muzaffar Ayitovich",
          position: "Direktor o'rinbosari",
          category: "Direktor o'rinbosari",
          phone: "+998 88 654 30 06",
          bio: "O'quv-tarbiya jarayonini tashkil etish, dars jadvali va pedagogik faoliyatni muvofiqlashtirish bo'yicha mas'ul.",
        },
        {
          id: 3,
          full_name: "Abduraimov G'ayrat Tajiboy o'g'li",
          position: "Direktor o'rinbosari",
          category: "Direktor o'rinbosari",
          phone: "+998 77 312 84 85",
          bio: "Ma'naviy-ma'rifiy ishlar, o'quvchilar intizomi va maktab jamoasini qo'llab-quvvatlash bo'yicha mas'ul.",
        },
        {
          id: 4,
          full_name: "Atadjanov Ikram Xakimovich",
          position: "Boshqaruv xodimi",
          category: "Boshqaruv xodimi",
          phone: "+998 77 312 84 85",
          bio: "Maktabning ma'muriy-xo'jalik va tashkiliy boshqaruv jarayonlariga mas'ul xodim.",
        },
        {
          id: 5,
          full_name: "Matsapayev Bekzod Dilshod o'g'li",
          position: "Tizim administratori",
          category: "Axborot xavfsizligi va IT",
          phone: "+998 88 654 30 06 / +998 77 312 84 85",
          bio: "Maktab 49 ta'lim platformasining texnik barqarorligi, ma'lumotlar xavfsizligi va foydalanuvchi murojaatlariga mas'ul.",
        },
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
      videos: [
        {
          id: 1,
          title: "O'quvchilar",
          category: "Maktab hayoti",
          description: "49-sonli umumiy o'rta ta'lim maktabi o'quvchilari hayotidan videolavha.",
          video_path: "oquvchilar.mp4",
          poster_path: "entrance.jpg",
        },
      ],
      schedule: [
        // Dushanba (1)
        { id: 1, class_name: "10-A", day_of_week: 1, lesson_number: 1, time_range: "08:30 - 09:15", subject: "Kelajak soati" },
        { id: 2, class_name: "10-A", day_of_week: 1, lesson_number: 2, time_range: "09:20 - 10:05", subject: "Adabiyot" },
        { id: 3, class_name: "10-A", day_of_week: 1, lesson_number: 3, time_range: "10:10 - 10:55", subject: "Rus tili" },
        { id: 4, class_name: "10-A", day_of_week: 1, lesson_number: 4, time_range: "11:00 - 11:45", subject: "Algebra" },
        { id: 5, class_name: "10-A", day_of_week: 1, lesson_number: 5, time_range: "11:50 - 12:35", subject: "Geografiya" },
        // Seshanba (2)
        { id: 6, class_name: "10-A", day_of_week: 2, lesson_number: 1, time_range: "08:30 - 09:15", subject: "O'zbekiston tarixi" },
        { id: 7, class_name: "10-A", day_of_week: 2, lesson_number: 2, time_range: "09:20 - 10:05", subject: "Fizika" },
        { id: 8, class_name: "10-A", day_of_week: 2, lesson_number: 3, time_range: "10:10 - 10:55", subject: "Huquq" },
        { id: 9, class_name: "10-A", day_of_week: 2, lesson_number: 4, time_range: "11:00 - 11:45", subject: "Biologiya" },
        { id: 10, class_name: "10-A", day_of_week: 2, lesson_number: 5, time_range: "11:50 - 12:35", subject: "Jismoniy tarbiya" },
        { id: 11, class_name: "10-A", day_of_week: 2, lesson_number: 6, time_range: "12:40 - 13:25", subject: "Algebra" },
        // Chorshanba (3)
        { id: 12, class_name: "10-A", day_of_week: 3, lesson_number: 1, time_range: "08:30 - 09:15", subject: "Ingliz tili" },
        { id: 13, class_name: "10-A", day_of_week: 3, lesson_number: 2, time_range: "09:20 - 10:05", subject: "Tarbiya" },
        { id: 14, class_name: "10-A", day_of_week: 3, lesson_number: 3, time_range: "10:10 - 10:55", subject: "Informatika" },
        { id: 15, class_name: "10-A", day_of_week: 3, lesson_number: 4, time_range: "11:00 - 11:45", subject: "Ona tili" },
        { id: 16, class_name: "10-A", day_of_week: 3, lesson_number: 5, time_range: "11:50 - 12:35", subject: "ChQBT" },
        // Payshanba (4)
        { id: 17, class_name: "10-A", day_of_week: 4, lesson_number: 1, time_range: "08:30 - 09:15", subject: "Adabiyot" },
        { id: 18, class_name: "10-A", day_of_week: 4, lesson_number: 2, time_range: "09:20 - 10:05", subject: "Geografiya" },
        { id: 19, class_name: "10-A", day_of_week: 4, lesson_number: 3, time_range: "10:10 - 10:55", subject: "Qoraqalpoq tili" },
        { id: 20, class_name: "10-A", day_of_week: 4, lesson_number: 4, time_range: "11:00 - 11:45", subject: "ChQBT" },
        { id: 21, class_name: "10-A", day_of_week: 4, lesson_number: 5, time_range: "11:50 - 12:35", subject: "Kimyo" },
        { id: 22, class_name: "10-A", day_of_week: 4, lesson_number: 6, time_range: "12:40 - 13:25", subject: "Fizika" },
        // Juma (5)
        { id: 23, class_name: "10-A", day_of_week: 5, lesson_number: 1, time_range: "08:30 - 09:15", subject: "Jismoniy tarbiya" },
        { id: 24, class_name: "10-A", day_of_week: 5, lesson_number: 2, time_range: "09:20 - 10:05", subject: "Algebra" },
        { id: 25, class_name: "10-A", day_of_week: 5, lesson_number: 3, time_range: "10:10 - 10:55", subject: "Informatika" },
        { id: 26, class_name: "10-A", day_of_week: 5, lesson_number: 4, time_range: "11:00 - 11:45", subject: "Kimyo" },
        { id: 27, class_name: "10-A", day_of_week: 5, lesson_number: 5, time_range: "11:50 - 12:35", subject: "Geometriya" },
        // Shanba (6)
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
          ip_address: "https-secure",
          details: "Maktab 49 himoyalangan ta'lim platformasi ishga tushirildi (PBKDF2-SHA256).",
          severity: "info",
          created_at: now,
        },
      ],
    };
  }

  function loadLocalStore() {
    try {
      const raw = localStorage.getItem(STORE_KEY);
      if (raw) return JSON.parse(raw);
    } catch { /* ignore */ }
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

  function checkStaticRateLimit(username) {
    try {
      const all = JSON.parse(localStorage.getItem(RATE_KEY) || "{}");
      const now = Date.now();
      const key = username.toLowerCase();
      const attempts = (all[key] || []).filter((t) => now - t < LOCKOUT_MS);
      all[key] = attempts;
      localStorage.setItem(RATE_KEY, JSON.stringify(all));
      if (attempts.length >= MAX_ATTEMPTS) {
        return Math.ceil((LOCKOUT_MS - (now - attempts[0])) / 1000);
      }
      return 0;
    } catch {
      return 0;
    }
  }

  function recordStaticFailure(username) {
    const all = JSON.parse(localStorage.getItem(RATE_KEY) || "{}");
    const now = Date.now();
    const key = username.toLowerCase();
    const attempts = (all[key] || []).filter((t) => now - t < LOCKOUT_MS);
    attempts.push(now);
    all[key] = attempts;
    localStorage.setItem(RATE_KEY, JSON.stringify(all));
    return Math.max(MAX_ATTEMPTS - attempts.length, 0);
  }

  function clearStaticFailure(username) {
    const all = JSON.parse(localStorage.getItem(RATE_KEY) || "{}");
    delete all[username.toLowerCase()];
    localStorage.setItem(RATE_KEY, JSON.stringify(all));
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
      const waitSec = checkStaticRateLimit(username);
      if (waitSec > 0) {
        addAudit(store, "LOGIN_LOCKED", username, `Ko'p xato urinish tufayli bloklandi (${waitSec}s).`, "danger");
        saveLocalStore(store);
        throw new Error(`Xavfsizlik sababli vaqtincha bloklandi. ${waitSec} soniyadan so'ng qayta urinib ko'ring.`);
      }
      const user = store.users.find((u) => u.username.toLowerCase() === username.toLowerCase() && u.is_active);
      const valid = user ? await verifyPasswordWeb(password, user.password_hash) : false;
      if (!user || !valid) {
        const rem = recordStaticFailure(username);
        addAudit(store, "LOGIN_FAILED", username || "noma'lum", `Noto'g'ri login yoki parol (qolgan: ${rem}).`, "warning");
        saveLocalStore(store);
        throw new Error(`Login yoki parol noto'g'ri. Qolgan urinishlar soni: ${rem}.`);
      }
      if (user.role !== "admin" && user.role !== "director") {
        addAudit(store, "LOGIN_DENIED", user.username, "Faqat admin va direktor kirishi mumkin.", "warning");
        saveLocalStore(store);
        throw new Error("Tizimga kirish faqat Tizim administratori va Maktab direktori uchun! Qolgan foydalanuvchilar saytni logindan o'tmasdan kuzatishlari mumkin.");
      }
      clearStaticFailure(username);
      const pubUser = { id: user.id, username: user.username, full_name: user.full_name, role: user.role, position: user.position };
      const csrf = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
      sessionStorage.setItem(SESSION_KEY, JSON.stringify({ user: pubUser, csrf_token: csrf, expires_at: Date.now() + SESSION_TTL_MS }));
      addAudit(store, "LOGIN_SUCCESS", user.username, `Muvaffaqiyatli kirish (${user.role}).`, "info");
      saveLocalStore(store);
      return { ok: true, csrf_token: csrf, user: pubUser };
    }

    const sess = getStaticSession();
    const isManager = Boolean(sess && (sess.user.role === "admin" || sess.user.role === "director"));

    if (url === "/api/dashboard" && method === "GET") {
      return {
        school: store.school,
        leadership: store.leadership,
        teachers: store.teachers,
        gallery: store.gallery,
        videos: store.videos,
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
      return { ok: true, message: "Murojaatingiz xavfsiz qabul qilindi!" };
    }

    if (!sess || !isManager) throw new Error("Bu amal faqat Tizim administratori va Maktab direktori uchun.");

    if (url === "/api/auth/logout" && method === "POST") {
      addAudit(store, "LOGOUT", sess.user.username, "Foydalanuvchi tizimdan chiqdi.", "info");
      saveLocalStore(store);
      sessionStorage.removeItem(SESSION_KEY);
      return { ok: true };
    }

    if (url === "/api/school" && method === "PUT") {
      const allowed = ["total_students", "total_teachers", "deputy_directors", "phone_1", "phone_2"];
      for (const k of allowed) {
        if (body[k] !== undefined && String(body[k]).trim() !== "") {
          store.school[k] = String(body[k]).trim();
        }
      }
      addAudit(store, "SCHOOL_INFO_UPDATE", sess.user.username, "Maktab ko'rsatkichlari yangilandi.", "info");
      saveLocalStore(store);
      return { ok: true, school: store.school };
    }

    if (url === "/api/appeals" && method === "GET") {
      return { appeals: store.appeals };
    }

    if (url.startsWith("/api/appeals/") && method === "PUT") {
      if (!isManager) throw new Error("Ruxsat yo'q.");
      const id = Number(url.split("/").pop());
      const item = store.appeals.find((a) => a.id === id);
      if (item) item.status = body.status;
      saveLocalStore(store);
      return { ok: true, appeals: store.appeals };
    }

    if (url === "/api/teachers" && method === "POST") {
      if (!isManager) throw new Error("Ruxsat yo'q.");
      if (!body.full_name || body.full_name.length < 3) throw new Error("F.I.Sh. kamida 3 ta harf bo'lishi kerak.");
      store.teachers.push({
        id: Date.now(),
        full_name: body.full_name,
        subject: body.subject || "O'qituvchi",
        category: body.category || "Pedagog xodim",
        phone: body.phone || "",
        experience_years: Number(body.experience_years || 0),
      });
      store.teachers.sort((a, b) => a.full_name.localeCompare(b.full_name));
      addAudit(store, "TEACHER_ADD", sess.user.username, `Yangi o'qituvchi qo'shildi: ${body.full_name}`, "info");
      saveLocalStore(store);
      return { ok: true, teachers: store.teachers };
    }

    if (url.startsWith("/api/teachers/") && method === "PUT") {
      if (!isManager) throw new Error("Ruxsat yo'q.");
      const id = Number(url.split("/").pop());
      const t = store.teachers.find((x) => x.id === id);
      if (!t) throw new Error("O'qituvchi topilmadi.");
      t.full_name = body.full_name;
      t.subject = body.subject || "O'qituvchi";
      t.category = body.category || "Pedagog xodim";
      t.phone = body.phone || "";
      t.experience_years = Number(body.experience_years || 0);
      addAudit(store, "TEACHER_UPDATE", sess.user.username, `Tahrirlandi: ${body.full_name}`, "info");
      saveLocalStore(store);
      return { ok: true, teachers: store.teachers };
    }

    if (url.startsWith("/api/teachers/") && method === "DELETE") {
      if (!isManager) throw new Error("Ruxsat yo'q.");
      const id = Number(url.split("/").pop());
      store.teachers = store.teachers.filter((x) => x.id !== id);
      addAudit(store, "TEACHER_DELETE", sess.user.username, `O'qituvchi #${id} o'chirildi.`, "warning");
      saveLocalStore(store);
      return { ok: true, teachers: store.teachers };
    }

    if (url === "/api/schedule" && method === "PUT") {
      if (!isManager) throw new Error("Faqat rahbariyat yoki administrator dars jadvalini o'zgartira oladi.");
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
      return { ok: true, schedule: store.schedule };
    }

    if (url === "/api/auth/change-password" && method === "POST") {
      const u = store.users.find((x) => x.id === sess.user.id);
      if (!u || !(await verifyPasswordWeb(body.current_password || "", u.password_hash))) {
        throw new Error("Joriy parol noto'g'ri kiritildi.");
      }
      const pwErr = validatePasswordStrength(body.new_password);
      if (pwErr) throw new Error(pwErr);
      u.password_hash = await hashPasswordWeb(body.new_password);
      addAudit(store, "PASSWORD_CHANGE", u.username, "Foydalanuvchi parolini yangiladi.", "info");
      saveLocalStore(store);
      return { ok: true, message: "Parol muvaffaqiyatli va xavfsiz yangilandi!" };
    }

    if (url === "/api/admin/users" && method === "POST") {
      if (sess.user.role !== "admin") throw new Error("Faqat tizim administratori yangi foydalanuvchi yarata oladi.");
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
        role: body.role || "teacher",
        position: body.position || "O'qituvchi",
        is_active: 1,
        created_at: Math.floor(Date.now() / 1000),
      });
      addAudit(store, "USER_CREATE", sess.user.username, `Yangi hisob yaratildi: ${body.username} (${body.role})`, "info");
      saveLocalStore(store);
      return { ok: true };
    }

    if (url === "/api/admin/security" && method === "GET") {
      if (!isManager) throw new Error("Ruxsat yo'q.");
      return { audit_logs: store.audit_logs };
    }

    throw new Error("So'rov manzili topilmadi.");
  }

  // ==================== 2. ASOSIY ILOVA HOLATI VA UI ====================
  let useStaticMode = false;

  const state = {
    user: null,
    csrfToken: "",
    school: {},
    leadership: [],
    teachers: [],
    gallery: [],
    videos: [],
    schedule: [],
    appeals: [],
    auditLogs: [],
    currentPage: "home",
    scheduleView: "daily",
    selectedDay: getInitialSchoolDay(),
    selectedClass: "10-A",
    galleryFilter: "all",
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
    videos: "Maktab videolari",
    location: "Maktab lokatsiyasi",
    contact: "Murojaatlar va aloqa",
    security: "Xavfsizlik va sozlamalar",
  };

  const ROLE_LABELS = {
    admin: "Tizim administratori",
    director: "Maktab direktori",
    teacher: "O'qituvchi / Xodim",
  };

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
    1: "08:30 - 09:15",
    2: "09:20 - 10:05",
    3: "10:10 - 10:55",
    4: "11:00 - 11:45",
    5: "11:50 - 12:35",
    6: "12:40 - 13:25",
  };

  const UZ_MONTHS = [
    "yanvar", "fevral", "mart", "aprel", "may", "iyun",
    "iyul", "avgust", "sentabr", "oktabr", "noyabr", "dekabr",
  ];

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
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
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
    if (useStaticMode) {
      return staticApiDispatch(url, options);
    }
    const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
    if (state.csrfToken && options.method && options.method !== "GET") {
      headers["X-CSRF-Token"] = state.csrfToken;
    }
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
  document.querySelectorAll("[data-close-modal]").forEach((el) => {
    el.addEventListener("click", () => closeModal(el.dataset.closeModal));
  });
  document.getElementById("open-help-btn").addEventListener("click", () => openModal("help-modal"));
  document.getElementById("open-help-btn-2").addEventListener("click", () => openModal("help-modal"));

  async function checkSession() {
    try {
      const res = await apiFetch("/api/auth/me");
      if (res.authenticated && (res.user.role === "admin" || res.user.role === "director")) {
        state.user = res.user;
        state.csrfToken = res.csrf_token;
      } else {
        state.user = null;
        state.csrfToken = "";
      }
    } catch {
      state.user = null;
      state.csrfToken = "";
    }
    await enterApp();
  }

  function openLoginScreen() {
    closeMobileSidebar();
    loginError.classList.add("hidden");
    loginPassword.value = "";
    syncHints();
    appView.classList.add("hidden");
    loginView.classList.remove("hidden");
    loginUsername.focus();
  }

  function closeLoginScreen() {
    loginView.classList.add("hidden");
    appView.classList.remove("hidden");
  }

  document.querySelectorAll("[data-open-login]").forEach((btn) => {
    btn.addEventListener("click", openLoginScreen);
  });
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
    loginError.classList.add("hidden");
    const username = loginUsername.value.trim();
    const password = loginPassword.value;
    if (!username || !password) {
      loginError.textContent = "Iltimos, login va parolni kiriting.";
      loginError.classList.remove("hidden");
      return;
    }
    loginSubmitBtn.disabled = true;
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
      loginError.textContent = err.message;
      loginError.classList.remove("hidden");
    } finally {
      loginSubmitBtn.disabled = false;
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
    state.videos = data.videos || [];
    state.schedule = data.schedule || [];
    state.appeals = data.appeals || [];

    renderHome();
    renderSchedule();
    renderLeadership();
    renderTeachers();
    renderGallery();
    renderVideos();
    renderLocation();
    renderAppeals();
    fillSchoolEditForm();

    if (state.user && (state.user.role === "admin" || state.user.role === "director")) {
      loadSecurityAudit();
    }
  }

  function fillSchoolEditForm() {
    const f1 = document.getElementById("si-students");
    if (!f1) return;
    f1.value = state.school.total_students || "473";
    document.getElementById("si-teachers").value = state.school.total_teachers || "43";
    document.getElementById("si-deputies").value = state.school.deputy_directors || "2";
    document.getElementById("si-phone1").value = state.school.phone_1 || "+998 88 654 30 06";
  }

  document.getElementById("school-info-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fb = document.getElementById("school-info-feedback");
    fb.className = "alert-box hidden";
    const payload = {
      total_students: document.getElementById("si-students").value.trim(),
      total_teachers: document.getElementById("si-teachers").value.trim(),
      deputy_directors: document.getElementById("si-deputies").value.trim(),
      phone_1: document.getElementById("si-phone1").value.trim(),
    };
    try {
      const res = await apiFetch("/api/school", { method: "PUT", body: JSON.stringify(payload) });
      state.school = res.school || state.school;
      renderHome();
      renderTeachers();
      fb.textContent = "Maktab ko'rsatkichlari muvaffaqiyatli saqlandi!";
      fb.className = "alert-box alert-success";
    } catch (err) {
      fb.textContent = err.message;
      fb.className = "alert-box alert-error";
    }
  });

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
    if (state.currentPage === "videos" && pageKey !== "videos") {
      document.querySelectorAll("#videos-grid video").forEach((v) => v.pause());
    }
    state.currentPage = pageKey;
    document.querySelectorAll(".nav-item").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.page === pageKey);
    });
    document.querySelectorAll(".page-section").forEach((sec) => {
      sec.classList.toggle("active", sec.id === `page-${pageKey}`);
    });
    document.getElementById("current-page-title").textContent = PAGE_TITLES[pageKey] || "Maktab 49";
    closeMobileSidebar();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  document.querySelectorAll(".nav-item").forEach((btn) => btn.addEventListener("click", () => switchPage(btn.dataset.page)));
  document.querySelectorAll("[data-goto]").forEach((btn) => btn.addEventListener("click", () => switchPage(btn.dataset.goto)));

  function renderHome() {
    document.getElementById("stat-students").textContent = state.school.total_students || "473";
    document.getElementById("students-page-total").textContent = state.school.total_students || "473";
    document.getElementById("stat-teachers").textContent = state.school.total_teachers || "43";
    document.getElementById("stat-deputies").textContent = state.school.deputy_directors || "2";

    const mini = document.getElementById("home-mini-gallery");
    const previewItems = state.gallery.slice(1, 5);
    mini.innerHTML = previewItems
      .map(
        (item, idx) => `
      <div class="mini-photo-card" data-preview-idx="${idx + 1}">
        <img src="${esc(item.image_path)}" alt="${esc(item.title)}" loading="lazy" />
        <span>${esc(item.title)}</span>
      </div>`
      )
      .join("");
    mini.querySelectorAll(".mini-photo-card").forEach((el) => {
      el.addEventListener("click", () => openLightbox(state.gallery, Number(el.dataset.previewIdx)));
    });
  }

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

  function renderSchedule() {
    renderDailySchedule();
    renderWeeklySchedule();
  }

  function renderDailySchedule() {
    const weekDates = getCurrentWeekDates();
    const strip = document.getElementById("daily-day-strip");
    strip.innerHTML = weekDates
      .map(
        (d) => `
      <button type="button" class="day-card ${d.day === state.selectedDay ? "active" : ""} ${d.day === 7 ? "is-sunday" : ""}" data-select-day="${d.day}">
        <span class="day-short">${esc(d.short)}</span>
        <span class="day-num">${d.dateNum}</span>
      </button>`
      )
      .join("");
    strip.querySelectorAll("[data-select-day]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.selectedDay = Number(btn.dataset.selectDay);
        renderDailySchedule();
      });
    });

    const curDayInfo = weekDates.find((d) => d.day === state.selectedDay) || weekDates[0];
    document.getElementById("daily-board-caption").textContent = `${curDayInfo.dateNum} ${curDayInfo.monthName} (${curDayInfo.full}) — ${state.selectedClass} sinf kunlik dars jadvali`;

    const body = document.getElementById("daily-board-body");
    const isManager = state.user && (state.user.role === "admin" || state.user.role === "director");
    if (state.selectedDay === 7) {
      body.innerHTML = `<div class="sunday-notice">Yakshanba — dam olish kuni. Darslar mavjud emas.</div>`;
      return;
    }

    let cellsHtml = `
      <div class="daily-head-cell">Sinf</div>
      ${[1, 2, 3, 4, 5, 6].map((n) => `<div class="daily-head-cell">${n}-dars</div>`).join("")}
      <div class="daily-class-cell">${esc(state.selectedClass)}</div>
    `;
    for (let n = 1; n <= 6; n++) {
      const slot = getSlot(state.selectedDay, n);
      const editableAttr = isManager ? `data-edit-slot="${state.selectedDay}:${n}"` : "";
      const editableCls = isManager ? "lesson-editable" : "";
      if (slot) {
        cellsHtml += `
          <div class="daily-lesson-cell ${editableCls}" data-lesson-label="${n}-dars" ${editableAttr}>
            <div class="lesson-mobile-wrap">
              <div class="lesson-time">${esc(slot.time_range)}</div>
              <div class="lesson-subject-pill">${esc(slot.subject)}</div>
            </div>
          </div>`;
      } else {
        cellsHtml += `
          <div class="daily-lesson-cell ${editableCls}" data-lesson-label="${n}-dars" ${editableAttr}>
            <div class="lesson-mobile-wrap"><div class="lesson-empty-dash">—</div></div>
          </div>`;
      }
    }
    body.innerHTML = `<div class="daily-grid-table">${cellsHtml}</div>`;
    if (isManager) {
      body.querySelectorAll("[data-edit-slot]").forEach((el) => {
        el.addEventListener("click", () => {
          const [d, l] = el.dataset.editSlot.split(":").map(Number);
          openScheduleEditModal(d, l);
        });
      });
    }
  }

  function renderWeeklySchedule() {
    const isManager = state.user && (state.user.role === "admin" || state.user.role === "director");
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
        for (let n = 1; n <= 6; n++) {
          const slot = getSlot(d.day, n);
          if (slot) daySlots.push(slot);
        }
        return `
          <div class="weekly-day-card">
            <div class="weekly-day-card-head">${esc(d.full)} (${daySlots.length} ta dars)</div>
            ${daySlots.map((s) => `<div class="weekly-day-card-row ${isManager ? "lesson-editable" : ""}" ${isManager ? `data-edit-slot="${d.day}:${s.lesson_number}"` : ""}><div><strong style="color:var(--accent-indigo);margin-right:6px;">${s.lesson_number}.</strong><strong>${esc(s.subject)}</strong></div><span class="lesson-time">${esc(s.time_range)}</span></div>`).join("")}
          </div>`;
      })
      .join("");

    if (isManager) {
      document.querySelectorAll("#schedule-weekly-panel [data-edit-slot]").forEach((el) => {
        el.addEventListener("click", () => {
          const [d, l] = el.dataset.editSlot.split(":").map(Number);
          openScheduleEditModal(d, l);
        });
      });
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
    } catch (err) {
      errEl.textContent = err.message;
      errEl.classList.remove("hidden");
    }
  });

  function renderLocation() {
    const lat = state.school.location_lat || "41.572770";
    const lng = state.school.location_lng || "60.890981";
    const coords = `${lat}, ${lng}`;
    document.getElementById("coords-text").textContent = coords;
    document.getElementById("google-maps-link").href = `https://www.google.com/maps/search/?api=1&query=${lat},${lng}`;
    document.getElementById("yandex-maps-link").href = `https://yandex.uz/maps/?pt=${lng},${lat}&z=17&l=sat,skl`;
  }

  document.getElementById("copy-coords-btn").addEventListener("click", async (e) => {
    const coords = document.getElementById("coords-text").textContent;
    try {
      await navigator.clipboard.writeText(coords);
      const orig = e.target.textContent;
      e.target.textContent = "Nusxalandi ✓";
      setTimeout(() => (e.target.textContent = orig), 1800);
    } catch {
      window.prompt("Koordinatani nusxalang:", coords);
    }
  });

  function renderLeadership() {
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
        </article>`;
      })
      .join("");
  }

  const teacherSearchInput = document.getElementById("teacher-search");
  teacherSearchInput.addEventListener("input", renderTeachers);

  function renderTeachers() {
    const query = teacherSearchInput.value.trim().toLowerCase();
    const filtered = state.teachers.filter((t) => t.full_name.toLowerCase().includes(query) || t.subject.toLowerCase().includes(query) || t.category.toLowerCase().includes(query));
    document.getElementById("teachers-count-badge").textContent = `Jami: ${state.school.total_teachers || "43"} nafar • Tizimda: ${state.teachers.length} nafar`;
    const isManager = state.user && (state.user.role === "admin" || state.user.role === "director");
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
      const res = id
        ? await apiFetch(`/api/teachers/${id}`, { method: "PUT", body: JSON.stringify(payload) })
        : await apiFetch("/api/teachers", { method: "POST", body: JSON.stringify(payload) });
      state.teachers = res.teachers;
      renderTeachers();
      closeModal("teacher-modal");
    } catch (err) {
      errEl.textContent = err.message;
      errEl.classList.remove("hidden");
    }
  });

  async function handleDeleteTeacher(id) {
    if (!window.confirm("Ushbu o'qituvchini ro'yxatdan o'chirishni tasdiqlaysizmi?")) return;
    try {
      const res = await apiFetch(`/api/teachers/${id}`, { method: "DELETE" });
      state.teachers = res.teachers;
      renderTeachers();
    } catch (err) { window.alert(err.message); }
  }

  document.getElementById("gallery-filters").addEventListener("click", (e) => {
    const btn = e.target.closest(".filter-chip");
    if (!btn) return;
    state.galleryFilter = btn.dataset.cat;
    document.querySelectorAll(".filter-chip").forEach((c) => c.classList.toggle("active", c === btn));
    renderGallery();
  });

  function renderGallery() {
    const items = state.galleryFilter === "all" ? state.gallery : state.gallery.filter((g) => g.category === state.galleryFilter);
    const grid = document.getElementById("gallery-grid");
    grid.innerHTML = items
      .map(
        (item, idx) => `
      <article class="gallery-card" data-gal-idx="${idx}">
        <div class="gallery-img-wrap"><img src="${esc(item.image_path)}" alt="${esc(item.title)}" loading="lazy" /><span class="gallery-cat-badge">${esc(item.category)}</span></div>
        <div class="gallery-card-body"><h4>${esc(item.title)}</h4><p>${esc(item.description)}</p></div>
      </article>`
      )
      .join("");
    grid.querySelectorAll(".gallery-card").forEach((card) => card.addEventListener("click", () => openLightbox(items, Number(card.dataset.galIdx))));
  }

  function renderVideos() {
    const grid = document.getElementById("videos-grid");
    if (!grid) return;
    if (!state.videos.length) {
      grid.innerHTML = `<div class="card" style="color:var(--text-soft);">Hozircha videolar qo'shilmagan.</div>`;
      return;
    }
    grid.innerHTML = state.videos
      .map(
        (v) => `
      <article class="video-card">
        <div class="video-player-wrap">
          <video controls playsinline preload="metadata" ${v.poster_path ? `poster="${esc(v.poster_path)}"` : ""}>
            <source src="${esc(v.video_path)}" type="video/mp4" />
            Brauzeringiz video ijrosini qo'llab-quvvatlamaydi.
          </video>
        </div>
        <div class="video-card-body">
          <div class="video-card-head"><h4>${esc(v.title)}</h4><span class="count-badge">${esc(v.category)}</span></div>
          <p>${esc(v.description)}</p>
        </div>
      </article>`
      )
      .join("");
  }

  document.querySelectorAll("[data-lightbox]").forEach((el) => {
    el.addEventListener("click", () => openLightbox([{ image_path: el.dataset.lightbox, title: el.dataset.caption || "" }], 0));
  });

  const lightbox = document.getElementById("lightbox");
  const lbImg = document.getElementById("lb-img");
  const lbCaption = document.getElementById("lb-caption");
  function openLightbox(items, index) {
    state.lightboxItems = items;
    state.lightboxIndex = index;
    updateLightbox();
    lightbox.classList.remove("hidden");
  }
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
    } catch (err) {
      fb.textContent = err.message;
      fb.className = "alert-box alert-error";
    }
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
      sel.addEventListener("change", async () => {
        await apiFetch(`/api/appeals/${sel.dataset.appealStatus}`, { method: "PUT", body: JSON.stringify({ status: sel.value }) });
      });
    });
  }

  document.getElementById("change-pw-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fb = document.getElementById("pw-feedback");
    fb.className = "alert-box hidden";
    const cur = document.getElementById("cur-pw").value;
    const nw = document.getElementById("new-pw").value;
    const cnf = document.getElementById("confirm-pw").value;
    if (nw !== cnf) {
      fb.textContent = "Yangi parol va tasdiqlash paroli bir xil emas.";
      fb.className = "alert-box alert-error";
      return;
    }
    try {
      const res = await apiFetch("/api/auth/change-password", { method: "POST", body: JSON.stringify({ current_password: cur, new_password: nw }) });
      fb.textContent = res.message;
      fb.className = "alert-box alert-success";
      e.target.reset();
    } catch (err) {
      fb.textContent = err.message;
      fb.className = "alert-box alert-error";
    }
  });

  document.getElementById("create-user-form").addEventListener("submit", async (e) => {
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
    } catch (err) {
      fb.textContent = err.message;
      fb.className = "alert-box alert-error";
    }
  });

  document.getElementById("refresh-audit-btn").addEventListener("click", loadSecurityAudit);

  function renderAuditLogs() {
    const list = document.getElementById("audit-list");
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
