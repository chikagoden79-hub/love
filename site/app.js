(() => {
  'use strict';

  const cfg = window.APP_CONFIG || {};
  const $ = (id) => document.getElementById(id);
  const LS = { key: 'love.familyKey', device: 'love.deviceId', vapid: 'love.vapid' };

  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* ignore */ } },
    del(k) { try { localStorage.removeItem(k); } catch (e) { /* ignore */ } }
  };

  const MESSAGES = {
    timeout: 'Сервер не ответил вовремя. Проверьте интернет и попробуйте ещё раз.',
    network: 'Нет связи с сервером. Проверьте интернет.',
    unauthorized: 'Неверный ключ семьи. Проверьте его в настройках ⚙︎.',
    origin: 'Сервер не разрешил адрес этого сайта (проверьте ALLOWED_ORIGIN).',
    server_config: 'Сервер настроен не полностью (не хватает секретов функции).',
    storage: 'База на сервере недоступна. Если проект Supabase «уснул» — откройте его в панели Supabase.',
    not_registered: 'Это устройство не подключено. Откройте ⚙︎ и нажмите «Подключить».',
    no_recipients: 'Второй телефон ещё не подключён.',
    recipients_gone: 'Второй телефон отключился (удалено приложение или запрещены уведомления). Его нужно подключить заново в ⚙︎.',
    push_failed: 'Push-сервис не принял сообщение. Попробуйте ещё раз чуть позже.',
    bad_subscription: 'Сервер не принял подписку этого устройства.',
    bad_json: 'Ошибка запроса.',
    bad_response: 'Сервер вернул непонятный ответ. Проверьте адрес функции в config.js.'
  };

  class ApiError extends Error { constructor(status, code) { super(code); this.status = status; this.code = code; } }
  class UiError extends Error {}
  const humanError = (e) => e instanceof UiError ? e.message
    : e instanceof ApiError ? (MESSAGES[e.code] || `Ошибка сервера (${e.status} ${e.code}).`)
    : 'Что-то пошло не так: ' + ((e && e.message) || 'неизвестная ошибка');

  const configured = () => typeof cfg.API_URL === 'string' && /^https:\/\/.+/.test(cfg.API_URL);

  async function api(action, payload) {
    if (!configured()) throw new UiError('Приложение не настроено: в config.js не указан адрес функции.');
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 20000);
    let res;
    try {
      // text/plain — «простой» CORS-запрос, без предварительного OPTIONS
      res = await fetch(cfg.API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
        body: JSON.stringify(Object.assign({ action }, payload)),
        signal: ctrl.signal,
        cache: 'no-store'
      });
    } catch (e) {
      throw new ApiError(0, e && e.name === 'AbortError' ? 'timeout' : 'network');
    } finally { clearTimeout(timer); }
    let data = null;
    try { data = await res.json(); } catch (e) { /* не JSON */ }
    if (!res.ok || !data || data.ok !== true) throw new ApiError(res.status, (data && data.error) || 'bad_response');
    return data;
  }

  // ---------- среда ----------
  const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  const isStandalone = () => navigator.standalone === true || (window.matchMedia && matchMedia('(display-mode: standalone)').matches);
  const pushSupported = () => 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;

  function deviceId() {
    let id = store.get(LS.device);
    if (!id || !/^[A-Za-z0-9-]{8,64}$/.test(id)) {
      id = (crypto.randomUUID ? crypto.randomUUID() : Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join(''));
      store.set(LS.device, id);
    }
    return id;
  }
  const creds = () => ({ key: store.get(LS.key) || '', deviceId: deviceId() });
  const isSetUp = () => !!store.get(LS.key);

  // ---------- UI-помощники ----------
  function setStatus(text, kind) {
    const el = $('status');
    el.textContent = text || '';
    el.className = 'status' + (kind ? ' ' + kind : '');
  }
  function note(id, text, kind) {
    const el = $(id);
    el.textContent = text || '';
    el.className = 'note' + (kind ? ' ' + kind : '');
  }
  function floatHearts(x, y) {
    for (let i = 0; i < 6; i++) {
      const h = document.createElement('div');
      h.className = 'float-heart';
      h.textContent = ['❤️', '💖', '💕', '💗'][i % 4];
      h.style.left = (x - 14 + (Math.random() * 80 - 40)) + 'px';
      h.style.top = (y - 14 + (Math.random() * 30 - 15)) + 'px';
      h.style.animationDelay = (i * 60) + 'ms';
      document.body.appendChild(h);
      setTimeout(() => h.remove(), 1400);
    }
  }
  const vibrate = (p) => { try { navigator.vibrate && navigator.vibrate(p); } catch (e) { /* ignore */ } };

  function b64uToBytes(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  }

  // ---------- push-подписка ----------
  let swReg = null;
  async function getReg() {
    if (swReg) return swReg;
    await navigator.serviceWorker.register('./sw.js', { scope: './' });
    swReg = await navigator.serviceWorker.ready;
    return swReg;
  }

  async function vapidKey() {
    const data = await api('config', {});
    return data.vapidPublicKey;
  }

  async function ensureSubscription(interactive) {
    if (!pushSupported()) {
      throw new UiError(isIOS ? 'На iPhone уведомления работают только из приложения на главном экране (iOS 16.4+).' : 'Этот браузер не поддерживает push-уведомления.');
    }
    if (isIOS && !isStandalone()) throw new UiError('Сначала добавьте приложение на главный экран и откройте его с иконки.');
    if (Notification.permission === 'denied') {
      throw new UiError(isIOS ? 'Уведомления запрещены: Настройки → Уведомления → «Люблю» → Разрешить.' : 'Уведомления запрещены в настройках браузера для этого сайта.');
    }
    if (Notification.permission !== 'granted') {
      if (!interactive) return null;
      const p = await Notification.requestPermission();
      if (p !== 'granted') throw new UiError('Без разрешения на уведомления сообщения не будут приходить.');
    }
    const reg = await getReg();
    const key = await vapidKey();
    let sub = await reg.pushManager.getSubscription();
    if (sub && store.get(LS.vapid) && store.get(LS.vapid) !== key) {
      await sub.unsubscribe().catch(() => {});
      sub = null;
    }
    if (!sub) {
      try {
        sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64uToBytes(key) });
      } catch (e) {
        throw new UiError('Не удалось оформить подписку на уведомления: ' + (e && e.message ? e.message : e));
      }
    }
    store.set(LS.vapid, key);
    return sub.toJSON();
  }

  async function register(interactive) {
    const sub = await ensureSubscription(interactive);
    if (!sub) return null;
    return api('register', Object.assign(creds(), { subscription: sub }));
  }

  // ---------- отправка ----------
  let sending = false;
  async function send(origin) {
    if (sending) return;
    if (!isSetUp()) { setStatus('Сначала подключите устройство в ⚙︎', 'error'); openSettings(); return; }
    sending = true;
    $('heartBtn').classList.add('busy');
    setStatus('Отправляем…');
    vibrate(20);
    try {
      await api('send', creds());
      setStatus('Отправлено ❤️', 'ok');
      if (origin) floatHearts(origin.x, origin.y);
      vibrate([30, 40, 30]);
      return true;
    } catch (e) {
      if (e instanceof ApiError && e.code === 'not_registered' && Notification.permission === 'granted') {
        // подписка потерялась на сервере — тихо переподключаемся и пробуем ещё раз
        try { await register(false); sending = false; return send(origin); } catch (_) { /* покажем ошибку ниже */ }
      }
      setStatus(humanError(e), 'error');
      vibrate(120);
      return false;
    } finally {
      sending = false;
      $('heartBtn').classList.remove('busy');
    }
  }

  // ---------- настройки ----------
  function openSettings() {
    $('familyKey').value = store.get(LS.key) || '';
    $('iosHint').hidden = !(isIOS && !isStandalone());
    $('settings').hidden = false;
  }
  function closeSettings() { $('settings').hidden = true; }

  async function onConnect() {
    const key = $('familyKey').value.trim();
    if (key.length < 16) return note('connectMsg', 'Вставьте ключ семьи полностью.', 'error');
    store.set(LS.key, key);
    const btn = $('connectBtn');
    btn.disabled = true;
    note('connectMsg', 'Подключаем…');
    try {
      const data = await register(true);
      note('connectMsg', data.others
        ? 'Готово! Устройство подключено ❤️ Второй телефон тоже на связи.'
        : 'Готово! Устройство подключено ❤️ Теперь подключите второй телефон с тем же ключом.', 'ok');
    } catch (e) {
      note('connectMsg', humanError(e), 'error');
    } finally { btn.disabled = false; }
  }

  async function onCheck() {
    note('checkMsg', 'Проверяем…');
    try {
      const data = await api('status', creds());
      $('linkInfo').textContent = (data.registered ? 'Это устройство подключено ✅' : 'Это устройство ещё не подключено ⚠️') +
        (data.others ? '. Второй телефон подключён ✅' : '. Второй телефон пока не подключён.');
      note('checkMsg', 'Связь с сервером есть ✅', 'ok');
    } catch (e) { note('checkMsg', humanError(e), 'error'); }
  }

  async function onTest() {
    note('checkMsg', '');
    try {
      const reg = await getReg();
      if (Notification.permission !== 'granted') throw new UiError('Уведомления ещё не разрешены — нажмите «Подключить».');
      await reg.showNotification('❤️', { body: 'Я тебя люблю ❤️', icon: 'icon-192.png' });
      note('checkMsg', 'Показали тестовое уведомление на этом устройстве.', 'ok');
    } catch (e) { note('checkMsg', humanError(e), 'error'); }
  }

  async function onDisconnect() {
    note('disconnectMsg', 'Отключаем…');
    try {
      if (store.get(LS.key)) await api('unregister', creds()).catch((e) => { if (!(e instanceof ApiError && e.code === 'unauthorized')) throw e; });
      if (pushSupported()) {
        const reg = await getReg();
        const sub = await reg.pushManager.getSubscription();
        if (sub) await sub.unsubscribe();
      }
      store.del(LS.key); store.del(LS.vapid);
      $('familyKey').value = '';
      note('disconnectMsg', 'Устройство отключено.', 'ok');
    } catch (e) { note('disconnectMsg', humanError(e), 'error'); }
  }

  // ---------- установка (Android) ----------
  let installEvt = null;
  window.addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); installEvt = e; $('installCard').hidden = false; });
  window.addEventListener('appinstalled', () => { $('installCard').hidden = true; installEvt = null; });

  // ---------- старт ----------
  function init() {
    $('heartBtn').addEventListener('click', (e) => {
      const r = e.currentTarget.getBoundingClientRect();
      send({ x: r.left + r.width / 2, y: r.top + r.height / 3 });
    });
    $('openSettings').addEventListener('click', openSettings);
    $('closeSettings').addEventListener('click', closeSettings);
    $('connectBtn').addEventListener('click', onConnect);
    $('checkBtn').addEventListener('click', onCheck);
    $('testBtn').addEventListener('click', onTest);
    $('disconnectBtn').addEventListener('click', onDisconnect);
    $('installBtn').addEventListener('click', async () => {
      if (!installEvt) return;
      installEvt.prompt();
      await installEvt.userChoice.catch(() => {});
      installEvt = null; $('installCard').hidden = true;
    });

    if (!configured()) { setStatus('В config.js не указан адрес функции.', 'error'); return; }
    if ('serviceWorker' in navigator) getReg().catch(() => {});
    if (!isSetUp()) { openSettings(); return; }

    // тихо обновляем подписку (iOS иногда меняет её) — без запроса разрешения
    if (pushSupported() && Notification.permission === 'granted') register(false).catch(() => {});
  }

  init();
})();
