// ==UserScript==
// @name         MAX Blinder
// @namespace    http://tampermonkey.net/
// @version      2.01
// @description  Ограничение телеметрии web-версии мессенджера MAX (Макс)
// @author       Echo91
// @match        https://*.max.ru/*
// @license      MIT
// @run-at       document-start
// @inject-into  page
// @sandbox      JavaScript
// @grant        none
// @downloadURL https://update.greasyfork.org/scripts/570049/MAX%20Blinder.user.js
// @updateURL https://update.greasyfork.org/scripts/570049/MAX%20Blinder.meta.js
// ==/UserScript==

(function() {
    'use strict';

    // ========================== КОНФИГУРАЦИЯ ==========================
    const CONFIG = {
        PROTECT_CLIENT_RECTS: true,          // защита getBoundingClientRect / getClientRects
        PROTECT_MEASURETEXT: true,           // защита measureText (font fingerprinting)
        FINGERPRINT_SEED: null,              // null = авто (sessionStorage), или число
        BLOCK_WEBRTC: true,
        // WEBRTC_STRICT: true — максимальная защита (iceServers очищаются,
        //   только relay) — может ломать звонки в строгих сетях (CGNAT,
        //   корпоративный firewall).
        // WEBRTC_STRICT: false — мягкий режим (iceServers не трогаются,
        //   только iceTransportPolicy: 'relay') — звонки работают даже
        //   в строгих сетях.
        WEBRTC_STRICT: false,
        BLOCK_FETCH_XHR: true,
        BLOCK_WEBSOCKET_OPCODE5: true,
        BLOCK_BEACON: true,
        BLOCK_SERVICE_WORKER: true,
        CLEAR_SERVICE_WORKERS: true,
        PROTECT_CANVAS: true,
        PROTECT_AUDIO: true,
        HIDE_WEBDRIVER: true,
        HIDE_CONNECTION: true,
        FAKE_PLUGINS: true,
        FIXED_SCREEN: false,
        LOG_SERVICE_WORKER: true,
        FAKE_FONTS: true,
        FAKE_BATTERY: true,
        FAKE_TIMEZONE: false,
        FAKE_LANGUAGE: false,
        IFRAME_PROTECTION: true,
        SCREEN_WIDTH: 1920,
        SCREEN_HEIGHT: 1080,
        COLOR_DEPTH: 24,
        INSPECT_POST_PAYLOAD: true,
        TIMING_NOISE: true,
        CLEAR_STORAGE_ON_START: false,
        TELEMETRY_KEYWORDS: ['events', 'host_reachability', 'telemetry', 'metrics', 'analytics', 'crash', 'perf', 'permission', 'permission_status', 'ptype', 'pstatus'],
        FAKE_USER_AGENT_DATA: false,
        PROTECT_WEBGL: true,
        BLOCK_CACHE_STORAGE: false,
        MOUSE_NOISE: false,
        BLOCK_PROBING: true,
        // Только opcode 5 (NAV_ANALYTICS / LOG) — единственный, подтверждённый
        // как аналитический. Остальные (2, 22, 31, 103, 161) — функциональные
        // или неизвестные, их блокировка ломает конфиг/звонки/жалобы.
        BLOCKED_OPCODES: [5],
        PROTECT_WORKERS: true,               // блокировка телеметрийных Worker/SharedWorker
        MONITOR_CLIPBOARD: true,             // логирование чтения буфера обмена
        MONITOR_PERMISSIONS: true,           // логирование проверок navigator.permissions.query
        AUDIO_NOISE_AMPLITUDE: 0.00005,      // увеличено с 0.000005
        PROTECT_OFFLINE_AUDIO: true,         // защита OfflineAudioContext
        HIDE_NETWORK_TYPE_DETAILS: true,     // маскировка типа сети и кода оператора
        BLOCK_VPN_DETECTION: true            // маскировка флага VPN в HOST_REACHABILITY
    };

    // ========================== ДЕТЕРМИНИРОВАННЫЙ PRNG ==========================
    // Генерирует стабильный шум для одного и того же зерна.
    // Это критично для anti-fingerprinting: случайный шум при каждом вызове
    // сам по себе становится отпечатком (нестабильность = уникальность).
    const FINGERPRINT_SEED = (() => {
        if (CONFIG.FINGERPRINT_SEED !== null) return CONFIG.FINGERPRINT_SEED;
        try {
            let seed = sessionStorage.getItem('__pm_seed');
            if (!seed) {
                seed = String(Math.floor(Math.random() * 0xFFFFFFFF));
                sessionStorage.setItem('__pm_seed', seed);
            }
            return parseInt(seed, 10) || 1234567;
        } catch (e) {
            return 1234567;
        }
    })();

    // Mulberry32 — быстрый и качественный PRNG
    function makeSeededRandom(seed) {
        let state = seed >>> 0;
        return function() {
            state |= 0;
            state = (state + 0x6D2B79F5) | 0;
            let t = Math.imul(state ^ (state >>> 15), 1 | state);
            t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
            return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
        };
    }

    // ========================== ПЕРЕМЕННЫЕ ==========================
    let blockedCount = 0;
    let fullLogHistory = [];
    const maxLogs = 20;
    const MAX_LOG_HISTORY = 5000;   // ограничение истории, чтобы не течь памяти
    let pendingLogs = [];
    let uiShadow = null;

    // Защита от дублирования записей
    let lastRecorded = new Map();
    const DEDUP_MS = 500;

    // ========================== ЧЁРНЫЙ СПИСОК ==========================
    // Разделён на два независимых списка для точного матчинга:
    //   BLOCK_DOMAINS — точные домены (матч по hostname)
    //   BLOCK_PATHS   — точные пути (матч по hostname + pathname)
    // Это устраняет ложные срабатывания коротких подстрок вроде 'crash',
    // 'analytics', 'metrics', которые могли случайно заблокировать
    // легитимные URL мессенджера.

    // Точные домены. Матч: hostname === domain ИЛИ hostname.endsWith('.' + domain)
    const BLOCK_DOMAINS = [
        // IP-определители
        'api.ipify.org', 'ifconfig.me', 'ident.me', 'checkip.amazonaws.com',
        'ip.mail.ru', '2ip.ru', 'ipinfo.io', 'ip-api.com', 'myexternalip.com',
        'icanhazip.com', 'jsonip.com', 'wtfismyip.com', 'ifconfig.co',
        'api.ipapi.is', 'iplocate.io', 'ip.sb',
        // Трекеры и аналитика
        'apptracer.ru', 'doubleclick.net', 'google-analytics.com',
        'top-fwz1.mail.ru', 'counter.yadro.ru', 'data.mail.ru', 'fb.do',
        'tracker-api.vk-analytics.ru', 'appsflyer.com',
        // MAX-телеметрия
        'stats.max.ru', 'telemetry.max.ru', 'collect.max.ru',
        'sphere.avantelecom.ru',
        'log-api.max.ru', 'error-report.max.ru', 'notify-stat.max.ru',
        // Mail.ru tracker
        'my.tracker.mail.ru',
        // Firebase / Google / Crashlytics
        'firebaseinstallations.googleapis.com',
        'firebase-settings.crashlytics.com',
        'app-measurement.com',
        'firebase.googleapis.com',
        'crashlytics.com',
        'googletagmanager.com',
        // Прочее
        'api.oneme.ru',
        'trace-flow.ru',
        // IP-адреса трекеров
        '155.212.204.143', '155.212.204.78', '155.212.204.193', '95.161.225.253'
    ];

    // Точные пути. Матч: hostname + pathname начинается с указанной строки
    const BLOCK_PATHS = [
        'vk.com/rkn',
        'googleapis.com/identitytoolkit',
        'httpbin.org/ip'
    ];

    // Домены, проверка которых блокируется как «зондирование»
    const probingDomains = [
        // Существующие домены
        't.me', 'telegram.org', 'whatsapp.com', 'gosuslugi.ru',
        'main.telegram.org', 'mmg.whatsapp.net', 'gstatic.com', 'calls.okcdn.ru',
        // Новые домены из отчётов InterSecLab / NTC / The Geek
        'mtalk.google.com',                     // Google push-сервис
        'ipv4-internet.yandex.net',             // Яндекс IP-чекер (IPv4)
        'ipv6-internet.yandex.net',             // Яндекс IP-чекер (IPv6)
        'pushtrs.push.hicloud.com',             // Huawei push (проверка доступности)
        'pushtrs1.push.hicloud.com',            // Huawei push (проверка доступности)
        'token-drcn.push.dbankcloud.com'        // Huawei push (проверка доступности)
    ];
    // ========================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========================
    function shouldBlock(url) {
        if (!url || !CONFIG.BLOCK_FETCH_XHR) return false;

        // Парсим URL — точный матч по hostname / pathname
        let hostname, pathname;
        try {
            const urlObj = new URL(url, location.href);
            hostname = urlObj.hostname.toLowerCase();
            pathname = urlObj.pathname.toLowerCase();
        } catch (e) {
            // Не удалось распарсить — fallback на подстрочный матч
            const sUrl = String(url).toLowerCase();
            return BLOCK_DOMAINS.some(d => sUrl.includes(d)) ||
                   BLOCK_PATHS.some(p => sUrl.includes(p));
        }

        // 1. Проверка доменов (exact или поддомен)
        for (const domain of BLOCK_DOMAINS) {
            if (hostname === domain || hostname.endsWith('.' + domain)) {
                return true;
            }
        }

        // 2. Проверка путей (hostname + pathname)
        const hostPath = hostname + pathname;
        for (const path of BLOCK_PATHS) {
            if (hostPath.startsWith(path)) {
                return true;
            }
        }

        return false;
    }

    function shouldBlockProbing(url) {
        if (!CONFIG.BLOCK_PROBING) return false;
        let hostname;
        try {
            hostname = new URL(url, location.href).hostname.toLowerCase();
        } catch (e) {
            return probingDomains.some(d => String(url).toLowerCase().includes(d));
        }
        for (const domain of probingDomains) {
            if (hostname === domain || hostname.endsWith('.' + domain)) {
                return true;
            }
        }
        return false;
    }

    function hasTelemetryInPayload(body) {
        if (!CONFIG.INSPECT_POST_PAYLOAD || !body) return false;

        let str = '';

        try {
            if (typeof body === 'string') {
                // Прямая строка — ищем ключевые слова
                str = body.toLowerCase();
            } else if (body instanceof URLSearchParams) {
                str = body.toString().toLowerCase();
            } else if (body instanceof FormData) {
                // FormData не сериализуется напрямую — собираем ключи и значения
                const parts = [];
                body.forEach((v, k) => parts.push(k, typeof v === 'string' ? v : ''));
                str = parts.join(' ').toLowerCase();
            } else if (typeof Blob !== 'undefined' && body instanceof Blob) {
                // Blob/File — не читаем (async), просто логируем факт
                return false;
            } else if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
                // Бинарные данные — не парсим
                return false;
            } else {
                // Объект — сериализуем
                str = JSON.stringify(body).toLowerCase();
            }
        } catch (e) {
            return false;
        }

        return CONFIG.TELEMETRY_KEYWORDS.some(keyword => str.includes(keyword));
    }

    // ========================== ПОНЯТНЫЕ НАЗВАНИЯ ДЛЯ ЛОГА ==========================
    // Словари переводят технические теги и домены в понятные пользователю фразы.

    // Понятные названия для тегов блокировки
    const FRIENDLY_LABELS = {
        'FETCH': 'Запрос',
        'XHR': 'Запрос',
        'POST-TELE': 'Телеметрия',
        'WS-TELE': 'Скрытая передача',
        'BEACON': 'Маячок',
        'PROBE': 'Проверка сети',
        'PERMISSION': 'Проверка разрешений',
        'CLIPBOARD': 'Доступ к буферу',
        'SW': 'Фоновый перехватчик',
        'WORKER': 'Скрытый поток',
        'CACHE': 'Кэш',
        'STORAGE': 'Локальные данные',
        'IDB': 'Локальная база',
        'FIREBASE': 'Firebase (Google)',
        'GOOGLE': 'Сервисы Google',
        'FETCH (iframe)': 'Запрос из вставки',
        'XHR (iframe)': 'Запрос из вставки',
        'FETCH (popup)': 'Запрос из окна'
    };

    // Понятные названия для сервисов (по домену)
    const SERVICE_LABELS = [
        { pattern: 'api.oneme.ru',        label: 'API мессенджера' },
        { pattern: 'apptracer.ru',        label: 'Сбор технических метрик' },
        { pattern: 'crashlytics.com',     label: 'Сбор крашей' },
        { pattern: 'app-measurement.com', label: 'Аналитика Firebase' },
        { pattern: 'stats.max.ru',        label: 'Статистика MAX' },
        { pattern: 'telemetry.max.ru',    label: 'Телеметрия MAX' },
        { pattern: 'collect.max.ru',      label: 'Сбор данных MAX' },
        { pattern: 'trace-flow.ru',       label: 'Скрытая передача данных' },
        { pattern: 'google-analytics.com', label: 'Аналитика Google' },
        { pattern: 'googletagmanager.com', label: 'Менеджер тегов Google' },
        { pattern: 'top-fwz1.mail.ru',    label: 'Счётчик Mail.ru' },
        { pattern: 'data.mail.ru',        label: 'Аналитика Mail.ru' },
        { pattern: 'tracker-api.vk-analytics.ru', label: 'Аналитика VK' },
        { pattern: 'appsflyer.com',       label: 'Аналитика AppsFlyer' },
        { pattern: 't.me',                label: 'Проверка Telegram' },
        { pattern: 'telegram.org',        label: 'Проверка Telegram' },
        { pattern: 'whatsapp.com',        label: 'Проверка WhatsApp' },
        { pattern: 'gosuslugi.ru',        label: 'Проверка Госуслуг' },
        { pattern: 'okcdn.ru',            label: 'Проверка OK.ru' },
        { pattern: 'yandex.net',          label: 'Проверка Yandex' },
        { pattern: 'hicloud.com',         label: 'Проверка Huawei' },
        { pattern: 'dbankcloud.com',      label: 'Проверка Huawei' },
        { pattern: 'gstatic.com',         label: 'Проверка Google' },
        { pattern: 'mtalk.google.com',    label: 'Проверка Google' },
        { pattern: 'api.ipify.org',       label: 'Определение IP' },
        { pattern: 'ifconfig.me',         label: 'Определение IP' },
        { pattern: 'ident.me',            label: 'Определение IP' },
        { pattern: 'ipinfo.io',           label: 'Определение IP' },
        { pattern: 'ip-api.com',          label: 'Определение IP' },
        { pattern: 'iplocate.io',         label: 'Определение IP' },
        { pattern: 'ip.sb',               label: 'Определение IP' },
        { pattern: 'api.ipapi.is',        label: 'Определение IP' },
        { pattern: '2ip.ru',              label: 'Определение IP' },
        { pattern: 'checkip.amazonaws.com', label: 'Определение IP' }
    ];

    // Понятные сообщения для WebSocket / Service Worker
    const FRIENDLY_MESSAGES = {
        'opcode 5 blocked': 'Заблокирована аналитика',
        'GET_HOST_REACHABILITY blocked': 'Заблокирована проверка сети',
        'HOST_REACHABILITY (any opcode) blocked': 'Заблокирована проверка сети',
        'чтение буфера обмена': 'Мессенджер читает буфер обмена',
        'чтение содержимого буфера': 'Мессенджер читает данные из буфера'
    };

    // Функции перевода
    function getFriendlyLabel(type) {
        return FRIENDLY_LABELS[type] || type;
    }

    function getServiceLabel(url) {
        const sUrl = String(url).toLowerCase();
        for (const svc of SERVICE_LABELS) {
            if (sUrl.includes(svc.pattern)) return svc.label;
        }
        return null;
    }

    function getFriendlyMessage(msg) {
        return FRIENDLY_MESSAGES[msg] || msg;
    }

    const makeNative = (obj, prop) => {
        const original = obj[prop];
        if (typeof original === 'function') {
            Object.defineProperty(original, 'toString', {
                value: () => `function ${prop}() { [native code] }`,
                configurable: true,
                writable: true
            });
        }
    };

    // ========================== ЛОГИРОВАНИЕ ==========================
    function addEntryToLog(container, data) {
        const entry = document.createElement('div');
        entry.style.cssText = 'border-bottom: 1px solid rgba(255,255,255,0.1); padding: 4px 0; color: #ffffff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-size: 9px;';
        const friendlyType = getFriendlyLabel(data.type);
        const fullText = `[${friendlyType}] ${data.uiText}`;
        entry.innerHTML = `<span style="color: #67b3ff;">[${friendlyType}]</span> ${data.uiText}`;
        container.prepend(entry);

        // Проверяем, обрезается ли текст, только после вставки в DOM
        requestAnimationFrame(() => {
            if (entry.scrollWidth > entry.clientWidth) {
                entry.title = fullText;
                entry.style.cursor = 'help';
            }
        });

        if (container.childNodes.length > maxLogs) container.removeChild(container.lastChild);
    }

    function logBlock(type, url, description) {
        const key = `${type}|${url}`;
        const now = Date.now();
        if (lastRecorded.has(key) && (now - lastRecorded.get(key) < DEDUP_MS)) return;
        lastRecorded.set(key, now);

        blockedCount++;
        const time = new Date().toLocaleTimeString();
        let displayUrl = String(url).split('?')[0];
        try {
            const urlObj = new URL(url);
            displayUrl = urlObj.hostname + urlObj.pathname;
        } catch(e) {}

        const friendlyType = getFriendlyLabel(type);
        const serviceLabel = getServiceLabel(displayUrl);
        // UI — понятное описание без URL
        const uiText = description || serviceLabel || displayUrl;
        // Copy log — понятное описание + URL (без query string)
        // Не дублируем, если displayUrl === uiText
        const fullText = (displayUrl && displayUrl !== uiText) ? `${uiText} (${displayUrl})` : uiText;

        const entryData = {
            type: type,
            url: displayUrl,
            uiText: uiText,
            full: `[${time}] [${friendlyType}] ${fullText}`
        };
        fullLogHistory.push(entryData.full);

        // Ограничение истории
        if (fullLogHistory.length > MAX_LOG_HISTORY) {
            fullLogHistory.splice(0, fullLogHistory.length - MAX_LOG_HISTORY);
        }

        if (uiShadow) {
            const icon = uiShadow.getElementById('pm-icon');
            const counter = uiShadow.getElementById('pm-counter');
            const counterExpanded = uiShadow.getElementById('pm-counter-expanded');
            const logContainer = uiShadow.getElementById('pm-log-list');

            requestAnimationFrame(() => {
                // Обновляем оба счётчика
                if (counter) counter.innerText = blockedCount;
                if (counterExpanded) counterExpanded.innerText = blockedCount;

                // Запускаем анимацию иконки в том же кадре
                if (icon) {
                    try {
                        icon.animate([
                            { opacity: 1 },
                            { opacity: 0.15 },
                            { opacity: 1 }
                        ], { duration: 300, easing: 'ease-out', fill: 'none' });
                    } catch (e) {}
                }

                // Добавляем запись в лог
                if (logContainer) {
                    addEntryToLog(logContainer, entryData);
                }
            });

            return;
        }
        pendingLogs.push(entryData);
    }

    // Логирование событий БЕЗ инкремента счётчика
    // (для мониторинга — например, чтения буфера обмена)
    function logEvent(type, url, description) {
        const key = `${type}|${url}`;
        const now = Date.now();
        if (lastRecorded.has(key) && (now - lastRecorded.get(key) < DEDUP_MS)) return;
        lastRecorded.set(key, now);

        const time = new Date().toLocaleTimeString();
        let displayUrl = String(url).split('?')[0];
        try {
            const urlObj = new URL(url);
            displayUrl = urlObj.hostname + urlObj.pathname;
        } catch(e) {}

        const friendlyType = getFriendlyLabel(type);
        const serviceLabel = getServiceLabel(displayUrl);
        const uiText = description || serviceLabel || displayUrl;
        const fullText = (displayUrl && displayUrl !== uiText) ? `${uiText} (${displayUrl})` : uiText;

        const entryData = {
            type: type,
            url: displayUrl,
            uiText: uiText,
            full: `[${time}] [${friendlyType}] ${fullText}`
        };
        fullLogHistory.push(entryData.full);

        if (fullLogHistory.length > MAX_LOG_HISTORY) {
            fullLogHistory.splice(0, fullLogHistory.length - MAX_LOG_HISTORY);
        }

        if (uiShadow) {
            const logContainer = uiShadow.getElementById('pm-log-list');
            if (logContainer) {
                addEntryToLog(logContainer, entryData);
            }
        }
    }

    // ========================== НОВЫЕ ЗАЩИТЫ ==========================

    // 1. User-Agent Client Hints
    if (CONFIG.FAKE_USER_AGENT_DATA && navigator.userAgentData) {
        try {
            Object.defineProperty(navigator, 'userAgentData', {
                get: () => ({
                    brands: [
                        { brand: 'Not(A:Brand', version: '99' },
                        { brand: 'Google Chrome', version: '124' },
                        { brand: 'Chromium', version: '124' }
                    ],
                    mobile: false,
                    platform: 'Windows',
                    getHighEntropyValues: (hints) => Promise.resolve({
                        architecture: 'x86',
                        bitness: '64',
                        model: '',
                        platform: 'Windows',
                        platformVersion: '10.0.0',
                        uaFullVersion: '124.0.6367.60'
                    })
                }),
                configurable: true
            });
        } catch(e) {}
    }

    // 2. WebGL Fingerprinting
    if (CONFIG.PROTECT_WEBGL && window.WebGLRenderingContext) {
        const protectWebGL = (ctx) => {
            if (!ctx || !ctx.getParameter) return;
            const originalGetParameter = ctx.getParameter;
            ctx.getParameter = function(param) {
                switch (param) {
                    // Unmasked vendor / renderer (WebGL 1 и 2)
                    case 0x9245: return 'Google Inc. (NVIDIA)';
                    case 0x9246: return 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)';
                    // VENDOR / RENDERER / VERSION / SHADING_LANGUAGE_VERSION
                    case 0x1F00: return 'WebKit';                    // VENDOR
                    case 0x1F01: return 'WebKit WebGL';              // RENDERER
                    case 0x1F02: return 'WebGL 1.0 (OpenGL ES 2.0 Chromium)'; // VERSION
                    case 0x8B8C: return 'WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)'; // SHADING_LANGUAGE_VERSION
                    // Лимиты, согласованные с RTX 3060
                    case 0x0D33: return 16384;  // MAX_TEXTURE_SIZE
                    case 0x8D57: return 16384;  // MAX_RENDERBUFFER_SIZE
                    case 0x0D3A: return new Int32Array([16384, 16384]); // MAX_VIEWPORT_DIMS
                    case 0x8869: return 16;     // MAX_VERTEX_ATTRIBS
                    case 0x8DFB: return 4096;   // MAX_VERTEX_UNIFORM_VECTORS
                    case 0x8DFD: return 4096;   // MAX_FRAGMENT_UNIFORM_VECTORS
                    case 0x8DFC: return 30;     // MAX_VARYING_VECTORS
                    case 0x846E: return new Float32Array([1, 64]); // ALIASED_LINE_WIDTH_RANGE
                }
                return originalGetParameter.call(this, param);
            };
        };
        const origGetContext = HTMLCanvasElement.prototype.getContext;
        HTMLCanvasElement.prototype.getContext = function(type, attributes) {
            const ctx = origGetContext.call(this, type, attributes);
            if (type === 'webgl' || type === 'experimental-webgl' || type === 'webgl2') {
                protectWebGL(ctx);
            }
            return ctx;
        };
        makeNative(HTMLCanvasElement.prototype, 'getContext');
    }

    // 3. Блокировка Cache Storage API (опционально)
    if (CONFIG.BLOCK_CACHE_STORAGE && window.caches) {
        const origOpen = caches.open;
        caches.open = function(name) {
            if (CONFIG.TELEMETRY_KEYWORDS.some(k => name.toLowerCase().includes(k))) {
                logBlock('CACHE', name, 'Заблокирован доступ к кэшу');
                return Promise.reject(new Error('Cache blocked by Blinder'));
            }
            return origOpen.apply(this, arguments);
        };
        makeNative(caches, 'open');
    }

    // 4. Шум в координатах мыши (опционально)
    if (CONFIG.MOUSE_NOISE) {
        ['mousemove', 'mousedown', 'mouseup', 'click'].forEach(eventType => {
            window.addEventListener(eventType, (e) => {
                const noiseX = Math.random() * 0.1 - 0.05;
                const noiseY = Math.random() * 0.1 - 0.05;
                try {
                    Object.defineProperty(e, 'screenX', { value: e.screenX + noiseX });
                    Object.defineProperty(e, 'screenY', { value: e.screenY + noiseY });
                } catch(ignore) {}
            }, true);
        });
    }

    // 4b. Защита Worker / SharedWorker
    // Рабочие потоки имеют собственный scope и свои fetch/XHR/WebSocket,
    // поэтому без этого блока телеметрия может уходить в обход перехватов.
    if (CONFIG.PROTECT_WORKERS) {
        const workerPatterns = [
            'telemetry', 'analytics', 'metrics', 'apptracer', 'vigo',
            'oneme', 'firebase', 'crashlytics', 'gtm', 'googletagmanager'
        ];
        const origWorker = window.Worker;
        if (origWorker) {
            window.Worker = function(scriptURL, options) {
                const sUrl = String(scriptURL).toLowerCase();
                if (workerPatterns.some(p => sUrl.includes(p))) {
                    logBlock('WORKER', scriptURL, 'Заблокирован фоновый процесс');
                    // Возвращаем пустой воркер-заглушку
                    const blob = new Blob(['self.onmessage=function(){};'], { type: 'application/javascript' });
                    return new origWorker(URL.createObjectURL(blob), options);
                }
                return new origWorker(scriptURL, options);
            };
            window.Worker.prototype = origWorker.prototype;
            makeNative(window, 'Worker');
        }

        const origSharedWorker = window.SharedWorker;
        if (origSharedWorker) {
            window.SharedWorker = function(scriptURL, options) {
                const sUrl = String(scriptURL).toLowerCase();
                if (workerPatterns.some(p => sUrl.includes(p))) {
                    logBlock('WORKER', scriptURL, 'Заблокирован фоновый процесс');
                    const blob = new Blob(['self.onconnect=function(){};'], { type: 'application/javascript' });
                    return new origSharedWorker(URL.createObjectURL(blob), options);
                }
                return new origSharedWorker(scriptURL, options);
            };
            window.SharedWorker.prototype = origSharedWorker.prototype;
            makeNative(window, 'SharedWorker');
        }
    }

    // 5. Защита от зондирования (блокировка проверки доступности t.me, whatsapp.com и др.)
    // ========================== [1.9] НОВЫЕ МОДУЛИ ==========================
    // 5c. [1.9] Маскировка типа сети и кода оператора
    if (CONFIG.HIDE_NETWORK_TYPE_DETAILS && 'connection' in navigator) {
        const conn = navigator.connection;
        if (conn) {
            try {
                Object.defineProperty(conn, 'type', { get: () => 'wifi', configurable: true });
                Object.defineProperty(conn, 'effectiveType', { get: () => '4g', configurable: true });
                Object.defineProperty(conn, 'downlink', { get: () => 10, configurable: true });
                Object.defineProperty(conn, 'downlinkMax', { get: () => 100, configurable: true });
                Object.defineProperty(conn, 'rtt', { get: () => 50, configurable: true });
                Object.defineProperty(conn, 'saveData', { get: () => false, configurable: true });
                Object.defineProperty(conn, 'onchange', { get: () => null, configurable: true });
            } catch(e) {}
        }
    }

    // 5d. [1.9] Безопасная маскировка VPN (не ломает WebRTC-звонки)
    if (CONFIG.BLOCK_VPN_DETECTION && window.RTCPeerConnection) {
        // Ничего не делаем — основной BLOCK_WEBRTC уже отключает ICE-серверы
        // и не даёт собрать реальные IP-адреса через addIceCandidate.
        // Дополнительная обёртка ломает звонки в мессенджере.
    }

    if (CONFIG.BLOCK_PROBING) {
        // Перехват fetch
        const origFetch = window.fetch;
        window.fetch = function(input, init) {
            const url = typeof input === 'string' ? input : (input && input.url) || '';
            if (shouldBlockProbing(url)) {
                logBlock('PROBE', url);
                return Promise.reject(new TypeError('Network request failed (Blinder)'));
            }
            return origFetch.apply(this, arguments);
        };
        makeNative(window, 'fetch');

        // Перехват XHR для probing (дополнительно)
        const origOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url) {
            this._url = url;
            this._isProbe = shouldBlockProbing(url);
            return origOpen.apply(this, arguments);
        };
        const origSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function(body) {
            if (this._isProbe) {
                logBlock('PROBE', this._url);
                // Имитируем ошибку сети, чтобы сайт не ждал ответа
                setTimeout(() => {
                    Object.defineProperty(this, 'readyState', { value: 4 });
                    Object.defineProperty(this, 'status', { value: 0 });
                    Object.defineProperty(this, 'statusText', { value: 'Network error' });
                    this.dispatchEvent(new Event('error'));
                    this.dispatchEvent(new Event('readystatechange'));
                }, 1);
                return;
            }
            return origSend.apply(this, arguments);
        };
        makeNative(XMLHttpRequest.prototype, 'open');
        makeNative(XMLHttpRequest.prototype, 'send');
    }

    // ========================== ОСТАЛЬНЫЕ МОДУЛИ ==========================
    // (шум в таймингах, очистка хранилищ, сетевые перехваты, WebSocket фильтрация, Beacon, iframe, анти-фингерпринтинг)

    // ========================== ШУМ В ТАЙМИНГАХ ==========================
    // Date.now() НЕ шумим — это может ломать таймеры мессенджера
    // (heartbeat, expiration, синхронизация).
    //
    // performance.now() — используем СТАТИЧЕСКИЙ offset, а не случайный шум.
    // Раньше был Math.random() при каждом вызове — это создавало нестабильность:
    // дельта между двумя последовательными вызовами могла быть отрицательной,
    // что физически невозможно и легко детектируется time-based fingerprinting.
    // Теперь offset генерируется один раз на сессию и применяется ко всем вызовам.
    if (CONFIG.TIMING_NOISE) {
        const perfOffset = (makeSeededRandom(FINGERPRINT_SEED)() - 0.5) * 0.1; // ±0.05 мс
        const origPerfNow = performance.now;
        performance.now = function() {
            return origPerfNow.call(this) + perfOffset;
        };
        makeNative(performance, 'now');
    }

    // ========================== ОЧИСТКА ХРАНИЛИЩ ==========================
    if (CONFIG.CLEAR_STORAGE_ON_START) {
        try {
            if (localStorage) {
                const keysToClear = [];
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    if (key && CONFIG.TELEMETRY_KEYWORDS.some(k => key.toLowerCase().includes(k))) {
                        keysToClear.push(key);
                    }
                }
                keysToClear.forEach(key => localStorage.removeItem(key));
                if (keysToClear.length) logBlock('STORAGE', '', `Очищено записей: ${keysToClear.length}`);
            }
            if (window.indexedDB) {
                indexedDB.databases().then(dbs => {
                    dbs.forEach(db => {
                        if (db.name && CONFIG.TELEMETRY_KEYWORDS.some(k => db.name.toLowerCase().includes(k))) {
                            indexedDB.deleteDatabase(db.name);
                            logBlock('IDB', db.name, 'Удалена база данных');
                        }
                    });
                }).catch(e => console.warn('IDB enumeration failed', e));
            }
        } catch (e) {}
    }

    // ========================== ОЧИСТКА SERVICE WORKER ==========================
    if (CONFIG.CLEAR_SERVICE_WORKERS && navigator.serviceWorker && navigator.serviceWorker.getRegistrations) {
        navigator.serviceWorker.getRegistrations().then(registrations => {
            registrations.forEach(reg => {
                reg.unregister();
                logBlock('SW', reg.scope, 'Удалён при старте');
            });
        }).catch(e => console.warn('SW cleanup failed', e));
    }

    // ========================== СЕТЕВЫЕ ПЕРЕХВАТЫ (основные) ==========================
    if (CONFIG.BLOCK_FETCH_XHR) {
        // fetch (уже переопределён выше для probing, но добавим блокировку по чёрному списку)
        const origFetch2 = window.fetch;
        window.fetch = function(input, init) {
            const url = typeof input === 'string' ? input : (input && input.url) || '';

            // 1. Блокировка по URL
            if (shouldBlock(url)) {
                logBlock('FETCH', url);
                return Promise.resolve(new Response('{"status":"ok"}', { status: 200 }));
            }
            if (CONFIG.BLOCK_PROBING && shouldBlockProbing(url)) {
                logBlock('PROBE', url);
                return Promise.reject(new TypeError('Network request failed (Blinder)'));
            }

            // 2. Анализ тела POST-запросов (раньше был только для XHR)
            if (CONFIG.INSPECT_POST_PAYLOAD) {
                const method = ((init && init.method) || (input && input.method) || 'GET').toUpperCase();
                if (method === 'POST') {
                    const body = init && init.body;
                    if (body && hasTelemetryInPayload(body)) {
                        logBlock('POST-TELE', url);
                        return Promise.resolve(new Response('{"status":"ok"}', { status: 200 }));
                    }
                }
            }

            return origFetch2.apply(this, arguments);
        };

        makeNative(window, 'fetch');
        // XHR (аналогично)
        const origOpenXHR = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url) {
            this._method = method;
            this._url = url;
            this._isTracker = shouldBlock(url);
            this._isProbe = CONFIG.BLOCK_PROBING && shouldBlockProbing(url);
            return origOpenXHR.apply(this, arguments);
        };
        makeNative(XMLHttpRequest.prototype, 'open');

        const origSendXHR = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function(body) {
            if (this._isTracker) {
                logBlock('XHR', this._url);
                setTimeout(() => {
                    Object.defineProperty(this, 'readyState', { value: 4 });
                    Object.defineProperty(this, 'status', { value: 200 });
                    Object.defineProperty(this, 'responseText', { value: '{"status":"ok"}' });
                    this.dispatchEvent(new Event('load'));
                    this.dispatchEvent(new Event('readystatechange'));
                }, 1);
                return;
            }
            if (this._isProbe) {
                logBlock('PROBE', this._url);
                setTimeout(() => {
                    Object.defineProperty(this, 'readyState', { value: 4 });
                    Object.defineProperty(this, 'status', { value: 0 });
                    Object.defineProperty(this, 'statusText', { value: 'Network error' });
                    this.dispatchEvent(new Event('error'));
                    this.dispatchEvent(new Event('readystatechange'));
                }, 1);
                return;
            }
            if (this._method === 'POST' && body && hasTelemetryInPayload(body)) {
                logBlock('POST-TELE', this._url);
                setTimeout(() => {
                    Object.defineProperty(this, 'readyState', { value: 4 });
                    Object.defineProperty(this, 'status', { value: 200 });
                    Object.defineProperty(this, 'responseText', { value: '{"status":"ok"}' });
                    this.dispatchEvent(new Event('load'));
                    this.dispatchEvent(new Event('readystatechange'));
                }, 1);
                return;
            }
            return origSendXHR.apply(this, arguments);
        };
        makeNative(XMLHttpRequest.prototype, 'send');
    }

    // ========================== WEBSOCKET ФИЛЬТРАЦИЯ (с новыми опкодами) ==========================
    if (CONFIG.BLOCK_WEBSOCKET_OPCODE5) {
        const origWSSend = WebSocket.prototype.send;
        WebSocket.prototype.send = function(data) {
            if (typeof data === 'string' && data.includes('"opcode"')) {
                try {
                    const msg = JSON.parse(data);
                    const opcode = msg.opcode;
                    if (CONFIG.BLOCKED_OPCODES.includes(opcode)) {
                        logBlock('WS-TELE', '', 'Заблокирована аналитика');
                        return;
                    }
                    // Дополнительная проверка на GET_HOST_REACHABILITY (для opcode 5)
                    if (opcode === 5 &&
                        msg.payload &&
                        msg.payload.events &&
                        Array.isArray(msg.payload.events) &&
                        msg.payload.events.some(e => e.event === 'GET_HOST_REACHABILITY')) {
                        logBlock('WS-TELE', '', 'Заблокирована проверка сети');
                        return;
                    }
                    // [1.9] Расширенная проверка HOST_REACHABILITY по любому opcode
                    if (msg.payload &&
                        msg.payload.events &&
                        Array.isArray(msg.payload.events) &&
                        msg.payload.events.some(e => e.event && e.event.includes('HOST_REACHABILITY'))) {
                        logBlock('WS-TELE', '', 'Заблокирована проверка сети');
                        return;
                    }
                } catch (e) {}
            }
            return origWSSend.apply(this, arguments);
        };
        makeNative(WebSocket.prototype, 'send');
    }

    // ========================== BEACON ==========================
    if (CONFIG.BLOCK_BEACON) {
        const origBeacon = navigator.sendBeacon;
        navigator.sendBeacon = function(url, data) {
            if (shouldBlock(url) || (CONFIG.BLOCK_PROBING && shouldBlockProbing(url))) {
                logBlock('BEACON', url);
                return true;
            }
            return origBeacon.call(this, url, data);
        };
        makeNative(navigator, 'sendBeacon');
    }

    // ========================== IFRAME ЗАЩИТА ==========================
    if (CONFIG.IFRAME_PROTECTION) {
        const origCreateElement = document.createElement;
        const origOpen = window.open;
        const origAttachShadow = Element.prototype.attachShadow;

        function protectIframe(iframe) {
            try {
                if (!iframe.contentWindow) return;
                const win = iframe.contentWindow;
                if (CONFIG.BLOCK_FETCH_XHR) {
                win.fetch = new Proxy(win.fetch, {
                    apply(target, thisArg, args) {
                        const url = typeof args[0] === 'object' ? args[0].url : args[0];
                        if (shouldBlock(url) || (CONFIG.BLOCK_PROBING && shouldBlockProbing(url))) {
                            logBlock('FETCH (iframe)', url);
                            return Promise.resolve(new Response('{"status":"ok"}', { status: 200 }));
                        }
                        return Reflect.apply(target, thisArg, args);
                    }
                });
                const origIOpen = win.XMLHttpRequest.prototype.open;
                win.XMLHttpRequest.prototype.open = function(method, url) {
                    this._isTracker = shouldBlock(url) || (CONFIG.BLOCK_PROBING && shouldBlockProbing(url));
                    this._blockUrl = url;
                    return origIOpen.apply(this, arguments);
                };
                const origISend = win.XMLHttpRequest.prototype.send;
                win.XMLHttpRequest.prototype.send = function() {
                    if (this._isTracker) {
                        logBlock('XHR (iframe)', this._blockUrl);
                        setTimeout(() => {
                            Object.defineProperty(this, 'readyState', { value: 4 });
                            Object.defineProperty(this, 'status', { value: 200 });
                            Object.defineProperty(this, 'responseText', { value: '{"status":"ok"}' });
                            this.dispatchEvent(new Event('load'));
                            this.dispatchEvent(new Event('readystatechange'));
                        }, 1);
                        return;
                    }
                    return origISend.apply(this, arguments);
                };
                }
            } catch (e) { /* cross-origin — игнорируем */ }
        }

        document.createElement = function(tagName, options) {
            const element = origCreateElement.call(document, tagName, options);
            if (tagName.toLowerCase() === 'iframe') {
                element.addEventListener('load', () => protectIframe(element));
                if (element.contentWindow) protectIframe(element);
            }
            return element;
        };
        makeNative(document, 'createElement');

        window.open = function(url, name, specs, replace) {
            const newWindow = origOpen.call(this, url, name, specs, replace);
            try {
                if (newWindow && newWindow.document) {
                    newWindow.addEventListener('load', () => {
                        if (CONFIG.BLOCK_FETCH_XHR && newWindow.fetch) {
                            newWindow.fetch = new Proxy(newWindow.fetch, {
                                apply(target, thisArg, args) {
                                    const url = typeof args[0] === 'object' ? args[0].url : args[0];
                                    if (shouldBlock(url) || (CONFIG.BLOCK_PROBING && shouldBlockProbing(url))) {
                                        logBlock('FETCH (popup)', url);
                                        return Promise.resolve(new Response('{"status":"ok"}', { status: 200 }));
                                    }
                                    return Reflect.apply(target, thisArg, args);
                                }
                            });
                        }
                    });
                }
            } catch (e) { /* cross-origin popup — игнорируем */ }
            return newWindow;
        };
        makeNative(window, 'open');

        Element.prototype.attachShadow = function(init) {
            return origAttachShadow.call(this, init);
        };
        makeNative(Element.prototype, 'attachShadow');
    }

    // ========================== ЗАЩИТА ОТ ФИНГЕРПРИНТИНГА ==========================
    try {
        // Улучшенные аппаратные характеристики (согласованы с UACH)
        Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
        Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });

        // Canvas
        if (CONFIG.PROTECT_CANVAS) {
            const orgGetImageData = CanvasRenderingContext2D.prototype.getImageData;
            // Кэш: canvas → Uint8Array (чтобы один и тот же холст давал один и тот же шум)
            const canvasNoiseCache = new WeakMap();

            CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {
                const imageData = orgGetImageData.call(this, x, y, w, h);
                const data = imageData.data;
                if (data.length > 0) {
                    const canvas = this.canvas;
                    let noisePattern = canvasNoiseCache.get(canvas);
                    if (!noisePattern) {
                        // Генерируем шум один раз на холст
                        noisePattern = new Uint8Array(256);
                        const rnd = makeSeededRandom(FINGERPRINT_SEED + (canvas.width * 31 + canvas.height));
                        for (let i = 0; i < 256; i++) {
                            noisePattern[i] = Math.floor(rnd() * 3) - 1; // -1, 0, +1
                        }
                        canvasNoiseCache.set(canvas, noisePattern);
                    }
                    // Применяем шум ко всем байтам
                    for (let i = 0; i < data.length; i++) {
                        const noise = noisePattern[i % 256];
                        if (noise !== 0) {
                            data[i] = Math.min(255, Math.max(0, data[i] + noise));
                        }
                    }
                }
                return imageData;
            };
            makeNative(CanvasRenderingContext2D.prototype, 'getImageData');
        }

        // Audio (стабильный шум на сессию через кэш WeakMap)
        if (CONFIG.PROTECT_AUDIO && window.AudioContext) {
            const originalGetChannelData = AudioBuffer.prototype.getChannelData;
            const audioNoiseCache = new WeakMap(); // буфер → {channel: noisyData}
            AudioBuffer.prototype.getChannelData = function(channel) {
                const originalData = originalGetChannelData.call(this, channel);
                const amp = CONFIG.AUDIO_NOISE_AMPLITUDE;

                // Проверяем кэш для этого буфера и канала
                let cached = audioNoiseCache.get(this);
                if (!cached) {
                    cached = {};
                    audioNoiseCache.set(this, cached);
                }
                if (cached[channel]) {
                    return cached[channel];
                }

                // Генерируем шум один раз, seed привязан к длине И каналу
                const rnd = makeSeededRandom(FINGERPRINT_SEED + (this.length || 0) * 31 + channel);
                const noisyData = new Float32Array(originalData.length);
                for (let i = 0; i < originalData.length; i++) {
                    noisyData[i] = originalData[i] + (rnd() * amp * 2 - amp);
                }
                cached[channel] = noisyData;
                return noisyData;
            };
            makeNative(AudioBuffer.prototype, 'getChannelData');
        }

        // OfflineAudioContext защита (новая)
        if (CONFIG.PROTECT_OFFLINE_AUDIO && window.OfflineAudioContext) {
            const origStartRendering = OfflineAudioContext.prototype.startRendering;
            OfflineAudioContext.prototype.startRendering = function() {
                const ctx = this;
                return origStartRendering.apply(ctx, arguments).then(buffer => {
                    if (buffer && buffer.numberOfChannels > 0) {
                        const data = buffer.getChannelData(0);
                        if (data && data.length) {
                            const rnd = makeSeededRandom(FINGERPRINT_SEED + (buffer.length || 0));
                            for (let i = 0; i < Math.min(100, data.length); i += 10) {
                                data[i] += (rnd() - 0.5) * 0.0002;
                            }
                        }
                    }
                    return buffer;
                });
            };
            makeNative(OfflineAudioContext.prototype, 'startRendering');
        }

        // WebRTC
        if (CONFIG.BLOCK_WEBRTC && window.RTCPeerConnection) {
            const OriginalRTCPeerConnection = window.RTCPeerConnection;
            window.RTCPeerConnection = new Proxy(OriginalRTCPeerConnection, {
                construct(target, args) {
                    let config = args[0] || {};
                    if (CONFIG.WEBRTC_STRICT) {
                        // Максимальная защита от IP-утечек.
                        // Может ломать звонки в строгих сетях (CGNAT, firewall).
                        config = { ...config, iceServers: [], iceTransportPolicy: 'relay' };
                    } else {
                        // Мягкий режим — iceServers сохраняются, звонки работают.
                        config = { ...config, iceTransportPolicy: 'relay' };
                    }
                    const pc = new target(config);
                    pc.addIceCandidate = function() { return Promise.resolve(); };
                    return pc;
                }
            });
            window.RTCPeerConnection.prototype = OriginalRTCPeerConnection.prototype;
            makeNative(window, 'RTCPeerConnection');
        }

        if (CONFIG.HIDE_CONNECTION && 'connection' in navigator) {
            const connection = navigator.connection;
            if (connection) {
                Object.defineProperty(connection, 'effectiveType', { get: () => '4g' });
                Object.defineProperty(connection, 'downlink', { get: () => 10 });
                Object.defineProperty(connection, 'rtt', { get: () => 50 });
            }
        }

        if (CONFIG.HIDE_WEBDRIVER && navigator.webdriver !== undefined) {
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        }

        // Client Rects — микрошум в субпиксельных размерах
        // Шум кэшируется через WeakMap: один элемент → один и тот же шум
        // при повторных вызовах. Иначе нестабильность сама становится отпечатком.
        if (CONFIG.PROTECT_CLIENT_RECTS) {
            const NOISE = 0.0001;
            const rectNoiseCache = new WeakMap();

            // Генерирует шум один раз на элемент
            const getRectNoise = (el) => {
                let noise = rectNoiseCache.get(el);
                if (!noise) {
                    // Seed привязан к элементу (через tagName + id + className)
                    const tag = (el.tagName || '') + '|' + (el.id || '') + '|' + (el.className || '');
                    let hash = 0;
                    for (let i = 0; i < tag.length; i++) {
                        hash = ((hash << 5) - hash) + tag.charCodeAt(i);
                        hash |= 0;
                    }
                    const rnd = makeSeededRandom(FINGERPRINT_SEED + hash);
                    noise = [
                        (rnd() - 0.5) * NOISE,
                        (rnd() - 0.5) * NOISE,
                        (rnd() - 0.5) * NOISE,
                        (rnd() - 0.5) * NOISE
                    ];
                    rectNoiseCache.set(el, noise);
                }
                return noise;
            };

            const origGetBoundingClientRect = Element.prototype.getBoundingClientRect;
            Element.prototype.getBoundingClientRect = function() {
                const rect = origGetBoundingClientRect.call(this);
                const [n1, n2, n3, n4] = getRectNoise(this);
                return {
                    x: rect.x + n1,
                    y: rect.y + n2,
                    width: rect.width + n3,
                    height: rect.height + n4,
                    top: rect.top + n2,
                    right: rect.right + n1 + n3,
                    bottom: rect.bottom + n2 + n4,
                    left: rect.left + n1,
                    toJSON: rect.toJSON.bind(rect)
                };
            };
            makeNative(Element.prototype, 'getBoundingClientRect');

            const origGetClientRects = Element.prototype.getClientRects;
            Element.prototype.getClientRects = function() {
                const rects = origGetClientRects.call(this);
                const [n1, n2, n3, n4] = getRectNoise(this);
                const noisy = [];
                for (let i = 0; i < rects.length; i++) {
                    const r = rects[i];
                    // Используем разные n для x/y и width/height,
                    // чтобы сохранить согласованность x + width = right
                    noisy.push({
                        x: r.x + n1,
                        y: r.y + n2,
                        width: r.width + n3,
                        height: r.height + n4,
                        top: r.top + n2,
                        right: r.right + n1 + n3,      // ← x + width
                        bottom: r.bottom + n2 + n4,    // ← y + height
                        left: r.left + n1
                    });
                }
                // Эмулируем DOMRectList: добавляем метод item()
                noisy.item = (i) => noisy[i] || null;
                return noisy;
            };
            makeNative(Element.prototype, 'getClientRects');
        }

        // Мониторинг запросов разрешений (аналог DailyAnalyticsWorker из Android)
        // Android-версия MAX ежедневно проверяет статус разрешений через
        // DailyAnalyticsWorker. В веб-версии аналог — navigator.permissions.query.
        if (CONFIG.MONITOR_PERMISSIONS && navigator.permissions && navigator.permissions.query) {
            const origPermissionsQuery = navigator.permissions.query;
            const PERM_NAMES = {
                'camera': 'Запрос доступа к камере',
                'microphone': 'Запрос доступа к микрофону',
                'geolocation': 'Запрос доступа к геолокации',
                'notifications': 'Запрос на уведомления',
                'clipboard-read': 'Запрос доступа к буферу',
                'clipboard-write': 'Запрос записи в буфер'
            };
            navigator.permissions.query = function(descriptor) {
                try {
                    const permName = (descriptor && descriptor.name) || 'unknown';
                    logEvent('PERMISSION', '', PERM_NAMES[permName] || `Проверка: ${permName}`);
                } catch (e) {}
                return origPermissionsQuery.call(this, descriptor);
            };
            makeNative(navigator.permissions, 'query');
        }

        if (CONFIG.MONITOR_CLIPBOARD && navigator.clipboard) {
            const origReadText = navigator.clipboard.readText;
            if (origReadText) {
                navigator.clipboard.readText = function() {
                    logEvent('CLIPBOARD', '', 'Мессенджер читает буфер обмена');
                    return origReadText.apply(this, arguments);
                };
                makeNative(navigator.clipboard, 'readText');
            }
            const origRead = navigator.clipboard.read;
            if (origRead) {
                navigator.clipboard.read = function() {
                    logEvent('CLIPBOARD', '', 'Мессенджер читает данные из буфера');
                    return origRead.apply(this, arguments);
                };
                makeNative(navigator.clipboard, 'read');
            }
        }

        if (CONFIG.FAKE_TIMEZONE && Intl.DateTimeFormat) {
            const origResolvedOptions = Intl.DateTimeFormat.prototype.resolvedOptions;
            Intl.DateTimeFormat.prototype.resolvedOptions = function() {
                const options = origResolvedOptions.call(this);
                options.timeZone = 'Europe/Moscow';
                return options;
            };
            makeNative(Intl.DateTimeFormat.prototype, 'resolvedOptions');
        }

        if (CONFIG.FAKE_LANGUAGE) {
            Object.defineProperty(navigator, 'language', { get: () => 'ru-RU' });
            Object.defineProperty(navigator, 'languages', { get: () => ['ru-RU', 'ru'] });
        }

        if (CONFIG.FAKE_PLUGINS && navigator.plugins) {
            const fakePlugins = [
                { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
                { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
                { name: 'Native Client', filename: 'internal-nacl-plugin', description: '' }
            ];
            const pluginArray = Object.create(PluginArray.prototype);
            pluginArray.length = fakePlugins.length;
            fakePlugins.forEach((p, i) => {
                pluginArray[i] = p;
                pluginArray[p.name] = p;
            });
            pluginArray.item = (index) => pluginArray[index];
            pluginArray.namedItem = (name) => fakePlugins.find(p => p.name === name) || null;
            Object.defineProperty(pluginArray, Symbol.toStringTag, { value: 'PluginArray', configurable: true });
            Object.defineProperty(navigator, 'plugins', { get: () => pluginArray, configurable: true });

            const fakeMimes = [
                { type: 'application/pdf', suffixes: 'pdf', description: '' },
                { type: 'text/pdf', suffixes: 'pdf', description: '' }
            ];
            const mimeArray = Object.create(MimeTypeArray.prototype);
            mimeArray.length = fakeMimes.length;
            fakeMimes.forEach((m, i) => {
                mimeArray[i] = m;
                mimeArray[m.type] = m;
            });
            mimeArray.item = (index) => mimeArray[index];
            mimeArray.namedItem = (type) => fakeMimes.find(m => m.type === type) || null;
            Object.defineProperty(mimeArray, Symbol.toStringTag, { value: 'MimeTypeArray', configurable: true });
            Object.defineProperty(navigator, 'mimeTypes', { get: () => mimeArray, configurable: true });
        }

        if (CONFIG.FAKE_FONTS) {
            if (document.fonts && document.fonts.query) {
                const origQuery = document.fonts.query;
                document.fonts.query = function() {
                    return Promise.resolve(['Arial', 'Verdana', 'Times New Roman', 'Courier New', 'Georgia']);
                };
                makeNative(document.fonts, 'query');
            }
        }

        // measureText — независимая защита (не привязана к FAKE_FONTS)
        if (CONFIG.PROTECT_MEASURETEXT) {
            const orgMeasureText = CanvasRenderingContext2D.prototype.measureText;
            CanvasRenderingContext2D.prototype.measureText = function(text) {
                const metrics = orgMeasureText.call(this, text);
                const NOISE = 0.001;
                // Стабильный шум на основе текста (одинаковый текст → одинаковый шум)
                let hash = 0;
                const str = String(text);
                for (let i = 0; i < str.length; i++) {
                    hash = ((hash << 5) - hash) + str.charCodeAt(i);
                    hash |= 0;
                }
                const rnd = makeSeededRandom(FINGERPRINT_SEED + hash);
                const n1 = (rnd() - 0.5) * NOISE;
                const n2 = (rnd() - 0.5) * NOISE;
                const n3 = (rnd() - 0.5) * NOISE;
                const n4 = (rnd() - 0.5) * NOISE;
                const n5 = (rnd() - 0.5) * NOISE;

                const define = (prop, val) => {
                    try {
                        Object.defineProperty(metrics, prop, {
                            get: () => val,
                            configurable: true
                        });
                    } catch(e) {}
                };
                if (metrics.width !== undefined) define('width', metrics.width + n1);
                if (metrics.actualBoundingBoxLeft !== undefined) define('actualBoundingBoxLeft', metrics.actualBoundingBoxLeft + n2);
                if (metrics.actualBoundingBoxRight !== undefined) define('actualBoundingBoxRight', metrics.actualBoundingBoxRight + n3);
                if (metrics.actualBoundingBoxAscent !== undefined) define('actualBoundingBoxAscent', metrics.actualBoundingBoxAscent + n4);
                if (metrics.actualBoundingBoxDescent !== undefined) define('actualBoundingBoxDescent', metrics.actualBoundingBoxDescent + n5);
                if (metrics.fontBoundingBoxAscent !== undefined) define('fontBoundingBoxAscent', metrics.fontBoundingBoxAscent + n4);
                if (metrics.fontBoundingBoxDescent !== undefined) define('fontBoundingBoxDescent', metrics.fontBoundingBoxDescent + n5);
                return metrics;
            };
            makeNative(CanvasRenderingContext2D.prototype, 'measureText');
        }

        if (CONFIG.FAKE_BATTERY && navigator.getBattery) {
            const origGetBattery = navigator.getBattery;
            navigator.getBattery = function() {
                const fakeBattery = {
                    charging: false,
                    level: 1,
                    chargingTime: Infinity,
                    dischargingTime: Infinity,
                    addEventListener: () => {},
                    removeEventListener: () => {},
                    dispatchEvent: () => true
                };
                return Promise.resolve(fakeBattery);
            };
            makeNative(navigator, 'getBattery');
        }

        if (CONFIG.FIXED_SCREEN && window.screen) {
            const w = CONFIG.SCREEN_WIDTH;
            const h = CONFIG.SCREEN_HEIGHT;
            const cd = CONFIG.COLOR_DEPTH;

            Object.defineProperty(screen, 'width', { get: () => w, configurable: true });
            Object.defineProperty(screen, 'height', { get: () => h, configurable: true });
            Object.defineProperty(screen, 'availWidth', { get: () => w, configurable: true });
            Object.defineProperty(screen, 'availHeight', { get: () => h, configurable: true });
            Object.defineProperty(screen, 'colorDepth', { get: () => cd, configurable: true });
            Object.defineProperty(screen, 'pixelDepth', { get: () => cd, configurable: true });

            try {
                Object.defineProperty(window, 'outerWidth', {
                    get: () => Math.min(w, window.innerWidth + 16),
                    configurable: true
                });
                Object.defineProperty(window, 'outerHeight', {
                    get: () => Math.min(h, window.innerHeight + 90),
                    configurable: true
                });
            } catch (e) {}
        }

        if (CONFIG.BLOCK_SERVICE_WORKER && navigator.serviceWorker && navigator.serviceWorker.register) {
            const originalRegister = navigator.serviceWorker.register;
            navigator.serviceWorker.register = function(scriptURL, options) {
                logBlock('SW', scriptURL, 'Заблокирована регистрация');
                return Promise.reject(new Error('Service Worker registration blocked'));
            };
            makeNative(navigator.serviceWorker, 'register');
        } else if (CONFIG.LOG_SERVICE_WORKER && navigator.serviceWorker && navigator.serviceWorker.register) {
            const originalRegister = navigator.serviceWorker.register;
            navigator.serviceWorker.register = function(scriptURL, options) {
                console.log("📦 Service Worker registered:", scriptURL);
                return originalRegister.call(this, scriptURL, options);
            };
            makeNative(navigator.serviceWorker, 'register');
        }

    } catch (e) {}

    // ========================== ИНТЕРФЕЙС В SHADOW DOM ==========================
    function createUI() {
        if (document.getElementById('privacy-monitor-shadow-host')) return;
        if (!document.body) {
            setTimeout(createUI, 100);
            return;
        }

        const host = document.createElement('div');
        host.id = 'privacy-monitor-shadow-host';
        host.style.cssText = 'all: initial; display: block;';
        document.body.appendChild(host);

        const shadow = host.attachShadow({ mode: 'open' });
        uiShadow = shadow;

                const style = document.createElement('style');
        style.textContent = `
            #pm-log-list::-webkit-scrollbar {
                width: 6px;
                height: 6px;
            }
            #pm-log-list::-webkit-scrollbar-track {
                background: rgba(255, 255, 255, 0.05);
                border-radius: 3px;
            }
            #pm-log-list::-webkit-scrollbar-thumb {
                background: rgba(255, 255, 255, 0.2);
                border-radius: 3px;
            }
            #pm-log-list::-webkit-scrollbar-thumb:hover {
                background: rgba(255, 255, 255, 0.3);
            }
            /* Прозрачность окна в свёрнутом виде */
            #privacy-monitor {
                opacity: 0.5;
                transition: opacity 0.2s ease;
            }
            #privacy-monitor:hover {
                opacity: 1;
            }
            /* Если окно развёрнуто — всегда непрозрачное */
            #privacy-monitor.pm-open {
                opacity: 1;
            }
        `;
        shadow.appendChild(style);

        const main = document.createElement('div');
        main.id = 'privacy-monitor';
        Object.assign(main.style, {
            position: 'fixed', bottom: '15px', right: '20px', zIndex: '2147483647',
            background: 'rgba(15, 15, 30, 0.6)', color: '#67b3ff', padding: '10px 14px',
            borderRadius: '10px', fontSize: '11px', fontFamily: 'monospace',
            boxShadow: '0 8px 32px rgba(0,0,0,0.3)', pointerEvents: 'auto',
            cursor: 'pointer'
        });

        main.innerHTML = `
            <div id="pm-header" style="display: flex; justify-content: space-between; align-items: center; cursor: pointer;">
                <span id="pm-title-collapsed"><span id="pm-icon" style="display: inline-block;">🪬</span> <span id="pm-counter">${blockedCount}</span></span>
                <span id="pm-title-expanded" style="display: none; flex: 1; text-align: center;"><span style="display: block; margin-bottom: 6px;">🪬 MAX Blinder</span>Заблокировано запросов: <span id="pm-counter-expanded">${blockedCount}</span></span>
                <span id="pm-arrow" style="display: none;">▲</span>
            </div>
            <div id="pm-content" style="display: none; margin-top: 10px; border-top: 1px solid rgba(255,255,255,0.2); padding-top: 8px; width: 260px; cursor: default;">
                <div id="pm-log-list" style="max-height: 150px; overflow-y: auto; margin-bottom: 8px;"></div>
                <div style="display: flex; gap: 6px;">
                    <button id="pm-copy" style="flex: 1; background: rgba(50,50,70,0.4); color: #67b3ff; border: none; padding: 2px 4px; cursor: pointer; border-radius: 3px; font-size: 9px; height: 18px;">Copy log</button>
                    <button id="pm-clear" style="flex: 1; background: rgba(50,50,70,0.4); color: #67b3ff; border: none; padding: 2px 4px; cursor: pointer; border-radius: 3px; font-size: 9px; height: 18px;">Clear log</button>
                </div>
            </div>
        `;

        main.onclick = (e) => {
            // Игнорируем клики внутри развёрнутого содержимого (лог, кнопки)
            if (e.target.closest('#pm-content')) return;

            const content = main.querySelector('#pm-content');
            const arrow = main.querySelector('#pm-arrow');
            const collapsed = main.querySelector('#pm-title-collapsed');
            const expanded = main.querySelector('#pm-title-expanded');
            const isOpen = content.style.display === 'block';

            content.style.display = isOpen ? 'none' : 'block';
            arrow.style.transform = isOpen ? 'rotate(0deg)' : 'rotate(180deg)';
            collapsed.style.display = isOpen ? 'inline' : 'none';
            expanded.style.display = isOpen ? 'none' : 'inline';

            // Управление прозрачностью
            if (isOpen) {
                main.classList.remove('pm-open');
            } else {
                main.classList.add('pm-open');
            }
        };

        main.querySelector('#pm-copy').onclick = async (e) => {
            e.stopPropagation();
            const btn = e.target;
            const originalText = btn.innerText;

            // Шапка лога — формат: DD.MM.YYYY HH:MM:SS
            const now = new Date();
            const pad = (n) => String(n).padStart(2, '0');
            const dateStr = `${pad(now.getDate())}.${pad(now.getMonth() + 1)}.${now.getFullYear()} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;

            const header =
                `MAX Blinder v2.01\n` +
                `— Журнал блокировок ${dateStr} —\n\n` +
                fullLogHistory.join('\n');

            const fullText = header;

            try {
                await navigator.clipboard.writeText(fullText);
                btn.innerText = 'Copied!';
                setTimeout(() => btn.innerText = originalText, 1000);
            } catch (err) {
                console.warn('Clipboard API failed, trying fallback...', err);
                try {
                    const textarea = document.createElement('textarea');
                    textarea.value = fullText;
                    document.body.appendChild(textarea);
                    textarea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textarea);
                    btn.innerText = 'Copied!';
                    setTimeout(() => btn.innerText = originalText, 1000);
                } catch (fallbackErr) {
                    console.error('Fallback copy failed:', fallbackErr);
                    btn.innerText = 'Error!';
                    setTimeout(() => btn.innerText = originalText, 1500);
                }
            }
        };
        main.querySelector('#pm-clear').onclick = (e) => {
            e.stopPropagation();
            blockedCount = 0;
            fullLogHistory = [];
            pendingLogs = [];
            main.querySelector('#pm-counter').innerText = '0';
            main.querySelector('#pm-log-list').innerHTML = '';
        };

        shadow.appendChild(main);
                // Сворачивание окна при клике вне его (только если развёрнуто)
        document.addEventListener('click', (e) => {
            const content = main.querySelector('#pm-content');
            if (content.style.display !== 'block') return;
            const path = e.composedPath ? e.composedPath() : [];
            if (path.includes(host)) return;

            content.style.display = 'none';

            const arrow = main.querySelector('#pm-arrow');
            if (arrow) arrow.style.transform = 'rotate(0deg)';

            // Возвращаем свёрнутый заголовок
            const collapsed = main.querySelector('#pm-title-collapsed');
            const expanded = main.querySelector('#pm-title-expanded');
            if (collapsed) collapsed.style.display = 'inline';
            if (expanded) expanded.style.display = 'none';

            // Сбрасываем прозрачность к свёрнутому состоянию
            main.classList.remove('pm-open');
        }, true);
        const logContainer = shadow.getElementById('pm-log-list');
        while (pendingLogs.length > 0) {
            addEntryToLog(logContainer, pendingLogs.shift());
        }
        shadow.getElementById('pm-counter').innerText = blockedCount;
    }

    // ========================== ОЧИСТКА КЭША ДЕДУПЛИКАЦИИ ==========================
    setInterval(() => {
        const now = Date.now();
        for (const [key, ts] of lastRecorded.entries()) {
            if (now - ts > 10000) {
                lastRecorded.delete(key);
            }
        }
    }, 10000);

    // ========================== ЗАПУСК ==========================
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => setTimeout(createUI, 500));
    } else {
        setTimeout(createUI, 500);
    }
    setInterval(() => {
        if (!document.getElementById('privacy-monitor-shadow-host') && document.body) {
            createUI();
        }
    }, 2000);
})();
