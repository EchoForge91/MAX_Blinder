// ==UserScript==
// @name         MAX Blinder
// @namespace    http://tampermonkey.net/
// @version      2.02
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
        FAKE_PLUGINS: true,
        FIXED_SCREEN: false,
        LOG_SERVICE_WORKER: true,
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
        TELEMETRY_KEYWORDS: ['"events":', '"host_reachability":', '"telemetry":', '"metrics":', '"analytics":', '"crash":', '"perf":', '"permission":', '"permission_status":', '"ptype":', '"pstatus":'],
        STORAGE_KEYWORDS: ['events', 'host_reachability', 'telemetry', 'metrics', 'analytics', 'crash', 'perf_'],
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
        BLOCK_VPN_DETECTION: true,           // маскировка флага VPN в HOST_REACHABILITY
        MUTE_SOUNDS: false                   // Отключить все звуки мессенджера
    };

    // Загружаем сохраненные настройки из localStorage
    try {
        CONFIG.MUTE_SOUNDS = localStorage.getItem('pm_mute_sounds') === 'true';
    } catch (e) {
        console.warn('Не удалось загрузить настройки из localStorage', e);
    }
    // ========================== ДЕТЕРМИНИРОВАННЫЙ PRNG ==========================
    // Генерируем сид на основе стабильных параметров браузера (не использует хранилища)
    const FINGERPRINT_SEED = (() => {
        if (CONFIG.FINGERPRINT_SEED !== null) return CONFIG.FINGERPRINT_SEED;
        let str = navigator.userAgent + navigator.language + screen.width + 'x' + screen.height + navigator.hardwareConcurrency;
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash |= 0;
        }
        return Math.abs(hash) || 1234567;
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
    const maxLogs = 40;
    const MAX_LOG_HISTORY = 5000;
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
        'WEBSOCKET': 'Соединение',
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
        'FETCH (popup)': 'Запрос из окна',
        'STATUS': 'Статус' // <-- НОВОЕ
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
        entry.className = 'pm-log-entry';
        const friendlyType = getFriendlyLabel(data.type);
        const fullText = `[${friendlyType}] ${data.uiText}`;
        const typeSpan = document.createElement('span');
        typeSpan.style.color = '#67b3ff';
        typeSpan.textContent = `[${friendlyType}]`;
        entry.appendChild(typeSpan);
        entry.appendChild(document.createTextNode(' ' + data.uiText));

        // 1. Вставляем элемент в DOM
        container.prepend(entry);
        // НОВОЕ: Автоматически прокручиваем список в самый верх
        container.scrollTop = 0;

        // 2. Узнаем итоговую высоту элемента (с учетом паддингов и рамок из CSS)
        const finalHeight = entry.offsetHeight;

        // 3. Если контейнер видим, запускаем анимацию
        if (finalHeight > 0) {
            const anim = entry.animate([
                {
                    maxHeight: '0px',
                    paddingTop: '0px',
                    paddingBottom: '0px',
                    opacity: 0,
                    borderBottomWidth: '0px'
                },
                {
                    maxHeight: finalHeight + 'px',
                    paddingTop: '5px',
                    paddingBottom: '5px',
                    opacity: 1,
                    borderBottomWidth: '1px'
                }
            ], {
                duration: 300, // Длительность анимации (0.3 сек)
                easing: 'ease-out'
            });

            // Когда анимация закончится, убираем ограничение maxHeight
            anim.onfinish = () => {
                entry.style.maxHeight = '';
                if (container.childNodes.length > maxLogs) {
                    container.removeChild(container.lastChild);
                }
            };
        } else {
            // Если окно свернуто (высота 0), просто удаляем старые записи
            if (container.childNodes.length > maxLogs) {
                container.removeChild(container.lastChild);
            }
        }

        // 4. Проверяем, обрезается ли текст (для всплывающей подсказки)
        requestAnimationFrame(() => {
            if (entry.scrollWidth > entry.clientWidth) {
                entry.setAttribute('data-tooltip', fullText);
                entry.style.cursor = 'help';
            }
        });
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

                // Запускаем анимацию иконки...
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
    // ========================== ОТКЛЮЧЕНИЕ ЗВУКОВ ==========================
    if (CONFIG.MUTE_SOUNDS) {
        // Блокируем стандартный HTML5 Audio
        const origPlay = HTMLMediaElement.prototype.play;
        HTMLMediaElement.prototype.play = function() {
            if (this.tagName === 'AUDIO' || this.tagName === 'VIDEO') {
                return Promise.resolve(); // Делаем вид, что звук играет, но глушим его
            }
            return origPlay.apply(this, arguments);
        };
        makeNative(HTMLMediaElement.prototype, 'play');

        // Блокируем Web Audio API (используется для звонков)
        if (window.AudioContext) {
            const origCreateOscillator = AudioContext.prototype.createOscillator;
            AudioContext.prototype.createOscillator = function() {
                const osc = origCreateOscillator.apply(this, arguments);
                osc.start = function() {}; // Запрещаем гудки
                return osc;
            };
            makeNative(AudioContext.prototype, 'createOscillator');
            const origCreateBufferSource = AudioContext.prototype.createBufferSource;
            AudioContext.prototype.createBufferSource = function() {
                const source = origCreateBufferSource.apply(this, arguments);
                source.start = function() {}; // Запрещаем мелодии
                return source;
            };
            makeNative(AudioContext.prototype, 'createBufferSource');
        }
    }

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
        const patchGetParameter = (proto) => {
            if (!proto || !proto.getParameter) return;
            const originalGetParameter = proto.getParameter;
            const customGetParameter = function(param) {
                switch (param) {
                    case 0x9245: return 'Google Inc. (NVIDIA)';
                    case 0x9246: return 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)';
                    case 0x1F00: return 'WebKit';
                    case 0x1F01: return 'WebKit WebGL';
                    case 0x1F02: return 'WebGL 1.0 (OpenGL ES 2.0 Chromium)';
                    case 0x8B8C: return 'WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)';
                    case 0x0D33: return 16384;
                    case 0x8D57: return 16384;
                    case 0x0D3A: return new Int32Array([16384, 16384]);
                    case 0x8869: return 16;
                    case 0x8DFB: return 4096;
                    case 0x8DFD: return 4096;
                    case 0x8DFC: return 30;
                    case 0x846E: return new Float32Array([1, 64]);
                }
                return originalGetParameter.apply(this, arguments);
            };
            Object.defineProperty(customGetParameter, 'length', { value: originalGetParameter.length });
            proto.getParameter = customGetParameter;
            makeNative(proto, 'getParameter');
        };

        patchGetParameter(WebGLRenderingContext.prototype);
        if (window.WebGL2RenderingContext) {
            patchGetParameter(WebGL2RenderingContext.prototype);
        }
    }
    // 3. Блокировка Cache Storage API (опционально)
    if (CONFIG.BLOCK_CACHE_STORAGE && window.CacheStorage) {
        const origOpen = CacheStorage.prototype.open;
        if (origOpen) {
            const customOpen = function(name) {
                    if (CONFIG.STORAGE_KEYWORDS.some(k => String(name).toLowerCase().includes(k))) {
                    logBlock('CACHE', name, 'Заблокирован доступ к кэшу');
                    return Promise.reject(new Error('Cache blocked by Blinder'));
                }
                return origOpen.apply(this, arguments);
            };
            Object.defineProperty(customOpen, 'length', { value: origOpen.length });
            CacheStorage.prototype.open = customOpen;
            makeNative(CacheStorage.prototype, 'open');
            try { delete caches.open; } catch(e) {}
        }
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
                    const blob = new Blob(['self.onmessage=function(){};'], { type: 'application/javascript' });
                    return new origWorker(URL.createObjectURL(blob), options);
                }
                return new origWorker(scriptURL, options);
            };
            // Выравниваем длину для обычного Worker
            Object.defineProperty(window.Worker, 'length', { value: origWorker.length });
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
            Object.defineProperty(window.SharedWorker, 'length', { value: origSharedWorker.length });
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
        Object.defineProperty(window.fetch, 'length', { value: 1 });
        makeNative(window, 'fetch');

        // Перехват XHR для probing (дополнительно)
        const origOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url) {
            this._url = url;
            this._isProbe = shouldBlockProbing(url);
            return origOpen.apply(this, arguments);
        };
        Object.defineProperty(XMLHttpRequest.prototype.open, 'length', { value: origOpen.length });
        const origSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function(body) {
            if (this._isProbe) {
                logBlock('PROBE', this._url);
                // Имитируем ошибку сети, чтобы сайт не ждал ответа
                setTimeout(() => {
                    Object.defineProperty(this, 'readyState', { value: 4, configurable: true });
                    Object.defineProperty(this, 'status', { value: 0, configurable: true });
                    Object.defineProperty(this, 'statusText', { value: 'Network error', configurable: true });
                    this.dispatchEvent(new Event('readystatechange'));
                    this.dispatchEvent(new Event('error'));
                    this.dispatchEvent(new Event('loadend'));
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
                    if (key && CONFIG.STORAGE_KEYWORDS.some(k => key.toLowerCase().includes(k))) {
                        keysToClear.push(key);
                    }
                }
                keysToClear.forEach(key => localStorage.removeItem(key));
                if (keysToClear.length) logBlock('STORAGE', '', `Очищено записей: ${keysToClear.length}`);
            }
            if (window.indexedDB) {
                indexedDB.databases().then(dbs => {
                    dbs.forEach(db => {
                        if (db.name && CONFIG.STORAGE_KEYWORDS.some(k => db.name.toLowerCase().includes(k))) {
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
        Object.defineProperty(window.fetch, 'length', { value: 1 });
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
        Object.defineProperty(XMLHttpRequest.prototype.open, 'length', { value: origOpenXHR.length });
        makeNative(XMLHttpRequest.prototype, 'open');

        const origSendXHR = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function(body) {
            if (this._isTracker) {
                logBlock('XHR', this._url);
                setTimeout(() => {
                    Object.defineProperty(this, 'readyState', { value: 4, configurable: true });
                    Object.defineProperty(this, 'status', { value: 200, configurable: true });
                    if (this.responseType === 'json') {
                        Object.defineProperty(this, 'response', { value: { status: "ok" }, configurable: true });
                    } else {
                        Object.defineProperty(this, 'responseText', { value: '{"status":"ok"}', configurable: true });
                        Object.defineProperty(this, 'response', { value: '{"status":"ok"}', configurable: true });
                    }
                    this.dispatchEvent(new Event('readystatechange'));
                    this.dispatchEvent(new Event('load'));
                    this.dispatchEvent(new Event('loadend'));
                }, 1);
                return;
            }
            if (this._isProbe) {
                logBlock('PROBE', this._url);
                setTimeout(() => {
                    Object.defineProperty(this, 'readyState', { value: 4, configurable: true });
                    Object.defineProperty(this, 'status', { value: 0, configurable: true });
                    Object.defineProperty(this, 'statusText', { value: 'Network error', configurable: true });
                    this.dispatchEvent(new Event('readystatechange'));
                    this.dispatchEvent(new Event('error'));
                    this.dispatchEvent(new Event('loadend'));
                }, 1);
                return;
            }
            if (this._method === 'POST' && body && hasTelemetryInPayload(body)) {
                logBlock('POST-TELE', this._url);
                setTimeout(() => {
                    Object.defineProperty(this, 'readyState', { value: 4, configurable: true });
                    Object.defineProperty(this, 'status', { value: 200, configurable: true });
                    if (this.responseType === 'json') {
                        Object.defineProperty(this, 'response', { value: { status: "ok" }, configurable: true });
                    } else {
                        Object.defineProperty(this, 'responseText', { value: '{"status":"ok"}', configurable: true });
                        Object.defineProperty(this, 'response', { value: '{"status":"ok"}', configurable: true });
                    }
                    this.dispatchEvent(new Event('readystatechange'));
                    this.dispatchEvent(new Event('load'));
                    this.dispatchEvent(new Event('loadend'));
                }, 1);
                return;
            }
            return origSendXHR.apply(this, arguments);
        };
        makeNative(XMLHttpRequest.prototype, 'send');
    }

    // ========================== WEBSOCKET ФИЛЬТРАЦИЯ ==========================
    // Перехват конструктора WebSocket
    const OrigWebSocket = window.WebSocket;
    window.WebSocket = new Proxy(OrigWebSocket, {
        construct(target, args) {
            const url = args[0];
            if (shouldBlock(url) || (CONFIG.BLOCK_PROBING && shouldBlockProbing(url))) {
                logBlock('WEBSOCKET', url, 'Заблокировано соединение');
                // Создаем полноценную заглушку
                const stub = {
                    binaryType: 'blob',
                    bufferedAmount: 0,
                    extensions: '',
                    protocol: '',
                    send: function() {},
                    close: function() {},
                    addEventListener: function() {},
                    removeEventListener: function() {},
                    dispatchEvent: function() { return true; },
                    readyState: 3, // CLOSED
                    url: url,
                    onopen: null,
                    onmessage: null,
                    onerror: null,
                    onclose: null
                };
                // Асинхронно уведомляем приложение, что соединение разорвано
                setTimeout(() => {
                    try {
                        if (typeof stub.onerror === 'function') stub.onerror(new Event('error'));
                        if (typeof stub.onclose === 'function') stub.onclose(new CloseEvent('close', { code: 1006 }));
                    } catch (e) {}
                }, 0);
                return stub;
            }
            return new target(...args);
        }
    });
    makeNative(window, 'WebSocket');
    const origWSSend = WebSocket.prototype.send;
    WebSocket.prototype.send = function(data) {
        if (typeof data === 'string' && data.includes('"opcode"')) {
            try {
                const msg = JSON.parse(data);
                const opcode = msg.opcode;

                // Перехват и скрытие статусов (работает всегда, если включены галочки)
                if (CONFIG.HIDE_READ_RECEIPTS && opcode === 50) {
                    logEvent('STATUS', '', 'Скрыт статус "Прочитано"');
                    return;
                }
                if (CONFIG.HIDE_TYPING && opcode === 65) {
                    logEvent('STATUS', '', 'Скрыт статус "Печатает"');
                    return;
                }

                // Существующая блокировка телеметрии (теперь внутри проверки)
                if (CONFIG.BLOCK_WEBSOCKET_OPCODE5 && CONFIG.BLOCKED_OPCODES.includes(opcode)) {
                    logBlock('WS-TELE', '', 'Заблокирована аналитика');
                    return;
                }
                // Дополнительная проверка на GET_HOST_REACHABILITY
                if (CONFIG.BLOCK_WEBSOCKET_OPCODE5 && opcode === 5 &&
                    msg.payload &&
                    msg.payload.events &&
                    Array.isArray(msg.payload.events) &&
                    msg.payload.events.some(e => e.event === 'GET_HOST_REACHABILITY')) {
                    logBlock('WS-TELE', '', 'Заблокирована проверка сети');
                    return;
                }
                // [1.9] Расширенная проверка HOST_REACHABILITY по любому опкоду
                if (CONFIG.BLOCK_WEBSOCKET_OPCODE5 &&
                    msg.payload &&
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
    // ========================== BEACON ==========================
    if (CONFIG.BLOCK_BEACON && window.Navigator) {
        const origBeacon = Navigator.prototype.sendBeacon;
        if (origBeacon) {
            const customBeacon = function(url, data) {
                if (shouldBlock(url) || (CONFIG.BLOCK_PROBING && shouldBlockProbing(url))) {
                    logBlock('BEACON', url);
                    return true;
                }
                return origBeacon.apply(this, arguments);
            };
            // Скрываем длину функции (нативный sendBeacon имеет length = 2, наш тоже, но на всякий случай)
            Object.defineProperty(customBeacon, 'length', { value: origBeacon.length });
            Navigator.prototype.sendBeacon = customBeacon;
            makeNative(Navigator.prototype, 'sendBeacon');
            // Удаляем собственное свойство, если оно было
            try { delete navigator.sendBeacon; } catch(e) {}
        }
    }

    // ========================== IFRAME ЗАЩИТА ==========================
    if (CONFIG.IFRAME_PROTECTION) {
        const origCreateElement = document.createElement;
        const origOpen = window.open;

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
                    Object.defineProperty(win.XMLHttpRequest.prototype.open, 'length', { value: origIOpen.length });
                    const origISend = win.XMLHttpRequest.prototype.send;
                    win.XMLHttpRequest.prototype.send = function() {
                        if (this._isTracker) {
                            logBlock('XHR (iframe)', this._blockUrl);
                            setTimeout(() => {
                                Object.defineProperty(this, 'readyState', { value: 4, configurable: true });
                                Object.defineProperty(this, 'status', { value: 200, configurable: true });
                                if (this.responseType === 'json') {
                                    Object.defineProperty(this, 'response', { value: { status: "ok" }, configurable: true });
                                } else {
                                    Object.defineProperty(this, 'responseText', { value: '{"status":"ok"}', configurable: true });
                                    Object.defineProperty(this, 'response', { value: '{"status":"ok"}', configurable: true });
                                }
                                this.dispatchEvent(new Event('readystatechange'));
                                this.dispatchEvent(new Event('load'));
                                this.dispatchEvent(new Event('loadend'));
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
        Object.defineProperty(document.createElement, 'length', { value: origCreateElement.length });
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
        Object.defineProperty(window.open, 'length', { value: origOpen.length });
        makeNative(window, 'open');

        // ===== НОВОЕ: Наблюдатель за динамически добавляемыми iframe =====
        const observer = new MutationObserver((mutations) => {
            for (const mutation of mutations) {
                for (const node of mutation.addedNodes) {
                    if (node.tagName === 'IFRAME') {
                        protectIframe(node);
                    } else if (node.querySelectorAll) {
                        node.querySelectorAll('iframe').forEach(protectIframe);
                    }
                }
            }
        });
            observer.observe(document, { childList: true, subtree: true });
        }
    // ================================================================

    try {
        // Улучшенные аппаратные характеристики (теперь в прототипе и с configurable)
        Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', { get: () => 8, configurable: true });
        Object.defineProperty(Navigator.prototype, 'deviceMemory', { get: () => 8, configurable: true });
        // Удаляем потенциальные собственные свойства, если они были созданы ранее
        try { delete navigator.hardwareConcurrency; delete navigator.deviceMemory; } catch(e) {}

        // Canvas
        if (CONFIG.PROTECT_CANVAS) {
            const ctx2dMap = new WeakMap();
            const origGetContext = HTMLCanvasElement.prototype.getContext;
            HTMLCanvasElement.prototype.getContext = function(type, ...attrs) {
                const ctx = origGetContext.call(this, type, ...attrs);
                if (type === '2d' && ctx) ctx2dMap.set(this, ctx);
                return ctx;
            };
            makeNative(HTMLCanvasElement.prototype, 'getContext');
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
            const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
            HTMLCanvasElement.prototype.toDataURL = function(type, quality) {
                const ctx = ctx2dMap.get(this);
                const w = this.width, h = this.height;
                if (ctx && w > 0 && h > 0) {
                    try {
                        const clean = orgGetImageData.call(ctx, 0, 0, w, h); // Чистая копия
                        const noisy = ctx.getImageData(0, 0, w, h);          // Наш шумный хук
                        ctx.putImageData(noisy, 0, 0);
                        const url = origToDataURL.call(this, type, quality);
                        ctx.putImageData(clean, 0, 0);                        // ВОССТАНОВЛЕНИЕ
                        return url;
                    } catch (e) {}
                }
                return origToDataURL.call(this, type, quality);
            };
            makeNative(HTMLCanvasElement.prototype, 'toDataURL');

            const origToBlob = HTMLCanvasElement.prototype.toBlob;
            HTMLCanvasElement.prototype.toBlob = function(callback, type, quality) {
                const ctx = ctx2dMap.get(this);
                const w = this.width, h = this.height;
                if (ctx && w > 0 && h > 0) {
                    try {
                        const clean = orgGetImageData.call(ctx, 0, 0, w, h);
                        const noisy = ctx.getImageData(0, 0, w, h);
                        ctx.putImageData(noisy, 0, 0);
                        const result = origToBlob.call(this, callback, type, quality);
                        ctx.putImageData(clean, 0, 0);
                        return result;
                    } catch (e) {}
                }
                return origToBlob.call(this, callback, type, quality);
            };
            makeNative(HTMLCanvasElement.prototype, 'toBlob');
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
                    // Блокируем кандидатов ТОЛЬКО в строгом режиме
                    if (CONFIG.WEBRTC_STRICT) {
                        pc.addIceCandidate = function() { return Promise.resolve(); };
                    }
                    return pc;
                }
            });
            window.RTCPeerConnection.prototype = OriginalRTCPeerConnection.prototype;
            makeNative(window, 'RTCPeerConnection');
        }

        if (CONFIG.HIDE_WEBDRIVER && 'webdriver' in navigator) {
            Object.defineProperty(Navigator.prototype, 'webdriver', { get: () => undefined, configurable: true });
            try { delete navigator.webdriver; } catch(e) {}
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
                // Возвращаем настоящий DOMRect
                return new DOMRect(
                    rect.x + n1,
                    rect.y + n2,
                    rect.width + n3,
                    rect.height + n4
                );
            };
            makeNative(Element.prototype, 'getBoundingClientRect');

            const origGetClientRects = Element.prototype.getClientRects;
            Element.prototype.getClientRects = function() {
                const rects = origGetClientRects.call(this);
                const [n1, n2, n3, n4] = getRectNoise(this);
                const list = [];
                for (let i = 0; i < rects.length; i++) {
                    const r = rects[i];
                    list.push(new DOMRect(
                        r.x + n1,
                        r.y + n2,
                        r.width + n3,
                        r.height + n4
                    ));
                }
                // Имитируем метод item() для совместимости
                list.item = function(index) {
                    return this[index] || null;
                };
                // НОВОЕ: Делаем вид, что это настоящий DOMRectList
                Object.defineProperty(list, Symbol.toStringTag, { value: 'DOMRectList', configurable: true });
                return list;
            };
            makeNative(Element.prototype, 'getClientRects');
        }

        // Мониторинг запросов разрешений (аналог DailyAnalyticsWorker из Android)
        // Android-версия MAX ежедневно проверяет статус разрешений через
        // DailyAnalyticsWorker. В веб-версии аналог — navigator.permissions.query.
        if (CONFIG.MONITOR_PERMISSIONS && navigator.permissions && window.Permissions) {
            const origPermissionsQuery = Permissions.prototype.query;
            const customQuery = function(descriptor) {
                try {
                    const permName = (descriptor && descriptor.name) || 'unknown';
                    const PERM_NAMES = {
                        'camera': 'Запрос доступа к камере',
                        'microphone': 'Запрос доступа к микрофону',
                        'geolocation': 'Запрос доступа к геолокации',
                        'notifications': 'Запрос на уведомления',
                        'clipboard-read': 'Запрос доступа к буферу',
                        'clipboard-write': 'Запрос записи в буфер'
                    };
                    logEvent('PERMISSION', '', PERM_NAMES[permName] || `Проверка: ${permName}`);
                } catch (e) {}
                return origPermissionsQuery.apply(this, arguments);
            };
            Object.defineProperty(customQuery, 'length', { value: origPermissionsQuery.length });
            Permissions.prototype.query = customQuery;
            makeNative(Permissions.prototype, 'query');
            try { delete navigator.permissions.query; } catch(e) {}
        }

        if (CONFIG.MONITOR_CLIPBOARD && window.Clipboard) {
            // readText
            const origReadText = Clipboard.prototype.readText;
            if (origReadText) {
                const customReadText = function() {
                    logEvent('CLIPBOARD', '', 'Мессенджер читает буфер обмена');
                    return origReadText.apply(this, arguments);
                };
                Object.defineProperty(customReadText, 'length', { value: origReadText.length });
                Clipboard.prototype.readText = customReadText;
                makeNative(Clipboard.prototype, 'readText');
                try { delete navigator.clipboard.readText; } catch(e) {}
            }
            // read
            const origRead = Clipboard.prototype.read;
            if (origRead) {
                const customRead = function() {
                    logEvent('CLIPBOARD', '', 'Мессенджер читает данные из буфера');
                    return origRead.apply(this, arguments);
                };
                Object.defineProperty(customRead, 'length', { value: origRead.length });
                Clipboard.prototype.read = customRead;
                makeNative(Clipboard.prototype, 'read');
                try { delete navigator.clipboard.read; } catch(e) {}
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

        if (CONFIG.FAKE_BATTERY && window.Navigator) {
            const origGetBattery = Navigator.prototype.getBattery;
            if (origGetBattery) {
                const customGetBattery = function() {
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
                Object.defineProperty(customGetBattery, 'length', { value: origGetBattery.length });
                Navigator.prototype.getBattery = customGetBattery;
                makeNative(Navigator.prototype, 'getBattery');
                try { delete navigator.getBattery; } catch(e) {}
            }
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

        if (window.ServiceWorkerContainer) {
            const origRegister = ServiceWorkerContainer.prototype.register;
            if (origRegister) {
                const customRegister = function(scriptURL, options) {
                    if (CONFIG.BLOCK_SERVICE_WORKER) {
                        logBlock('SW', scriptURL, 'Заблокирована регистрация');
                        return Promise.reject(new Error('Service Worker registration blocked'));
                    } else if (CONFIG.LOG_SERVICE_WORKER) {
                        console.log("📦 Service Worker registered:", scriptURL);
                    }
                    return origRegister.apply(this, arguments);
                };
                Object.defineProperty(customRegister, 'length', { value: origRegister.length });
                ServiceWorkerContainer.prototype.register = customRegister;
                makeNative(ServiceWorkerContainer.prototype, 'register');
                try { delete navigator.serviceWorker.register; } catch(e) {}
            }
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

        // Объявляем все переменные состояния в самом начале функции, чтобы не было конфликтов
        let currentLogHeight = 180;
        let isResizing = false;
        let justFinishedResizing = false;
        let startY = 0;
        let startHeight = 0;
        let startMainTop = 0; // Исходная верхняя координата при изменении высоты сверху

        const style = document.createElement('style');
        style.textContent = `
            #pm-log-list::-webkit-scrollbar {
                width: 8px;
                height: 8px;
            }

            #pm-copy {
                position: relative;
            }
            #pm-copy::after {
                content: attr(data-tooltip);
                position: absolute;
                bottom: 100%;
                left: 50%;
                transform: translateX(-50%) translateY(-8px);
                background: #343f50;
                color: #ffffff;
                padding: 6px 10px;
                border-radius: 4px;
                font-size: 10px;
                /* НОВЫЕ ПРАВИЛА ДЛЯ ПЕРЕНОСА: */
                white-space: pre-wrap; /* Уважаем \n */
                text-align: center;    /* Текст по центру */
                width: max-content;    /* Ширина по содержимому */
                max-width: 140px;      /* Ограничиваем ширину, чтобы не вылезал */
                pointer-events: none;
                opacity: 0;
                transition: opacity 0.2s ease;
                border: 1px solid rgba(255, 255, 255, 0.15);
                box-shadow: 0 4px 12px rgba(0,0,0,0.25);
                z-index: 100;
            }
            #pm-copy:hover::after {
                opacity: 1;
                transition-delay: 0.4s; /* Задержка 0.4 сек перед появлением */
            }
            /* Скрываем ручки, когда окно свернуто, и показываем, когда развернуто */
            #pm-resize-handle, #pm-resize-handle-bottom {
                display: none;
                cursor: ns-resize;
            }
            #privacy-monitor.pm-open #pm-resize-handle,
            #privacy-monitor.pm-open #pm-resize-handle-bottom {
                display: block;
            }

            /* --- СТИЛИ ДЛЯ СТРОК ЛОГА --- */
            .pm-log-entry {
                position: relative;
                border-bottom: 1px solid rgba(255,255,255,0.1);
                padding: 5px 0;
                color: #ffffff;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
                font-size: 10px;
                box-sizing: border-box;
            }
            /* Показываем тултип ТОЛЬКО если есть атрибут data-tooltip */
            .pm-log-entry[data-tooltip]::after {
                content: attr(data-tooltip);
                position: absolute;
                bottom: 100%;
                left: 0;
                background: #343f50;
                color: #ffffff;
                padding: 6px 10px;
                border-radius: 4px;
                font-size: 10px;
                white-space: normal;
                max-width: 300px;
                word-wrap: break-word;
                pointer-events: none;
                opacity: 0;
                transition: opacity 0.2s ease;
                transition-delay: 0s;
                border: 1px solid rgba(255, 255, 255, 0.15);
                box-shadow: 0 4px 12px rgba(0,0,0,0.25);
                z-index: 100;
            }
            .pm-log-entry[data-tooltip]:hover::after {
                opacity: 1;
                transition-delay: 0.4s;
            }
            /* Управление курсорами и прозрачностью */
            #privacy-monitor {
                cursor: pointer; /* В свёрнутом виде — рука (клик для разворота) */
                opacity: 0.4; /* Возвращаем полупрозрачность */
                transition: opacity 0.2s ease;
            }
            #privacy-monitor:hover {
                opacity: 1; /* Окрашивается при наведении */
            }
            #privacy-monitor.pm-open {
                cursor: default;
                opacity: 1;
            }

            /* --- НОВЫЕ СТИЛИ (ШАГ 1) --- */
            /* Универсальный класс для тултипов */
            .pm-has-tooltip {
                position: relative;
            }
            .pm-has-tooltip::after {
                content: attr(data-tooltip);
                position: absolute;
                bottom: 100%;
                left: 50%;
                transform: translateX(-50%) translateY(-6px);
                background: #343f50;
                color: #ffffff;
                padding: 6px 10px;
                border-radius: 4px;
                font-size: 10px;
                white-space: normal;
                width: max-content;
                max-width: 220px;
                word-wrap: break-word;
                text-align: center;
                pointer-events: none;
                opacity: 0;
                transition: opacity 0.2s ease;
                border: 1px solid rgba(255, 255, 255, 0.15);
                box-shadow: 0 4px 12px rgba(0,0,0,0.25);
                z-index: 100;
            }
            .pm-has-tooltip:hover::after {
                opacity: 1;
                transition-delay: 0.4s;
            }

            /* Стили для чекбоксов */
            .pm-chk-label {
                display: flex;
                align-items: center;
                cursor: pointer;
                font-size: 10px;
                color: #67b3ff; /* Синий цвет текста */
                user-select: none;
            }

            /* Стили для кастомных чекбоксов */
            .pm-chk-label input[type="checkbox"] {
                -webkit-appearance: none;
                appearance: none;
                margin: 0 5px 0 0; /* Отступ справа */
                cursor: pointer;
                width: 14px;  /* Размер 14x14 */
                height: 14px;
                background-color: rgba(50, 50, 70, 0.4); /* Прозрачный фон */
                border: 1px solid rgba(255, 255, 255, 0.15);
                border-radius: 3px;
                position: relative;
                display: inline-block;
                vertical-align: middle;
                outline: none;
            }

            /* Сама отметка (символ ✓) */
            .pm-chk-label input[type="checkbox"]::after {
                content: '✓';
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                display: flex;
                justify-content: center;
                align-items: center;
                font-size: 11px; /* <-- УМЕНЬШИЛИ РАЗМЕР (было 14px) */
                color: #ffffff;
                line-height: 1;
                opacity: 0;
            }

            /* Показываем галочку, когда чекбокс выбран */
            .pm-chk-label input[type="checkbox"]:checked::after {
                opacity: 1;
            }
            /* --- КОНЕЦ НОВЫХ СТИЛЕЙ --- */
        `;
        shadow.appendChild(style);

        const main = document.createElement('div');
        main.id = 'privacy-monitor';
        Object.assign(main.style, {
            position: 'fixed', zIndex: '2147483647',
            background: 'rgba(15, 15, 30, 0.8)', color: '#67b3ff', padding: '10px 14px',
            borderRadius: '12px', fontSize: '12px', fontFamily: 'monospace',
            boxShadow: '0 8px 32px rgba(0,0,0,0.3)', pointerEvents: 'auto',
            width: 'max-content', // Ширина ровно по содержимому
            whiteSpace: 'nowrap', // Запрет переноса текста
        });

        main.innerHTML = `
            <!-- Невидимая ручка на самом верху окна -->
            <div id="pm-resize-handle" style="position: absolute; top: 0; left: 0; width: 100%; height: 15px; z-index: 10;"></div>
            <!-- НОВОЕ: Невидимая ручка в самом низу окна -->
            <div id="pm-resize-handle-bottom" style="position: absolute; bottom: 0; left: 0; width: 100%; height: 15px; z-index: 10;"></div>
            <div id="pm-header" style="display: flex; justify-content: space-between; align-items: center; cursor: pointer;">
                <span id="pm-title-collapsed"><span id="pm-icon" style="display: inline-block;">🪬</span> <span id="pm-counter">${blockedCount}</span></span>
                <span id="pm-title-expanded" style="display: none; flex: 1; text-align: center;"><span style="display: block; margin-bottom: 4px;">🪬 MAX Blinder</span>Заблокировано запросов: <span id="pm-counter-expanded">${blockedCount}</span></span>
                <span id="pm-arrow" style="display: none;">▲</span>
            </div>
            <div id="pm-content" style="display: none; margin-top: 8px; border-top: 1px solid rgba(255,255,255,0.2); padding-top: 6px; width: 250px; cursor: default;">
                <div id="pm-log-list" style="overflow-y: auto; margin-bottom: 10px;"></div>
                <!-- НОВАЯ ПАНЕЛЬ УПРАВЛЕНИЯ -->
                <div style="display: flex; gap: 8px; align-items: center; justify-content: space-between;">
                    <!-- Левая часть: Чекбокс отключения звука -->
                    <div style="display: flex; gap: 8px;">
                        <label class="pm-chk-label pm-has-tooltip" data-tooltip="Полностью отключить все звуки уведомлений и звонков">
                            <input type="checkbox" id="pm-chk-mute">
                            Без звука
                        </label>
                    </div>

                    <!-- Правая часть: Меню -->
                    <div style="position: relative;">
                        <!-- Новая SVG-иконка с узкими полосками -->
                        <button id="pm-menu-btn" class="pm-has-tooltip" data-tooltip="Меню" style="background: rgba(50,50,70,0.4); color: #67b3ff; border: none; cursor: pointer; border-radius: 4px; width: 24px; height: 24px; display: flex; justify-content: center; align-items: center; padding: 0;">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
                                <line x1="4" y1="6" x2="20" y2="6"></line>
                                <line x1="4" y1="12" x2="20" y2="12"></line>
                                <line x1="4" y1="18" x2="20" y2="18"></line>
                            </svg>
                        </button>
                        <!-- Выпадающее меню -->
                        <div id="pm-menu-dropdown" style="display: none; position: absolute; bottom: 100%; right: 0; margin-bottom: 6px; background: #343f50; border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 4px; padding: 4px; z-index: 200; white-space: nowrap; box-shadow: 0 4px 12px rgba(0,0,0,0.25);">
                            <button id="pm-menu-save" style="display: block; width: 100%; text-align: left; background: none; color: #ffffff; border: none; padding: 6px 10px; cursor: pointer; font-size: 10px; border-radius: 2px; transition: background 0.2s;">Сохранить лог</button>
                            <button id="pm-menu-clear" style="display: block; width: 100%; text-align: left; background: none; color: #ffffff; border: none; padding: 6px 10px; cursor: pointer; font-size: 10px; border-radius: 2px; transition: background 0.2s;">Очистить лог</button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        shadow.appendChild(main);

        // Сохраняем позицию как расстояние в пикселях от выбранных краёв.
        // Проценты оставляем только для совместимости со старыми версиями.
        function saveWindowPosition(rect = main.getBoundingClientRect()) {
            if (typeof main._isLeft !== 'boolean') {
                main._isLeft = rect.left < (window.innerWidth / 2);
            }
            if (typeof main._isTop !== 'boolean') {
                main._isTop = rect.top < (window.innerHeight / 2);
            }

            const offsetX = main._isLeft ? rect.left : window.innerWidth - rect.right;
            const offsetY = main._isTop ? rect.top : window.innerHeight - rect.bottom;
            main._offsetX = offsetX;
            main._offsetY = offsetY;

            try {
                localStorage.setItem('pm_window_anchor_x', main._isLeft ? 'left' : 'right');
                localStorage.setItem('pm_window_anchor_y', main._isTop ? 'top' : 'bottom');
                localStorage.setItem('pm_window_offset_x_px', String(offsetX));
                localStorage.setItem('pm_window_offset_y_px', String(offsetY));

                // Для совместимости при откате на старую версию.
                localStorage.setItem('pm_window_left_pct', String((rect.left / window.innerWidth) * 100));
                localStorage.setItem('pm_window_top_pct', String((rect.top / window.innerHeight) * 100));
            } catch (err) {}
        }

        // ===== ЗАЩИТА ОТ ВЫХОДА ОКНА ЗА ГРАНИЦЫ VIEWPORT =====
        const viewportSafetyGap = 8;

        // Если раскрытая панель не помещается по высоте, временно уменьшаем
        // только список логов. currentLogHeight хранит желаемую высоту и позволяет
        // восстановить её, когда браузер снова станет выше.
        function fitExpandedPanelHeight() {
            if (!main.classList.contains('pm-open')) return;
            const list = main.querySelector('#pm-log-list');
            if (!list) return;

            const listHeight = list.offsetHeight;
            const extraHeight = Math.max(0, main.offsetHeight - listHeight);
            const availableListHeight = Math.max(
                0,
                window.innerHeight - viewportSafetyGap * 2 - extraHeight
            );
            const preferredHeight = Number.isFinite(currentLogHeight)
                ? Math.max(0, currentLogHeight)
                : listHeight;
            const targetHeight = Math.min(preferredHeight, availableListHeight);

            list.style.height = targetHeight + 'px';
            list.style.maxHeight = targetHeight + 'px';
        }

        // Если панель после изменения размера или смены состояния выходит за экран,
        // выбираем ближайший из четырёх углов и закрепляем её там.
        function snapToNearestCornerIfOutside() {
            const rect = main.getBoundingClientRect();
            const viewportWidth = window.innerWidth;
            const viewportHeight = window.innerHeight;
            const outside = rect.left < 0 || rect.top < 0 ||
                rect.right > viewportWidth || rect.bottom > viewportHeight;
            if (!outside) return false;

            const canFitHorizontally = rect.width <= viewportWidth - viewportSafetyGap * 2;
            const canFitVertically = rect.height <= viewportHeight - viewportSafetyGap * 2;
            const rightLeft = canFitHorizontally
                ? viewportWidth - rect.width - viewportSafetyGap
                : viewportSafetyGap;
            const bottomTop = canFitVertically
                ? viewportHeight - rect.height - viewportSafetyGap
                : viewportSafetyGap;

            const horizontalCandidates = [
                { left: viewportSafetyGap, isLeft: true },
                { left: rightLeft, isLeft: canFitHorizontally ? false : true }
            ];
            const verticalCandidates = [
                { top: viewportSafetyGap, isTop: true },
                { top: bottomTop, isTop: canFitVertically ? false : true }
            ];

            let best = null;
            let bestDistance = Infinity;
            for (const horizontal of horizontalCandidates) {
                for (const vertical of verticalCandidates) {
                    const dx = rect.left - horizontal.left;
                    const dy = rect.top - vertical.top;
                    const distance = dx * dx + dy * dy;
                    if (distance < bestDistance) {
                        bestDistance = distance;
                        best = { ...horizontal, ...vertical };
                    }
                }
            }

            main._isLeft = best.isLeft;
            main._isTop = best.isTop;
            main.style.left = best.left + 'px';
            main.style.top = best.top + 'px';
            main.style.right = 'auto';
            main.style.bottom = 'auto';
            main._offsetX = viewportSafetyGap;
            main._offsetY = viewportSafetyGap;
            return true;
        }
        // ========================================================

        // ===== ЛОГИКА ПЕРЕТАСКИВАНИЯ ОКНА =====
        const savedLeftPct = localStorage.getItem('pm_window_left_pct');
        const savedTopPct = localStorage.getItem('pm_window_top_pct');
        const savedAnchorX = localStorage.getItem('pm_window_anchor_x');
        const savedAnchorY = localStorage.getItem('pm_window_anchor_y');
        const savedOffsetX = parseFloat(localStorage.getItem('pm_window_offset_x_px'));
        const savedOffsetY = parseFloat(localStorage.getItem('pm_window_offset_y_px'));
        const hasPixelPosition =
            (savedAnchorX === 'left' || savedAnchorX === 'right') &&
            (savedAnchorY === 'top' || savedAnchorY === 'bottom') &&
            Number.isFinite(savedOffsetX) && Number.isFinite(savedOffsetY);

        if (hasPixelPosition) {
            main._isLeft = savedAnchorX === 'left';
            main._isTop = savedAnchorY === 'top';
            main._offsetX = savedOffsetX;
            main._offsetY = savedOffsetY;
            main.style.left = (main._isLeft
                ? savedOffsetX
                : window.innerWidth - savedOffsetX - main.offsetWidth) + 'px';
            main.style.top = (main._isTop
                ? savedOffsetY
                : window.innerHeight - savedOffsetY - main.offsetHeight) + 'px';
        } else if (savedLeftPct !== null && savedTopPct !== null) {
            // Миграция координат из старого процентного формата.
            main.style.left = (parseFloat(savedLeftPct) / 100 * window.innerWidth) + 'px';
            main.style.top = (parseFloat(savedTopPct) / 100 * window.innerHeight) + 'px';
            const initialRect = main.getBoundingClientRect();
            main._isLeft = initialRect.left < (window.innerWidth / 2);
            main._isTop = initialRect.top < (window.innerHeight / 2);
            saveWindowPosition(initialRect);
        } else {
            main.style.left = (window.innerWidth - 100) + 'px';
            main.style.top = (window.innerHeight - 50) + 'px';
            const initialRect = main.getBoundingClientRect();
            main._isLeft = initialRect.left < (window.innerWidth / 2);
            main._isTop = initialRect.top < (window.innerHeight / 2);
            saveWindowPosition(initialRect);
        }

        // Сохраняем размер viewport для обработки его изменения.
        main._lastViewportWidth = window.innerWidth;
        main._lastViewportHeight = window.innerHeight;
        if (snapToNearestCornerIfOutside()) saveWindowPosition();

        let isDragging = false;
        let dragStartX, dragStartY, startLeft, startTop;
        let isMouseDown = false;

        main.addEventListener('mousedown', (e) => {
            if (main.classList.contains('pm-open') && !e.target.closest('#pm-header')) return;
            if (e.target.closest('#pm-menu-btn') || e.target.closest('.pm-chk-label')) return;

            isResizing = false;
            e.preventDefault();
            isMouseDown = true;
            isDragging = false;

            const rect = main.getBoundingClientRect();
            startLeft = rect.left;
            startTop = rect.top;
            dragStartX = e.clientX;
            dragStartY = e.clientY;
        });

        document.addEventListener('mousemove', (e) => {
            if (!isMouseDown) return;
            const deltaX = e.clientX - dragStartX;
            const deltaY = e.clientY - dragStartY;
            if (!isDragging && (Math.abs(deltaX) > 3 || Math.abs(deltaY) > 3)) {
                isDragging = true;
                document.body.style.cursor = 'grabbing';
            }
            if (isDragging) {
                let newLeft = startLeft + deltaX;
                let newTop = startTop + deltaY;

                const rect = main.getBoundingClientRect();
                const gap = viewportSafetyGap;
                const minLeft = gap;
                const minTop = gap;
                const maxLeft = Math.max(minLeft, window.innerWidth - rect.width - gap);
                const maxTop = Math.max(minTop, window.innerHeight - rect.height - gap);

                if (newLeft < minLeft) newLeft = minLeft;
                if (newLeft > maxLeft) newLeft = maxLeft;
                if (newTop < minTop) newTop = minTop;
                if (newTop > maxTop) newTop = maxTop;

                main.style.left = newLeft + 'px';
                main.style.top = newTop + 'px';
            }
        });

        document.addEventListener('mouseup', () => {
            if (isMouseDown) {
                isMouseDown = false;
                document.body.style.cursor = '';
                if (isDragging) {
                    isDragging = false;
                    isResizing = false;
                    justFinishedResizing = true;
                    setTimeout(() => { justFinishedResizing = false; }, 100);

                    let rect = main.getBoundingClientRect();
                    // После перетаскивания выбираем угол по положению окна.
                    main._isLeft = rect.left < (window.innerWidth / 2);
                    main._isTop = rect.top < (window.innerHeight / 2);
                    if (snapToNearestCornerIfOutside()) {
                        rect = main.getBoundingClientRect();
                    }
                    saveWindowPosition(rect);
                }
            }
        });

        // Единый обработчик resize для свёрнутого и раскрытого окна.
        // Сохраняем привязку к краям, а при риске выхода за экран переносим панель
        // в ближайший угол. При необходимости временно уменьшаем список логов.
        window.addEventListener('resize', () => {
            const currentWidth = window.innerWidth;
            const currentHeight = window.innerHeight;
            const previousWidth = main._lastViewportWidth ?? currentWidth;
            const previousHeight = main._lastViewportHeight ?? currentHeight;

            fitExpandedPanelHeight();
            const rect = main.getBoundingClientRect();

            if (typeof main._isLeft !== 'boolean') {
                main._isLeft = rect.left < (currentWidth / 2);
            }
            if (typeof main._isTop !== 'boolean') {
                main._isTop = rect.top < (currentHeight / 2);
            }

            // Запасной расчёт нужен только если позиция ещё не была сохранена.
            const offsetX = Number.isFinite(main._offsetX)
                ? main._offsetX
                : (main._isLeft ? rect.left : previousWidth - rect.right);
            const offsetY = Number.isFinite(main._offsetY)
                ? main._offsetY
                : (main._isTop ? rect.top : previousHeight - rect.bottom);

            main.style.left = (main._isLeft
                ? offsetX
                : currentWidth - offsetX - rect.width) + 'px';
            main.style.top = (main._isTop
                ? offsetY
                : currentHeight - offsetY - rect.height) + 'px';
            main.style.right = 'auto';
            main.style.bottom = 'auto';

            snapToNearestCornerIfOutside();
            saveWindowPosition();
            main._lastViewportWidth = currentWidth;
            main._lastViewportHeight = currentHeight;
        });
        // ======================================================
        // ===== ВЫСЧИТЫВАЕМ ВЫСОТУ РОВНО ДЛЯ 3 СТРОК =====
        const tempEntry = document.createElement('div');
        // Применяем те же стили, что и у обычной строки лога
        tempEntry.style.cssText = 'border-bottom: 1px solid rgba(255,255,255,0.1); padding: 5px 0; color: #ffffff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-size: 10px;';
        tempEntry.innerHTML = 'test';
        main.appendChild(tempEntry);
        const singleLineHeight = tempEntry.offsetHeight; // Измеряем одну строку
        main.removeChild(tempEntry); // Удаляем
        const defaultHeight = singleLineHeight * 3; // Высота ровно для 3 строк
        currentLogHeight = defaultHeight; // Обновляем переменную (без повторного let)

        const logList = main.querySelector('#pm-log-list');
        // Сразу применяем эту высоту к списку логов
        logList.style.height = currentLogHeight + 'px';
        logList.style.maxHeight = currentLogHeight + 'px';
        const resizeHandle = main.querySelector('#pm-resize-handle');

        // ===== ОБРАБОТЧИКИ КЛИКОВ =====
        main.onclick = (e) => {
            if (justFinishedResizing) return;
            if (e.target.closest('#pm-content') || e.target.id === 'pm-resize-handle' || e.target.id === 'pm-resize-handle-bottom') return;

            const content = main.querySelector('#pm-content');
            const arrow = main.querySelector('#pm-arrow');
            const collapsed = main.querySelector('#pm-title-collapsed');
            const expanded = main.querySelector('#pm-title-expanded');
            const isOpen = content.style.display === 'block';

            // 1. Запоминаем координаты ДО изменения
            const rectBefore = main.getBoundingClientRect();

            if (!isOpen) {
                // РАЗВОРАЧИВАЕМ
                // Определяем квадрант ТОЛЬКО когда окно маленькое, и запоминаем его
                main._isLeft = rectBefore.left < (window.innerWidth / 2);
                main._isTop = rectBefore.top < (window.innerHeight / 2);

                content.style.display = 'block';
                arrow.style.transform = 'rotate(180deg)';
                collapsed.style.display = 'none';
                expanded.style.display = 'inline';
                main.classList.add('pm-open');

                if (logList) {
                    logList.style.height = currentLogHeight + 'px';
                    logList.style.maxHeight = currentLogHeight + 'px';
                    logList.scrollTop = 0;
                }
            } else {
                // СВОРАЧИВАЕМ
                content.style.display = 'none';
                arrow.style.transform = 'rotate(0deg)';
                collapsed.style.display = 'inline';
                expanded.style.display = 'none';
                main.classList.remove('pm-open');
                if (logList) {
                    logList.style.height = '';
                    logList.style.maxHeight = '';
                }
            }

            // Перед расчётом геометрии подгоняем список логов под доступную высоту.
            fitExpandedPanelHeight();

            // 2. Принудительно заставляем браузер пересчитать размеры
            main.offsetHeight;
            const rectAfter = main.getBoundingClientRect();

            // 3. Привязываем к нужному краю (используя СОХРАНЕННЫЙ квадрант)
            let newLeft = rectBefore.left;
            let newTop = rectBefore.top;

            // Если окно было в правой половине, фиксируем ПРАВЫЙ край
            if (main._isLeft === false) {
                newLeft = rectBefore.right - rectAfter.width;
            }
            // Если окно было в нижней половине, фиксируем НИЖНИЙ край
            if (main._isTop === false) {
                newTop = rectBefore.bottom - rectAfter.height;
            }

            // 4. Применяем новые координаты
            main.style.left = newLeft + 'px';
            main.style.top = newTop + 'px';
            main.style.right = 'auto';
            main.style.bottom = 'auto';

            // Если после разворачивания/сворачивания панель вышла за экран,
            // переносим её в ближайший угол и сохраняем уже безопасную позицию.
            snapToNearestCornerIfOutside();
            saveWindowPosition();
        };
        main.querySelector('#pm-menu-save').onclick = (e) => {
            e.stopPropagation();
            main.querySelector('#pm-menu-dropdown').style.display = 'none'; // Закрываем меню после клика

            const now = new Date();
            const pad = (n) => String(n).padStart(2, '0');
            const dateStr = `${pad(now.getDate())}.${pad(now.getMonth() + 1)}.${now.getFullYear()} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
            const safeDateStr = `${pad(now.getDate())}.${pad(now.getMonth() + 1)}.${now.getFullYear()} ${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds())}`;

            const header = `MAX Blinder v2.02\n— Журнал блокировок ${dateStr} —\n\n` + fullLogHistory.join('\n');
            const filename = `MAX Blinder v2.02 — Журнал блокировок ${safeDateStr}.txt`;

            const blob = new Blob([header], { type: 'text/plain;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.id = 'pm-download-temp';
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();

            setTimeout(() => {
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
            }, 100);
        };

        main.querySelector('#pm-menu-clear').onclick = (e) => {
            e.stopPropagation();
            main.querySelector('#pm-menu-dropdown').style.display = 'none'; // Закрываем меню после клика
            blockedCount = 0;
            fullLogHistory = [];
            pendingLogs = [];
            main.querySelector('#pm-counter').innerText = '0';
            main.querySelector('#pm-counter-expanded').innerText = '0';
            main.querySelector('#pm-log-list').innerHTML = '';

        };
        // ===== ЛОГИКА ВЫПАДАЮЩЕГО МЕНЮ (ШАГ 4.3) =====
        const menuBtn = main.querySelector('#pm-menu-btn');
        const menuDropdown = main.querySelector('#pm-menu-dropdown');

        menuBtn.addEventListener('click', (e) => {
            e.stopPropagation(); // Чтобы клик не сворачивал всё окно
            const isHidden = menuDropdown.style.display === 'none' || !menuDropdown.style.display;
            menuDropdown.style.display = isHidden ? 'block' : 'none';
        });

        // Закрываем меню при клике в любом другом месте
        document.addEventListener('click', (e) => {
            if (menuDropdown.style.display === 'block') {
                const path = e.composedPath ? e.composedPath() : [];
                if (!path.includes(menuDropdown) && !path.includes(menuBtn)) {
                    menuDropdown.style.display = 'none';
                }
            }
        });
        // =====================================

        // ===== ЛОГИКА ИЗМЕНЕНИЯ РАЗМЕРА ОКНА =====
        const resizeHandleBottom = main.querySelector('#pm-resize-handle-bottom');
        // Обработчик для ВЕРХНЕЙ ручки (тянем вверх)
        resizeHandle.addEventListener('mousedown', (e) => {
            e.preventDefault();
            e.stopPropagation();
            isResizing = 'top'; // Запоминаем, какую ручку тянут
            startY = e.clientY;
            startHeight = logList.offsetHeight;
            startMainTop = main.getBoundingClientRect().top;
            logList.style.maxHeight = startHeight + 'px';
            logList.style.height = startHeight + 'px';
            document.body.style.cursor = 'ns-resize';
        });

        // Обработчик для НИЖНЕЙ ручки (тянем вниз)
        if (resizeHandleBottom) {
            resizeHandleBottom.addEventListener('mousedown', (e) => {
                e.preventDefault();
                e.stopPropagation();
                isResizing = 'bottom';
                startY = e.clientY;
                startHeight = logList.offsetHeight;
                logList.style.maxHeight = startHeight + 'px';
                logList.style.height = startHeight + 'px';
                document.body.style.cursor = 'ns-resize';
            });
        }

        document.addEventListener('mousemove', (e) => {
            if (!isResizing || isMouseDown) return;
            if (e.buttons === 0) {
                isResizing = false;
                document.body.style.cursor = '';
                justFinishedResizing = true;
                setTimeout(() => { justFinishedResizing = false; }, 100);
                currentLogHeight = logList.offsetHeight;
                saveWindowPosition();
                return;
            }

            const deltaY = startY - e.clientY;
            let newHeight = startHeight;

            if (isResizing === 'top') {
                // Верхняя ручка: движение вверх увеличивает высоту
                newHeight = startHeight + deltaY;
            } else if (isResizing === 'bottom') {
                // Нижняя ручка: движение вниз увеличивает высоту
                newHeight = startHeight - deltaY;
            }
            const minHeight = defaultHeight;
            const extraHeight = main.offsetHeight - logList.offsetHeight;
            // Сохраняем минимальный отступ от нижнего края viewport.
            const maxTotalHeight = window.innerHeight - viewportSafetyGap;
            let maxHeight = maxTotalHeight - extraHeight;
            if (maxHeight < minHeight) maxHeight = minHeight;

            // При растягивании сверху нижний край остаётся на месте.
            // Не позволяем верхнему краю уйти выше начала окна браузера.
            if (isResizing === 'top') {
                const maxHeightFromTop = startHeight + startMainTop - viewportSafetyGap;
                if (maxHeight > maxHeightFromTop) maxHeight = maxHeightFromTop;
            } else if (isResizing === 'bottom') {
                // При растягивании снизу верхний край остаётся на месте.
                // Сохраняем viewportSafetyGap между панелью и нижним краем viewport.
                const currentTop = main.getBoundingClientRect().top;
                const maxHeightFromBottom = Math.max(
                    0,
                    window.innerHeight - viewportSafetyGap - currentTop - extraHeight
                );
                if (maxHeight > maxHeightFromBottom) maxHeight = maxHeightFromBottom;
            }

            if (newHeight < minHeight) newHeight = minHeight;
            if (newHeight > maxHeight) newHeight = maxHeight;

            if (isResizing === 'top') {
                main.style.top = (startMainTop + startHeight - newHeight) + 'px';
            }
            logList.style.maxHeight = newHeight + 'px';
            logList.style.height = newHeight + 'px';
        });

        document.addEventListener('mouseup', () => {
            if (isResizing) {
                isResizing = false;
                document.body.style.cursor = '';
                justFinishedResizing = true;
                setTimeout(() => { justFinishedResizing = false; }, 100);
                currentLogHeight = logList.offsetHeight;
                fitExpandedPanelHeight();
                snapToNearestCornerIfOutside();
                saveWindowPosition();
            }
        });
        // ===== ОБРАБОТЧИК ЧЕКБОКСА "БЕЗ ЗВУКА" =====
        const chkMute = main.querySelector('#pm-chk-mute');
        if (chkMute) {
            // Восстанавливаем состояние из памяти при загрузке
            chkMute.checked = (CONFIG.MUTE_SOUNDS === true);
            chkMute.addEventListener('change', (e) => {
                CONFIG.MUTE_SOUNDS = e.target.checked;
                try {
                    // Сохраняем СТРОГО как строку
                    localStorage.setItem('pm_mute_sounds', e.target.checked ? 'true' : 'false');
                } catch(err) {
                    console.warn('Не удалось сохранить настройку звука', err);
                }
                // Перезагружаем страницу, чтобы применить настройку
                location.reload();
            });
        }
        // =================================================================

        // Сворачивание окна при клике вне его
        document.addEventListener('click', (e) => {

            if (isResizing || justFinishedResizing) return;

            const content = main.querySelector('#pm-content');
            if (content.style.display !== 'block') return;

            const path = e.composedPath ? e.composedPath() : [];
            if (path.includes(host) || path.some(el => el && el.id === 'pm-download-temp')) return;

            // Запоминаем геометрию раскрытого окна, чтобы после сворачивания
            // закрепить мини-виджет за тем же углом.
            const rectBefore = main.getBoundingClientRect();
            content.style.display = 'none';

            const arrow = main.querySelector('#pm-arrow');
            if (arrow) arrow.style.transform = 'rotate(0deg)';

            const collapsed = main.querySelector('#pm-title-collapsed');
            const expanded = main.querySelector('#pm-title-expanded');
            if (collapsed) collapsed.style.display = 'inline';
            if (expanded) expanded.style.display = 'none';

            main.classList.remove('pm-open');
            if (logList) {
                logList.style.height = '';
                logList.style.maxHeight = '';
            }

            // Пересчитываем размер и привязываем мини-виджет к тому же углу.
            main.offsetHeight;
            const rectAfter = main.getBoundingClientRect();
            let newLeft = rectBefore.left;
            let newTop = rectBefore.top;
            if (main._isLeft === false) newLeft = rectBefore.right - rectAfter.width;
            if (main._isTop === false) newTop = rectBefore.bottom - rectAfter.height;
            main.style.left = newLeft + 'px';
            main.style.top = newTop + 'px';
            main.style.right = 'auto';
            main.style.bottom = 'auto';
            snapToNearestCornerIfOutside();
            saveWindowPosition();
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
