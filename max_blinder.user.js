// ==UserScript==
// @name         MAX Blinder
// @namespace    http://tampermonkey.net/
// @version      1.92
// @description  Ограничение телеметрии мессенджера MAX
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
        BLOCK_FETCH_XHR: true,
        BLOCK_WEBSOCKET_OPCODE5: true,
        BLOCK_WEBRTC: true,
        BLOCK_BEACON: true,
        BLOCK_SERVICE_WORKER: true,
        CLEAR_SERVICE_WORKERS: true,
        PROTECT_CANVAS: true,
        PROTECT_CANVAS_TO_DATA_URL: true,
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
        TELEMETRY_KEYWORDS: ['events', 'host_reachability', 'telemetry', 'metrics', 'analytics', 'crash', 'perf'],
        // НОВЫЕ ОПЦИИ
        FAKE_USER_AGENT_DATA: true,
        PROTECT_WEBGL: true,
        BLOCK_CACHE_STORAGE: false,
        MOUSE_NOISE: false,
        BLOCK_PROBING: true,
        BLOCKED_OPCODES: [2, 5, 22, 31, 103, 161],
        AUDIO_NOISE_AMPLITUDE: 0.00005,      // увеличено с 0.000005
        PROTECT_OFFLINE_AUDIO: true,         // защита OfflineAudioContext
        BLOCK_FIREBASE: true,                // блокировка Firebase Installations / Analytics
        BLOCK_GOOGLE_APIS: true,             // блокировка gstatic.com, firebaseinstallations.googleapis.com
        HIDE_NETWORK_TYPE_DETAILS: true,     // маскировка типа сети и кода оператора
        BLOCK_VPN_DETECTION: true            // маскировка флага VPN в HOST_REACHABILITY
    };

    // ========================== ПЕРЕМЕННЫЕ ==========================
    let blockedCount = 0;
    let fullLogHistory = [];
    const maxLogs = 20;
    let pendingLogs = [];
    let uiShadow = null;

    // Защита от дублирования записей
    let lastRecorded = new Map();
    const DEDUP_MS = 500;

    // ========================== ЧЁРНЫЙ СПИСОК (расширен) ==========================
    const blackList = [
        // IP-определители и трекеры
        'api.ipify.org', 'ifconfig.me', 'ident.me', 'checkip.amazonaws.com',
        'ip.mail.ru', '2ip.ru', 'ipinfo.io', 'ip-api.com', 'myexternalip.com',
        'icanhazip.com', 'jsonip.com', 'httpbin.org/ip', 'wtfismyip.com',
        'apptracer.ru', 'sdk-api', 'crash', 'metrics', 'telemetry', 'analytics',
        'vigo', 'collector', 'log-api', 'error_report', 'notify-stat', 'event/send',
        'tracker-api.vk-analytics.ru', 'my.tracker', 'data.mail.ru', 'fb.do',
        'doubleclick.net', 'google-analytics.com', 'top-fwz1.mail.ru', 'counter.yadro.ru',
        'stats.max.ru', 'telemetry.max.ru', 'collect.max.ru', 'vk.com', 'ifconfig.co', 'yandex.net',
        'vk.com/rkn', 'sphere.avantelecom.ru', 'api.ipapi.is', 'iplocate.io', 'ip.sb', 'appsflyer.com',
        '155.212.204.143', '155.212.204.78', '155.212.204.193', '95.161.225.253', '127.0.0.1',
        'firebaseinstallations.googleapis.com',
        'firebase-settings.crashlytics.com',
        'app-measurement.com',
        'firebase.googleapis.com',
        'googleapis.com/identitytoolkit',
        'api.oneme.ru',
        'crashlytics.com',
        'googletagmanager.com'
    ];

    // Домены, проверка которых блокируется как «зондирование»
        const probingDomains = [
        't.me', 'telegram.org', 'whatsapp.com', 'gosuslugi.ru',
        'main.telegram.org',
        'mmg.whatsapp.net',
        'gstatic.com',
        'calls.okcdn.ru'
    ];

    // ========================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========================
    function shouldBlock(url) {
        if (!url || !CONFIG.BLOCK_FETCH_XHR) return false;
        const sUrl = String(url).toLowerCase();
        return blackList.some(bad => sUrl.includes(bad));
    }

    function shouldBlockProbing(url) {
        if (!CONFIG.BLOCK_PROBING) return false;
        const sUrl = String(url).toLowerCase();
        return probingDomains.some(domain => sUrl.includes(domain));
    }

    function hasTelemetryInPayload(body) {
        if (!CONFIG.INSPECT_POST_PAYLOAD || !body) return false;
        try {
            let data = body;
            if (typeof body === 'string') {
                data = JSON.parse(body);
            }
            const str = JSON.stringify(data).toLowerCase();
            return CONFIG.TELEMETRY_KEYWORDS.some(keyword => str.includes(keyword));
        } catch (e) {
            return false;
        }
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
        entry.innerHTML = `<span style="color: #67b3ff;">[${data.type}]</span> ${data.url}`;
        container.prepend(entry);
        if (container.childNodes.length > maxLogs) container.removeChild(container.lastChild);
    }

    function logBlock(type, url) {
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
        const entryData = {
            type: type,
            url: displayUrl,
            full: `[${time}] [${type}] ${url}`
        };
        fullLogHistory.push(entryData.full);

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
                if (param === 0x9245) return 'Google Inc. (NVIDIA)';
                if (param === 0x9246) return 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)';
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
                logBlock('CACHE', `blocked access to: ${name}`);
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
                Object.defineProperty(conn, 'rtt', { get: () => 50, configurable: true });
                Object.defineProperty(conn, 'saveData', { get: () => false, configurable: true });
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
            const url = typeof input === 'string' ? input : input.url;
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
    if (CONFIG.TIMING_NOISE) {
        const origPerfNow = performance.now;
        performance.now = function() {
            return origPerfNow.call(this) + (Math.random() * 0.1 - 0.05);
        };
        makeNative(performance, 'now');

        const origDateNow = Date.now;
        Date.now = function() {
            return origDateNow.call(this) + Math.floor(Math.random() * 2 - 1);
        };
        makeNative(Date, 'now');
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
                if (keysToClear.length) logBlock('STORAGE', `cleared ${keysToClear.length} items`);
            }
            if (window.indexedDB) {
                indexedDB.databases().then(dbs => {
                    dbs.forEach(db => {
                        if (db.name && CONFIG.TELEMETRY_KEYWORDS.some(k => db.name.toLowerCase().includes(k))) {
                            indexedDB.deleteDatabase(db.name);
                            logBlock('IDB', `deleted database: ${db.name}`);
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
                logBlock('SW', `unregistered: ${reg.scope}`);
            });
        }).catch(e => console.warn('SW cleanup failed', e));
    }

    // ========================== СЕТЕВЫЕ ПЕРЕХВАТЫ (основные) ==========================
    if (CONFIG.BLOCK_FETCH_XHR) {
        // fetch (уже переопределён выше для probing, но добавим блокировку по чёрному списку)
        const origFetch2 = window.fetch;
        window.fetch = function(input, init) {
            const url = typeof input === 'string' ? input : input.url;
            if (shouldBlock(url)) {
                logBlock('FETCH', url);
                return Promise.resolve(new Response('{"status":"ok"}', { status: 200 }));
            }
            if (CONFIG.BLOCK_PROBING && shouldBlockProbing(url)) {
                logBlock('PROBE', url);
                return Promise.reject(new TypeError('Network request failed (Blinder)'));
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
                        logBlock('WS-TELE', `opcode ${opcode} blocked`);
                        return;
                    }
                    // Дополнительная проверка на GET_HOST_REACHABILITY (для opcode 5)
                    if (opcode === 5 &&
                        msg.payload &&
                        msg.payload.events &&
                        Array.isArray(msg.payload.events) &&
                        msg.payload.events.some(e => e.event === 'GET_HOST_REACHABILITY')) {
                        logBlock('WS-TELE', 'GET_HOST_REACHABILITY blocked');
                        return;
                    }
                    // [1.9] Расширенная проверка HOST_REACHABILITY по любому opcode
                    if (msg.payload &&
                        msg.payload.events &&
                        Array.isArray(msg.payload.events) &&
                        msg.payload.events.some(e => e.event && e.event.includes('HOST_REACHABILITY'))) {
                        logBlock('WS-TELE', 'HOST_REACHABILITY (any opcode) blocked');
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
            CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {
                const imageData = orgGetImageData.call(this, x, y, w, h);
                const data = imageData.data;
                if (data.length > 0) {
                    data[0] = Math.min(255, Math.max(0, data[0] + (Math.random() > 0.5 ? 1 : -1)));
                }
                return imageData;
            };
        }

        if (CONFIG.PROTECT_CANVAS_TO_DATA_URL && CONFIG.PROTECT_CANVAS) {
            const orgToDataURL = HTMLCanvasElement.prototype.toDataURL;
            HTMLCanvasElement.prototype.toDataURL = function(type, quality) {
                const canvas = this;
                const ctx = canvas.getContext('2d');
                if (ctx && canvas.width > 0 && canvas.height > 0) {
                    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                    ctx.putImageData(imageData, 0, 0);
                }
                return orgToDataURL.call(this, type, quality);
            };
            makeNative(HTMLCanvasElement.prototype, 'toDataURL');
        }

        // Audio (увеличенная амплитуда шума)
        if (CONFIG.PROTECT_AUDIO && window.AudioContext) {
            const originalGetChannelData = AudioBuffer.prototype.getChannelData;
            AudioBuffer.prototype.getChannelData = function(channel) {
                const originalData = originalGetChannelData.call(this, channel);
                const noisyData = new Float32Array(originalData.length);
                const amp = CONFIG.AUDIO_NOISE_AMPLITUDE;
                for (let i = 0; i < originalData.length; i++) {
                    noisyData[i] = originalData[i] + (Math.random() * amp * 2 - amp);
                }
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
                            for (let i = 0; i < Math.min(100, data.length); i += 10) {
                                data[i] += (Math.random() - 0.5) * 0.0002;
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
                    config = { ...config, iceServers: [], iceTransportPolicy: 'relay' };
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
            const orgMeasureText = CanvasRenderingContext2D.prototype.measureText;
            CanvasRenderingContext2D.prototype.measureText = function(text) {
                const metrics = orgMeasureText.call(this, text);
                if (metrics.width) {
                    const originalWidth = metrics.width;
                    Object.defineProperty(metrics, 'width', {
                        get: () => originalWidth + (Math.random() * 0.1 - 0.05)
                    });
                }
                return metrics;
            };
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
        }

        if (CONFIG.BLOCK_SERVICE_WORKER && navigator.serviceWorker && navigator.serviceWorker.register) {
            const originalRegister = navigator.serviceWorker.register;
            navigator.serviceWorker.register = function(scriptURL, options) {
                logBlock('SW', `blocked: ${scriptURL}`);
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
            boxShadow: '0 8px 32px rgba(0,0,0,0.3)', pointerEvents: 'auto'
        });

        main.innerHTML = `
            <div id="pm-header" style="display: flex; justify-content: space-between; align-items: center; cursor: pointer;">
                <span id="pm-title-collapsed"><span id="pm-icon" style="display: inline-block;">🪬</span> <span id="pm-counter">${blockedCount}</span></span>
                <span id="pm-title-expanded" style="display: none;">🪬 MAX Blinder: <span id="pm-counter-expanded">${blockedCount}</span></span>
                <span id="pm-arrow" style="display: none;">▲</span>
            </div>
            <div id="pm-content" style="display: none; margin-top: 10px; border-top: 1px solid rgba(255,255,255,0.2); padding-top: 8px; width: 260px;">
                <div id="pm-log-list" style="max-height: 150px; overflow-y: auto; margin-bottom: 8px;"></div>
                <div style="display: flex; gap: 6px;">
                    <button id="pm-copy" style="flex: 1; background: rgba(50,50,70,0.4); color: #67b3ff; border: none; padding: 2px 4px; cursor: pointer; border-radius: 3px; font-size: 9px; height: 18px;">Copy log</button>
                    <button id="pm-clear" style="flex: 1; background: rgba(50,50,70,0.4); color: #67b3ff; border: none; padding: 2px 4px; cursor: pointer; border-radius: 3px; font-size: 9px; height: 18px;">Clear log</button>
                </div>
            </div>
        `;

        main.querySelector('#pm-header').onclick = () => {
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
            try {
                await navigator.clipboard.writeText(fullLogHistory.join('\n'));
                btn.innerText = 'Copied!';
                setTimeout(() => btn.innerText = originalText, 1000);
            } catch (err) {
                console.warn('Clipboard API failed, trying fallback...', err);
                try {
                    const textarea = document.createElement('textarea');
                    textarea.value = fullLogHistory.join('\n');
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
