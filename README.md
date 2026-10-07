# 🪬 MAX Blinder

[![Version](https://img.shields.io/badge/version-2.01-blue.svg)](https://github.com/EchoForge91/MAX_Blinder/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Greasy Fork](https://img.shields.io/badge/Greasy%20Fork-570049-green.svg)](https://greasyfork.org/ru/scripts/570049)

Userscript для ограничения телеметрии web-версии мессенджера MAX.

**[📥 Установить скрипт](https://github.com/EchoForge91/MAX_Blinder/raw/main/MAX_Blinder.user.js)** · 

---

Мессенджер MAX периодически собирает и отправляет телеметрию о вашей активности, устройстве и сети. Скрипт пресекает эти попытки сбора данных и отслеживания, наглядно показывая количество блокировок.

> ⚠️ **Важно понимать:** мессенджер MAX не использует сквозное шифрование — содержание сообщений может быть по-прежнему доступно третьим лицам.
> Скрипт не шифрует переписку, но именно использование web-версии мессенджера (в отличие от десктопной и мобильной) позволяет ему работать максимально эффективно: блокировать телеметрию, фингерпринт и другие методы отслеживания активности в браузере. Мессенджер постоянно обновляется — но вместе с тем появляются новые независимые исследования его телеметрии. Эти данные ложатся в основу обновлений скрипта.

## ✨ Возможности скрипта

- Блокировка трекеров (Apptracer, Vigo, Logalyzer и др.).
- Блокировка Firebase (Installations, Analytics, Crashlytics), Google Tag Manager, Google Identity Toolkit.
- Блокировка проверки доступности сторонних сайтов (Telegram, WhatsApp, Госуслуги, Google, OK.ru, Yandex, Huawei Push) — одна из защит от определения VPN.
- Блокировка регистрации Service Worker и удаление существующих.
- Перехват телеметрийных Worker и SharedWorker — они заменяются на пустые заглушки, чтобы сайт не падал.
- Защита от сбора технических данных об устройстве и браузере.
- Снижение риска утечки IP через WebRTC и блокировка сервисов его определения.
- Подмена параметров фингерпринта (Canvas, Audio, WebGL, Client Rects, measureText, шрифты, батарея, User-Agent Client Hints).
- Детерминированный генератор шума (Mulberry32) — отпечаток стабилен в рамках сессии и не выдаёт себя нестабильностью.
- Маскировка типа соединения (type = wifi, effectiveType = 4g, downlinkMax = 100, saveData = false) — скрывает мобильную сеть и оператора.
- Фильтрация WebSocket (блокировка телеметрического opcode 5 и события HOST_REACHABILITY по любому opcode).
- Мониторинг чтения буфера обмена и проверок разрешений (`navigator.permissions.query`).
- Устойчивость к cross-origin (try/catch в iframe и popup) — скрипт не падает на сторонних фреймах.
- Интерфейс с живым отображением блокировок и понятными названиями сервисов.

## 🚫 Скрипт не может скрывать

- IP-адрес (для сокрытия трафика используйте сторонние инструменты).
- Сетевые характеристики (TLS fingerprint, HTTP/2).
- Данные, доступные серверу напрямую.
- Не шифрует сообщения.

## 🛠 Как использовать

1. Установите расширение [Tampermonkey](https://www.tampermonkey.net/).
2. Установите данный скрипт (ссылка в шапке README).
3. В правом нижнем углу появится компактный индикатор 🪬 BLINDER.
4. Нажмите на него, чтобы развернуть лог заблокированных запросов.
5. Кнопка **Copy log** позволит скопировать историю блокировок (с датой и версией скрипта) для анализа.

## 📱 Регистрация в MAX без смартфона

Если вы используете мессенджер MAX впервые и не хотите устанавливать его на смартфон для регистрации:

1. Установите эмулятор Android на ПК.
2. Скачайте и установите в эмуляторе APK-версию мессенджера MAX.
3. Зарегистрируйтесь в эмулированной версии мессенджера, получив код на своём смартфоне.
4. Запустите web-версию MAX в браузере с установленным скриптом 🪬 MAX Blinder.
5. Запустите сканер QR-кода в эмулированной версии и отсканируйте его в браузере.
6. После регистрации эмулятор больше не нужен.

<details>
<summary><strong>📖 ПОДРОБНОЕ ОПИСАНИЕ ФУНКЦИЙ И ЛОГОВ (развернуть) ▼</strong></summary>

<br>

- **Перехват и блокировка сетевых запросов** – скрипт перехватывает fetch, XMLHttpRequest, Beacon API и WebSocket, блокируя отправку данных на трекеры (Apptracer, Vigo, Logalyzer и др.).
- **Анализ тела POST-запросов** – проверка содержимого fetch и XHR на телеметрические ключевые слова (`events`, `host_reachability`, `telemetry`, `metrics`, `analytics`, `crash`, `perf`, `permission`, `permission_status`, `ptype`, `pstatus`). Поддерживаются string, URLSearchParams, FormData, Blob, ArrayBuffer.
- **Точный чёрный список** – разделён на домены (`BLOCK_DOMAINS`) и пути (`BLOCK_PATHS`). Это устраняет ложные срабатывания коротких подстрок вроде `crash`, `metrics`, `analytics`, которые раньше могли случайно заблокировать легитимные запросы мессенджера.
- **Блокировка Firebase и Google-инфраструктуры** – запросы к `firebaseinstallations.googleapis.com`, `firebase-settings.crashlytics.com`, `app-measurement.com`, `firebase.googleapis.com`, `googletagmanager.com`, `googleapis.com/identitytoolkit`, `crashlytics.com`.
- **Блокировка API MAX** – запросы к `api.oneme.ru`, куда уходит событие HOST_REACHABILITY.
- **Фильтрация WebSocket** – блокировка пакетов с opcode 5 (событие GET_HOST_REACHABILITY) и любых пакетов с событием HOST_REACHABILITY **по любому opcode**. Список опкодов намеренно сужен до `[5]` — остальные (2, 22, 31, 103, 161) оказались функциональными или неизвестными, их блокировка ломала конфиг, звонки и жалобы.
- **Блокировка Service Worker** – удаление существующих и запрет новых регистраций SW, чтобы исключить перехват запросов в обход fetch/XHR.
- **Перехват Worker и SharedWorker** – телеметрийные воркеры (`telemetry`, `analytics`, `metrics`, `apptracer`, `vigo`, `oneme`, `firebase`, `crashlytics`, `gtm`, `googletagmanager`) заменяются на пустую заглушку через Blob. Сайт не падает, но данные не уходят.
- **Защита от iframe-обхода** – перехват создания iframe и новых окон, блокировка попыток отправки телеметрии через изолированные контексты. Устойчиво к cross-origin (try/catch).
- **Canvas Fingerprinting** – детерминированный микро-шум в getImageData (по всем байтам, а не только первому). Шум кэшируется через WeakMap: один холст — один отпечаток.
- **Audio Fingerprinting** – подмена AudioBuffer.getChannelData с усиленным микро-шумом (amplitude 0.00005) и защита OfflineAudioContext. Seed привязан к длине буфера и каналу, шум кэшируется.
- **Client Rects** – микро-шум в getBoundingClientRect и getClientRects (±0.0001). Сохранена согласованность: `x + width = right`, `y + height = bottom`.
- **measureText** – вынесен в отдельную опцию `PROTECT_MEASURETEXT`. Шум детерминированный (по хэшу текста), подменяются width, actualBoundingBoxLeft/Right/Ascent/Descent, fontBoundingBoxAscent/Descent.
- **WebRTC Hardening** – перехват addIceCandidate и принудительный relay-режим (`iceTransportPolicy: 'relay'`). Опция `WEBRTC_STRICT` (по умолчанию false) сохраняет iceServers — это позволяет звонкам работать даже в строгих сетях (CGNAT, корпоративный firewall). При `WEBRTC_STRICT: true` iceServers очищаются для максимальной защиты от IP-утечек.
- **Детерминированный PRNG (Mulberry32)** – общий для Canvas, Audio, Client Rects и measureText. Seed хранится в sessionStorage (или задаётся числом через `FINGERPRINT_SEED`). Раньше случайный шум при каждом вызове сам становился отпечатком из-за нестабильности — теперь отпечаток стабилен в рамках сессии.
- **Тайминги** – `performance.now()` получает статический offset на сессию (дельта монотонна, не детектируется). Шум из `Date.now()` убран, чтобы не ломать таймеры мессенджера (heartbeat, expiration, синхронизация).
- **Подмена аппаратных характеристик** – hardwareConcurrency (8 ядер), deviceMemory (8 ГБ).
- **Сокрытие типа соединения** – подмена `navigator.connection`: type = wifi, effectiveType = 4g, downlink = 10, downlinkMax = 100, rtt = 50, saveData = false, onchange = null. Скрывает мобильную сеть и код оператора.
- **Подмена шрифтов** – `document.fonts.query` возвращает стандартный набор шрифтов.
- **Подмена Battery API** – `navigator.getBattery` всегда возвращает 100% заряда.
- **Подмена плагинов** – `navigator.plugins` и `navigator.mimeTypes` заменяются на стандартный набор.
- **Скрытие автоматизации** – удаление флага `navigator.webdriver`.
- **Маскировка нативных функций** – подмена toString перехваченных функций, чтобы они выглядели как нативный код.
- **Подмена User-Agent Client Hints (UACH)** – маскировка архитектуры, платформы и версии браузера.
- **Защита WebGL** – подмена Unmasked Vendor/Renderer, VENDOR, RENDERER, VERSION, SHADING_LANGUAGE_VERSION, а также лимитов (MAX_TEXTURE_SIZE, MAX_RENDERBUFFER_SIZE, MAX_VIEWPORT_DIMS, MAX_VERTEX_ATTRIBS, MAX_*_UNIFORM_VECTORS и др.).
- **Защита от зондирования (Anti-Probing)** – блокировка запросов к `t.me`, `telegram.org`, `whatsapp.com`, `gosuslugi.ru`, `main.telegram.org`, `mmg.whatsapp.net`, `gstatic.com`, `calls.okcdn.ru`, `mtalk.google.com`, `ipv4-internet.yandex.net`, `ipv6-internet.yandex.net`, `pushtrs.push.hicloud.com`, `pushtrs1.push.hicloud.com`, `token-drcn.push.dbankcloud.com` (используются для определения VPN).
- **Расширенный чёрный список** – домены и IP телеметрии (`stats.max.ru`, `telemetry.max.ru`, `collect.max.ru`, `log-api.max.ru`, `error-report.max.ru`, `notify-stat.max.ru`, `vk.com/rkn`, `sphere.avantelecom.ru`, `trace-flow.ru`, `appsflyer.com`, `api.oneme.ru`, Firebase Installations, Crashlytics, Google Tag Manager, а также IP `155.212.204.143`, `155.212.204.78`, `155.212.204.193`, `95.161.225.253`).
- **Мониторинг разрешений и буфера** – логирование `navigator.permissions.query` (запросы доступа к камере, микрофону, геолокации, уведомлениям, буферу) и `navigator.clipboard.readText` / `.read`. Мониторинг не увеличивает счётчик блокировок.
- **Понятные логи** – технические теги и домены переводятся в понятные фразы («Сбор крашей», «Проверка Telegram», «Заблокирована аналитика»). В логе разделены: интерфейсная строка (без URL) и полная строка (с URL) — для Copy log.
- **Защита от утечки через Copy log** – из логов убран query string (в нём могут быть токены). В шапку копируемого лога добавляются версия скрипта и дата.
- **Ограничение истории** – `MAX_LOG_HISTORY = 5000` записей. Кэш дедупликации чистится каждые 10 секунд. Скрипт не течёт по памяти при долгой работе.

#### Расшифровка записей в логе

| Тип | Описание | Когда возникает |
| :--- | :--- | :--- |
| **Запрос (FETCH)** | Блокировка обычного fetch-запроса | Запрос к домену из чёрного списка |
| **Запрос (XHR)** | Блокировка XMLHttpRequest | Запрос к домену из чёрного списка |
| **Телеметрия (POST-TELE)** | Блокировка POST-запроса с телеметрией | Запрос содержит в теле ключевые слова: `events`, `host_reachability`, `telemetry`, `metrics`, `analytics`, `crash`, `perf`, `permission`, `permission_status`, `ptype`, `pstatus` |
| **Скрытая передача (WS-TELE)** | Блокировка WebSocket-сообщения | Сообщение содержит opcode 5 (GET_HOST_REACHABILITY) или событие HOST_REACHABILITY по любому opcode |
| **Маячок (BEACON)** | Блокировка Beacon API | Отправка данных через `navigator.sendBeacon` к домену из чёрного списка |
| **Проверка сети (PROBE)** | Блокировка «зондирования» (проверка доступности сторонних сайтов) | Запрос к `t.me`, `telegram.org`, `whatsapp.com`, `gosuslugi.ru`, `yandex.net`, `hicloud.com`, `dbankcloud.com`, `mtalk.google.com`, `calls.okcdn.ru` и др. (используется для определения VPN) |
| **Фоновый перехватчик (SW)** | Блокировка или удаление Service Worker | Попытка регистрации SW или очистка существующих при старте |
| **Скрытый поток (WORKER)** | Блокировка телеметрийного Worker / SharedWorker | Создание воркера с подозрительным именем скрипта |
| **Проверка разрешений (PERMISSION)** | Логирование проверки разрешений | Вызов `navigator.permissions.query` (камера, микрофон, геолокация, уведомления, буфер). Счётчик блокировок не растёт |
| **Доступ к буферу (CLIPBOARD)** | Логирование чтения буфера обмена | Вызов `navigator.clipboard.readText` / `.read`. Счётчик блокировок не растёт |
| **Запрос из вставки (FETCH/XHR iframe)** | Блокировка fetch/XHR в iframe | Запрос из iframe к домену из чёрного списка |
| **Запрос из окна (FETCH popup)** | Блокировка fetch в новом окне | Запрос из всплывающего окна к домену из чёрного списка |

</details>

---

## 📜 Лицензия

MIT — используйте, модифицируйте, распространяйте свободно.

---

*Этот скрипт предоставляется «как есть». Автор не несёт ответственности за возможные ограничения аккаунта со стороны платформы. Используйте для защиты личных данных и повышения анонимности.*
