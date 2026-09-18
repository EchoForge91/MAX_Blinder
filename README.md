# MAX Blinder

Ограничение телеметрии мессенджера MAX.

[![Установить через Greasy Fork](https://img.shields.io/badge/Установить-Greasy%20Fork-green?style=for-the-badge&logo=tampermonkey)](https://greasyfork.org/ru/scripts/570049-max-blinder)

---

Мессенджер MAX периодически собирает и отправляет телеметрию о вашей активности, устройстве и сети. Скрипт пресекает эти попытки сбора данных и отслеживания, наглядно показывая количество блокировок.

⚠️ **Важно понимать:** мессенджер MAX не использует сквозное шифрование. Это значит, что содержание сообщений может быть по-прежнему доступно третьим лицам.
Данный скрипт не шифрует сообщения, но он эффективно блокирует телеметрию, фингерпринт и другие методы отслеживания вашей активности в браузере.

---

## 🛡️ Скрипт содержит

- Блокировку трекеров (Apptracer, Vigo, Logalyzer и др.).
- Блокировку Firebase (Installations, Analytics, Crashlytics), Google Tag Manager, Google Identity Toolkit.
- Блокировку проверки доступности сторонних сайтов (Telegram, WhatsApp, Госуслуги, Google, OK.ru) – одна из защит от определения VPN.
- Блокировку регистрации Service Worker и удаление существующих.
- Защиту от сбора технических данных об устройстве и браузере.
- Снижение риска утечки IP через WebRTC и блокировку сервисов его определения.
- Подмену параметров фингерпринта (Canvas, Audio, шрифты, батарея, WebGL, User-Agent Client Hints).
- Маскировку типа соединения (type = wifi, effectiveType = 4g, saveData = false) — скрывает мобильную сеть и оператора.
- Расширенную фильтрацию WebSocket (блокировка телеметрических кодов: DEBUG, CONFIG, COMPLAIN, а также HOST_REACHABILITY по любому opcode).
- Устойчивость к cross-origin (try/catch в iframe и popup) — скрипт не падает на сторонних фреймах.
- Интерфейс с живым отображением блокировок.

---

## ⚠️ Скрипт не может скрывать

- IP-адрес.
- Сетевые характеристики (TLS fingerprint, HTTP/2).
- Данные, доступные серверу напрямую.
- Не шифрует сообщения.
- 
⚠️ **Для большей анонимности дополнительно используйте VPN.**

---

## 🚀 Как использовать

1. Установите расширение [Tampermonkey](https://www.tampermonkey.net/).
2. Установите данный скрипт.
3. В правом нижнем углу появится компактный индикатор 🪬 BLINDER.
4. Нажмите на него, чтобы развернуть лог заблокированных запросов.
5. Кнопка **Copy Log** позволит скопировать историю блокировок для анализа.

⚠️ **Каждый раз после перезагрузки компьютера и первого открытия браузера необходимо принудительно обновить страницу мессенджера для активации скрипта.**

---

## 📱 Если вы используете MAX впервые

Если вы используете мессенджер MAX впервые и не хотите устанавливать его на смартфон для регистрации:

1. Установите эмулятор Андроид на ПК.
2. Скачайте и установите в эмуляторе apk версию мессенджера MAX.
3. Зарегистрируйтесь в эмулированной версии мессенджера, получив код на своем смартфоне.
4. Запустите веб версию MAX в браузере с установленным скриптом MAX Blinder.
5. Запустите сканер Qr-кода в эмулированной версии и отсканируйте его в браузере. После регистрации эмулированная версия будет не нужна.

---

<details>
<summary><strong>🔍 ПОДРОБНОЕ ОПИСАНИЕ ФУНКЦИЙ И ЛОГОВ (развернуть)▼</strong></summary>

### Перехват и блокировка сетевых запросов

Скрипт перехватывает `fetch`, `XMLHttpRequest`, `Beacon API` и `WebSocket`, блокируя отправку данных на трекеры (Apptracer, Vigo, Logalyzer и др.).

### Анализ тела POST-запросов

Проверка содержимого на наличие телеметрических ключевых слов (`events`, `host_reachability`, `telemetry`, `metrics`, `crash`, `perf`).

### Блокировка Firebase и Google-инфраструктуры

Запросы к `firebaseinstallations.googleapis.com`, `firebase-settings.crashlytics.com`, `app-measurement.com`, `firebase.googleapis.com`, `googletagmanager.com`, `googleapis.com/identitytoolkit`, `crashlytics.com`.

### Блокировка API MAX

Запросы к `api.oneme.ru`, куда уходит событие `HOST_REACHABILITY`.

### Фильтрация WebSocket

Блокировка пакетов с opcode 5 (событие `GET_HOST_REACHABILITY`), любых пакетов с событием `HOST_REACHABILITY` по любому opcode, а также дополнительных кодов телеметрии: `2 (DEBUG)`, `22 (CONFIG)`, `31 (SEARCH_FEEDBACK)`, `103 (GET_INBOUND_CALLS)`, `161 (COMPLAIN)`.

### Блокировка Service Worker

Удаление существующих и запрет новых регистраций SW, чтобы исключить перехват запросов в обход fetch/XHR.

### Защита от iframe-обхода

Перехват создания iframe и новых окон, блокировка попыток отправки телеметрии через изолированные контексты. Устойчиво к cross-origin (try/catch).

### Canvas Fingerprinting

Микро-шум в `getImageData` и `toDataURL`. Отпечаток холста уникален для каждой сессии.

### Audio Fingerprinting

Подмена `AudioBuffer.getChannelData` с добавлением усиленного микро-шума, а также защита `OfflineAudioContext` для предотвращения глубокого фингерпринтинга.

### WebRTC Hardening

Очистка ICE-серверов, принудительный relay-режим и перехват `addIceCandidate` для предотвращения утечки IP.

### Подмена аппаратных характеристик

`hardwareConcurrency` (8 ядер), `deviceMemory` (8 ГБ).

### Сокрытие типа соединения

Подмена `navigator.connection`: `type = wifi`, `effectiveType = 4g`, `downlink = 10`, `rtt = 50`, `saveData = false`. Скрывает мобильную сеть и код оператора.

### Шум в таймингах

Микро-рандомизация `performance.now` и `Date.now` (±0.05 мс, ±1 мс).

### Подмена шрифтов

`document.fonts.query` возвращает стандартный набор шрифтов.

### Подмена Battery API

`navigator.getBattery` всегда возвращает 100% заряда.

### Подмена плагинов

`navigator.plugins` и `navigator.mimeTypes` заменяются на стандартный набор.

### Скрытие автоматизации

Удаление флага `navigator.webdriver`.

### Маскировка нативных функций

Подмена `toString` перехваченных функций, чтобы они выглядели как нативный код.

### Подмена User-Agent Client Hints (UACH)

Маскировка архитектуры, платформы и версии браузера.

### Защита WebGL

Подмена данных о видеокарте (Unmasked Vendor/Renderer).

### Защита от зондирования (Anti-Probing)

Блокировка запросов к `t.me`, `telegram.org`, `whatsapp.com`, `gosuslugi.ru`, `main.telegram.org`, `mmg.whatsapp.net`, `gstatic.com`, `calls.okcdn.ru`, `api.oneme.ru` (используются для определения VPN).

### Расширенный чёрный список

Домены и IP телеметрии: `stats.max.ru`, `telemetry.max.ru`, `collect.max.ru`, `vk.com/rkn`, `sphere.avantelecom.ru`, `appsflyer.com`, `api.oneme.ru`, Firebase Installations, Crashlytics, Google Tag Manager, а также IP `155.212.204.143`, `155.212.204.78`, `155.212.204.193`, `95.161.225.253`.

---

### 📖 Расшифровка записей в логе

| Тип | Описание | Когда возникает |
|-----|----------|-----------------|
| **FETCH** | Блокировка обычного fetch-запроса | Запрос к домену из чёрного списка |
| **XHR** | Блокировка XMLHttpRequest | Запрос к домену из чёрного списка |
| **POST-TELE** | Блокировка POST-запроса с телеметрией | Запрос содержит в теле ключевые слова: events, host_reachability, telemetry, metrics, analytics, crash, perf |
| **WS-TELE** | Блокировка WebSocket-сообщения | Сообщение содержит opcode: 5 (GET_HOST_REACHABILITY), событие HOST_REACHABILITY по любому opcode, или коды 2, 22, 31, 103, 161 |
| **BEACON** | Блокировка Beacon API | Отправка данных через navigator.sendBeacon к домену из чёрного списка |
| **FIREBASE** | Блокировка Firebase Installations / Analytics / Crashlytics | Запрос к firebaseinstallations.googleapis.com, app-measurement.com, firebase-settings.crashlytics.com, firebase.googleapis.com |
| **GOOGLE** | Блокировка Google APIs | Запрос к gstatic.com, googleapis.com, googletagmanager.com |
| **SW** | Блокировка или удаление Service Worker | Попытка регистрации SW или очистка существующих при старте |
| **FETCH (iframe)** | Блокировка fetch в iframe | Запрос из iframe к домену из чёрного списка |
| **XHR (iframe)** | Блокировка XHR в iframe | Запрос из iframe к домену из чёрного списка |
| **FETCH (popup)** | Блокировка fetch в новом окне | Запрос из всплывающего окна к домену из чёрного списка |
| **PROBE** | Блокировка «зондирования» (проверки доступности сторонних сайтов) | Запрос к t.me, telegram.org, whatsapp.com, gosuslugi.ru, main.telegram.org, mmg.whatsapp.net, gstatic.com, calls.okcdn.ru, api.oneme.ru (используется для определения VPN) |

</details>

---

## 📄 Лицензия

MIT

---

Этот скрипт предоставляется «как есть». Автор не несет ответственности за возможные ограничения аккаунта со стороны платформы. Используйте для защиты личных данных и повышения анонимности.
