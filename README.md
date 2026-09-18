# MAX Blinder

Ограничение телеметрии мессенджера MAX.

[![Установить через Greasy Fork](https://img.shields.io/badge/Установить-Greasy%20Fork-green?style=for-the-badge&logo=tampermonkey)](https://greasyfork.org/ru/scripts/570049-max-blinder)

---

## ⚠️ Требуется Tampermonkey

Для работы скрипта нужен менеджер пользовательских скриптов:
- **Chrome / Edge / Opera**: [Tampermonkey в Chrome Web Store](https://chromewebstore.google.com/detail/tampermonkey/dhdgffkkebhmkfjojejmpbldmpobfkfo)
- **Firefox**: [Tampermonkey в Firefox Add-ons](https://addons.mozilla.org/ru/firefox/addon/tampermonkey/)
- **Safari (macOS)**: [Tampermonkey в App Store](https://apps.apple.com/app/tampermonkey/id1482490089)

---

## 📦 Установка

**Способ 1 (рекомендуемый)** — через Greasy Fork:

👉 [Установить MAX Blinder](https://greasyfork.org/ru/scripts/570049-max-blinder)

Greasy Fork автоматически предложит установить скрипт в Tampermonkey.

**Способ 2** — напрямую с GitHub:

👉 [Скачать max_blinder.user.js](https://github.com/abrisdv-cloud/MAX_Blinder/raw/main/max_blinder.user.js)

При открытии этой ссылки Tampermonkey сам предложит установить скрипт.

---

## 🛡️ Что делает скрипт

- Блокировка трекеров (Apptracer, Vigo, Logalyzer и др.)
- Блокировка Firebase Installations / Analytics / Crashlytics
- Блокировка Google Tag Manager и Google Identity Toolkit
- Блокировка проверки доступности сторонних сайтов (Telegram, WhatsApp, Госуслуги, Google, OK.ru)
- Блокировка регистрации Service Worker и удаление существующих
- Защита от сбора технических данных об устройстве и браузере
- Снижение риска утечки IP через WebRTC
- Подмена параметров фингерпринта (Canvas, Audio, шрифты, батарея, WebGL, UACH)
- Расширенная фильтрация WebSocket (DEBUG, CONFIG, COMPLAIN, HOST_REACHABILITY)
- Интерфейс с живым отображением блокировок

---

## 📄 Лицензия

MIT
