# G15 Vulnerability Gate — Remediation Log
**Дата начала:** 2026-08-15 вечер · **Продолжение:** 2026-08-16 утро
**Архитектор:** Aelin AquaSoul · **Исполнитель:** Claude

## Контекст

G15 ("vulnerability gate", EXP-023 Binary Gate) вписан в `MASTER_GUARDIAN.sh`
(cron `5 0 * * *`, раз в сутки) — запускает `scan_own_domains.py` (пассивный
GET-only сканер EilatSecure) и жёстко ставит `OVERALL=CRITICAL` при любой
находке, без права модели продолжать (hard stop, семантика из EXP-023).

Первый ночной прогон (2026-08-16 00:05 IDT) нашёл реальные проблемы на
13 из 14 доменов. План: чинить группами по типу деплоя, каждую находку
проверять живьём (headers + headless-браузер на console-ошибки CSP),
не полагаться на "wrangler сказал Success".

## Инфраструктура сканера

- `/home/sipa/apps/eilatsecure/scan_own_domains.py` — читает 13 доменов
  (был 14, убрала `api.soulinpsyabstract.com` — не её домен, подтверждено
  оператором, NS на AWS Route53 не Cloudflare)
- **Найден и починен реальный баг** до первого прогона: `urlopen()` в Python
  молча следует за редиректом → проверка HTTP→HTTPS всегда видела финальный
  200 вместо самого 301, ложно репортила "нет редиректа" даже там где он
  реально работал. Добавлена `fetch_no_redirect()` (свой opener без
  auto-follow). Без этого фикса G15 бы каждый день кричал ложную тревогу.

## Готово

### critical (2/2 закрыто)
| Домен | Проблема | Фикс |
|---|---|---|
| `shell.sipa-os.org` | DNS-записи не было вообще (Worker route настроен, но без DNS не резолвился) | Добавлена placeholder `A 192.0.2.1 proxied=true` в Cloudflare — тот же паттерн что у `terminal.sipa-os.org` |
| `api.soulinpsyabstract.com` | Не её домен | Убрана из списка целей сканера |

### high (1/1 закрыто)
| Домен | Проблема | Фикс |
|---|---|---|
| `sipa-os.online` | Нет форс-HTTPS-редиректа | Найден live-код воркера `sipa-os-portal` через CF API (локальной копии не было вообще), добавлен редирект + все 6 security-заголовков. Сохранён локально: `/home/sipa/apps/sipa-os-portal/worker.js` |

### medium/low — группа 1: простые Workers (4/4 закрыто)
Паттерн: свой `worker.js`/`_headers`, легко добавить заголовки, проверено
headless-браузером на реальные CSP-ошибки в консоли (не только curl заголовков).

| Домен | Worker | Что нашли живым тестом |
|---|---|---|
| `deck.sipa-os.org` | `sipa-deck` (`_headers` файл, CF Pages assets) | Уже был частичный `_headers` от 13 августа — дополнила CSP+Permissions-Policy |
| `community.sipa-os.org` | `sipa-community` | CSP сломал 2 реальные вещи: Google Fonts, авто-инжектируемый Cloudflare Insights beacon — обе пойманы live, не угаданы |
| `app.soulinpsyabstract.store` | `soul-protocol-mind` (TanStack Start) | Пересобран `vite build`, задеплоен, 0 ошибок сразу |
| `games.sipa-os.org` | `sipa-games-app` | CSP сломал 3 вещи: ElevenLabs widget, CF Insights, Google Translate widget (несколько googleapis-поддоменов) — все пойманы и починены итеративно |

**Методология для каждого фикса:**
1. Найти реальный источник (локальный репо или live-код через CF API, если локального нет)
2. grep исходников/бандла на внешние origin'ы (scripts/fonts/iframe/connect)
3. Написать CSP на основе найденного, не угадывая
4. Задеплоить
5. Проверить заголовки curl'ом
6. Проверить headless-браузером (Playwright) на реальные console-ошибки CSP — это поймало то, что grep пропустил (CF Insights beacon и Google Fonts грузятся не из JS-бандла, а автоматически/из HTML)
7. Если есть ошибки — расширить CSP по конкретной ошибке, передеплоить, перепроверить
8. sha256 + TAG на изменённый файл

### Группа 2: SPA/TanStack-Workers (3/3 закрыто) ✅
Все три — TanStack Start приложения с `src/server.ts`/`worker.ts` (`run_worker_first: true`
в wrangler.jsonc), не простой worker.js. Grep бандла оказался ненадёжен даже
больше чем в группе 1 — реальный маркетинговый стек виден только живым тестом.

| Домен | Worker | Что нашли живым тестом |
|---|---|---|
| `focus.sipa-os.org` | `sipa-adhd-focus` | Самый сложный: 4 итерации деплоя. Реальный стек — Auth0, Supabase, ElevenLabs, Google Pay, Calendly, Umami (`gateway.umami.is`, не `cloud.umami.is`), Google Translate, GTM, Google Analytics (`analytics.google.com`/`stats.g.doubleclick.net`), Amplitude (`api2.amplitude.com`, не `api.amplitude.com`), Apollo.io tracker (script на `assets.apollo.io`, beacon на `aplo-evnt.com` — разные хосты!), Intercom, YouTube. `Permissions-Policy: payment=(self)` — у этого домена реальный Google Pay |
| `ai.sipa-os.org` | `sipa-ai-app` | CSP взят как надмножество от `focus` (тот же "SIPA OS" стек) — сработало с первого раза, 0 нарушений |
| `neuropower.sipa-os.org` | `sipa-neuropower-app` | CSP от `focus` как база + 2 итерации: нашли уникальные для этого домена интеграции — собственный `tts.sipa-os.org` виджет и realtime-бэкенд Convex (`wss://focused-anaconda-100.convex.cloud`) |

**Ключевой урок группы 2:** три сиблинг-приложения одной экосистемы разделяют
общий маркетинговый/аналитический стек (Auth0, ElevenLabs, GTM, Amplitude,
Apollo.io, Intercom, Umami, Google Translate, YouTube) — после первого
полного цикла на `focus` остальные чинились быстрее через "CSP-надмножество +
живая проверка", а не с нуля.

### Группа 3: CF Pages (1/1 закрыто) ✅
| Домен | Проект | Что нашли |
|---|---|---|
| `pixels.sipa-os.org` | `sipa-million-pixels` | Простая статика (canvas-игра "купи пиксель"), `_headers` не было вообще — создан с нуля. API (`/api/pixels`, `/api/checkout`, `/api/confirm`) same-origin через Pages Functions. 0 CSP-ошибок с первого раза |

### Группа 4: Cloudflare Tunnel origin (1/2 закрыто)
Оба домена шли не через тот же tunnel что в остальном каноне
(`config.yml` на сервере), а через отдельный **третий, ранее незадокументированный
tunnel** `sipa-syntax-status` (id `a8d3685a-166f-4e54-bf67-67f33da7e5d7`),
конфиг которого живёт целиком в облаке Cloudflare (token-режим, не в
локальном `config.yml`). Достала ingress-правила через `CF API
/cfd_tunnel/{id}/configurations`:
- `syntax.sipa-os.org` → `localhost:5004`
- `status.sipa-os.org` → `localhost:3001`
- `neurocoach.sipa-os.org` → `localhost:9926` (бонус-находка, не в scope сегодня)

| Домен | Что за приложение | Статус |
|---|---|---|
| `syntax.sipa-os.org` | Её собственный FastAPI (`/home/sipa/apps/sipa-syntax-api/api.py`, systemd user service `sipa-syntax-api.service`) | ✅ Готово — добавлен `@app.middleware("http")` с заголовками+CSP прямо в код, рестарт сервиса, живой тест 0 ошибок. Реальная находка: дашборд ходит на **другой** домен `sipa-syntax-api.soulinpsy.info/api/dashboard`, не на себя |
| `status.sipa-os.org` | **Стороннее ПО** — Docker-контейнер `louislam/uptime-kuma:2` (порт 3001), не её код | ⏸️ Требует решения архитектора — см. ниже |

**Почему `status.sipa-os.org` не чиню как остальные:** это готовый opensource
продукт (Uptime Kuma), не её исходники — нельзя просто дописать заголовки
в код. У самого Uptime Kuma нет настройки для CSP/security headers через
переменные окружения. Варианты:
1. **Поставить nginx-прокси** между Cloudflare Tunnel и контейнером (сейчас
   tunnel ingress идёт прямо на `localhost:3001`), прокси добавляет заголовки.
   Требует правки ingress-конфига через CF API (`PUT /cfd_tunnel/{id}/configurations`,
   поменять `service` на новый порт) — трогает живой мониторинг аптайма,
   которым она реально пользуется.
2. **Оставить как есть** — Uptime Kuma отдаёт "X-Powered-By: Express" и без
   security-заголовков, но это осознанное ограничение стороннего ПО, не дыра
   в собственном коде.
3. Проверить, нет ли у более новой версии Uptime Kuma (образ `:2`) скрытой
   настройки для reverse-proxy заголовков — не проверено.

**Решение оператора:** "кума вообще-то на сервере, ты и ставил" — то есть это
не чужая инфраструктура, а её собственный сервис (перенесён на SERVER после
смерти Hermes VPS 63.250.59.83, см. SESSIONS_LOG строка 4177: раньше перед
Kuma там ЖЕ стоял nginx с заголовками, просто после переноса на новый сервер
контейнер подняли напрямую без прокси). Восстановила тот же паттерн:

1. Nginx уже стоял на сервере (использовался для других доменов) — написала
   новый vhost `/etc/nginx/sites-available/sipa-status`, `proxy_pass` на
   `127.0.0.1:3001` + WebSocket upgrade (Kuma использует socket.io для live-
   обновлений) + все 6 security-заголовков через `add_header`
2. Нет passwordless sudo для записи в `/etc/nginx/` — записала конфиг во
   временный путь, дала оператору готовую команду на копипаст (`sudo cp ... &&
   sudo nginx -t && sudo systemctl reload nginx`), выполнено оператором
3. Проверила локально (`curl -H "Host: status.sipa-os.org" http://127.0.0.1:80/`)
   ДО переключения тоннеля — заголовки на месте
4. Переключила Cloudflare Tunnel ingress (`PUT /cfd_tunnel/{id}/configurations`)
   с `http://localhost:3001` (напрямую в контейнер) на `http://localhost:80`
   (через новый nginx-vhost)
5. Живой тест поймал реальный CSP-промах (тот же CF Insights beacon, что и
   везде) — дописала `static.cloudflareinsights.com`, оператор применил
   обновлённый конфиг тем же способом
6. Финальная проверка headless-браузером: **0 CSP-ошибок**

Конфиг сохранён: `/home/sipa/PROJECT/PAYTON_HUBS/HUB_CODE_FILE/nginx_configs/sipa-status`
(+ sha256/TAG).

**Побочная находка, вне scope сегодня:** Kuma редиректит `/` → `/setup-database`
— похоже, база данных контейнера не проинициализирована (возможно, потеряна
при переносе с упавшего VPS). Реальные мониторы на публичной странице статуса,
возможно, сейчас не отображаются как надо. Не трогала — отдельная задача,
не связана с заголовками.

## ФИНАЛЬНАЯ ПРОВЕРКА (2026-08-16 05:54 UTC)

```
EilatSecure self-scan: 13 targets, clean
```

Полный повторный прогон `scan_own_domains.py` — **0 находок на всех 13 доменах**.

**Два хвоста, найденные именно этим финальным прогоном (не были в исходном
scope, потому что раньше не проходили дальше critical-уровня):**
- `shell.sipa-os.org` — воркер `sipa-shell-app` никогда не получал реального
  трафика до сегодняшнего DNS-фикса, поэтому его medium/low находки (CSP,
  Permissions-Policy и т.д.) не всплывали раньше. Дочинила отдельно — CSP
  оказался самым насыщенным из всех (Auth0, tts.sipa-os.org, PostHog
  (`edge.soulinpsy.info`), Umami, GTM, Sentry, Apollo.io, accessibility-виджет
  acsbapp.com) — 3 итерации живого теста.
- `status.sipa-os.org` — `X-Powered-By: Express` от Uptime Kuma скрыт через
  `proxy_hide_header X-Powered-By;` в том же nginx-конфиге.

## Продолжение — LoRA-обучение vulnerability-gate специалиста (2026-08-16, позже)

Оператор подняла Brev GPU (L40S 48GB, massedcompute, $1.06/ч, instance
`experienced-aquamarine-scallop`). Датасет из 6 групп (1196 строк) конвертирован
в SFT-формат (`prep_vuln_dataset.py` → `vuln_gate_sft_v1.jsonl`, только positive-
поведение, тот же принцип что у honesty specialist-cd — модель никогда не видит
негативный/эскалационный текст как training target). Обучающий скрипт
`train_vuln_specialist_qwen25.py` — Qwen2.5-7B-Instruct, LoRA r=16, тот же паттерн
что у остальных specialist-cd моделей серии.

Доступ к инстансу — `brev exec`/`brev copy` с самого SERVER (brev CLI уже
авторизован тем же пользователем `sipa`, отдельный SSH-ключ не понадобился).
Venv `.venv` пришёл пустым (без pip) — пересоздан системным `python3 -m venv`
после `sudo apt-get install python3.10-venv`. Установка torch+CUDA+transformers/
peft/trl/datasets/accelerate/bitsandbytes запущена в фоне.

## ИТОГ: 13 из 13 доменов закрыто ✅

| Категория | Домены | Статус |
|---|---|---|
| Critical | `shell.sipa-os.org`, `api.soulinpsyabstract.com` | ✅ 2/2 |
| High | `sipa-os.online` | ✅ 1/1 |
| Группа 1 (простые Workers) | `deck`, `community`, `app.soulinpsyabstract.store`, `games` | ✅ 4/4 |
| Группа 2 (SPA/TanStack) | `focus`, `ai`, `neuropower` | ✅ 3/3 |
| Группа 3 (CF Pages) | `pixels` | ✅ 1/1 |
| Группа 4 (Cloudflare Tunnel origin) | `syntax`, `status` | ✅ 2/2 |

Каждый фикс проверен живьём: `curl` на заголовки + headless-браузер (Playwright)
на реальные CSP console-ошибки — не просто "wrangler/nginx сказал Success".
Найдено и починено попутно: баг в самом сканере (ложноположительный HTTPS-redirect
finding), отсутствующая DNS-запись для `shell`, третий незадокументированный
Cloudflare Tunnel (`sipa-syntax-status`), потерянный nginx-слой перед Uptime Kuma.
