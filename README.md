# Information Exchange Service

REST-сервис для обмена информацией об угрозах по MD5.
Python 3.13, FastAPI, Pydantic 2 и SQLite. Исходное задание сохранено в
[docs/assignment.md](docs/assignment.md).

Поддерживаются локальный запуск, Docker и HTTPS через Caddy.
Инструкция развёртывания и проверки сертификата: [docs/deployment.md](docs/deployment.md).
Для ограничения доступа задайте `THREAT_API_KEY` в `.env` и передавайте его в
заголовке `X-API-Key` при обращении к `/info`.

## Быстрый запуск в Visual Studio Code

Создайте виртуальное окружение и установите зависимости командами ниже, затем
откройте `ThreatExchange.code-workspace`. Для отладки установите расширения Python
и Python Debugger, выберите конфигурацию **Threat API: debug** и нажмите **F5**.
Без расширений сервер можно запустить через **Terminal → Run Task → Run API**.
Задача **Test API** запускает тесты, **Regenerate OpenAPI models** обновляет модели.

Установка с нуля, Windows PowerShell, из корня проекта:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -c requirements.lock -e ".[dev]"
.\.venv\Scripts\python.exe -m uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000 --reload --no-proxy-headers
```

Linux/macOS:

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install -c requirements.lock -e '.[dev]'
.venv/bin/python -m uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000 --reload --no-proxy-headers
```

Для установки только сервиса замените `-e ".[dev]"` на `.`.
`requirements.lock` фиксирует проверенные версии зависимостей; при передаче через
`-c` устанавливаются только пакеты, необходимые выбранному набору зависимостей.

После запуска:

В терминале появляется полная ссылка `Swagger UI: http://127.0.0.1:8000/docs`.
Базовый адрес `http://127.0.0.1:8000/` также автоматически перенаправляет на `/docs`.
Для другого адреса или порта задайте `THREAT_PUBLIC_URL`; Docker Compose формирует
адрес из выбранного HTTP/HTTPS-порта автоматически.

- Swagger UI: <http://127.0.0.1:8000/docs>.
- ReDoc: <http://127.0.0.1:8000/redoc>.
- OpenAPI: <http://127.0.0.1:8000/openapi.json> и <http://127.0.0.1:8000/openapi.yaml>.
- Готовность приложения и БД: <http://127.0.0.1:8000/health>.

База `data/threats.db` создаётся при первом старте. Данные сохраняются при перезапуске.
Остановить сервер в терминале можно сочетанием **Ctrl+C**, отладку — **Shift+F5**.

## Реализованный контракт

| Метод | Путь | Результат |
|---|---|---|
| POST | `/info` | Создание записи: `201`, заголовок `Location`; повтор MD5: `409` |
| GET | `/info/{md5}` | Полная информация: `200`; нет записи: `404` |
| PUT | `/info/{md5}` | Полная замена существующей записи: `200`; нет записи: `404` |
| GET | `/health` | Проверка таблицы БД: `200`; БД недоступна: `503` |

Некорректные MD5, JSON и данные возвращают `400`, включая ошибки валидации FastAPI,
которые по умолчанию возвращали бы `422`. Остальные ответы: `401` для неверного ключа,
`413` для слишком большого тела, `415` для неверного Content-Type, `429` при превышении
частоты запросов и `500` при внутренней ошибке. Все ошибки имеют форму:

```json
{
  "message": "Threat not found",
  "details": "No threat with the supplied MD5 found"
}
```

MD5 состоит ровно из 32 шестнадцатеричных символов. Регистр не влияет на поиск и
уникальность; хранение и ответы используют нижний регистр. MD5 служит идентификатором
записи; сервис не загружает и не анализирует файлы.

### Дополненная модель

| Поле | Правило и назначение |
|---|---|
| `md5` | Обязателен при POST; неизменяем, в PUT берётся из URL |
| `name` | Обязательная непустая строка, до 200 символов; внешние пробелы удаляются |
| `description` | Описание поведения, до 4000 символов; по умолчанию `""` |
| `threat_type` | `unknown`, `trojan`, `ransomware`, `worm`, `spyware`, `adware`, `rootkit`, `other`; по умолчанию `unknown` |
| `severity` | `unknown`, `low`, `medium`, `high`, `critical`; по умолчанию `unknown` |
| `tags` | До 20 уникальных меток, по 1–50 символов; `[a-z0-9][a-z0-9._-]*`; по умолчанию `[]` |
| `first_seen` | Первое наблюдение: RFC 3339 с часовым поясом либо `null` |
| `last_seen` | Последнее наблюдение: требует `first_seen`, не раньше него; либо `null` |
| `created_at` | UTC-время создания; заполняет сервер, PUT не изменяет |
| `updated_at` | UTC-время последней записи; заполняет сервер |

Даты наблюдения приводятся к UTC. Неизвестные поля и попытки задать серверные даты
отклоняются. `null` разрешён только для дат наблюдения.
PUT полностью заменяет изменяемые поля: например, `{"name":"New"}` сбрасывает описание,
теги, классификацию и даты наблюдения к значениям по умолчанию. PUT не создаёт запись.

### Пример PowerShell

```powershell
$base = 'http://127.0.0.1:8000'
$headers = @{}
if (Test-Path .env) {
    $apiKey = (Get-Content .env | Where-Object { $_ -like 'THREAT_API_KEY=*' }) -replace '^THREAT_API_KEY=', ''
    if ($apiKey) { $headers['X-API-Key'] = $apiKey }
}
$body = @{
    md5 = 'd41d8cd98f00b204e9800998ecf8427e'
    name = 'Trojan.Win32.Generic'
    threat_type = 'trojan'
    severity = 'high'
    tags = @('windows', 'banking')
    first_seen = '2026-01-02T12:00:00+03:00'
} | ConvertTo-Json
Invoke-RestMethod "$base/info" -Method Post -Headers $headers -ContentType 'application/json' -Body $body
Invoke-RestMethod "$base/info/d41d8cd98f00b204e9800998ecf8427e" -Headers $headers
Invoke-RestMethod "$base/info/d41d8cd98f00b204e9800998ecf8427e" -Method Put `
    -Headers $headers -ContentType 'application/json' -Body '{"name":"Trojan.Win32.Updated","severity":"critical"}'
```

Готовые запросы для расширения VS Code REST Client находятся в
[examples/requests.http](examples/requests.http). Повторный POST с тем же MD5 ожидаемо
возвращает `409`.

## OpenAPI и устройство проекта

Источник контракта — [app/openapi.yaml](app/openapi.yaml), расширенная спецификация
OpenAPI 3.0.3 на основе задания. Swagger и ReDoc используют именно этот контракт.
При включённом ключе доступа опубликованная схема требует `X-API-Key`.

`datamodel-code-generator` генерирует Pydantic-модели в `app/generated/models.py`.
Этот файл включён в проект: генератор не требуется при запуске сервиса. Дополнительные
правила, например порядок дат и уникальность тегов, находятся в `app/models.py` и
сохраняются при перегенерации.

```powershell
.\.venv\Scripts\python.exe scripts/generate_models.py
.\.venv\Scripts\python.exe scripts/generate_models.py --check
```

`--check` завершается с ошибкой, если модели расходятся со спецификацией. Этот же шаг
включён в CI. Генерация основана на [datamodel-code-generator](https://docs.pydantic.dev/latest/integrations/datamodel_code_generator/).
Тесты проверяют валидность OpenAPI, соответствие маршрутов и реальные ответы сервиса.

```text
app/
  openapi.yaml           контракт API
  generated/models.py    сгенерированные модели
  models.py              дополнительная валидация
  main.py                фабрика приложения, маршруты и обработчики ошибок
  database.py            транзакции и репозиторий
  migrations/            начальная SQL-миграция
  config.py              настройки окружения
  security.py            API key, rate limit, ограничение тела
tests/                   HTTP-, контрактные и модульные тесты
scripts/                 генерация и проверка запущенного сервера
examples/                примеры REST-запросов
.vscode/                 запуск, отладка и тесты
```

SQLite выбрана для запуска без отдельного сервера СУБД. Она работает в режиме WAL,
каждая операция получает отдельное соединение, записи выполняются в транзакциях.
Уникальность обеспечивается первичным ключом БД, поэтому одновременные POST не
создают дубликаты. SQL использует параметры. Начальная миграция атомарна, версия
хранится в `PRAGMA user_version`; неизвестная более новая версия не перезаписывается.

## Конфигурация и защита

При необходимости скопируйте `.env.example` в `.env`; файл с секретами исключён из Git.
Переменные окружения имеют приоритет над `.env`.

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `THREAT_DB_PATH` | `data/threats.db` | Путь SQLite; в Docker `/data/threats.db` |
| `THREAT_PUBLIC_URL` | `http://127.0.0.1:8000` | Базовый адрес для ссылки на Swagger в сообщении запуска |
| `THREAT_API_KEY` | пусто | Общий ключ для всех операций `/info` |
| `THREAT_RATE_LIMIT_REQUESTS` | `60` | Число запросов с одного IP за окно |
| `THREAT_RATE_LIMIT_WINDOW_SECONDS` | `60` | Размер фиксированного окна в секундах |
| `THREAT_RATE_LIMIT_MAX_CLIENTS` | `10000` | Ограничение памяти таблицы клиентов |
| `THREAT_MAX_BODY_BYTES` | `65536` | Максимальный размер тела POST/PUT |
| `THREAT_BIND_ADDRESS` | `127.0.0.1` | Только Compose: адрес публикации порта |
| `THREAT_HTTP_PORT` | `8000` | Только Compose: внешний HTTP-порт |
| `THREAT_HTTPS_PORT` | `8443` | Только HTTPS Compose: внешний TLS-порт |

Без ключа сервис открыт для локальной разработки и слушает localhost в приведённых
командах. Чтобы включить доступ по ключу, создайте случайное значение и задайте его в
`THREAT_API_KEY` перед запуском:

```powershell
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
```

Клиент передаёт `X-API-Key: <значение>`. В Swagger используется кнопка **Authorize**.
Проверка ключа использует сравнение за постоянное время; короткий ключ или ключ с
пробелами отклоняется при старте. Неверные попытки тоже учитываются rate limiter.
`/health`, документация и схема доступны без ключа.

Ограничение тела проверяет фактическое число байт, включая потоковые запросы без
Content-Length. Ответы содержат `Cache-Control: no-store` и
`X-Content-Type-Options: nosniff`. Внутренние ошибки логируются на сервере; клиент
получает общий `500` без traceback, SQL и внутренних подробностей.

Готовое HTTPS-развёртывание с автоматическим локальным CA находится в
`compose.https.yaml`; запуск и проверка описаны в [docs/deployment.md](docs/deployment.md).
Также доступен прямой запуск Uvicorn с уже выданными сертификатами:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8443 --no-proxy-headers --ssl-keyfile certs/server.key --ssl-certfile certs/server.crt
```

TLS также может завершаться на доверенном reverse proxy. Команды запуска не доверяют
`X-Forwarded-For`: его подмена не меняет лимит клиента. За proxy все запросы будут
учитываться по адресу proxy; в такой конфигурации лимиты по исходным IP нужно
настроить на самом proxy.

Ограничения выбранного масштаба: один процесс Uvicorn, фиксированные окна rate limit
в памяти (счётчики сбрасываются при рестарте; возможен всплеск на границе окон), общий
ключ без ролей и ротации, SQLite на локальном диске. Для нескольких реплик нужны
общий limiter, например Redis, и серверная СУБД. `/health` проверяет чтение таблицы,
но не гарантирует наличие свободного дискового места. Конкурирующие PUT используют
семантику последней записи; версионирование и аудит заданием не предусмотрены.

## Docker

```powershell
docker compose up --build -d
docker compose logs -f api
docker compose down
```

По умолчанию порт публикуется только на `127.0.0.1:8000`. Образ запускается от UID 10001,
Compose включает файловую систему только для чтения, снимает capabilities и запрещает
повышение привилегий. База хранится в именованном volume `threat_data`, сохраняющемся
после `docker compose down`. `docker compose down -v` удаляет этот volume и данные.
Образ содержит HTTP healthcheck.

## Проверки

```powershell
.\.venv\Scripts\python.exe -m pytest --cov=app --cov-report=term-missing --cov-fail-under=90
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe scripts/generate_models.py --check
.\.venv\Scripts\python.exe -m pip check
```

Тесты используют изолированные SQLite-файлы и не изменяют рабочую базу. Проверяются
CRUD, коды ошибок, замена полей при PUT, регистр MD5, параллельное создание,
сохранение после перезапуска, миграция, ограничения данных, авторизация, размер тела,
rate limit, готовность БД и отсутствие внутренних данных в ошибках.
Lifespan приложения запускается через контекстный менеджер TestClient согласно
[рекомендациям FastAPI](https://fastapi.tiangolo.com/advanced/testing-events/).

Для отдельной проверки сервера по TCP предусмотрен `python scripts/smoke_test.py`:
он запускает Uvicorn на свободном локальном порту с временной базой, проверяет HTTP
и завершает процесс. В Windows используйте `.\.venv\Scripts\python.exe` вместо `python`.

В `.github/workflows/ci.yml` подготовлены lint, тесты, проверка генерации и сборка с
HTTP-проверкой Docker. Фактический отчёт о локальных проверках —
[docs/verification.md](docs/verification.md).
