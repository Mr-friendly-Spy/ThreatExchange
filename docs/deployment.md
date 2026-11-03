# Развёртывание с Docker и HTTPS

Требуются Docker Engine или Docker Desktop и Docker Compose версии 2.24.4 или новее.
На Windows можно использовать Docker Engine в дистрибутиве Ubuntu / WSL 2.
PowerShell-обёртка `scripts/docker.ps1` вызывает доступный `docker.exe`, а при его
отсутствии — Docker в Ubuntu / WSL. Docker должен быть установлен и запущен заранее.
На Linux и macOS используйте обычную команду `docker` вместо этой обёртки.

Для проекта `threat-exchange` PowerShell-обёртка запускает скрытый процесс WSL
`sleep infinity`, который держит окружение активным после закрытия терминала.
Команда `down` через ту же обёртку завершает только этот процесс (с проверкой PID
и времени создания). Это учитывает [поведение systemd в WSL](https://learn.microsoft.com/en-us/windows/wsl/systemd/):
службы systemd сами по себе не удерживают дистрибутив запущенным. Автозапуск Windows
и глобальная конфигурация WSL не изменяются; после перезагрузки повторите команду запуска.

## Запуск

В VS Code: **Terminal → Run Task → Docker: HTTPS start**.
Или из корня проекта в PowerShell:

```powershell
.\scripts\docker.ps1 compose --project-name threat-exchange -f compose.yaml -f compose.https.yaml up --build -d --wait
.\.venv\Scripts\python.exe scripts/export_ca.py
```

Адреса: `https://localhost:8443/docs`, `https://localhost:8443/health`.
В HTTPS-конфигурации порт HTTP приложения не публикуется; Caddy обращается к API
через внутреннюю сеть Compose. Внешний TLS-порт привязан к `127.0.0.1`.

Для ограничения доступа скопируйте `.env.example` в `.env` и задайте случайный
`THREAT_API_KEY` длиной не менее 32 символов. Файл `.env` исключён из Git и Docker build
context. Передавайте ключ в `X-API-Key` либо вводите через **Authorize** в Swagger.
Без заданного ключа доступ открыт. Скрипты проверки не выводят ключ и не передают его
в аргументах командной строки.

## Сертификаты

Caddy выпускает и обновляет сертификаты для **localhost** и **127.0.0.1** через свой
локальный CA. Ключи и цепочка сертификатов хранятся в отдельном Docker volume
`threat-exchange_caddy_data`. Приватные ключи не копируются в репозиторий и не монтируются
в контейнер API. Настройка основана на [официальной директиве Caddy `tls internal`](https://caddyserver.com/docs/caddyfile/directives/tls).

`scripts/export_ca.py` сохраняет только публичный корневой сертификат в
`certs/local-ca.crt`. Скрипт не изменяет системное хранилище доверия. Для локального CA
клиенту нужно явно передать этот сертификат; браузер без доверия к нему покажет
предупреждение. Это локальный сертификат, а не сертификат публичного домена.

Проверка HTTPS из Windows с валидацией цепочки и имени сервера:

```powershell
curl.exe --cacert certs/local-ca.crt https://localhost:8443/health
.\.venv\Scripts\python.exe scripts/check_deployment.py --base-url https://localhost:8443 --ca-file certs/local-ca.crt
```

Проверочный скрипт читает API key из окружения или `.env`, проверяет health, POST/GET/PUT,
ошибки 400/404/409 и отказ без ключа. Он создаёт одну уникальную тестовую запись.
Дополнительно проверяется TLS 1.2/1.3, доверенная цепочка, имя хоста, отказ с недоверенным
CA и отказ с неправильным именем TLS-сервера. Проверка сертификата нигде не отключается.

Для собственного публичного домена замените адреса в `deploy/Caddyfile` и настройте
выпуск публичного сертификата на своей инфраструктуре. Текущий конфиг предназначен
для localhost и не требует домена или внешней публикации.

## Управление и сохранение данных

```powershell
.\scripts\docker.ps1 compose --project-name threat-exchange -f compose.yaml -f compose.https.yaml ps
.\scripts\docker.ps1 compose --project-name threat-exchange -f compose.yaml -f compose.https.yaml logs --tail 50
.\scripts\docker.ps1 compose --project-name threat-exchange -f compose.yaml -f compose.https.yaml down
```

Также доступны задачи VS Code **Docker: HTTPS status** и **Docker: HTTPS stop**.
Обычный `down` сохраняет SQLite и CA в volumes; последующий `up` их использует снова.
Флаг `--volumes` удаляет и данные, и CA. После удаления CA потребуется заново экспортировать
публичный сертификат. В репозитории используется Compose 2.24.4+ с `!override`, чтобы
HTTPS-конфигурация действительно убирала HTTP-порт из базового файла.

Для отдельной HTTP-проверки можно использовать только `compose.yaml`.
`THREAT_HTTP_PORT` задаёт порт HTTP (по умолчанию 8000), `THREAT_HTTPS_PORT` — порт HTTPS
(по умолчанию 8443). Контейнер API работает от UID 10001 с файловой системой только
для чтения, данные записываются в отдельный SQLite volume.

## Что проверяется автоматически

В CI подготовлен тот же сценарий, который выполнен локально: сборка образа,
HTTP-проверки, пересоздание контейнера с чтением сохранённой записи, запуск Caddy,
экспорт CA и проверки HTTPS. Для автоматических проверок используется отдельное
имя Compose-проекта, поэтому его удаление не затрагивает рабочую базу.

Фактические результаты и версии записаны в [verification.md](verification.md).
