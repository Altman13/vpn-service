# VPN Service

Сервис управления VPN-устройствами на Go: выдаёт клиентские конфиги WireGuard,
хранит пользователей и устройства в PostgreSQL, кэш — в Redis.

## Возможности

- 🔒 WireGuard: генерация ключей Curve25519, аллокация адресов из подсети,
  выдача клиентских конфигов, применение и снятие пиров через `wg`
- 🛡️ OpenVPN: встроенный CA, выпуск клиентских сертификатов, `.ovpn` со
  встроенными блоками и отзыв через CRL
- 🔑 JWT аутентификация с проверкой статуса пользователя на каждом запросе
- 🗄️ PostgreSQL + Redis
- 🐳 Docker и Kubernetes
- 🔄 Graceful shutdown
- 📝 Структурированное логирование (zap)
- ❤️ Раздельные проверки: `/health` (liveness) и `/readyz` (БД + Redis)

OpenVPN: при `vpn.openvpn.enabled: true` сервис выпускает клиентские
сертификаты встроенным CA и собирает `.ovpn` со встроенными блоками
`<ca>`, `<cert>`, `<key>`; при отзыве устройства сертификат попадает в CRL.
При `enabled: false` протокол отвечает 503 («не настроен»).

## Быстрый старт

```bash
git clone https://github.com/yourusername/vpn-service
cd vpn-service

go mod download

# Конфигурация: шаблон лежит рядом с кодом конфига
cp internal/config/config.example.yaml configs/config.yaml
# Отредактируйте configs/config.yaml: как минимум jwt.secret и vpn.wireguard.*

# PostgreSQL + Redis
make docker-up

# Приложение
make run
```

## Настройка WireGuard

| Параметр | Значение |
|---|---|
| `vpn.wireguard.network_cidr` | подсеть выдачи адресов, например `10.0.0.0/24` |
| `vpn.wireguard.endpoint` | адрес сервера для клиентских конфигов |
| `vpn.wireguard.public_key` | публичный ключ сервера |
| `vpn.wireguard.dns` | DNS, который попадёт в клиентский конфиг |
| `vpn.wireguard.allowed_ips` | какие сети клиент направляет в туннель (`0.0.0.0/0` по умолчанию) |
| `vpn.wireguard.enabled` | `true` — применять пиров через `wg set` (нужны права на интерфейс); `false` — только выдача конфигов |

Адресация: адрес сети и шлюз (`network+1`) клиентам не выдаются, первым
клиентам достаются `network+2`, `network+3`, … Занятость адресов обеспечивается
частичным уникальным индексом `idx_devices_ip_active`; отозванное устройство
адрес освобождает.

## Настройка OpenVPN

| Параметр | Значение |
|---|---|
| `vpn.openvpn.enabled` | `true` — выпускать сертификаты; `false` — протокол отвечает 503 |
| `vpn.openvpn.pki_dir` | каталог CA: `ca.crt`, `ca.key` (права 0600), `crl.pem`, `revoked.json` |
| `vpn.openvpn.endpoint` | адрес сервера в клиентском конфиге |
| `vpn.openvpn.port`, `proto` | порт и транспорт (`udp` по умолчанию) |

CA создаётся при первом обращении и переиспользуется: клиентские сертификаты
подписываются одним ключом, поэтому ранее выданные конфиги остаются валидными
после рестарта. Устройство получает сертификат при выдаче конфига; повторная
выдача гасит предыдущий сертификат, а отзыв устройства добавляет серийный
номер в CRL.

Чтобы отзыв действовал, сервер OpenVPN должен проверять CRL:

```conf
crl-verify /var/lib/vpn-service/pki/crl.pem
```

Каталог `pki_dir` нельзя коммитить в репозиторий (в `.gitignore` уже исключён):
там лежит приватный ключ CA.

## API

| Метод | Путь | Описание |
|---|---|---|
| `POST` | `/api/v1/auth/register` | регистрация |
| `POST` | `/api/v1/auth/login` | вход, выдаёт пару `access_token` + `refresh_token` |
| `POST` | `/api/v1/auth/refresh` | обмен refresh-токена на новую пару |
| `POST` | `/api/v1/auth/logout` | отзыв access-токена и refresh-токена |
| `GET` | `/api/v1/user/profile` | профиль текущего пользователя |
| `POST` | `/api/v1/vpn/devices` | создать устройство (`device_name`, `protocol`) |
| `GET` | `/api/v1/vpn/devices` | устройства текущего пользователя |
| `GET` | `/api/v1/vpn/devices/:id/config` | конфиг устройства |
| `DELETE` | `/api/v1/vpn/devices/:id` | отозвать устройство |
| `GET` | `/health` | liveness |
| `GET` | `/readyz` | readiness (проверяет БД и Redis) |

Владелец устройства всегда берётся из JWT: `user_id` в теле или query
игнорируется, чужое устройство неотличимо от несуществующего (404).

## Безопасность

| Механизм | Настройка | Поведение |
|---|---|---|
| Access-токен | `jwt.expire_time` (часы) | JWT с `jti`, тип `access` |
| Refresh-токен | `jwt.refresh_expire_time` (часы) | непрозрачная строка, в Redis только SHA-256; одноразовый (ротация) |
| Отзыв доступа | — | `POST /auth/logout` кладёт `jti` в блэклист до истечения срока; заблокированный пользователь теряет доступ сразу |
| Rate limit | `security.rate_limit.*` | 10 запросов/минуту на IP для `/auth/login`, `/auth/register`, `/auth/refresh`; счётчики в Redis, общие для всех реплик |
| CORS | `security.cors.allowed_origins` | пустой список = CORS-заголовки не отдаются |
| Шифрование ключей | `security.encryption_key` | AES-256-GCM для приватных ключей устройств в БД; пусто = без шифрования (только для разработки) |

Требования к Redis: в нём живут refresh-токены, блэклист и счётчики лимитера,
поэтому без Redis вход и ограничение частоты работать не будут — это видно
по `/readyz`.

## Тесты

```bash
make test
```
