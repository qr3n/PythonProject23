# VPN Subscription Manager

FastAPI-сервис для управления VPN-подписками. Парсит outbounds от провайдера, формирует персональные xray JSON конфиги для пользователей с балансировщиком и автоматическим killswitch при истечении подписки.

## Быстрый старт

```bash
# 1. Настроить окружение
cp .env.example .env
# Отредактировать .env: BASE_URL, ADMIN_API_KEY

# 2. Запустить
docker compose up -d

# 3. Проверить
curl http://localhost:8000/health
```

## Как работает killswitch

Каждый пользователь получает полный xray JSON конфиг, в котором:

1. **Outbounds** — прокси-серверы провайдера с префиксами `p-X-Y` + blackhole с тегом `block`
2. **burstObservatory** настроен на `probeUrl = BASE_URL/check/{token}` и проверяет все `p-*` outbounds
3. **Balancer** с `fallbackTag: "block"` и стратегией `leastPing`

**Поток:**
- xray-клиент каждые `PROBE_INTERVAL_SECONDS` секунд пробивает каждый прокси через `GET /check/{token}`
- Сервер смотрит в Redis: есть ли ключ `sub:active:{token}`?
- `200` → outbound жив, `503` → outbound мёртв
- Когда все outbounds мертвы → balancer уходит в `block` → весь трафик в blackhole

При истечении подписки пользователя — Redis-ключ `sub:active:{token}` истекает автоматически (TTL = секунды до `subscription_expires_at`).

> **Важно:** xray-core v1.8.0+ требуется для `burstObservatory`. Интервал 300s (5 мин) — разумный баланс между скоростью реакции и нагрузкой на серверы провайдера.

## Admin API

Все запросы требуют заголовок: `Authorization: Bearer {ADMIN_API_KEY}`

### Provider Subscriptions

```bash
# Добавить подписку провайдера
curl -X POST http://localhost:8000/api/admin/provider-subs \
  -H "Authorization: Bearer your-key" \
  -H "Content-Type: application/json" \
  -d '{"alias": "Provider A June", "url": "https://provider.example.com/sub/abc", "expires_at": "2025-07-01T00:00:00Z", "traffic_total_gb": 100}'

# Список подписок
curl http://localhost:8000/api/admin/provider-subs \
  -H "Authorization: Bearer your-key"

# Обновить подписку (продлить, изменить лимит)
curl -X PATCH http://localhost:8000/api/admin/provider-subs/{id} \
  -H "Authorization: Bearer your-key" \
  -H "Content-Type: application/json" \
  -d '{"expires_at": "2025-08-01T00:00:00Z"}'

# Перефетчить outbounds с провайдера
curl -X POST http://localhost:8000/api/admin/provider-subs/{id}/refresh \
  -H "Authorization: Bearer your-key"

# Удалить подписку
curl -X DELETE http://localhost:8000/api/admin/provider-subs/{id} \
  -H "Authorization: Bearer your-key"
```

### Users

```bash
# Создать пользователя
curl -X POST http://localhost:8000/api/admin/users \
  -H "Authorization: Bearer your-key" \
  -H "Content-Type: application/json" \
  -d '{"name": "Alice", "subscription_expires_at": "2025-07-01T00:00:00Z"}'
# Ответ содержит token, sub_url и check_url

# Список пользователей
curl http://localhost:8000/api/admin/users \
  -H "Authorization: Bearer your-key"

# Продлить подписку пользователя
curl -X PATCH http://localhost:8000/api/admin/users/{id} \
  -H "Authorization: Bearer your-key" \
  -H "Content-Type: application/json" \
  -d '{"subscription_expires_at": "2025-08-01T00:00:00Z"}'

# Сбросить токен (инвалидирует конфиг и активный ключ)
curl -X POST http://localhost:8000/api/admin/users/{id}/reset-token \
  -H "Authorization: Bearer your-key"

# Деактивировать пользователя
curl -X PATCH http://localhost:8000/api/admin/users/{id} \
  -H "Authorization: Bearer your-key" \
  -d '{"is_active": false}'

# Удалить пользователя
curl -X DELETE http://localhost:8000/api/admin/users/{id} \
  -H "Authorization: Bearer your-key"
```

## Client API (без авторизации)

```bash
# Получить xray конфиг (URL отдаётся пользователю)
curl http://localhost:8000/sub/{token}

# Health check (вызывается xray, не пользователем)
curl http://localhost:8000/check/{token}
```

## Алгоритм балансировки outbounds

**Health score** для каждой подписки провайдера:
```
time_health    = clamp((expires_at - now).days / 30, 0, 1)
traffic_health = clamp(remaining_gb / total_gb, 0, 1)
health         = min(time_health, traffic_health)
```

Подписки с `health < MIN_HEALTH_SCORE` (default 0.05) исключаются из пула.

**Round-robin merge** (interleaving):
```
sub_a: [a0, a1, a2, a3]
sub_b: [b0, b1]
sub_c: [c0, c1, c2]
pool:  [a0, b0, c0, a1, b1, c1, a2, c2, a3]
```

Каждый пользователь получает `K` outbounds со смещением `offset = int(token[:8], 16) % N`. Честно: каждый outbound получает ровно `K/N` долю пользователей.

## Кеширование

| Ключ Redis | Содержимое | TTL |
|---|---|---|
| `sub:active:{token}` | `"1"` | до истечения подписки |
| `pool:version` | integer | без TTL |
| `pool:data` | JSON пула outbounds | 1h |
| `config:{user_id}:{version}` | JSON xray конфига | 24h |

При изменении пула (добавление/удаление/обновление подписки провайдера) — инкрементируем `pool:version`. Старые `config:*` ключи автоматически перестают использоваться и истекают через 24h.

## Переменные окружения

| Переменная | По умолчанию | Описание |
|---|---|---|
| `DATABASE_URL` | — | PostgreSQL async URL |
| `REDIS_URL` | — | Redis URL |
| `ADMIN_API_KEY` | — | Ключ для admin API |
| `BASE_URL` | — | Публичный URL сервера (без `/` в конце) |
| `OUTBOUNDS_PER_USER` | `6` | Кол-во outbounds в конфиге пользователя |
| `PROBE_INTERVAL_SECONDS` | `300` | Интервал probe xray observatory |
| `CONFIG_CACHE_TTL_SECONDS` | `86400` | TTL кеша конфигов (24h) |
| `MIN_HEALTH_SCORE` | `0.05` | Порог health для включения в пул |

## Структура проекта

```
vpn-sub-manager/
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── alembic.ini
├── requirements.txt
├── alembic/
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
│       └── 0001_initial.py
└── app/
    ├── main.py          # lifespan, app factory
    ├── config.py        # Settings (pydantic-settings)
    ├── deps.py          # FastAPI dependencies
    ├── parser.py        # Xray parser (копия парсера)
    ├── api/
    │   ├── admin.py     # /api/admin/* — защищённые эндпоинты
    │   └── client.py   # /sub/{token}, /check/{token}
    ├── db/
    │   ├── base.py      # engine, sessionmaker
    │   └── models.py    # SQLAlchemy models
    ├── schemas/
    │   ├── provider.py
    │   └── user.py
    └── services/
        ├── provider.py  # fetch + parse provider sub
        ├── pool.py      # pool construction + balancing
        └── builder.py   # xray config assembly + Redis cache
```
