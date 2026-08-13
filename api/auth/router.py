"""
Эндпоинты авторизации: вход через провайдеров, вход по коду на email, обновление токена
"""

import os
import re
import hashlib
import secrets
import logging
import httpx
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel

from database import get_db
from api.schemas import (
    YandexAuthRequest, RefreshRequest, TokenResponse,
    EmailLoginRequest, EmailLoginResponse,
)
from api.auth.jwt import create_tokens, decode_token
from api.auth.email_service import send_login_code_email
from api.rate_limit import limiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Стартовый user_id для app-пользователей (чтобы не пересекаться с Telegram ID)
APP_USER_ID_START = 5_000_000_000

# OAuth client IDs из переменных окружения
YANDEX_CLIENT_ID = os.getenv("YANDEX_CLIENT_ID")
YANDEX_CLIENT_SECRET = os.getenv("YANDEX_CLIENT_SECRET")

# === Вход по коду на email ===
EMAIL_CODE_TTL_MINUTES = 10            # срок жизни кода из письма
EMAIL_CODE_MAX_ATTEMPTS = 5            # макс. попыток ввода одного кода
EMAIL_RATELIMIT_PER_HOUR = 5           # макс. запросов кода на один адрес в час
EMAIL_RATELIMIT_COOLDOWN_SECONDS = 60  # не чаще одного запроса в минуту

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Таблица создаётся лениво при первом обращении (одна попытка на процесс).
_email_codes_table_ready = False


async def _get_next_app_user_id(conn) -> int:
    """Получить следующий свободный user_id для app-пользователя"""
    max_id = await conn.fetchval("""
        SELECT COALESCE(MAX(user_id), $1) FROM users WHERE user_id >= $1
    """, APP_USER_ID_START)
    return max_id + 1


async def _find_or_create_user(
    conn,
    provider: str,
    provider_user_id: str,
    email: str = None,
    first_name: str = None,
) -> int:
    """
    Найти юзера по (provider, provider_user_id) или создать нового.
    Возвращает user_id.
    """
    # Ищем существующего юзера
    existing = await conn.fetchval("""
        SELECT user_id FROM users
        WHERE auth_provider = $1 AND provider_user_id = $2
    """, provider, provider_user_id)

    if existing:
        # Обновляем активность
        await conn.execute("""
            UPDATE users
            SET last_activity = CURRENT_TIMESTAMP, last_action = $2
            WHERE user_id = $1
        """, existing, f"{provider}_login")
        return existing

    # Создаём нового
    user_id = await _get_next_app_user_id(conn)

    await conn.execute("""
        INSERT INTO users (
            user_id, email, first_name,
            auth_provider, provider_user_id,
            last_activity, last_action
        )
        VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, $6)
    """, user_id, email, first_name, provider, provider_user_id, f"{provider}_register")

    await conn.execute("""
        INSERT INTO user_settings (user_id) VALUES ($1)
        ON CONFLICT (user_id) DO NOTHING
    """, user_id)

    await conn.execute("""
        INSERT INTO subscriptions (user_id, plan) VALUES ($1, 'free')
        ON CONFLICT (user_id) DO NOTHING
    """, user_id)

    logger.info(f"✅ Новый {provider}-пользователь: user_id={user_id}, email={email}")
    return user_id


# === Хелперы входа по коду ===

def _hash_code(email: str, code: str) -> str:
    """
    SHA-256 хеш кода (в БД храним только хеши, не сами коды).
    Email в составе хеша, чтобы одинаковые коды у разных адресов
    давали разные хеши.
    """
    return hashlib.sha256(f"{email}:{code}".encode("utf-8")).hexdigest()


def _generate_code() -> str:
    """Случайный 6-значный код, допускаются ведущие нули."""
    return f"{secrets.randbelow(1_000_000):06d}"


def _is_test_login(email: str, code: str) -> bool:
    """
    Тестовый вход для проверяющих (ЮKassa, модерация стора).

    Вход в приложение идёт по одноразовому коду на почту, поэтому проверяющему
    без доступа к ящику войти нечем. Здесь разрешаем фиксированный код для
    ОДНОГО адреса из TEST_LOGIN_EMAIL / TEST_LOGIN_CODE.

    Fail-closed: если хотя бы одна переменная не задана или код не из 6 цифр —
    тестовый вход выключен полностью. Сравнение через compare_digest, чтобы
    по времени ответа нельзя было подбирать код посимвольно.

    Переменные читаются на каждый вызов: убрали их из окружения и
    перезапустили контейнер — вход сразу перестал работать.
    """
    allowed_email = os.getenv("TEST_LOGIN_EMAIL", "").strip().lower()
    allowed_code = os.getenv("TEST_LOGIN_CODE", "").strip()

    if not allowed_email or not allowed_code:
        return False
    if len(allowed_code) != 6 or not allowed_code.isdigit():
        logger.error(
            "⚠️ TEST_LOGIN_CODE должен быть ровно из 6 цифр — тестовый вход отключён"
        )
        return False
    return (
        secrets.compare_digest(email, allowed_email)
        and secrets.compare_digest(code, allowed_code)
    )


async def _ensure_email_codes_table(conn) -> None:
    """Создаёт таблицу кодов входа, если её ещё нет."""
    global _email_codes_table_ready
    if _email_codes_table_ready:
        return
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS email_login_codes (
            id BIGSERIAL PRIMARY KEY,
            email TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            used_at TIMESTAMP,
            attempts INTEGER NOT NULL DEFAULT 0
        )
    """)
    await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_email_login_codes_email
        ON email_login_codes (email)
    """)
    _email_codes_table_ready = True


async def _exchange_yandex_code_for_token(code: str) -> str:
    """
    Обменивает authorization code на access_token через oauth.yandex.ru/token.
    Возвращает access_token. Бросает HTTPException при ошибках.
    """
    if not YANDEX_CLIENT_ID or not YANDEX_CLIENT_SECRET:
        logger.error("YANDEX_CLIENT_ID или YANDEX_CLIENT_SECRET не заданы")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Yandex авторизация не настроена",
        )

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                "https://oauth.yandex.ru/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                },
                auth=(YANDEX_CLIENT_ID, YANDEX_CLIENT_SECRET),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
    except httpx.HTTPError as e:
        logger.warning(f"Ошибка запроса к Yandex token endpoint: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Не удалось обменять код Yandex",
        )

    if response.status_code != 200:
        logger.warning(
            f"Yandex token обмен не удался: status={response.status_code}, "
            f"body={response.text[:300]}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Невалидный или просроченный код Yandex",
        )

    payload = response.json()
    access_token = payload.get("access_token")
    if not access_token:
        logger.warning(f"Yandex token endpoint: нет access_token в ответе: {payload}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Yandex не вернул access_token",
        )

    return access_token


async def _fetch_yandex_user_info(access_token: str) -> dict:
    """Запрашивает данные пользователя через login.yandex.ru/info."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                "https://login.yandex.ru/info",
                params={"format": "json"},
                headers={"Authorization": f"OAuth {access_token}"},
            )
    except httpx.HTTPError as e:
        logger.warning(f"Ошибка запроса к Yandex info: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Не удалось проверить токен Yandex",
        )

    if response.status_code != 200:
        logger.warning(
            f"Yandex info вернул ошибку: status={response.status_code}, "
            f"body={response.text[:200]}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Невалидный Yandex токен",
        )

    return response.json()


@router.post("/yandex", response_model=TokenResponse)
@limiter.limit("20/minute")
async def auth_yandex(request: Request, req: YandexAuthRequest):
    """
    Вход или регистрация через Yandex ID.
    Принимает authorization code, полученный мобильным клиентом из OAuth
    callback (?code=...). Обменивает его на access_token через
    oauth.yandex.ru/token и валидирует через login.yandex.ru/info.
    """
    # Шаг 1: обмен code на access_token
    access_token = await _exchange_yandex_code_for_token(req.code)

    # Шаг 2: валидируем токен и получаем данные пользователя
    info = await _fetch_yandex_user_info(access_token)

    yandex_id = info.get("id")
    if not yandex_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Не удалось получить идентификатор пользователя от Yandex",
        )

    # Извлекаем email и имя
    email = info.get("default_email")
    if not email:
        emails = info.get("emails") or []
        email = emails[0] if emails else None

    first_name = (
        info.get("first_name")
        or info.get("display_name")
        or info.get("login")
    )

    # Находим или создаём юзера
    db = await get_db()
    async with db.pool.acquire() as conn:
        user_id = await _find_or_create_user(
            conn,
            provider="yandex",
            provider_user_id=str(yandex_id),
            email=email,
            first_name=first_name,
        )

    return TokenResponse(**create_tokens(user_id))


@router.post("/email/request", response_model=EmailLoginResponse)
@limiter.limit("10/hour")
@limiter.limit("3/minute")
async def auth_email_request(request: Request, req: EmailLoginRequest):
    """
    Шаг 1 входа по коду: принять email, отправить письмо с 6-значным кодом.
    Ответ одинаковый при любом исходе валидного запроса (не раскрываем,
    зарегистрирован адрес или нет).

    Лимиты slowapi (по IP) защищают от перебора множества чужих адресов
    с одного места. Лимиты ниже в БД (по конкретному адресу) защищают
    конкретный ящик от спама. Это разные защиты, обе нужны.
    """
    email = req.email.strip().lower()
    if len(email) > 254 or not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Некорректный email")

    db = await get_db()
    async with db.pool.acquire() as conn:
        await _ensure_email_codes_table(conn)

        # Антиспам по адресу
        hour_count = await conn.fetchval("""
            SELECT COUNT(*) FROM email_login_codes
            WHERE email = $1
              AND created_at > CURRENT_TIMESTAMP - INTERVAL '1 hour'
        """, email)
        if hour_count and hour_count >= EMAIL_RATELIMIT_PER_HOUR:
            raise HTTPException(
                status_code=429,
                detail="Слишком много запросов, попробуйте позже",
            )

        cooldown_count = await conn.fetchval(f"""
            SELECT COUNT(*) FROM email_login_codes
            WHERE email = $1
              AND created_at > CURRENT_TIMESTAMP
                  - INTERVAL '{EMAIL_RATELIMIT_COOLDOWN_SECONDS} seconds'
        """, email)
        if cooldown_count and cooldown_count >= 1:
            raise HTTPException(
                status_code=429,
                detail="Код уже отправлен, подождите минуту",
            )

        code = _generate_code()
        code_hash = _hash_code(email, code)

        # Гасим предыдущие активные коды адреса: действует только последний
        await conn.execute("""
            UPDATE email_login_codes
            SET used_at = CURRENT_TIMESTAMP
            WHERE email = $1 AND used_at IS NULL
        """, email)

        await conn.execute(f"""
            INSERT INTO email_login_codes (email, code_hash, expires_at)
            VALUES ($1, $2,
                    CURRENT_TIMESTAMP + INTERVAL '{EMAIL_CODE_TTL_MINUTES} minutes')
        """, email, code_hash)

    try:
        await send_login_code_email(email, code)
    except Exception as e:  # noqa: BLE001
        logger.error(f"Не удалось отправить письмо с кодом на {email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Не удалось отправить письмо, попробуйте позже",
        )

    return EmailLoginResponse(success=True, message="Код отправлен")


class EmailVerifyCodeRequest(BaseModel):
    email: str
    code: str


@router.post("/email/verify-code", response_model=TokenResponse)
@limiter.limit("10/minute")
async def auth_email_verify_code(request: Request, req: EmailVerifyCodeRequest):
    """
    Шаг 2 входа по коду: клиент присылает email и код из письма,
    получает JWT. Код одноразовый, максимум EMAIL_CODE_MAX_ATTEMPTS
    попыток ввода, после чего нужно запрашивать новый.
    """
    email = req.email.strip().lower()
    code = req.code.strip()

    if not _EMAIL_RE.match(email) or not code.isdigit() or len(code) != 6:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный код",
        )

    # Тестовый вход для проверяющих: фиксированный код для одного адреса.
    # Отдельная ветка до работы с таблицей кодов, чтобы письмо было не нужно.
    # Включается только переменными окружения, см. _is_test_login.
    if _is_test_login(email, code):
        client_ip = request.client.host if request.client else "?"
        logger.warning(
            "🔑 Использован ТЕСТОВЫЙ вход: email=%s ip=%s", email, client_ip
        )
        db = await get_db()
        async with db.pool.acquire() as conn:
            user_id = await _find_or_create_user(
                conn,
                provider="email",
                provider_user_id=email,
                email=email,
                first_name=None,
            )
        return TokenResponse(**create_tokens(user_id))

    code_hash = _hash_code(email, code)

    db = await get_db()
    async with db.pool.acquire() as conn:
        await _ensure_email_codes_table(conn)

        # Берём последний активный код этого адреса
        row = await conn.fetchrow("""
            SELECT id, code_hash, attempts
            FROM email_login_codes
            WHERE email = $1
              AND used_at IS NULL
              AND expires_at > CURRENT_TIMESTAMP
            ORDER BY created_at DESC
            LIMIT 1
        """, email)

        if row is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Код не найден или истёк. Запросите новый.",
            )

        if row["attempts"] >= EMAIL_CODE_MAX_ATTEMPTS:
            # На всякий случай: гасим и просим новый
            await conn.execute(
                "UPDATE email_login_codes SET used_at = CURRENT_TIMESTAMP WHERE id = $1",
                row["id"],
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Слишком много попыток. Запросите новый код.",
            )

        if code_hash != row["code_hash"]:
            attempts = row["attempts"] + 1
            if attempts >= EMAIL_CODE_MAX_ATTEMPTS:
                # Последняя неудачная попытка: гасим код
                await conn.execute("""
                    UPDATE email_login_codes
                    SET attempts = $2, used_at = CURRENT_TIMESTAMP
                    WHERE id = $1
                """, row["id"], attempts)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Слишком много попыток. Запросите новый код.",
                )
            await conn.execute(
                "UPDATE email_login_codes SET attempts = $2 WHERE id = $1",
                row["id"], attempts,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Неверный код",
            )

        # Код верный: гасим и логиним
        await conn.execute(
            "UPDATE email_login_codes SET used_at = CURRENT_TIMESTAMP WHERE id = $1",
            row["id"],
        )

        user_id = await _find_or_create_user(
            conn,
            provider="email",
            provider_user_id=email,
            email=email,
            first_name=None,
        )

    return TokenResponse(**create_tokens(user_id))


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("30/minute")
async def refresh(request: Request, req: RefreshRequest):
    """Обновление пары токенов по refresh_token"""
    payload = decode_token(req.refresh_token)

    if payload is None or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Невалидный refresh token",
        )

    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Невалидный токен",
        )

    user_id = int(user_id_str)

    db = await get_db()
    async with db.pool.acquire() as conn:
        exists = await conn.fetchval(
            "SELECT 1 FROM users WHERE user_id = $1", user_id
        )

    if not exists:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Пользователь не найден",
        )

    return TokenResponse(**create_tokens(user_id))
