
import logging
import time
from typing import Optional

import pyotp
from django.core.cache import cache

from cfmauth.models import BaseUser, Session
from cfmauth.bot.jwt_token import create_token

logger = logging.getLogger(__name__)

OTP_INTERVAL = 60
OTP_CACHE_TTL = OTP_INTERVAL + 10


async def create_or_get_session(
    telegram_id: int,
) -> tuple[Optional[BaseUser], Optional[str], Optional[str], bool]:
    """
    Returns:
        (user, otp_code, jwt_token, is_cached)
    """
    try:
        user = await BaseUser.objects.aget(
            telegram_id=telegram_id,
        )
    except BaseUser.DoesNotExist:
        logger.warning(
            "Foydalanuvchi topilmadi: telegram_id=%s",
            telegram_id,
        )
        return None, None, None, False
    except Exception:
        logger.exception(
            "Foydalanuvchini olishda xato: telegram_id=%s",
            telegram_id,
        )
        return None, None, None, False

    otp_cache_key = f"otp_code:{telegram_id}"
    jwt_cache_key = f"jwt:{telegram_id}"

    # Avval keshdagi amaldagi OTP va JWT ni tekshiramiz.
    try:
        cached_otp = await cache.aget(otp_cache_key)
        cached_jwt = await cache.aget(jwt_cache_key)

        if cached_otp and cached_jwt:
            return user, cached_otp, cached_jwt, True

    except Exception:
        logger.exception(
            "Keshni o'qishda xato: telegram_id=%s",
            telegram_id,
        )

    try:
        # Foydalanuvchining mavjud sessiyasini olamiz.
        try:
            session = await Session.objects.aget(user_id=user.pk)
        except Session.DoesNotExist:
            session = None

        # Yangi yoki mavjud sessiya uchun secret yaratamiz/olamiz.
        if session is None:
            secret = pyotp.random_base32()
            session = await Session.objects.acreate(
                user=user,
                secret_key=secret,
                iat=0,
                exp=0,
            )
        else:
            secret = session.secret_key

        # JWT token yaratamiz.
        iat, jwt_token, exp = create_token(
            telegram_id=telegram_id,
        )

        session.iat = iat
        session.exp = exp
        await session.asave(update_fields=["iat", "exp"])

        # OTP yaratamiz.
        totp = pyotp.TOTP(
            secret,
            interval=OTP_INTERVAL,
        )
        otp_code = totp.now()

        # JWT muddati tugagan bo'lsa, tokenni bermaymiz.
        now = int(time.time())
        jwt_ttl = int(exp) - now

        if jwt_ttl <= 0:
            logger.error(
                "JWT muddati yaroqsiz: telegram_id=%s, exp=%s",
                telegram_id,
                exp,
            )
            return None, None, None, False

        # OTP ning joriy 60 soniyalik davri tugashigacha qolgan vaqt.
        remaining = OTP_INTERVAL - (now % OTP_INTERVAL)

        # OTP va JWT ni keshga yozamiz.
        await cache.aset(
            otp_cache_key,
            otp_code,
            timeout=remaining,
        )
        await cache.aset(
            jwt_cache_key,
            jwt_token,
            timeout=jwt_ttl,
        )

        # OTP bo'yicha telegram_id qidirish kerak bo'lsa, alohida indeks.
        await cache.aset(
            f"{otp_code}",
            str(telegram_id),
            timeout=remaining,
        )

        return user, otp_code, jwt_token, False

    except Exception:
        logger.exception(
            "Sessiya yoki OTP yaratishda xato: telegram_id=%s",
            telegram_id,
        )
        return None, None, None, False
