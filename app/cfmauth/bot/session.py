
import logging
import time
from typing import Optional

import pyotp
from asgiref.sync import sync_to_async
from django.core.cache import cache

from cfmauth.models import BaseUser, Session
from cfmauth.bot.jwt_token import create_token


logger = logging.getLogger(__name__)

OTP_INTERVAL = 60
OTP_CACHE_TTL = OTP_INTERVAL + 10
JWT_CACHE_TTL = OTP_CACHE_TTL + 10


async def create_or_get_session(telegram_id: int) -> tuple[Optional[BaseUser], Optional[str], Optional[str], bool]:
    try:
        user = await BaseUser.objects.aget(telegram_id=telegram_id)
    except BaseUser.DoesNotExist:
        logger.warning("Foydalanuvchi topilmadi: telegram_id=%s", telegram_id)
        return None, None, None, False
    except Exception:
        logger.exception(
            "Foydalanuvchini olishda xato: telegram_id=%s",
            telegram_id,
        )
        return None, None, None, False

    otp_cache_key = f"otp_code:{telegram_id}"
    jwt_cache_key = f"jwt:{telegram_id}"

    try:
        cached_otp = await cache.aget(otp_cache_key)
        cached_jwt = await cache.aget(jwt_cache_key)

        if cached_otp and cached_jwt:
            return user, cached_otp, cached_jwt, True

    except Exception:
        logger.exception("Keshni o'qishda xato")
    try:
        try:
            session = await Session.objects.aget(user_id=user.pk)
        except Session.DoesNotExist:
            session = None

        if session is None:
            secret = pyotp.random_base32()
            iat, jwt_token, exp = create_token(telegram_id=telegram_id)
            session = await Session.objects.acreate(user=user, secret_key=secret, iat=iat, exp=exp)
        else:
            secret = session.secret_key
            iat, jwt_token, exp = create_token(telegram_id=telegram_id)

            session.iat = iat
            session.exp = exp
            await session.asave(update_fields=["iat", "exp"])

        totp = pyotp.TOTP(secret, interval=OTP_INTERVAL)
        otp_code = totp.now()

        # OTP faqat joriy TOTP oralig'i tugaguncha saqlanadi.
        remaining = OTP_INTERVAL - (int(time.time()) % OTP_INTERVAL)
        await cache.aset(otp_code, str(telegram_id), cache_time=OTP_INTERVAL)
        await cache.aset(otp_cache_key, otp_code, timeout=remaining)

        # JWT kesh muddati tokenning haqiqiy exp qiymatidan oshmaydi.
        jwt_ttl = int(exp) - int(time.time())

        if jwt_ttl > 0:
            await cache.aset(jwt_cache_key, jwt_token, timeout=jwt_ttl)
        else:
            logger.error("Yaratilgan JWT muddati allaqachon tugagan")
            return None, None, None, False

        return user, otp_code, jwt_token, False

    except Exception:
        logger.exception(
            "Sessiya yaratishda xato: telegram_id=%s",
            telegram_id,
        )
        return None, None, None, False
