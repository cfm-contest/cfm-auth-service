
import logging
import time
from typing import Optional

import pyotp
from django.core.cache import cache

from cfmauth.models import BaseUser, Session
from cfmauth.bot.jwt_token import create_token, decode_token

logger = logging.getLogger(__name__)

OTP_INTERVAL = 60
OTP_CACHE_TTL = OTP_INTERVAL + 10


async def create_or_get_session(
    telegram_id: int,
) -> tuple[Optional[BaseUser], Optional[str], Optional[str], bool]:
    try:
        user = await BaseUser.objects.aget(telegram_id=telegram_id)
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

    # Keshda amaldagi OTP va JWT bo'lsa, qayta ishlatamiz.
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

        # TOTP kalitini yaratish yoki mavjudini ishlatish.
        if session is None:
            secret = pyotp.random_base32()
        else:
            secret = session.totp_secret or pyotp.random_base32()

        iat, jwt_token, exp = create_token(telegram_id=telegram_id)

        # O'zimiz yaratgan JWT ichidan uning jti identifikatorini olamiz.
        token_jti = decode_token(jwt_token)["jti"]

        if session is None:
            session = await Session.objects.acreate(
                user=user,
                token_jti=token_jti,
                totp_secret=secret,
                iat=iat,
                exp=exp,
            )
        else:
            session.token_jti = token_jti
            session.totp_secret = secret
            session.iat = iat
            session.exp = exp

            await session.asave(
                update_fields=[
                    "token_jti",
                    "totp_secret",
                    "iat",
                    "exp",
                ]
            )

        # 60 soniyalik TOTP kodini yaratamiz.
        totp = pyotp.TOTP(secret, interval=OTP_INTERVAL)
        otp_code = totp.now()

        remaining = OTP_INTERVAL - (int(time.time()) % OTP_INTERVAL)

        await cache.aset(
            otp_cache_key,
            otp_code,
            timeout=remaining,
        )
        await cache.aset(
            jwt_cache_key,
            jwt_token,
            timeout=max(1, int(exp) - int(time.time())),
        )

        # Agar OTP orqali telegram_id qidirish ishlatilsa,
        # shu kesh yozuvi ham saqlanadi.
        await cache.aset(
            otp_code,
            str(telegram_id),
            timeout=OTP_INTERVAL,
        )

        return user, otp_code, jwt_token, False

    except Exception:
        logger.exception(
            "Sessiya yoki OTP yaratishda xato: telegram_id=%s",
            telegram_id,
        )
        return None, None, None, False
