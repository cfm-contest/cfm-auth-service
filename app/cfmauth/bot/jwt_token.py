
import time
import uuid
import jwt

from pathlib import Path
from django.conf import settings


PRIVATE_KEY = Path(settings.JWT_PRIVATE_KEY_PATH).read_text()
PUBLIC_KEY = Path(settings.JWT_PUBLIC_KEY_PATH).read_text()

ISSUER = "https://auth.cfm.uz"
AUDIENCE = "https://cfm.uz"
TOKEN_TTL = 90 * 24 * 60 * 60  # 90 kun

ALGORITHM = "RS256"


def create_token(telegram_id: int) -> tuple[int, str, int]:
    """
    JWT yaratadi.

    Qaytaradi:
        iat: token yaratilgan vaqt
        token: JWT satri
        exp: token muddati tugaydigan vaqt
    """
    now = int(time.time())
    exp = now + TOKEN_TTL

    payload = {
        "sub": str(telegram_id),
        "iat": now,
        "exp": exp,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "jti": str(uuid.uuid4()),
    }

    token = jwt.encode(
        payload,
        PRIVATE_KEY,
        algorithm=ALGORITHM,
        headers={"typ": "JWT"},
    )

    return now, token, exp


def decode_token(token: str) -> dict:
    """
    Token imzosini tekshirmasdan, faqat payload qismini o'qiydi.

    Faqat ma'lumotni ko'rish/debug uchun.
    Autentifikatsiya uchun ishlatmang.
    """
    return jwt.decode(
        token,
        options={
            "verify_signature": False,
            "verify_exp": False,
            "verify_iss": False,
            "verify_aud": False,
        },
        algorithms=[ALGORITHM],
    )


def verify_token(token: str) -> dict:
    """
    Token imzosi, muddati, issuer va audience qiymatlarini tekshiradi.
    Token yaroqsiz bo'lsa, PyJWT xato chiqaradi.
    """
    return jwt.decode(
        token,
        PUBLIC_KEY,
        algorithms=[ALGORITHM],
        issuer=ISSUER,
        audience=AUDIENCE,
        options={
            "require": [
                "sub",
                "iat",
                "exp",
                "iss",
                "aud",
                "jti",
            ],
        },
    )
