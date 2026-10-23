import re
import logging
from typing import Annotated

import msgspec
from django_bolt import Router, Request, rate_limit
from django_bolt.param_functions import Form
from django_bolt.exceptions import Forbidden
from django.core.cache import cache
from django.utils import timezone

from cfmauth.models import BaseUser, Session
from cfmauth.bot.jwt_token import verify_token


logger = logging.getLogger(__name__)

api = Router(tags=["cfm-auth"])


class OtpForm(msgspec.Struct):
    otp: Annotated[str, msgspec.Meta(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")]

@api.post("/login")
@rate_limit(rps=10, burst=20)
async def login_otp(
    request: Request,
    form: Annotated[OtpForm, Form()],
):
    # 1. OTP formatini tekshirish
    otp = form.otp.strip()

    if not re.fullmatch(r"[0-9]{6}", otp):
        raise Forbidden(detail="OTP 6 xonali raqam bo‘lishi kerak")

    # 2. OTP orqali Telegram ID ni olish
    try:
        telegram_id = await cache.aget(otp)
    except Exception:
        logger.exception("OTP keshini o‘qishda xato")
        raise Forbidden(detail="Autentifikatsiya xatosi")

    if telegram_id is None:
        raise Forbidden(detail="OTP noto‘g‘ri yoki muddati tugagan")

    try:
        telegram_id = int(telegram_id)
    except (ValueError, TypeError):
        logger.warning("OTP uchun noto‘g‘ri Telegram ID")
        raise Forbidden(detail="OTP noto‘g‘ri")

    # 3. Foydalanuvchini tekshirish
    try:
        user = await BaseUser.objects.aget(
            telegram_id=telegram_id,
        )
    except BaseUser.DoesNotExist:
        raise Forbidden(detail="Foydalanuvchi topilmadi")

    if not user.is_active:
        raise Forbidden(detail="Foydalanuvchi bloklangan")

    # 4. Sessiyani olish
    try:
        session = await Session.objects.aget(user_id=user.pk)
    except Session.DoesNotExist:
        raise Forbidden(detail="Faol sessiya topilmadi")

    # 5. Keshdan JWT olish
    try:
        jwt_token = await cache.aget(f"jwt:{telegram_id}")
    except Exception:
        logger.exception("JWT keshini o‘qishda xato")
        raise Forbidden(detail="Autentifikatsiya xatosi")

    if not jwt_token:
        raise Forbidden(detail="Token topilmadi, qayta login qiling")

    # 6. JWT imzosi, muddati, issuer va audience ni tekshirish
    try:
        payload = verify_token(jwt_token)
    except Exception:
        logger.warning(
            "JWT tekshiruvi muvaffaqiyatsiz: telegram_id=%s",
            telegram_id,
        )
        raise Forbidden(detail="JWT noto‘g‘ri yoki muddati tugagan")

    # 7. JWT foydalanuvchiga tegishliligini tekshirish
    if payload.get("sub") != str(telegram_id):
        raise Forbidden(detail="Token boshqa foydalanuvchiga tegishli")

    # 8. JWT jti ni DB dagi sessiya bilan solishtirish
    if not session.token_jti or payload.get("jti") != session.token_jti:
        raise Forbidden(detail="Sessiya bekor qilingan yoki token eskirgan")

    # 9. DB dagi sessiya muddati ham tekshirilsin
    if session.exp <= int(timezone.now().timestamp()):
        raise Forbidden(detail="Sessiya muddati tugagan")

    # 10. Oxirgi kirish vaqtini saqlash
    session.last_login = timezone.now()
    await session.asave(update_fields=["last_login"])

    # 11. OTP ni bir martalik ishlatish uchun o‘chirish
    try:
        await cache.adelete(otp)
        await cache.adelete(f"otp_code:{telegram_id}")
    except Exception:
        logger.exception("OTP keshini o‘chirishda xato")
        # OTP o‘chmay qolsa, loginni muvaffaqiyatli deb qaytarmang.
        raise Forbidden(detail="OTP ni yakunlashda xato")

    # 12. Frontendga javob
    return {
        "t": jwt_token,
        "u": {
            "id": user.telegram_id,
            "u": user.username,
            "p": user.phone,
            "f": user.full_name,
            "l": (
                session.last_login.isoformat()
                if session.last_login
                else None
            ),
        },
    }



# # =========================================================
# # Pydantic schema
# # =========================================================

# class OTPSchema(BaseModel):
#     otp: str

#     @model_validator(mode="before")
#     @classmethod
#     def validate_entire_input(cls, data: Any) -> Any:
#         if not isinstance(data, dict) or "otp" not in data:
#             raise ValueError(
#                 "Yuborilgan ma'lumotlar formati noto'g'ri. "
#                 "'otp' maydoni majburiy!"
#             )

#         otp = str(data["otp"])

#         if not otp.isdigit() or len(otp) != 6:
#             raise ValueError(
#                 "OTP kodi aniq 6 xonali raqam bo'lishi kerak!"
#             )

#         return data


# @web.middleware
# async def cors_middleware(
#     request: web.Request,
#     handler: Any,
# ) -> web.Response:
#     origin = request.headers.get("Origin", "")

#     origin_allowed = (
#         _CORS["allow_all"]
#         or origin in _CORS["origins"]
#     )

#     allowed_origin = (
#         "*"
#         if _CORS["allow_all"]
#         else origin if origin_allowed else ""
#     )

#     if request.method == "OPTIONS":
#         if not origin_allowed:
#             return web.Response(status=403)

#         return web.Response(
#             status=204,
#             headers={
#                 "Access-Control-Allow-Origin": allowed_origin,
#                 "Access-Control-Allow-Methods": _CORS["methods"],
#                 "Access-Control-Allow-Headers": _CORS["headers"],
#                 "Access-Control-Max-Age": _CORS["max_age"],
#             },
#         )

#     response = await handler(request)

#     if origin_allowed and allowed_origin:
#         response.headers["Access-Control-Allow-Origin"] = allowed_origin
#         response.headers["Access-Control-Allow-Methods"] = _CORS["methods"]
#         response.headers["Access-Control-Allow-Headers"] = _CORS["headers"]

#     return response


# # =========================================================
# # Rate limit middleware
# # =========================================================

# @web.middleware
# async def rate_limit_middleware(
#     request: web.Request,
#     handler: Any,
# ) -> web.Response:
#     ip = request.remote or "unknown"
#     key = f"rate:{ip}:{request.path}:{request.method}"

#     try:
#         count, _ = await get_cache(key)

#         if count is None:
#             await set_cache(key, 1, RATE_LIMIT_WINDOW)

#         elif int(count) >= RATE_LIMIT_REQUESTS:
#             return web.json_response(
#                 {"error": "Too many requests"},
#                 status=429,
#             )

#         else:
#             await set_cache(
#                 key,
#                 int(count) + 1,
#                 RATE_LIMIT_WINDOW,
#             )

#     except Exception:
#         # Kesh ishlamasa, xatoni log qilamiz.
#         # Bu variantda so'rovni davom ettirish siyosati saqlanadi.
#         logger.exception("Rate limit kesh xatosi")

#     return await handler(request)

# @web.middleware
# async def auth_middleware(
#     request: web.Request,
#     handler: Any,
# ) -> web.Response:
#     if request.path not in _PROTECTED_PATHS:
#         return await handler(request)

#     auth_header = request.headers.get("Authorization", "")
#     parts = auth_header.split()

#     if len(parts) != 2 or parts[0].lower() != "bearer":
#         return web.json_response(
#             {"error": "Token kerak"},
#             status=401,
#         )

#     try:
#         payload = await verify_token(parts[1])

#     except Exception:
#         logger.exception("Token tekshirishda xato")
#         return web.json_response(
#             {"error": "Token tekshirishda xato"},
#             status=401,
#         )

#     if not payload:
#         return web.json_response(
#             {"error": "Token noto'g'ri yoki eskirgan"},
#             status=401,
#         )

#     telegram_id = payload.get("telegram_id")

#     if telegram_id is None:
#         return web.json_response(
#             {"error": "Token ichida foydalanuvchi ID mavjud emas"},
#             status=401,
#         )

#     request["telegram_id"] = telegram_id

#     return await handler(request)


# # =========================================================
# # Health check
# # =========================================================

# async def health_check(request: web.Request) -> web.Response:
#     return web.json_response({"status": "ok"})


# # =========================================================
# # OTP login
# # =========================================================

# async def otp_login(request: web.Request) -> web.Response:
#     try:
#         body = await request.json()

#     except Exception:
#         return web.json_response(
#             {"error": "JSON formatda yuborilishi kerak"},
#             status=400,
#         )

#     try:
#         payload = OTPSchema.model_validate(body)

#     except ValidationError as exc:
#         errors = exc.errors()

#         error_msg = (
#             errors[0].get("msg", "Validatsiya xatosi yuz berdi")
#             if errors
#             else "Kiritilgan ma'lumotlar noto'g'ri"
#         )

#         if error_msg.startswith("Value error, "):
#             error_msg = error_msg.removeprefix("Value error, ")

#         return web.json_response(
#             {"error": error_msg},
#             status=422,
#         )

#     otp = payload.otp
#     ip = request.remote or "unknown"
#     try:
#         telegram_id, _ = await get_cache(otp)

#     except Exception:
#         logger.exception("OTP keshini o'qishda xato")
#         return web.json_response(
#             {"error": "Ichki xato, qayta urinib ko'ring"},
#             status=500,
#         )

#     if telegram_id is None:
#         return web.json_response(
#             {"error": "OTP eskirgan yoki noto'g'ri"},
#             status=400,
#         )

#     # -----------------------------------------------------
#     # Foydalanuvchi va sessiyani tekshirish
#     # -----------------------------------------------------

#     try:
#         user = await User.get_or_none(
#             telegram_id=telegram_id,
#         )

#         if user is None:
#             return web.json_response(
#                 {"error": "Foydalanuvchi topilmadi"},
#                 status=404,
#             )

#         if not user.is_active:
#             return web.json_response(
#                 {"error": "Foydalanuvchi bloklangan"},
#                 status=403,
#             )

#         session = await Session.get_or_none(
#             user_id=user.id,
#         )

#         if session is None:
#             return web.json_response(
#                 {"error": "Sessiya topilmadi"},
#                 status=404,
#             )

#     except OperationalError:
#         logger.exception("Ma'lumotlar bazasi xatosi")
#         return web.json_response(
#             {"error": "Ma'lumotlar bazasi xatosi"},
#             status=503,
#         )

#     except Exception:
#         logger.exception("Foydalanuvchini tekshirishda xato")
#         return web.json_response(
#             {"error": "Ichki xato"},
#             status=500,
#         )

#     # -----------------------------------------------------
#     # JWT token olish yoki yaratish
#     # -----------------------------------------------------

#     try:
#         jwt_token, _ = await get_cache(
#             f"jwt:{telegram_id}",
#         )

#         if not jwt_token:
#             iat, jwt_token, exp = create_token(
#                 user.telegram_id,
#             )

#             session.iat = iat
#             session.exp = exp
#             await session.save()

#     except Exception:
#         logger.exception("JWT yaratishda xato")
#         return web.json_response(
#             {"error": "Token yaratishda xato"},
#             status=500,
#         )

#     # -----------------------------------------------------
#     # OTP keshini tozalash
#     # -----------------------------------------------------

#     try:
#         await delete_cache(
#             otp,
#             otp_attempt_key,
#             f"jwt:{telegram_id}",
#             f"otp_code:{telegram_id}",
#         )

#     except Exception:
#         logger.exception("Kesh tozalashda xato")

#     # -----------------------------------------------------
#     # Javob
#     # -----------------------------------------------------

#     return web.json_response(
#         {
#             "t": jwt_token,
#             "u": {
#                 "id": user.telegram_id,
#                 "u": user.username,
#                 "p": user.phone,
#                 "f": user.full_name,
#                 "l": str(session.last_login),
#             },
#         }
#     )


# # =========================================================
# # Get current user
# # =========================================================

# async def get_user(request: web.Request) -> web.Response:
#     try:
#         user = await User.get_or_none(
#             telegram_id=request["telegram_id"],
#         )

#         if user is None:
#             return web.json_response(
#                 {"error": "Foydalanuvchi topilmadi"},
#                 status=404,
#             )

#         session = await Session.get_or_none(
#             user_id=user.id,
#         )

#         last_login = (
#             str(session.last_login)
#             if session is not None
#             else None
#         )

#     except OperationalError:
#         logger.exception("get_user: ma'lumotlar bazasi xatosi")
#         return web.json_response(
#             {"error": "Ma'lumotlar bazasi xatosi"},
#             status=503,
#         )

#     except Exception:
#         logger.exception("get_user: kutilmagan xato")
#         return web.json_response(
#             {"error": "Ichki xato"},
#             status=500,
#         )

#     return web.json_response(
#         {
#             "id": user.telegram_id,
#             "u": user.username,
#             "p": user.phone,
#             "f": user.full_name,
#             "l": last_login,
#         }
#     )


# # =========================================================
# # Verify token
# # =========================================================

# async def verify(request: web.Request) -> web.Response:
#     return web.Response(status=200)


# # =========================================================
# # Application
# # =========================================================

# app = web.Application(
#     middlewares=[
#         error_middleware,
#         cors_middleware,
#         rate_limit_middleware,
#         auth_middleware,
#     ]
# )

# app.add_routes(
#     [
#         web.get("/", health_check),
#         web.post("/api/login", otp_login),
#         web.get("/api/user", get_user),
#         web.get("/api/verify", verify),
#     ]
# )


# # =========================================================
# # Database initialization
# # =========================================================

# async def init_db() -> None:
#     ssl_ctx = (
#         ssl.create_default_context()
#         if DB_SSL
#         else False
#     )

#     await Tortoise.init(
#         config={
#             "connections": {
#                 "default": {
#                     "engine": "tortoise.backends.asyncpg",
#                     "credentials": {
#                         "host": DB_HOST,
#                         "port": DB_PORT,
#                         "user": DB_USER,
#                         "password": DB_PASSWORD,
#                         "database": DB_DATABASE,
#                         "ssl": ssl_ctx,
#                     },
#                 }
#             },
#             "apps": {
#                 "models": {
#                     "models": ["utils.database"],
#                     "default_connection": "default",
#                 }
#             },
#         }
#     )

#     await Tortoise.generate_schemas()
#     logger.info("Ma'lumotlar bazasiga ulanish muvaffaqiyatli.")
