
import asyncio
import logging
from decouple import config

from aiogram import Bot, Dispatcher
from aiogram.enums import ParseMode
from aiogram.filters import Command
from aiogram.types import (
    KeyboardButton,
    Message,
    ReplyKeyboardMarkup,
    ReplyKeyboardRemove,
)

from cfmauth.models import BaseUser
from cfmauth.bot.session import create_or_get_session


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TOKEN = config("BOT_TOKEN")

dp = Dispatcher()

OTP_TTL = 60

contact_keyboard = ReplyKeyboardMarkup(
    keyboard=[
        [
            KeyboardButton(
                text="📱 Telefon raqamni yuborish",
                request_contact=True,
            )
        ]
    ],
    resize_keyboard=True,
    one_time_keyboard=True,
)


async def send_otp(message: Message, otp_code: str) -> None:
    first_name = message.from_user.first_name if message.from_user else "foydalanuvchi"
    text = (
        f"✅ Salom, <b>{first_name}</b>!\n\n"
        f"🔑 Sizning OTP kodingiz: <code>{otp_code}</code>\n\n"
        f"⏳ Kod <b>{OTP_TTL} soniya</b> amal qiladi.\n"
        "❗ Iltimos, bu kodni hech kimga bermang."
    )

    await message.answer(
        text,
        parse_mode=ParseMode.HTML,
    )


async def reply_cached_otp(message: Message) -> None:
    await message.answer(
        "⚠️ Siz uchun avval yaratilgan OTP kodi mavjud.\n"
        "⏳ Avval yuborilgan koddan foydalaning."
    )


@dp.message(Command("start"))
async def start_handler(message: Message) -> None:
    await message.answer(
        "👋 Salom! Ro‘yxatdan o‘tish uchun "
        "telefon raqamingizni yuboring 👇",
        reply_markup=contact_keyboard,
    )


@dp.message(lambda message: message.contact is not None)
async def contact_handler(message: Message) -> None:
    if message.from_user is None or message.contact is None:
        return

    # Faqat foydalanuvchining o'z kontaktini qabul qilish.
    if message.contact.user_id != message.from_user.id:
        await message.answer(
            "Iltimos, o‘z telefon raqamingizni yuboring.",
            reply_markup=contact_keyboard,
        )
        return

    telegram_id = message.from_user.id
    phone = message.contact.phone_number
    username = message.from_user.username or f"user{telegram_id}"

    full_name = (
        f"{message.contact.first_name or ''} "
        f"{message.contact.last_name or ''}"
    ).strip()

    if not full_name:
        full_name = message.from_user.full_name or username

    try:
        user, created = await BaseUser.objects.aget_or_create(
            telegram_id=telegram_id,
            defaults={
                "phone": phone,
                "full_name": full_name,
                "username": username,
            },
        )
    except Exception:
        logger.exception(
            "Foydalanuvchini saqlashda xato: telegram_id=%s",
            telegram_id,
        )
        await message.answer(
            "❌ Ro‘yxatdan o‘tishda xatolik yuz berdi. "
            "Keyinroq qayta urinib ko‘ring."
        )
        return

    if not created:
        user.phone = phone
        user.full_name = full_name
        user.username = username

        await user.asave(
            update_fields=["phone", "full_name", "username"],
        )

        await message.answer(
            f"👋 Salom, <b>{full_name}</b>!\n"
            "Siz avval ro‘yxatdan o‘tgansiz.\n"
            "🔑 Kirish uchun /login buyrug‘ini bosing.",
            parse_mode=ParseMode.HTML,
            reply_markup=ReplyKeyboardRemove(),
        )
        return

    # Sessiya faqat bir marta so'raladi.
    user, otp_code, jwt_token, is_cached = (
        await create_or_get_session(telegram_id)
    )

    if user is None or otp_code is None:
        await message.answer(
            "❌ Sessiya yoki OTP yaratilmadi. "
            "Iltimos, keyinroq qayta urinib ko‘ring.",
            reply_markup=ReplyKeyboardRemove(),
        )
        return

    await message.answer(
        "🎉 Ro‘yxatdan o‘tish muvaffaqiyatli yakunlandi!",
        reply_markup=ReplyKeyboardRemove(),
    )

    if is_cached:
        await reply_cached_otp(message)
    else:
        await send_otp(message, otp_code)


@dp.message(Command("login"))
async def login_handler(message: Message) -> None:
    if message.from_user is None:
        return

    telegram_id = message.from_user.id

    try:
        user = await BaseUser.objects.aget(
            telegram_id=telegram_id,
        )
    except BaseUser.DoesNotExist:
        await message.answer(
            "⚠️ Siz hali ro‘yxatdan o‘tmagansiz.\n"
            "❗ Avval /start buyrug‘i orqali ro‘yxatdan o‘ting."
        )
        return
    except Exception:
        logger.exception(
            "Foydalanuvchini tekshirishda xato: telegram_id=%s",
            telegram_id,
        )
        await message.answer(
            "❌ Xatolik yuz berdi. Keyinroq urinib ko‘ring."
        )
        return

    if not user.is_active:
        await message.answer("⛔ Hisobingiz bloklangan.")
        return

    user, otp_code, jwt_token, is_cached = (
        await create_or_get_session(telegram_id)
    )

    if user is None or otp_code is None:
        await message.answer(
            "❌ OTP yaratishda xatolik yuz berdi. "
            "Keyinroq qayta urinib ko‘ring."
        )
        return

    if is_cached:
        await reply_cached_otp(message)
    else:
        await send_otp(message, otp_code)


async def main() -> None:
    if not TOKEN:
        raise RuntimeError(
            "BOT_TOKEN topilmadi. Environment variable sozlang."
        )

    bot = Bot(token=TOKEN)

    try:
        await dp.start_polling(bot)
    finally:
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
