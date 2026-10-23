import asyncio
from decouple import config

from django.core.management.base import BaseCommand, CommandError
from aiogram import Bot

from cfmauth.bot.main import dp

class Command(BaseCommand):
    help = "Telegram botni polling rejimida ishga tushirish"

    def handle(self, *args, **options):
        token = config("BOT_TOKEN")

        if not token:
            raise CommandError("BOT_TOKEN environment variable topilmadi")

        try:
            asyncio.run(self.run_bot(token))
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING("Bot to‘xtatildi."))

    async def run_bot(self, token):
        bot = Bot(token=token)

        try:
            self.stdout.write(self.style.SUCCESS("Telegram bot ishga tushdi!"))
            await dp.start_polling(bot)
        finally:
            await bot.session.close()
