
from django.db import models


class BaseUser(models.Model):
    telegram_id = models.BigIntegerField(
        unique=True,
        verbose_name="Telegram ID",
        help_text="Telegram foydalanuvchisining noyob ID raqami",
    )

    username = models.CharField(
        max_length=255,
        blank=True,
        default="",
        verbose_name="Telegram username",
    )

    phone = models.CharField(
        max_length=32,
        blank=True,
        default="",
        verbose_name="Telefon raqami",
    )

    full_name = models.CharField(
        max_length=255,
        verbose_name="To‘liq ism",
    )

    is_active = models.BooleanField(
        default=True,
        db_index=True,
        verbose_name="Faolmi",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Yaratilgan vaqt",
    )

    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name="Oxirgi yangilanish",
    )

    class Meta:
        verbose_name = "Foydalanuvchi"
        verbose_name_plural = "Foydalanuvchilar"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.full_name} ({self.telegram_id})"


class Session(models.Model):
    id = models.BigAutoField(
        primary_key=True,
        verbose_name="Sessiya ID",
    )

    user = models.OneToOneField(
        BaseUser,
        on_delete=models.CASCADE,
        related_name="session",
        verbose_name="Foydalanuvchi",
    )

    # JWT uchun maxfiy imzo kaliti emas,
    # sessiyani aniqlash uchun noyob identifikator.
    token_jti = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        verbose_name="Token identifikatori",
    )

    # Faqat 2FA ishlatilganda kerak bo'ladi.
    # Haqiqiy TOTP kalitini himoyasiz saqlamang.
    totp_secret = models.CharField(
        max_length=255,
        blank=True,
        default="",
        verbose_name="Ikki bosqichli tasdiqlash kaliti",
    )

    iat = models.PositiveBigIntegerField(
        verbose_name="Token yaratilgan vaqt (Unix)",
    )

    exp = models.PositiveBigIntegerField(
        verbose_name="Token tugash vaqti (Unix)",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Sessiya yaratilgan vaqt",
    )

    last_login = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Oxirgi kirish vaqti",
    )

    class Meta:
        verbose_name = "Sessiya"
        verbose_name_plural = "Sessiyalar"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user} — sessiya #{self.pk}"
