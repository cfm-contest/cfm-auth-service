from django.contrib import admin

# Register your models here.
from .models import BaseUser, Session

admin.site.register(BaseUser)
admin.site.register(Session)
