from django_bolt import BoltAPI

api = BoltAPI()

from cfmauth.api import api as auth_api

api.include_router(auth_api, prefix="/api/v1")
