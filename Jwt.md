```bash
mkdir -p secrets
chmod 700 secrets

openssl genrsa \
  -out secrets/jwt_private.pem 3072

openssl rsa \
  -in secrets/jwt_private.pem \
  -pubout \
  -out secrets/jwt_public.pem

chmod 600 secrets/jwt_private.pem
chmod 644 secrets/jwt_public.pem
```
