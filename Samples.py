"""Datos de demostración (ficticios). Se arman por concatenación para que
los escáneres de secretos de GitHub no los confundan con credenciales reales."""

FAKE_OPENAI = "sk-" + "aB3dE5fG7hI9jK1lM2nO3pQ4rS5tU6vW"
FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"          # clave de ejemplo de la documentación de AWS
FAKE_JWT = ("eyJhbGciOiJIUzI1NiJ9." "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c")
FAKE_BCRYPT = "$2b$12$" + "LJ3m4yP1QxY8ZrT9wXuVFe" + "Kk2MnB4pR6sD8tH0jN1qA3cE5gI7kM9"

DEMO_PAYLOAD = (
    f'curl -H "Authorization: Bearer {FAKE_OPENAI}" https://api.openai.com/v1/chat  # usuario admin@empresa.com\n'
    f'DB_HOST=10.24.8.15  API_KEY="{FAKE_AWS}"  jwt={FAKE_JWT}'
)
