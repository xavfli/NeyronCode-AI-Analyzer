# NeyronCode AI Analyzer

Python asosidagi lokal kod tahlili va optimallashtirish dashboardi.

## Ishga tushirish

```powershell
python app.py
```

Brauzerda oching:

```text
http://127.0.0.1:8000
```

## Login

Boshlang'ich login:

```text
login: admin
parol: admin123
```

O'zgartirish uchun serverni environment variable bilan ishga tushirish mumkin:

```powershell
$env:NEYRON_USERNAME="admin"
$env:NEYRON_PASSWORD="yangi-parol"
python app.py
```

Foydalanuvchi sessiyasi cookie orqali yuradi. Tahlil qilingan kodlar, natijalar va oxirgi holat `data/store.json` faylida saqlanadi.
Yangi yoki tozalangan ombor default demo ma'lumotlar bilan to'ldiriladi: `sample.py`, `security_demo.py`, `optimization_demo.py`.

## Imkoniyatlar

- Python kodini `ast` orqali sintaksis, murakkablik va sifat bo'yicha tekshiradi.
- SQL injection, `eval`, `exec`, `shell=True`, hardcoded secret, debug rejimi kabi xavfsizlik risklarini topadi.
- Kod sifati uchun 0-100 ball beradi.
- Oddiy avtomatik optimallashtirish parchalarini taklif qiladi.
- Ollama ishlayotgan bo'lsa, `qwen2.5-coder` modeli orqali qisqa neyron xulosa qo'shadi.

Ollama modeli nomini o'zgartirish:

```powershell
$env:NEYRON_MODEL="qwen2.5-coder"
python app.py
```
# NeyronCode-AI-Analyzer
