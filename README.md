# NeyronCode AI Analyzer

Python asosidagi lokal kod tahlili, xavfsizlik auditi va optimallashtirish dashboardi.

## Ishga Tushirish

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python app.py
```

Brauzerda oching:

```text
http://127.0.0.1:8000/login
```

## Login

```text
login: admin
parol: admin123
```

Login/parolni o'zgartirish:

```powershell
$env:NEYRON_USERNAME="admin"
$env:NEYRON_PASSWORD="yangi-parol"
python app.py
```

Sessiya cookie orqali yuradi. Kodlar, tahlil natijalari, history va oxirgi holat `data/store.json` faylida saqlanadi. Yangi yoki tozalangan ombor default demo ma'lumotlar bilan to'ldiriladi: `sample.py`, `security_demo.py`, `optimization_demo.py`.

## Imkoniyatlar

- Python kodidagi barcha topilgan xatolarni ro'yxat qilib chiqaradi.
- Har bir xato uchun qator raqami, xavf darajasi, izoh va yechim beradi.
- Sintaksis xatosi bo'lsa ham qo'shimcha heuristic tekshiruv bilan bir nechta muammoni ko'rsatadi.
- SQL injection, `eval`, `exec`, `shell=True`, hardcoded secret va debug rejimi kabi xavfsizlik risklarini topadi.
- Mutable default argument, wildcard import, debug `print`, `assert`, TODO/FIXME, uzun qator, trailing whitespace, tab indent va built-in nomlarni soya qilish kabi sifat muammolarini topadi.
- Kod sifati uchun 0-100 ball beradi.
- Optimallashtirish va o'qilishi osonroq variantlarni taklif qiladi.
- Topilmalarni `Critical`, `High`, `Medium`, `Low` bo'yicha filterlaydi.
- Hisobotni `JSON` yoki `Markdown` formatida export qiladi.
- Qilingan ishlar tarixini saqlaydi, yozuvni qayta ochadi, o'chiradi yoki butun tarixni tozalaydi.
- Ollama statusini tekshiradi va model tayyor yoki tayyor emasligini ko'rsatadi.

## Ollama AI Tavsiya

Ollama o'rnatilgan va ishlayotgan bo'lsa, tizim qoidaviy topilmalar ustiga AI tavsiya ham beradi.

1. Ollama'ni o'rnating: `https://ollama.com`
2. Modelni yuklang:

```powershell
ollama pull qwen2.5-coder
```

3. Ollama serverini ishga tushiring:

```powershell
ollama serve
```

4. NeyronCode'ni ishga tushiring:

```powershell
$env:NEYRON_MODEL="qwen2.5-coder"
$env:OLLAMA_HOST="http://localhost:11434"
$env:OLLAMA_TIMEOUT="20"
python app.py
```

Kod tahlili sahifasida `Ollama AI tavsiya` tugmasi yoqilgan bo'lsa, `/api/analyze` Ollama'dan AI tavsiya olib, `Hisobotlar` sahifasida ko'rsatadi. Ollama topilmasa, tizim qoidaviy tahlilni baribir chiqaradi.

## API

- `POST /api/login` - login qiladi.
- `POST /api/logout` - sessiyani tugatadi.
- `GET /api/me` - foydalanuvchi, state va history qaytaradi.
- `POST /api/analyze` - kodni tahlil qiladi va historyga saqlaydi.
- `GET /api/history` - saqlangan ishlarni qaytaradi.
- `POST /api/history/delete` - bitta history yozuvini o'chiradi.
- `POST /api/history/clear` - historyni tozalaydi.
- `GET /api/ollama/status` - Ollama serveri va model holatini tekshiradi.

## Requirements

`requirements.txt` bo'sh paketli loyiha sifatida qoldirilgan, chunki backend Python standard library bilan ishlaydi. Ollama Python paketi emas, alohida desktop/CLI dastur sifatida o'rnatiladi.
