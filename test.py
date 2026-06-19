import requests
import base64
import json

# Укажите вашу полную ссылку на подписку (с токеном/uuid)
URL = "https://sub.hazeevpn.com/9bc5SHMKupmS0-jS"

# Эмулируем заголовки. Если знаете точный User-Agent вашего приложения — впишите его сюда.
HEADERS = {
    "User-Agent": "Happ",
    "Accept": "application/json, text/plain, */*"
}

print(f"Отправка запроса на {URL}...")
try:
    response = requests.get(URL, headers=HEADERS, timeout=10)
    print(f"Статус ответа: {response.status_code}")
    print(f"Content-Type ответа: {response.headers.get('Content-Type')}\n")

    raw_data = response.text.strip()

    # 1. Проверяем, не пустой ли ответ
    if not raw_data:
        print("❌ Сервер вернул пустой ответ.")
        exit()

    # 2. Пробуем распарсить как обычный JSON
    try:
        parsed_json = json.loads(raw_data)
        print("✅ Получен чистый JSON:")
        print(json.dumps(parsed_json, indent=2, ensure_ascii=False))  # Выведем первые 2000 символов
    except json.JSONDecodeError:
        # 3. Если не JSON, возможно, бэкенд кодирует весь ответ в Base64 (стандарт для подписок)
        print("Строка не является JSON. Пробуем декодировать из Base64...")
        try:
            decoded_bytes = base64.b64decode(raw_data)
            decoded_str = decoded_bytes.decode('utf-8')
            parsed_json = json.loads(decoded_str)
            print("✅ Получен Base64, внутри оказался JSON:")
            print(json.dumps(parsed_json, indent=2, ensure_ascii=False))
        except Exception as b64_err:
            print(f"❌ Не удалось раскодировать как Base64 JSON. Сырой ответ сервера:\n{raw_data[:500]}")

except Exception as e:
    print(f"❌ Ошибка сетевого запроса: {e}")