import os
import re
import json
import subprocess
from flask import Flask, render_template, request, jsonify, make_response
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCANNER_BINARY = os.path.join(BASE_DIR, "scanner.exe")

# Проверка наличия бинарника при старте
if not os.path.isfile(SCANNER_BINARY):
    print(f"⚠️ ВНИМАНИЕ: Сканер не найден: {SCANNER_BINARY}")
    print("   Скомпилируйте scanner.exe из scanner.cpp перед запуском.")

# Валидация URL для защиты от инъекций
def is_valid_url(url):
    """Проверка что URL безопасен для сканирования"""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        if not parsed.hostname:
            return False
        # Блокируем внутренние IP и localhost
        hostname = parsed.hostname.lower()
        blocked_hosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
        if hostname in blocked_hosts:
            return False
        if hostname.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                                '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                                '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')):
            return False
        # Проверка на опасные символы
        if re.search(r'[;|&$`\\]', url):
            return False
        return True
    except Exception:
        return False

def generate_text_report(data):
    """Генерация детального технического отчета со всеми блоками"""
    score = data.get('score', 0)
    vulns = data.get('vulnerabilities', [])
    
    if score >= 85: status = "ВЕЛИКОЛЕПНО"
    elif score >= 70: status = "БЕЗОПАСНО"
    elif score >= 40: status = "СРЕДНЯЯ ЗАЩИТА"
    else: status = "КРИТИЧЕСКИ УЯЗВИМО"

    report = []
    report.append("="*70)
    report.append(f"🛡  SECURITY MONKEY - ПОЛНЫЙ ТЕХНИЧЕСКИЙ АУДИТ")
    report.append(f"Цель: {data.get('target_url')} | {data.get('scan_date')}")
    report.append(f"Режим: {data.get('scan_mode', 'STANDARD')} | Рейтинг: {score}/100 [{status}]")
    report.append("="*70)
    
    # SSL
    ssl_ok = data.get('ssl_ok')
    report.append(f"\n[0] ШИФРОВАНИЕ И SSL: {'✅ Действителен' if ssl_ok else '❌ ОШИБКА: Невалидный сертификат'}")
    
    # HTTP Заголовки
    report.append("\n[1] АНАЛИЗ HTTP ЗАГОЛОВКОВ:")
    checks = data.get('checks', {})
    mapping = {
        "CSP": "Content-Security-Policy",
        "HSTS": "Strict-Transport-Security",
        "X-Frame": "X-Frame-Options",
        "X-Content": "X-Content-Type-Options",
        "XSS-Protection": "X-XSS-Protection",
        "Referrer-Policy": "Referrer-Policy",
        "Permissions-Policy": "Permissions-Policy"
    }
    for key, name in mapping.items():
        icon = "✅" if checks.get(key) else "❌"
        state = "НАЙДЕН" if checks.get(key) else "ОТСУТСТВУЕТ"
        report.append(f"  - {name}: {icon} {state}")

    # Cookies и Crawler
    report.append(f"\n[2] БЕЗОПАСНОСТЬ COOKIE: {'✅ Используются' if data.get('has_cookies') else 'ℹ️ Не обнаружены'}")

    vectors = data.get('attack_vectors', [])
    if vectors:
        report.append("\n[3] ВЕКТОРЫ АТАКИ (CRAWLER):")
        for v in vectors[:10]: # Выводим до 10 векторов
            report.append(f"  - Найден URL: {v}")

    # Скрытые файлы
    files = data.get('files_found', [])
    if files:
        report.append("\n[4] СКРЫТЫЕ ФАЙЛЫ (FUZZING):")
        for f in files:
            report.append(f"  - [!] ОБНАРУЖЕН ДОСТУП: {f}")

    # Уязвимости
    report.append("\n[!] ОБНАРУЖЕННЫЕ УЯЗВИМОСТИ:")
    if vulns:
        for i, v in enumerate(vulns, 1):
            report.append(f"  {i}. [{v.get('severity')}] {v.get('type')}: {v.get('description')}")
    elif score < 50:
        report.append("  ⚠️ ВНИМАНИЕ: Прямых инъекций не найдено, но сайт критически незащищен.")
    else:
        report.append("  ✅ Критических уязвимостей в коде страниц не обнаружено.")

    report.append("\n" + "="*70)
    report.append("ОТЧЕТ СФОРМИРОВАН SECURITY MONKEY ENGINE")
    return "\n".join(report)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url', '').strip()
    mode = request.form.get('mode', 'standard')
    
    # Валидация режима
    modes_config = {'quick': ('15', 'quick.txt'), 'standard': ('10', 'common.txt'), 'deep': ('25', 'full.txt')}
    if mode not in modes_config:
        return jsonify({"error": "Недопустимый режим сканирования"}), 400
    threads, wordlist = modes_config[mode]

    # Добавляем схему если нет
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Валидация URL
    if not is_valid_url(url):
        return jsonify({"error": "Недопустимый URL. Разрешены только внешние http/https сайты."}), 400

    try:
        # Проверка наличия бинарника
        if not os.path.isfile(SCANNER_BINARY):
            return jsonify({"error": f"Сканер не найден: {SCANNER_BINARY}. Скомпилируйте scanner.exe из scanner.cpp"}), 500
        
        process = subprocess.run([SCANNER_BINARY, url, threads, wordlist],
                                 capture_output=True, text=True, encoding='utf-8', errors='ignore',
                                 timeout=300)  # 5 минут таймаут
        data = None
        for line in process.stdout.splitlines():
            if line.strip().startswith('{'):
                data = json.loads(line)
                break
        
        if not data: return jsonify({"error": f"Движок не вернул данных: {process.stderr}"}), 500
        
        data['scan_mode'] = mode.upper()
        data['scan_date'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['text_report'] = generate_text_report(data)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/results')
def results():
    data = request.args.get('scan_data')
    if not data: return "Нет данных", 400
    return render_template('results.html', results=json.loads(data))

@app.route('/download_report', methods=['POST'])
def download_report():
    report = request.form.get('report_text', '')
    response = make_response(report)
    filename = f"security_report_{datetime.now().strftime('%H%M%S')}.txt"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    return response

if __name__ == '__main__':
    app.run(debug=True)