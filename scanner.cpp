#include <iostream>
#include <string>
#include <vector>
#include <regex>
#include <algorithm>
#include <thread>
#include <mutex>
#include <queue>
#include <fstream>
#include <curl/curl.h>
#include "nlohmann/json.hpp"
using json = nlohmann::json;

std::queue<std::string> fuzz_queue;
std::mutex q_mtx;
std::vector<std::string> found_files;
std::mutex f_mtx;
std::vector<json> global_vulns;
std::mutex v_mtx;

struct HeaderData {
    bool csp = false, hsts = false, x_frame = false, x_content = false, xss_prot = false;
    bool has_cookies = false;
    bool referrer_policy = false, permissions_policy = false;
    bool cors_header = false; // Access-Control-Allow-Origin
    bool server_header = false; // Server version disclosure
    bool x_powered_by = false; // X-Powered-By disclosure
    std::string location_header = ""; // Для проверки открытых редиректов
    std::string cors_value = ""; // Значение CORS заголовка
    std::string server_value = ""; // Значение Server заголовка
    std::string x_powered_by_value = ""; // Значение X-Powered-By заголовка
    std::vector<std::string> cookie_headers; // Для анализа флагов cookie
};

// TLS Certificate info structure
struct TlsCertInfo {
    bool valid = true;
    std::string issuer;
    std::string subject;
    std::string expiry_date;
    bool self_signed = false;
    std::string error_msg;
};

size_t WriteCB(void* c, size_t s, size_t n, void* u) { 
    ((std::string*)u)->append((char*)c, s * n); 
    return s * n; 
}

size_t HeadCB(char* b, size_t s, size_t n, void* u) {
    HeaderData* hd = (HeaderData*)u;
    std::string h(b, s * n);
    std::string h_lower = h;
    std::transform(h_lower.begin(), h_lower.end(), h_lower.begin(), ::tolower);

    if (h_lower.find("set-cookie:") != std::string::npos) {
        hd->has_cookies = true;
        // Сохраняем cookie для анализа флагов
        size_t pos = h.find(':');
        if (pos != std::string::npos) {
            hd->cookie_headers.push_back(h.substr(pos + 1));
        }
    }
    if (h_lower.find("content-security-policy") != std::string::npos) hd->csp = true;
    if (h_lower.find("strict-transport-security") != std::string::npos) hd->hsts = true;
    if (h_lower.find("x-frame-options") != std::string::npos) hd->x_frame = true;
    if (h_lower.find("x-content-type-options") != std::string::npos) hd->x_content = true;
    if (h_lower.find("x-xss-protection") != std::string::npos) hd->xss_prot = true;
    if (h_lower.find("referrer-policy") != std::string::npos) hd->referrer_policy = true;
    if (h_lower.find("permissions-policy") != std::string::npos) hd->permissions_policy = true;
    if (h_lower.find("access-control-allow-origin") != std::string::npos) {
        hd->cors_header = true;
        size_t pos = h.find(':');
        if (pos != std::string::npos) {
            hd->cors_value = h.substr(pos + 1);
            // Trim
            hd->cors_value.erase(0, hd->cors_value.find_first_not_of(" \t\r\n"));
        }
    }
    if (h_lower.find("server:") == 0) {
        hd->server_header = true;
        size_t pos = h.find(':');
        if (pos != std::string::npos) {
            hd->server_value = h.substr(pos + 1);
            // Trim
            hd->server_value.erase(0, hd->server_value.find_first_not_of(" \t\r\n"));
        }
    }
    if (h_lower.find("x-powered-by:") == 0) {
        hd->x_powered_by = true;
        size_t pos = h.find(':');
        if (pos != std::string::npos) {
            hd->x_powered_by_value = h.substr(pos + 1);
            // Trim
            hd->x_powered_by_value.erase(0, hd->x_powered_by_value.find_first_not_of(" \t\r\n"));
        }
    }
    // Сохраняем Location для проверки открытых редиректов
    if (h_lower.find("location:") == 0) {
        hd->location_header = h.substr(h.find(':') + 1);
        hd->location_header.erase(0, hd->location_header.find_first_not_of(" \t\r\n"));
    }
    return n * s;
}

// Проверка текста на наличие уязвимостей
void analyze_content(const std::string& body, const std::string& source, bool is_file = false) {
    std::string b = body;
    std::transform(b.begin(), b.end(), b.begin(), ::tolower);

    std::lock_guard<std::mutex> lock(v_mtx);
    
    // === Детектор SQL-инъекций (расширенный) ===
    // Используем более специфичные паттерны для уменьшения ложных срабатываний
    std::vector<std::string> sqli_patterns = {
        "sql syntax error", "mysql_fetch_array", "mysql_fetch_row",
        "database error", "sql error", "warning: mysql_query",
        "unclosed quotation mark after the character string",
        "sqlstate[", "syntax error in sql expression",
        "ora-009", "ora-017", "postgresql error:",
        "sqlite3::databaseexception", "pdoexception: sqlstate",
        "mssql error:", "odbc drivers error",
        "jdbc sql exception", "you have an error in your sql syntax"
    };
    for (const auto& pattern : sqli_patterns) {
        if (b.find(pattern) != std::string::npos) {
            global_vulns.push_back({{"type", "SQL INJECTION"}, {"severity", "HARD"}, {"description", "Обнаружена ошибка БД (паттерн: '" + pattern + "') в: " + source}});
            return;
        }
    }

    // === Детектор XSS (отраженный ввод) ===
    // Проверяем только если payload был внедрён сканером
    std::vector<std::string> xss_patterns = {
        "<script>alert(1)</script>", "<script>alert('xss')</script>",
        "javascript:alert(1)", "onerror=\"alert(1)\"",
        "onload=\"alert(1)\"", "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>"
    };
    for (const auto& pattern : xss_patterns) {
        if (b.find(pattern) != std::string::npos) {
            global_vulns.push_back({{"type", "XSS (CROSS-SITE SCRIPTING)"}, {"severity", "HARD"}, {"description", "Обнаружен отражённый XSS вектор в: " + source}});
            return;
        }
    }

    // === Детектор утечки чувствительных данных ===
    if (is_file) {
        std::vector<std::string> secret_patterns = {
            "db_password=", "aws_access_key_id=", "aws_secret_access_key=",
            "api_key=", "secret_key=", "password=", "passwd=",
            "private_key=", "access_token=", "auth_token=",
            "connection_string=", "mongodb+srv://", "mysql://",
            "postgres://", "redis://:"
        };
        for (const auto& pattern : secret_patterns) {
            if (b.find(pattern) != std::string::npos) {
                global_vulns.push_back({{"type", "LEAKED CREDENTIALS"}, {"severity", "HARD"}, {"description", "В файле " + source + " найдены пароли или ключи!"}});
                return;
            }
        }
    }

    // === Детектор Command Injection ===
    // Только специфичные паттерны, исключающие нормальный контент
    std::vector<std::string> cmdi_patterns = {
        "root:x:0:0:", "daemon:x:", "bin:x:",
        "uid=0(root)", "gid=0(root)",
        "windows nt 10.0", "uname -a\nlinux",
        "/etc/passwd\nroot:", "/etc/shadow\nroot:"
    };
    for (const auto& pattern : cmdi_patterns) {
        if (b.find(pattern) != std::string::npos) {
            global_vulns.push_back({{"type", "COMMAND INJECTION"}, {"severity", "HARD"}, {"description", "Возможная Command Injection (паттерн: '" + pattern + "') в: " + source}});
            return;
        }
    }

    // === Детектор Directory Traversal ===
    // Только явные признаки чтения системных файлов
    std::vector<std::string> traversal_patterns = {
        "root:x:0:0:", "daemon:x:1:1:", "bin:x:2:2:",
        "c:\\windows\\system32\\config\\sam",
        "boot.ini", "documents and settings\\all users"
    };
    for (const auto& pattern : traversal_patterns) {
        if (b.find(pattern) != std::string::npos) {
            global_vulns.push_back({{"type", "DIRECTORY TRAVERSAL"}, {"severity", "HARD"}, {"description", "Обнаружена уязвимость Directory Traversal в: " + source}});
            return;
        }
    }

    // === Детектор Information Disclosure ===
    // Только явные ошибки и stack traces
    std::vector<std::string> info_patterns = {
        "stack trace:", "traceback (most recent call last)",
        "exception in thread", "fatal error: uncaught exception",
        "php fatal error:", "asp.net runtime error",
        "server error in '/' application",
        "java.lang.nullpointerexception", "system.argumentexception"
    };
    for (const auto& pattern : info_patterns) {
        if (b.find(pattern) != std::string::npos) {
            global_vulns.push_back({{"type", "INFORMATION DISCLOSURE"}, {"severity", "MEDIUM"}, {"description", "Раскрытие информации (паттерн: '" + pattern + "') в: " + source}});
            return;
        }
    }

    // === Детектор CSRF (улучшенный v2) ===
    // Проверяем формы, но учитываем альтернативные механизмы защиты
    if (b.find("<form") != std::string::npos) {
        bool has_csrf_protection = false;
        
        // 1. CSRF в HTML (input hidden)
        if (b.find("csrf") != std::string::npos ||
            b.find("_token") != std::string::npos ||
            b.find("authenticity_token") != std::string::npos) {
            has_csrf_protection = true;
        }
        
        // 2. CSRF в meta тегах
        if (b.find("<meta name=\"csrf-token\"") != std::string::npos ||
            b.find("<meta name='csrf-token'") != std::string::npos ||
            b.find("<meta name=\"x-csrf-token\"") != std::string::npos) {
            has_csrf_protection = true;
        }
        
        // 3. CSRF в JavaScript переменных
        if (b.find("window.csrf") != std::string::npos ||
            b.find("var csrf") != std::string::npos ||
            b.find("csrf_token") != std::string::npos ||
            b.find("x-csrf-token") != std::string::npos) {
            has_csrf_protection = true;
        }
        
        // 4. Формы без action (вероятно JS-обработка)
        if (b.find("<form") != std::string::npos && b.find("action=") == std::string::npos) {
            has_csrf_protection = true;
        }
        
        // 5. Формы с GET методом (не требуют CSRF защиты)
        if (b.find("<form") != std::string::npos && b.find("method=\"get\"") != std::string::npos) {
            has_csrf_protection = true;
        }
        if (b.find("<form") != std::string::npos && b.find("method='get'") != std::string::npos) {
            has_csrf_protection = true;
        }
        
        // 6. Формы с action на внешний домен (поиск, редиректы)
        if (b.find("<form") != std::string::npos && b.find("action=\"http") != std::string::npos) {
            has_csrf_protection = true;
        }
        
        // 7. Формы поиска (обычно GET и не требуют CSRF)
        if (b.find("<form") != std::string::npos && b.find("search") != std::string::npos) {
            has_csrf_protection = true;
        }
        
        if (!has_csrf_protection) {
            global_vulns.push_back({{"type", "CSRF (CROSS-SITE REQUEST FORGERY)"}, {"severity", "MEDIUM"}, {"description", "Обнаружена форма без CSRF токена в: " + source}});
        }
    }
}

void fuzz_worker(std::string base_url) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::lock_guard<std::mutex> lock(v_mtx);
        global_vulns.push_back({{"type", "SCANNER ERROR"}, {"severity", "INFO"}, {"description", "Не удалось инициализировать CURL в fuzz_worker"}});
        return;
    }
    
    while (true) {
        std::string p;
        {
            std::lock_guard<std::mutex> lock(q_mtx);
            if (fuzz_queue.empty()) {
                curl_easy_cleanup(curl); // Очищаем CURL при выходе
                return;
            }
            p = fuzz_queue.front(); fuzz_queue.pop();
        }
        // Убираем слэш в конце base_url, если он есть
if (!base_url.empty() && base_url.back() == '/') {
    base_url.pop_back();
}
std::string url = base_url + "/" + p;
        std::string res_body;

       
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCB);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res_body);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);

        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            long code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
            if (code == 200 || code == 403 || code == 301 || code == 302) {  // 403 тоже интересен - защищенный файл
                {
                    std::lock_guard<std::mutex> l(f_mtx);
                    found_files.push_back(p + " (HTTP " + std::to_string(code) + ")");
                }
                if (code == 200) {
                    analyze_content(res_body, p, true);
                }
            }
        }
        // Очищаем body для следующего запроса
        res_body.clear();
    }
    // Неreachable, но на всякий случай
    curl_easy_cleanup(curl);
}

int main(int argc, char* argv[]) {
    // Отключаем буферизацию, чтобы Python сразу получал вывод
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 4) {
        std::cout << "{\"error\": \"Usage: <target_url> <threads> <wordlist_path>\"}" << std::endl;
        return 1;
    }

    std::string target = argv[1];
    int threads = std::stoi(argv[2]);
    std::string w_path = argv[3];

    // 1. Проверка файла словаря (Фаззинг)
    std::ifstream f(w_path);
    if (!f.is_open()) {
        json err_res;
        err_res["error"] = "Wordlist file not found: " + w_path;
        std::cout << err_res.dump() << std::endl;
        return 1;
    }

    curl_global_init(CURL_GLOBAL_ALL);
    CURL* curl = curl_easy_init();
    if (!curl) return 1;

    HeaderData hd;
    std::string body;
    bool ssl_ok = true;
    TlsCertInfo cert_info;

    // 2. Настройка основного запроса С ПРОВЕРКОЙ SSL для получения инфо о сертификате
    curl_easy_setopt(curl, CURLOPT_URL, target.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCB);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeadCB);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &hd);
    
    // Маскируемся под браузер
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    // Сначала пробуем с проверкой SSL для получения информации о сертификате
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L); // Включаем получение информации о сертификате

    // Первый запрос для анализа заголовков и поиска ссылок
    CURLcode main_res = curl_easy_perform(curl);
    if (main_res != CURLE_OK) {
        ssl_ok = false;
        cert_info.valid = false;
        cert_info.error_msg = curl_easy_strerror(main_res);
        
        // Повторяем без проверки SSL для получения контента
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        body.clear();
        curl_easy_perform(curl);
    } else {
        // Получаем информацию о сертификате
        struct curl_certinfo *certinfo = nullptr;
        curl_easy_getinfo(curl, CURLINFO_CERTINFO, &certinfo);
        
        if (certinfo && certinfo->num_of_certs > 0) {
            // Берём первый сертификат (конечный)
            struct curl_slist *slist = certinfo->certinfo[0];
            while (slist) {
                std::string line = slist->data;
                if (line.find("Subject:") == 0) {
                    cert_info.subject = line.substr(8);
                } else if (line.find("Issuer:") == 0) {
                    cert_info.issuer = line.substr(7);
                } else if (line.find("Expire date:") == 0) {
                    cert_info.expiry_date = line.substr(12);
                } else if (line.find("Self-signed:") == 0) {
                    cert_info.self_signed = (line.find("TRUE") != std::string::npos);
                }
                slist = slist->next;
            }
            
            // Проверяем на self-signed
            if (cert_info.self_signed) {
                std::lock_guard<std::mutex> lock(v_mtx);
                global_vulns.push_back({{"type", "SELF-SIGNED CERTIFICATE"}, {"severity", "HARD"}, {"description", "Сертификат является самоподписанным"}});
            }
            
            // Проверяем issuer (если неизвестный CA)
            if (cert_info.issuer.find("Let's Encrypt") == std::string::npos &&
                cert_info.issuer.find("DigiCert") == std::string::npos &&
                cert_info.issuer.find("GlobalSign") == std::string::npos &&
                cert_info.issuer.find("Comodo") == std::string::npos &&
                cert_info.issuer.find("GoDaddy") == std::string::npos &&
                cert_info.issuer.find("Sectigo") == std::string::npos &&
                cert_info.issuer.find("Google") == std::string::npos &&
                cert_info.issuer.find("Cloudflare") == std::string::npos &&
                cert_info.issuer.empty() == false) {
                // Неизвестный CA - не обязательно уязвимость, но стоит отметить
            }
        }
    }

    // 3. Заполнение очереди для фаззинга
    std::string line;
    while (std::getline(f, line)) { 
        line.erase(line.find_last_not_of("\r\n\t")+1);
        line.erase(0, line.find_first_not_of("\r\n\t"));

        if(!line.empty()) fuzz_queue.push(line); 
    }
    f.close();

    // Запуск потоков фаззинга
    std::vector<std::thread> workers;
    for (int i = 0; i < threads; ++i) workers.emplace_back(fuzz_worker, target);
    for (auto& t : workers) t.join();

    // 4. Поиск векторов атак (параметры в ссылках)
    std::regex link_re(R"(href=["']([^"']+\?[^"']+)["'])");
    auto it = std::sregex_iterator(body.begin(), body.end(), link_re);
    std::vector<std::string> attack_vectors;
    for (; it != std::sregex_iterator(); ++it) {
        std::string link = (*it)[1].str();
        attack_vectors.push_back(link);
        
        CURL* t = curl_easy_init();
        if (!t) continue;
        std::string rb;
        std::string t_url = (link.find("http") == 0 ? link : target + "/" + link);
        
        curl_easy_setopt(t, CURLOPT_URL, t_url.c_str());
        curl_easy_setopt(t, CURLOPT_WRITEFUNCTION, WriteCB);
        curl_easy_setopt(t, CURLOPT_WRITEDATA, &rb);
        curl_easy_setopt(t, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(t, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(t, CURLOPT_TIMEOUT, 5L);
        
        if (curl_easy_perform(t) == CURLE_OK) analyze_content(rb, link);
        curl_easy_cleanup(t);
    }

    // 5. Анализ cookie на безопасность (Secure, HttpOnly, SameSite)
    // Улучшенная логика: флаг только если ВСЕ cookie без Secure/HttpOnly
    bool insecure_cookies = false;
    int total_cookies = hd.cookie_headers.size();
    int insecure_count = 0;
    
    for (const auto& cookie : hd.cookie_headers) {
        std::string c_lower = cookie;
        std::transform(c_lower.begin(), c_lower.end(), c_lower.begin(), ::tolower);
        bool has_secure = c_lower.find("secure") != std::string::npos;
        bool has_httponly = c_lower.find("httponly") != std::string::npos;
        
        // Считаем insecure только если нет обоих флагов
        if (!has_secure || !has_httponly) {
            insecure_count++;
        }
    }
    
    // Флаг только если >50% cookie insecure
    if (total_cookies > 0 && insecure_count > total_cookies / 2) {
        insecure_cookies = true;
    }
    
    if (insecure_cookies && hd.has_cookies) {
        std::lock_guard<std::mutex> lock(v_mtx);
        global_vulns.push_back({{"type", "INSECURE COOKIE"}, {"severity", "MEDIUM"}, {"description", "Большинство cookie без Secure/HttpOnly флагов (" + std::to_string(insecure_count) + "/" + std::to_string(total_cookies) + ")"}});
    }

    // 6. Проверка CORS конфигурации
    if (hd.cors_header) {
        if (hd.cors_value == "*" || hd.cors_value.find("http://") == 0) {
            std::lock_guard<std::mutex> lock(v_mtx);
            global_vulns.push_back({{"type", "CORS MISCONFIGURATION"}, {"severity", "MEDIUM"}, {"description", "Небезопасная CORS конфигурация: " + hd.cors_value}});
        }
    }

    // 7. Проверка раскрытия информации через заголовки
    // Не считаем уязвимостью, если заголовок не содержит версию
    // (например, "Server: gws" без версии - это не уязвимость)
    // Проверяем только если есть конкретная версия
    if (hd.server_header) {
        // Проверяем, содержит ли заголовок версию (например, "Apache/2.4.41")
        bool has_version = false;
        for (size_t i = 0; i < hd.server_value.length(); i++) {
            if (std::isdigit(hd.server_value[i])) {
                has_version = true;
                break;
            }
        }
        if (has_version) {
            std::lock_guard<std::mutex> lock(v_mtx);
            global_vulns.push_back({{"type", "INFORMATION DISCLOSURE"}, {"severity", "LOW"}, {"description", "Заголовок Server раскрывает версию веб-сервера: " + hd.server_value}});
        }
    }
    if (hd.x_powered_by) {
        std::lock_guard<std::mutex> lock(v_mtx);
        global_vulns.push_back({{"type", "INFORMATION DISCLOSURE"}, {"severity", "LOW"}, {"description", "Заголовок X-Powered-By раскрывает технологии"}});
    }

    // 8. Расчет рейтинга безопасности
    int score = 100;
    if (!ssl_ok) score -= 25;
    if (cert_info.self_signed) score -= 30;
    if (!cert_info.valid && !ssl_ok) score -= 10; // Не штрафуем дважды
    if (!hd.csp) score -= 15;
    if (!hd.hsts) score -= 15;
    if (!hd.x_frame) score -= 10;
    if (!hd.x_content) score -= 10;
    if (!hd.xss_prot) score -= 5;
    if (insecure_cookies && hd.has_cookies) score -= 10;
    if (hd.cors_header && (hd.cors_value == "*" || hd.cors_value.find("http://") == 0)) score -= 10;
    if (hd.server_header) score -= 5;
    if (hd.x_powered_by) score -= 5;
    
    score -= (std::min)(20, (int)found_files.size() * 5);
    for (const auto& vuln : global_vulns) {
        std::string sev = vuln.value("severity", "");
        if (sev == "HARD") score -= 25;
        else if (sev == "MEDIUM") score -= 15;
        else if (sev == "LOW") score -= 5;
    }

    // 6. Формирование финального JSON (со всеми нужными Flask-у ключами)
    json res;
    res["target_url"] = target;
    res["score"] = (std::max)(0, score);
    res["ssl_ok"] = ssl_ok;
    res["has_cookies"] = hd.has_cookies;
    res["files_found"] = found_files;
    res["attack_vectors"] = attack_vectors;
    res["vulnerabilities"] = global_vulns;
    res["checks"] = {
        {"CSP", hd.csp},
        {"HSTS", hd.hsts},
        {"X-Frame", hd.x_frame},
        {"X-Content", hd.x_content},
        {"XSS-Protection", hd.xss_prot},
        {"Referrer-Policy", hd.referrer_policy},
        {"Permissions-Policy", hd.permissions_policy},
        {"Secure Cookies", !insecure_cookies},
        {"Safe CORS", !(hd.cors_header && (hd.cors_value == "*" || hd.cors_value.find("http://") == 0))}
    };
    
    // Добавляем информацию о TLS сертификате
    res["tls_certificate"] = {
        {"valid", cert_info.valid},
        {"issuer", cert_info.issuer},
        {"subject", cert_info.subject},
        {"expiry_date", cert_info.expiry_date},
        {"self_signed", cert_info.self_signed}
    };
    
    // Вывод результата для Python
    std::cout << res.dump() << std::endl;

    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;
}