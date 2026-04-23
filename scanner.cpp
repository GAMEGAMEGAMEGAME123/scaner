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

    if (h_lower.find("set-cookie:") != std::string::npos) hd->has_cookies = true;
    if (h_lower.find("content-security-policy") != std::string::npos) hd->csp = true;
    if (h_lower.find("strict-transport-security") != std::string::npos) hd->hsts = true;
    if (h_lower.find("x-frame-options") != std::string::npos) hd->x_frame = true;
    if (h_lower.find("x-content-type-options") != std::string::npos) hd->x_content = true;
    if (h_lower.find("x-xss-protection") != std::string::npos) hd->xss_prot = true;
    return n * s;
}

// Проверка текста на наличие SQL-ошибок или утечек данных
void analyze_content(const std::string& body, const std::string& source, bool is_file = false) {
    std::string b = body;
    std::transform(b.begin(), b.end(), b.begin(), ::tolower);

    std::lock_guard<std::mutex> lock(v_mtx);
    
    // Детектор SQL-инъекций
    if (b.find("sql syntax") != std::string::npos || b.find("mysql_fetch") != std::string::npos || b.find("database error") != std::string::npos) {
        global_vulns.push_back({{"type", "SQL INJECTION"}, {"severity", "HARD"}, {"description", "Обнаружена ошибка БД в: " + source}});
    }

    // Детектор утечки чувствительных данных (Sensitive Data Exposure)
    if (is_file) {
        if (b.find("db_password") != std::string::npos || b.find("aws_key") != std::string::npos || b.find("api_key") != std::string::npos) {
            global_vulns.push_back({{"type", "LEAKED CREDENTIALS"}, {"severity", "HARD"}, {"description", "В файле " + source + " найдены пароли или ключи!"}});
        }
    }
}

void fuzz_worker(std::string base_url) {
    CURL* curl = curl_easy_init();
    if (!curl) return;
    while (true) {
        std::string p;
        { 
            std::lock_guard<std::mutex> lock(q_mtx); 
            if (fuzz_queue.empty()) break; 
            p = fuzz_queue.front(); fuzz_queue.pop(); 
        }
        std::string url = base_url + (p[0] == '/' ? "" : "/") + p;
        std::string res_body;
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCB);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res_body);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

        if (curl_easy_perform(curl) == CURLE_OK) {
            long code; curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
            if (code == 200) {
                {
                    std::lock_guard<std::mutex> l(f_mtx); 
                    found_files.push_back(p + " (HTTP 200)");
                }
                // Если нашли файл, проверяем его содержимое на секреты
                analyze_content(res_body, p, true);
            }
        }
    }
    curl_easy_cleanup(curl);
}

int main(int argc, char* argv[]) {
    if (argc < 4) return 1;
    std::string target = argv[1];
    int threads = std::stoi(argv[2]);
    std::string w_path = argv[3];

    curl_global_init(CURL_GLOBAL_ALL);
    CURL* curl = curl_easy_init();
    HeaderData hd; std::string body; bool ssl_ok = true;

    curl_easy_setopt(curl, CURLOPT_URL, target.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCB);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeadCB);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &hd);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

    if (curl_easy_perform(curl) != CURLE_OK) {
        ssl_ok = false;
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        body.clear(); curl_easy_perform(curl);
    }

    // Фаззинг (запускаем раньше для полноты отчета)
    std::ifstream f(w_path); std::string line;
    while (std::getline(f, line)) { if(!line.empty()) fuzz_queue.push(line); }
    std::vector<std::thread> workers;
    for (int i = 0; i < threads; ++i) workers.emplace_back(fuzz_worker, target);
    for (auto& t : workers) t.join();

    // Поиск векторов атак
    std::regex link_re(R"(href=["']([^"']+\?[^"']+)["'])");
    auto it = std::sregex_iterator(body.begin(), body.end(), link_re);
    std::vector<std::string> attack_vectors;
    for (; it != std::sregex_iterator(); ++it) {
        std::string link = (*it)[1].str(); 
        attack_vectors.push_back(link);
        
        CURL* t = curl_easy_init(); std::string rb;
        std::string t_url = (link.find("http") == 0 ? link : target + "/" + link) + "'";
        curl_easy_setopt(t, CURLOPT_URL, t_url.c_str());
        curl_easy_setopt(t, CURLOPT_WRITEFUNCTION, WriteCB);
        curl_easy_setopt(t, CURLOPT_WRITEDATA, &rb);
        curl_easy_setopt(t, CURLOPT_SSL_VERIFYPEER, 0L);
        if (curl_easy_perform(t) == CURLE_OK) analyze_content(rb, link);
        curl_easy_cleanup(t);
    }

    // --- РАСЧЕТ РЕЙТИНГА ---
    int score = 100;
    if (!ssl_ok) score -= 40;
    if (!hd.csp) score -= 20;
    if (!hd.hsts) score -= 20;
    if (!hd.x_frame) score -= 15;

    score -= (std::min)(50, (int)found_files.size() * 10);

    score -= (int)global_vulns.size() * 40;

    json res;
    res["target_url"] = target; 
    res["score"] = (std::max)(0, score);
    res["ssl_ok"] = ssl_ok; 
    res["has_cookies"] = hd.has_cookies;
    res["files_found"] = found_files;
    res["attack_vectors"] = attack_vectors; 
    res["vulnerabilities"] = global_vulns;
    res["checks"] = {{"CSP", hd.csp}, {"HSTS", hd.hsts}, {"X-Frame", hd.x_frame}, {"XSS-Protection", hd.xss_prot}};
    
    std::cout << res.dump() << std::endl;
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;
}