from flask import Flask, request, make_response
import sqlite3

app = Flask(__name__)

# База данных
conn = sqlite3.connect(':memory:', check_same_thread=False)
conn.execute("CREATE TABLE users (id INT, name TEXT)")
conn.execute("INSERT INTO users VALUES (1, 'Admin')")

@app.route('/')
def index():
    # Ставим куки максимально просто
    resp = make_response("<h1>Vulnerable Site</h1><a href='/search?id=1'>Search</a>")
    resp.set_cookie('auth_token', '12345-secret-token', path='/')
    return resp

@app.route('/search')
def search():
    user_id = request.args.get('id', '')
    # Специально выводим ошибку SQL прямо в текст страницы
    try:
        # УЯЗВИМОСТЬ: SQL Injection
        res = conn.execute(f"SELECT name FROM users WHERE id = {user_id}").fetchone()
        return f"User: {res[0] if res else 'None'}"
    except Exception as e:
        # Это именно то, что ищет твой сканер (текст ошибки)
        return f"SQL Error: {str(e)}", 200 

if __name__ == '__main__':
    app.run(port=5001)