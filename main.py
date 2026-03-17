from fastapi.responses import HTMLResponse
from typing import Optional, Dict, List

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import bcrypt
import jwt
import time
import uuid

app = FastAPI(
    title="Auth System API",
    description="Собственная система аутентификации и авторизации",
    version="1.0.0"
)

SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
TOKEN_LIFETIME_SECONDS = 3600

security = HTTPBearer()

users: Dict[int, dict] = {}
user_roles: Dict[int, str] = {}
sessions: Dict[str, dict] = {}

access_rules = {
    "admin": {
        "products": ["read", "create", "update", "delete"],
        "access_rules": ["read", "update"]
    },
    "user": {
        "products": ["read", "create"]
    }
}

products = [
    {"id": 1, "name": "Product 1", "owner_id": 1},
    {"id": 2, "name": "Product 2", "owner_id": 2}
]


class RegisterRequest(BaseModel):
    last_name: str
    first_name: str
    middle_name: Optional[str] = None
    email: EmailStr
    password: str
    password_repeat: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UpdateProfileRequest(BaseModel):
    last_name: Optional[str] = None
    first_name: Optional[str] = None
    middle_name: Optional[str] = None
    email: Optional[EmailStr] = None


class CreateProductRequest(BaseModel):
    name: str


class SetRoleRequest(BaseModel):
    user_id: int
    role: str


class MessageResponse(BaseModel):
    message: str


class RegisterResponse(BaseModel):
    message: str
    user_id: int


class LoginResponse(BaseModel):
    token: str


class UserResponse(BaseModel):
    id: int
    last_name: str
    first_name: str
    middle_name: Optional[str] = None
    email: EmailStr
    is_active: bool
    role: str


class ProductResponse(BaseModel):
    id: int
    name: str
    owner_id: int


def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def check_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)


def create_token(user_id: int) -> str:
    jti = str(uuid.uuid4())
    payload = {
        "sub": str(user_id),
        "jti": jti,
        "exp": int(time.time()) + TOKEN_LIFETIME_SECONDS
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    sessions[jti] = {
        "user_id": user_id,
        "is_revoked": False
    }

    return token


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
        jti = payload["jti"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    session = sessions.get(jti)
    if not session or session["is_revoked"]:
        raise HTTPException(status_code=401, detail="Session is invalid or revoked")

    user = users.get(user_id)
    if not user or not user["is_active"]:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    return user, jti


def check_permission(user: dict, resource: str, action: str):
    role = user_roles.get(user["id"], "user")
    permissions = access_rules.get(role, {}).get(resource, [])

    if action not in permissions:
        raise HTTPException(status_code=403, detail="Forbidden")


from fastapi.responses import HTMLResponse

@app.get("/", response_class=HTMLResponse, tags=["UI"])
def ui():
    return """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Auth System UI</title>
        <style>
            * {
                box-sizing: border-box;
            }

            body {
                margin: 0;
                font-family: Inter, Arial, sans-serif;
                background:
                    radial-gradient(circle at top left, rgba(124, 58, 237, 0.18), transparent 30%),
                    radial-gradient(circle at top right, rgba(59, 130, 246, 0.18), transparent 30%),
                    linear-gradient(135deg, #0f172a, #111827 45%, #1e293b);
                color: #e5e7eb;
                min-height: 100vh;
                padding: 32px 16px;
            }

            .container {
                max-width: 1180px;
                margin: 0 auto;
            }

            .hero {
                display: grid;
                grid-template-columns: 1.2fr 0.8fr;
                gap: 20px;
                margin-bottom: 24px;
            }

            .hero-card,
            .status-card,
            .card,
            .output-card {
                background: rgba(15, 23, 42, 0.72);
                border: 1px solid rgba(255, 255, 255, 0.08);
                backdrop-filter: blur(14px);
                -webkit-backdrop-filter: blur(14px);
                border-radius: 24px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.35);
            }

            .hero-card {
                padding: 28px;
                position: relative;
                overflow: hidden;
            }

            .hero-card::after {
                content: "";
                position: absolute;
                width: 220px;
                height: 220px;
                right: -60px;
                top: -60px;
                background: radial-gradient(circle, rgba(59, 130, 246, 0.35), transparent 70%);
                pointer-events: none;
            }

            .status-card {
                padding: 24px;
                display: flex;
                flex-direction: column;
                justify-content: space-between;
            }

            .eyebrow {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                padding: 8px 12px;
                border-radius: 999px;
                background: rgba(59, 130, 246, 0.14);
                color: #93c5fd;
                font-size: 13px;
                font-weight: 600;
                margin-bottom: 18px;
                width: fit-content;
            }

            h1 {
                margin: 0 0 10px;
                font-size: 40px;
                line-height: 1.05;
                letter-spacing: -0.02em;
                color: #f8fafc;
            }

            .subtitle {
                margin: 0;
                color: #cbd5e1;
                font-size: 16px;
                line-height: 1.6;
                max-width: 760px;
            }

            .chips {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                margin-top: 20px;
            }

            .chip {
                padding: 8px 12px;
                border-radius: 999px;
                font-size: 13px;
                color: #dbeafe;
                background: rgba(59, 130, 246, 0.12);
                border: 1px solid rgba(147, 197, 253, 0.18);
            }

            .status-title {
                margin: 0 0 12px;
                font-size: 18px;
                color: #f8fafc;
            }

            .status-box {
                border-radius: 18px;
                padding: 16px;
                background: rgba(255, 255, 255, 0.04);
                border: 1px solid rgba(255, 255, 255, 0.06);
                margin-bottom: 16px;
            }

            .status-label {
                font-size: 13px;
                color: #94a3b8;
                margin-bottom: 6px;
            }

            .status-value {
                font-size: 16px;
                font-weight: 700;
                color: #f8fafc;
                word-break: break-word;
            }

            .token-preview {
                font-size: 12px;
                color: #93c5fd;
                margin-top: 8px;
                word-break: break-all;
            }

            .grid {
                display: grid;
                grid-template-columns: repeat(12, 1fr);
                gap: 20px;
                margin-bottom: 24px;
            }

            .card {
                padding: 22px;
            }

            .span-4 { grid-column: span 4; }
            .span-6 { grid-column: span 6; }
            .span-8 { grid-column: span 8; }
            .span-12 { grid-column: span 12; }

            .card h2 {
                margin: 0 0 8px;
                font-size: 22px;
                color: #f8fafc;
            }

            .card p {
                margin: 0 0 18px;
                color: #94a3b8;
                font-size: 14px;
                line-height: 1.5;
            }

            .field-group {
                display: grid;
                gap: 12px;
            }

            .field-row {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 12px;
            }

            label {
                display: block;
                font-size: 13px;
                color: #cbd5e1;
                margin-bottom: 6px;
                font-weight: 600;
            }

            input {
                width: 100%;
                padding: 14px 14px;
                border-radius: 14px;
                border: 1px solid rgba(255, 255, 255, 0.08);
                background: rgba(255, 255, 255, 0.04);
                color: #f8fafc;
                outline: none;
                transition: 0.2s ease;
                font-size: 14px;
            }

            input::placeholder {
                color: #64748b;
            }

            input:focus {
                border-color: rgba(96, 165, 250, 0.8);
                box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.16);
                background: rgba(255, 255, 255, 0.06);
            }

            .btn-row {
                display: flex;
                flex-wrap: wrap;
                gap: 12px;
                margin-top: 18px;
            }

            button {
                border: none;
                border-radius: 14px;
                padding: 14px 18px;
                font-size: 14px;
                font-weight: 700;
                cursor: pointer;
                transition: transform 0.15s ease, opacity 0.15s ease, box-shadow 0.2s ease;
            }

            button:hover {
                transform: translateY(-1px);
            }

            button:active {
                transform: translateY(0);
            }

            .btn-primary {
                color: white;
                background: linear-gradient(135deg, #2563eb, #7c3aed);
                box-shadow: 0 10px 24px rgba(37, 99, 235, 0.28);
            }

            .btn-secondary {
                color: #e2e8f0;
                background: rgba(255, 255, 255, 0.06);
                border: 1px solid rgba(255, 255, 255, 0.08);
            }

            .btn-danger {
                color: white;
                background: linear-gradient(135deg, #dc2626, #ea580c);
                box-shadow: 0 10px 24px rgba(220, 38, 38, 0.24);
            }

            .btn-success {
                color: white;
                background: linear-gradient(135deg, #059669, #0ea5e9);
                box-shadow: 0 10px 24px rgba(5, 150, 105, 0.24);
            }

            .output-card {
                padding: 22px;
            }

            .output-head {
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 12px;
                margin-bottom: 14px;
                flex-wrap: wrap;
            }

            .output-head h2 {
                margin: 0;
                color: #f8fafc;
                font-size: 22px;
            }

            .mini-actions {
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
            }

            .mini-btn {
                padding: 10px 14px;
                border-radius: 12px;
                font-size: 13px;
            }

            pre {
                margin: 0;
                padding: 20px;
                border-radius: 18px;
                background: #020617;
                color: #c4f1ff;
                overflow: auto;
                min-height: 260px;
                border: 1px solid rgba(255, 255, 255, 0.08);
                font-size: 13px;
                line-height: 1.5;
                white-space: pre-wrap;
                word-break: break-word;
            }

            .hint {
                margin-top: 10px;
                color: #64748b;
                font-size: 12px;
            }

            .footer-note {
                margin-top: 18px;
                color: #64748b;
                font-size: 12px;
                text-align: center;
            }

            @media (max-width: 980px) {
                .hero {
                    grid-template-columns: 1fr;
                }

                .span-4,
                .span-6,
                .span-8,
                .span-12 {
                    grid-column: span 12;
                }
            }

            @media (max-width: 640px) {
                h1 {
                    font-size: 32px;
                }

                .field-row {
                    grid-template-columns: 1fr;
                }

                .hero-card,
                .status-card,
                .card,
                .output-card {
                    border-radius: 20px;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <section class="hero">
                <div class="hero-card">
                    <div class="eyebrow">Для выполнения</div>
                    <h1>Auth System ТЗ</h1>
                    <p class="subtitle">
                        Тестовое задание
                    </p>
                </div>

                <div class="status-card">
                    <div>
                        <h3 class="status-title">Состояние сессии</h3>

                        <div class="status-box">
                            <div class="status-label">Статус</div>
                            <div class="status-value" id="authStatus">Не авторизован</div>
                        </div>

                        <div class="status-box">
                            <div class="status-label">Текущий пользователь</div>
                            <div class="status-value" id="currentUser">—</div>
                            <div class="token-preview" id="tokenPreview">Токен отсутствует</div>
                        </div>
                    </div>

                    <div class="btn-row">
                        <button class="btn-secondary" onclick="loadSavedSession()">Восстановить сессию</button>
                        <button class="btn-danger" onclick="logout()">Logout</button>
                    </div>
                </div>
            </section>

            <section class="grid">
                <div class="card span-6">
                    <h2>Регистрация</h2>
                    <p>Создай нового пользователя. Первый зарегистрированный пользователь автоматически получит роль admin.</p>

                    <div class="field-group">
                        <div class="field-row">
                            <div>
                                <label>Фамилия</label>
                                <input id="reg_last_name" placeholder="Иванов" />
                            </div>
                            <div>
                                <label>Имя</label>
                                <input id="reg_first_name" placeholder="Иван" />
                            </div>
                        </div>

                        <div>
                            <label>Отчество</label>
                            <input id="reg_middle_name" placeholder="Иванович" />
                        </div>

                        <div>
                            <label>Email</label>
                            <input id="reg_email" placeholder="ivan@test.com" />
                        </div>

                        <div class="field-row">
                            <div>
                                <label>Пароль</label>
                                <input id="reg_password" type="password" placeholder="Введите пароль" />
                            </div>
                            <div>
                                <label>Повтор пароля</label>
                                <input id="reg_password2" type="password" placeholder="Повторите пароль" />
                            </div>
                        </div>
                    </div>

                    <div class="btn-row">
                        <button class="btn-primary" onclick="register()">Зарегистрироваться</button>
                        <button class="btn-secondary" onclick="fillDemoRegister()">Заполнить пример</button>
                    </div>
                </div>

                <div class="card span-6">
                    <h2>Логин</h2>
                    <p>Войди по email и паролю. Токен автоматически сохранится в браузере.</p>

                    <div class="field-group">
                        <div>
                            <label>Email</label>
                            <input id="login_email" placeholder="ivan@test.com" />
                        </div>
                        <div>
                            <label>Пароль</label>
                            <input id="login_password" type="password" placeholder="Введите пароль" />
                        </div>
                    </div>

                    <div class="btn-row">
                        <button class="btn-success" onclick="login()">Войти</button>
                        <button class="btn-secondary" onclick="fillDemoLogin()">Заполнить логин</button>
                    </div>
                </div>

                <div class="card span-4">
                    <h2>Профиль</h2>
                    <p>Проверка текущего пользователя по токену.</p>

                    <div class="btn-row">
                        <button class="btn-primary" onclick="getMe()">Получить профиль</button>
                        <button class="btn-secondary" onclick="deleteMe()">Удалить аккаунт</button>
                    </div>
                </div>

                <div class="card span-4">
                    <h2>Продукты</h2>
                    <p>Mock бизнес-ресурсы, доступ к которым регулируется правами.</p>

                    <div>
                        <label>Название нового продукта</label>
                        <input id="product_name" placeholder="Например, Premium Product" />
                    </div>

                    <div class="btn-row">
                        <button class="btn-primary" onclick="getProducts()">Получить продукты</button>
                        <button class="btn-success" onclick="createProduct()">Создать продукт</button>
                    </div>
                </div>

                <div class="card span-4">
                    <h2>Админ-панель</h2>
                    <p>Доступно только пользователю с ролью admin.</p>

                    <div class="field-group">
                        <div>
                            <label>ID пользователя</label>
                            <input id="role_user_id" placeholder="2" />
                        </div>
                        <div>
                            <label>Новая роль</label>
                            <input id="role_name" placeholder="user или admin" />
                        </div>
                    </div>

                    <div class="btn-row">
                        <button class="btn-primary" onclick="getAccessRules()">Права доступа</button>
                        <button class="btn-secondary" onclick="setRole()">Назначить роль</button>
                    </div>
                </div>
            </section>

            <section class="output-card">
                <div class="output-head">
                    <h2>Ответ сервера</h2>
                    <div class="mini-actions">
                        <button class="btn-secondary mini-btn" onclick="clearOutput()">Очистить</button>
                        <button class="btn-secondary mini-btn" onclick="copyOutput()">Скопировать</button>
                    </div>
                </div>
                <pre id="output">Готово к работе. Зарегистрируй пользователя или войди в существующий аккаунт.</pre>
                <div class="hint">Подсказка: первый зарегистрированный пользователь становится admin.</div>
            </section>

            <div class="footer-note">
                FastAPI UI for custom authentication and authorization demo
            </div>
        </div>

        <script>
            let token = localStorage.getItem("auth_token") || "";
            let currentUserEmail = localStorage.getItem("auth_user_email") || "";

            function setOutput(data, title = null) {
                const output = document.getElementById("output");
                if (typeof data === "string") {
                    output.textContent = title ? title + "\\n\\n" + data : data;
                } else {
                    output.textContent = (title ? title + "\\n\\n" : "") + JSON.stringify(data, null, 2);
                }
            }

            function updateStatus() {
                const authStatus = document.getElementById("authStatus");
                const currentUser = document.getElementById("currentUser");
                const tokenPreview = document.getElementById("tokenPreview");

                if (token) {
                    authStatus.textContent = "Авторизован";
                    currentUser.textContent = currentUserEmail || "Пользователь определён";
                    tokenPreview.textContent = "Токен: " + token.slice(0, 28) + "...";
                } else {
                    authStatus.textContent = "Не авторизован";
                    currentUser.textContent = "—";
                    tokenPreview.textContent = "Токен отсутствует";
                }
            }

            function saveSession(newToken, email = "") {
                token = newToken || "";
                currentUserEmail = email || currentUserEmail || "";
                localStorage.setItem("auth_token", token);
                if (currentUserEmail) {
                    localStorage.setItem("auth_user_email", currentUserEmail);
                }
                updateStatus();
            }

            function clearSession() {
                token = "";
                currentUserEmail = "";
                localStorage.removeItem("auth_token");
                localStorage.removeItem("auth_user_email");
                updateStatus();
            }

            function fillDemoRegister() {
                document.getElementById("reg_last_name").value = "Иванов";
                document.getElementById("reg_first_name").value = "Иван";
                document.getElementById("reg_middle_name").value = "Иванович";
                document.getElementById("reg_email").value = "ivan@test.com";
                document.getElementById("reg_password").value = "123456";
                document.getElementById("reg_password2").value = "123456";
                setOutput("Демо-данные для регистрации заполнены.");
            }

            function fillDemoLogin() {
                document.getElementById("login_email").value = "ivan@test.com";
                document.getElementById("login_password").value = "123456";
                setOutput("Демо-данные для логина заполнены.");
            }

            function clearOutput() {
                setOutput("Поле ответа очищено.");
            }

            async function copyOutput() {
                const text = document.getElementById("output").textContent;
                try {
                    await navigator.clipboard.writeText(text);
                    setOutput("Ответ сервера скопирован в буфер обмена.");
                } catch (e) {
                    setOutput("Не удалось скопировать текст.");
                }
            }

            async function request(url, options = {}, title = "Ответ сервера") {
                const headers = {
                    "Content-Type": "application/json",
                    ...(options.headers || {})
                };

                if (token) {
                    headers["Authorization"] = "Bearer " + token;
                }

                try {
                    const res = await fetch(url, {
                        ...options,
                        headers
                    });

                    const text = await res.text();
                    let data;

                    try {
                        data = text ? JSON.parse(text) : {};
                    } catch {
                        data = text;
                    }

                    if (!res.ok) {
                        setOutput({
                            status: res.status,
                            error: data
                        }, title);
                        return { ok: false, status: res.status, data };
                    }

                    setOutput(data, title);
                    return { ok: true, status: res.status, data };
                } catch (error) {
                    setOutput({
                        error: "Network error",
                        detail: String(error)
                    }, title);
                    return { ok: false, status: 0, data: error };
                }
            }

            async function register() {
                const payload = {
                    last_name: document.getElementById("reg_last_name").value.trim(),
                    first_name: document.getElementById("reg_first_name").value.trim(),
                    middle_name: document.getElementById("reg_middle_name").value.trim(),
                    email: document.getElementById("reg_email").value.trim(),
                    password: document.getElementById("reg_password").value,
                    password_repeat: document.getElementById("reg_password2").value
                };

                const result = await request("/register", {
                    method: "POST",
                    body: JSON.stringify(payload)
                }, "Регистрация");

                if (result.ok) {
                    document.getElementById("login_email").value = payload.email;
                    document.getElementById("login_password").value = payload.password;
                    currentUserEmail = payload.email;
                    localStorage.setItem("auth_user_email", currentUserEmail);
                    updateStatus();
                }
            }

            async function login() {
                const payload = {
                    email: document.getElementById("login_email").value.trim(),
                    password: document.getElementById("login_password").value
                };

                const result = await request("/login", {
                    method: "POST",
                    body: JSON.stringify(payload)
                }, "Логин");

                if (result.ok && result.data.token) {
                    saveSession(result.data.token, payload.email);
                }
            }

            async function logout() {
                if (!token) {
                    setOutput("Сначала нужно войти в систему.", "Logout");
                    return;
                }

                const result = await request("/logout", {
                    method: "POST"
                }, "Logout");

                clearSession();

                if (!result.ok) {
                    setOutput("Сессия очищена локально. Серверный logout мог уже быть выполнен ранее.", "Logout");
                }
            }

            async function getMe() {
                if (!token) {
                    setOutput("Сначала авторизуйся.", "Профиль");
                    return;
                }

                const result = await request("/me", {
                    method: "GET"
                }, "Профиль пользователя");

                if (result.ok && result.data.email) {
                    currentUserEmail = result.data.email;
                    localStorage.setItem("auth_user_email", currentUserEmail);
                    updateStatus();
                }
            }

            async function deleteMe() {
                if (!token) {
                    setOutput("Сначала авторизуйся.", "Удаление аккаунта");
                    return;
                }

                const result = await request("/me", {
                    method: "DELETE"
                }, "Мягкое удаление аккаунта");

                if (result.ok) {
                    clearSession();
                }
            }

            async function getProducts() {
                if (!token) {
                    setOutput("Сначала авторизуйся.", "Продукты");
                    return;
                }

                await request("/products", {
                    method: "GET"
                }, "Список продуктов");
            }

            async function createProduct() {
                if (!token) {
                    setOutput("Сначала авторизуйся.", "Создание продукта");
                    return;
                }

                const name = document.getElementById("product_name").value.trim() || "New Product";

                await request("/products", {
                    method: "POST",
                    body: JSON.stringify({ name })
                }, "Создание продукта");
            }

            async function getAccessRules() {
                if (!token) {
                    setOutput("Сначала авторизуйся.", "Права доступа");
                    return;
                }

                await request("/access-rules", {
                    method: "GET"
                }, "Права доступа");
            }

            async function setRole() {
                if (!token) {
                    setOutput("Сначала авторизуйся.", "Назначение роли");
                    return;
                }

                const user_id = Number(document.getElementById("role_user_id").value);
                const role = document.getElementById("role_name").value.trim();

                if (!user_id || !role) {
                    setOutput("Заполни ID пользователя и роль.", "Назначение роли");
                    return;
                }

                await request("/admin/set-role", {
                    method: "POST",
                    body: JSON.stringify({ user_id, role })
                }, "Назначение роли");
            }

            async function loadSavedSession() {
                if (!token) {
                    updateStatus();
                    setOutput("Сохранённой сессии нет.");
                    return;
                }

                updateStatus();
                setOutput("Локальная сессия восстановлена. Для проверки нажми «Получить профиль».");
            }

            updateStatus();
        </script>
    </body>
    </html>
    """


@app.post(
    "/register",
    response_model=RegisterResponse,
    tags=["Authentication"],
    summary="Регистрация пользователя"
)
def register(data: RegisterRequest):
    if data.password != data.password_repeat:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    for user in users.values():
        if user["email"] == data.email:
            raise HTTPException(status_code=400, detail="Email already registered")

    user_id = len(users) + 1

    users[user_id] = {
        "id": user_id,
        "last_name": data.last_name,
        "first_name": data.first_name,
        "middle_name": data.middle_name,
        "email": data.email,
        "password": hash_password(data.password),
        "is_active": True
    }

    if user_id == 1:
        user_roles[user_id] = "admin"
    else:
        user_roles[user_id] = "user"

    return {
        "message": "User registered successfully",
        "user_id": user_id
    }


@app.post(
    "/login",
    response_model=LoginResponse,
    tags=["Authentication"],
    summary="Вход в систему"
)
def login(data: LoginRequest):
    for user in users.values():
        if user["email"] == data.email:
            if not user["is_active"]:
                raise HTTPException(status_code=401, detail="User is inactive")

            if check_password(data.password, user["password"]):
                token = create_token(user["id"])
                return {"token": token}

    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.post(
    "/logout",
    response_model=MessageResponse,
    tags=["Authentication"],
    summary="Выход из системы"
)
def logout(current=Depends(get_current_user)):
    user, jti = current
    sessions[jti]["is_revoked"] = True
    return {"message": "Logged out successfully"}


@app.get(
    "/me",
    response_model=UserResponse,
    tags=["Users"],
    summary="Получить текущего пользователя"
)
def me(current=Depends(get_current_user)):
    user, _ = current
    return {
        "id": user["id"],
        "last_name": user["last_name"],
        "first_name": user["first_name"],
        "middle_name": user["middle_name"],
        "email": user["email"],
        "is_active": user["is_active"],
        "role": user_roles.get(user["id"], "user")
    }


@app.patch(
    "/me",
    response_model=MessageResponse,
    tags=["Users"],
    summary="Обновить профиль"
)
def update_me(data: UpdateProfileRequest, current=Depends(get_current_user)):
    user, _ = current

    update_data = data.model_dump(exclude_unset=True)

    if "email" in update_data:
        for existing_user in users.values():
            if existing_user["id"] != user["id"] and existing_user["email"] == update_data["email"]:
                raise HTTPException(status_code=400, detail="Email already registered")

    for key, value in update_data.items():
        user[key] = value

    return {"message": "Profile updated successfully"}


@app.delete(
    "/me",
    response_model=MessageResponse,
    tags=["Users"],
    summary="Мягкое удаление аккаунта"
)
def delete_me(current=Depends(get_current_user)):
    user, _ = current
    user["is_active"] = False

    for jti, session in sessions.items():
        if session["user_id"] == user["id"]:
            session["is_revoked"] = True

    return {"message": "User deactivated successfully"}


@app.get(
    "/products",
    response_model=List[ProductResponse],
    tags=["Products"],
    summary="Получить список продуктов"
)
def get_products(current=Depends(get_current_user)):
    user, _ = current
    check_permission(user, "products", "read")
    return products


@app.post(
    "/products",
    response_model=ProductResponse,
    tags=["Products"],
    summary="Создать продукт"
)
def create_product(data: CreateProductRequest, current=Depends(get_current_user)):
    user, _ = current
    check_permission(user, "products", "create")

    new_product = {
        "id": len(products) + 1,
        "name": data.name,
        "owner_id": user["id"]
    }
    products.append(new_product)

    return new_product


@app.get(
    "/access-rules",
    tags=["Admin"],
    summary="Получить правила доступа"
)
def get_access_rules(current=Depends(get_current_user)):
    user, _ = current

    if user_roles.get(user["id"]) != "admin":
        raise HTTPException(status_code=403, detail="Only admin can view access rules")

    return access_rules


@app.post(
    "/admin/set-role",
    response_model=MessageResponse,
    tags=["Admin"],
    summary="Назначить роль пользователю"
)
def set_role(data: SetRoleRequest, current=Depends(get_current_user)):
    user, _ = current

    if user_roles.get(user["id"]) != "admin":
        raise HTTPException(status_code=403, detail="Only admin can change roles")

    if data.user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")

    if data.role not in access_rules:
        raise HTTPException(status_code=400, detail="Unknown role")

    user_roles[data.user_id] = data.role
    return {"message": "Role updated successfully"}
