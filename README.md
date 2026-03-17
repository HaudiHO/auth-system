# Auth System API

## 🚀 Описание

Backend-приложение с собственной системой аутентификации и авторизации.

Реализовано:
- регистрация и логин пользователей
- JWT токены
- logout через отзыв токена
- роли (admin / user)
- разграничение прав доступа (RBAC)
- mock бизнес-объекты (products)
- UI интерфейс для тестирования

---

## ⚙️ Технологии

- Python 3
- FastAPI
- bcrypt
- JWT (PyJWT)

---

## 🔐 Аутентификация

- Пользователь логинится по email и паролю
- Пароль хранится в виде bcrypt-хеша
- После логина выдается JWT-токен
- Создается серверная сессия
- Logout реализован через revoke токена

---

## 🛡 Авторизация

Реализована через роли и правила доступа:

### Роли:
- admin
- user

### Ресурсы:
- products
- access_rules

### Действия:
- read
- create
- update
- delete

---

## ❗ Ошибки

- 401 — пользователь не авторизован
- 403 — нет доступа к ресурсу

---

## 📦 API

### Аутентификация
- POST /register
- POST /login
- POST /logout

### Пользователь
- GET /me
- PATCH /me
- DELETE /me

### Продукты
- GET /products
- POST /products

### Админ
- GET /access-rules
- POST /admin/set-role

---

## 💻 Запуск

```bash
pip install fastapi uvicorn bcrypt pyjwt
python3 -m uvicorn main:app --reload
