# Flask Project Template

## Descripción
Esta es una plantilla reutilizable para proyectos basados en Flask, diseñada para ser modular y escalable. Incluye funcionalidades comunes como autenticación, manejo de sesiones, integración con OAuth2 (Google, GitHub, Microsoft), y mucho más. Esta plantilla está pensada para ser utilizada como base en la mayoría de los proyectos Flask que vayas a desarrollar.

## Funcionalidades
- Autenticación con JWT y manejo de sesiones.
- Registro, recuperación de contraseñas, y cierre de sesión.
- Integración con OAuth2 (Google, GitHub, Microsoft) para inicio de sesión.
- Modularización de rutas y blueprints.
- Configuración y uso de cookies y sesiones.
- Manejo de errores personalizados.

## Estructura del Proyecto
```
├── server/
│   ├── __init__.py
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── auth_routes.py
│   │   ├── main_routes.py
│   ├── oidc/
│   │   ├── __init__.py
│   │   ├── google_login.py
│   │   ├── github_login.py
│   │   ├── microsoft_login.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── auth_api.py
│   ├── forms/
│   │   ├── __init__.py
│   │   ├── login_form.py
│   │   ├── register_form.py
│   │   ├── forgot_password_form.py
│   │   └── reset_password_form.py
│   ├── config.py
├── mail/
│   ├── __init__.py
│   ├── email_utils.py
├── database/
│   ├── __init__.py
│   ├── models.py
│   ├── engine.py
│   ├── session.py
├── templates/
│   ├── auth_templates/
│   ├── email_templates/
│   ├── main_templates/
├── static/
│   ├── css/
│   ├── js/
│   └── img/
├── run.py
└── .env
```

## Instalación y Configuración
1. Clona el repositorio:
    ```sh
    git clone https://github.com/gabrielbaute/flask-project-template.git
    cd flask-project-template
    ```

2. Crea y activa un entorno virtual:
    ```sh
    python -m venv venv
    source venv/bin/activate  # En Windows: venv\Scripts\activate
    ```

3. Instala las dependencias:
    ```sh
    pip install -r requirements.txt
    ```

4. Configura las variables de entorno:
    - Crea un archivo `.env` en la raíz del proyecto con las siguientes variables:
        ```
        SECRET_KEY=una_clave_secreta_segura
        JWT_SECRET_KEY=otra_clave_secreta_segura
        GOOGLE_CLIENT_ID=tu_cliente_id
        GOOGLE_CLIENT_SECRET=tu_cliente_secreto
        GOOGLE_REDIRECT_URI=http://localhost:5000/authorize/google
        MICROSOFT_CLIENT_ID=tu_cliente_id
        MICROSOFT_CLIENT_SECRET=tu_cliente_secreto
        MICROSOFT_REDIRECT_URI=http://localhost:5000/authorize/microsoft
        GITHUB_CLIENT_ID=tu_cliente_id
        GITHUB_CLIENT_SECRET=tu_cliente_secreto
        GITHUB_REDIRECT_URI=http://localhost:5000/authorize/github
        ```

5. Ejecuta la aplicación:
    ```sh
    flask run
    ```

## Uso
- Visita `http://localhost:5000/` para acceder a la aplicación.
- Utiliza las rutas `/login`, `/register`, `/forgot_password`, `/reset_password`, `/logout` para manejar la autenticación y la gestión de usuarios.
- Utiliza las rutas `/login/google`, `/login/github`, `/login/microsoft` para iniciar sesión utilizando OAuth2.

## Contribuciones
Las contribuciones son bienvenidas. Siéntete libre de abrir un issue o enviar un pull request.

## Licencia
Este proyecto está bajo la licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.