# 🔐 Gestor de Contraseñas Seguro

Gestor de contraseñas de línea de comandos escrito en Ruby puro, sin dependencias externas. Cifra tu almacén con **AES-256-GCM** y deriva la clave maestra con **PBKDF2-HMAC-SHA256** (100 000 iteraciones).

---

## ✨ Características

| Categoría | Funcionalidad |
|---|---|
| **Seguridad** | Cifrado AES-256-GCM · PBKDF2-SHA256 · Verificación de integridad SHA-256 |
| **Entradas** | Ver · Buscar · Añadir · Editar · Eliminar |
| **Contraseñas** | Generador personalizable · Validación de fortaleza · Historial de cambios |
| **Sesión** | Autocierre por inactividad · Confirmación para ver contraseñas |
| **Auditoría** | Registro de todos los accesos y cambios con purga automática |
| **Backup** | Exportar e importar backups cifrados entre máquinas |
| **Tests** | Suite de 66 tests unitarios con Minitest |

---

## 📋 Requisitos

- **Ruby** >= 3.0
- Solo librerías estándar: `openssl`, `json`, `io/console`, `securerandom`, `time`

Sin gemas, sin bundler, sin dependencias externas.

---

## 🚀 Instalación y uso

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/gestor-contrasenas.git
cd gestor-contrasenas

# Ejecutar
ruby gestor_contrasenas.rb
```

La primera vez que lo ejecutes, se te pedirá que elijas una **contraseña maestra**. Esta contraseña cifra todo el almacén y nunca se guarda en disco.

---

## 🗂️ Archivos del proyecto

```
gestor-contrasenas/
├── gestor_contrasenas.rb       ← Programa principal
├── test_password_manager.rb    ← Suite de tests unitarios
├── .gitignore                  ← Protege vault.json y audit.log
└── README.md
```

> ⚠️ El archivo `vault.json` se crea **localmente** en tu máquina y **nunca** se sube a GitHub gracias al `.gitignore`.

---

## 🔑 Menú principal

```
┌─────────────────────────────────────────────────┐
│                MENÚ PRINCIPAL                   │
├─────────────────────────────────────────────────┤
│   1. Ver entradas                               │
│   2. Buscar entradas                            │
│   3. Añadir entrada                             │
│   4. Editar entrada                             │
│   5. Eliminar entrada                           │
│   6. Cambiar contraseña maestra                 │
│   7. Ver registro de auditoría                  │
│   8. Historial de contraseñas                   │
│   9. Exportar backup                            │
│  10. Importar backup                            │
│   0. Salir                                      │
└─────────────────────────────────────────────────┘
```

---

## 🔒 Seguridad

### Cifrado

El almacén `vault.json` se cifra completamente con **AES-256-GCM**:

```
Contraseña maestra
      ↓
PBKDF2-HMAC-SHA256 (100 000 iteraciones, salt aleatorio 16 bytes)
      ↓
Clave AES-256 (32 bytes)
      ↓
AES-256-GCM (IV aleatorio 12 bytes, auth_tag 16 bytes)
      ↓
vault.json (todo cifrado, incluyendo nombres de servicios)
```

- **Salt e IV aleatorios** en cada escritura → dos cifrados del mismo texto producen resultados distintos.
- **Auth tag** de 128 bits → cualquier manipulación del archivo es detectada automáticamente.
- La contraseña maestra **nunca se guarda en disco**, solo existe en memoria durante la sesión.

### Verificación de integridad

Cada vez que se guarda el almacén, se genera un **hash SHA-256** en `vault.json.sha256`. Al iniciar sesión, se verifica que el hash coincide. Si alguien modifica `vault.json` externamente, el programa lo detecta y avisa antes de continuar.

### Autocierre por inactividad

Si no hay actividad durante **5 minutos** (configurable), la sesión se bloquea automáticamente, la contraseña maestra se elimina de la memoria y se requiere autenticación para continuar.

### Confirmación para ver contraseñas

Ver una contraseña almacenada requiere introducir la contraseña maestra. Con 3 intentos fallidos el acceso se deniega y el evento queda registrado en el log.

---

## 🛡️ Generador de contraseñas

El generador usa `SecureRandom` (aleatoriedad criptográfica) y permite personalizar:

| Opción | Default |
|---|---|
| Longitud | 16 caracteres |
| Mayúsculas (A–Z) | ✅ |
| Minúsculas (a–z) | ✅ |
| Dígitos (0–9) | ✅ |
| Símbolos (!@#$…) | ✅ |

Se garantiza al menos un carácter de cada categoría activa. Si escribes una contraseña manualmente, el programa evalúa su fortaleza:

```
  Fortaleza : ██████████  Muy fuerte  (16 caracteres)
  Criterios : ≥12 chars ✓  mayúsculas ✓  minúsculas ✓  dígitos ✓  símbolos ✓
```

Si la contraseña es débil, ofrece tres opciones:

```
  (s) usar esta  ·  (g) generar segura  ·  (n / Enter) cancelar
```

---

## 🔍 Búsqueda con autocompletado

La opción **Buscar** incluye autocompletado en tiempo real mientras escribes:

```
  🔍 Buscar: git
  ↳ Gitea  [GitHub]  GitLab
```

- **Tab** → cicla por las sugerencias
- **Enter** → confirma y busca
- **Esc** → cancela

La búsqueda cubre tanto el nombre del servicio como el usuario, con resaltado en color de los términos que coinciden.

---

## 📊 Registro de auditoría

Cada acción queda registrada con fecha, hora y servicio afectado:

```
  Fecha y hora          Acción                   Servicio
  ────────────────────────────────────────────────────────────────────
  14/06/2026 09:14:02   [OK] Inicio de sesion    —
  14/06/2026 09:14:15   [+]  Nueva entrada       GitHub
  14/06/2026 09:15:44   [!!] Fallo ver contrasena Netflix
  14/06/2026 09:20:00   [!!] Bloqueo automatico  —
  14/06/2026 09:22:10   [-]  Entrada eliminada   Netflix
```

Los eventos se purgan automáticamente cada **15 días**.

---

## 💾 Backup y migración

**Exportar** (opción 9): crea un archivo `.bak` cifrado con AES-256-GCM.

**Importar** (opción 10): carga el `.bak` en cualquier máquina con dos modos:

- **Reemplazar** — sustituye todo el almacén actual.
- **Mezclar** — añade solo las entradas nuevas, omite las que ya existen.

```bash
# En la máquina de origen
ruby gestor_contrasenas.rb → opción 9 → vault_backup_2026-06-14.bak

# Copia el .bak a la nueva máquina y luego:
ruby gestor_contrasenas.rb → opción 10 → mezclar
```

---

## 🧪 Tests unitarios

```bash
# Ejecutar todos los tests
ruby test_password_manager.rb

# Modo detallado
ruby test_password_manager.rb --verbose

# Solo un grupo
ruby test_password_manager.rb --name TestCrypto
```

**66 tests** organizados en 8 grupos:

| Grupo | Tests |
|---|---|
| `TestPasswordGenerator` | Longitud, tipos de caracteres, opciones, unicidad |
| `TestCrypto` | Cifrado/descifrado, contraseña incorrecta, manipulación |
| `TestPasswordStrength` | Los 6 niveles de fortaleza, criterios individuales |
| `TestSearch` | Búsqueda parcial, case-insensitive, por usuario |
| `TestHistory` | Prepend, límite MAX_HISTORY, timestamps |
| `TestAuditLog` | Append, strip ANSI, purga automática |
| `TestVaultIntegrity` | SHA-256, detección de tampering, roundtrip save/load |
| `TestHelpers` | strip_ansi, truncate, sort, format_timeout |

---

## ⚙️ Configuración

Ajusta estas constantes al inicio de la clase `PasswordManager`:

```ruby
INACTIVITY_TIMEOUT   = 5 * 60   # Autocierre en segundos (default: 5 min)
AUDIT_RETENTION_DAYS = 15       # Días que se conserva el log de auditoría
MAX_HISTORY          = 5        # Versiones anteriores de contraseña por entrada
MIN_MASTER_LEN       = 8        # Longitud mínima de la contraseña maestra
```

---

## 📁 .gitignore recomendado

```gitignore
# Almacén cifrado — NUNCA subir a GitHub
vault.json
vault.json.sha256

# Registro de auditoría
audit.log

# Backups
*.bak

# Sistema operativo
.DS_Store
Thumbs.db

# Editores
*.swp
*.swo
*~
.vscode/
.idea/
```

---

## 🗓️ Roadmap

- [x] Cifrado AES-256-GCM con PBKDF2
- [x] Generador de contraseñas personalizable
- [x] Validación de fortaleza en tiempo real
- [x] Búsqueda con autocompletado por prefijo
- [x] Historial de contraseñas con restauración
- [x] Autocierre por inactividad (5 min)
- [x] Confirmación con contraseña maestra para ver contraseñas
- [x] Registro de auditoría con purga automática
- [x] Verificación de integridad SHA-256
- [x] Backup y migración cifrada entre máquinas
- [x] Suite de 66 tests unitarios
- [ ] Copiar contraseña al portapapeles
- [ ] Exportar a texto plano (modo emergencia)
- [ ] Sincronización entre dispositivos
- [ ] 2FA para la contraseña maestra

---

## 📄 Licencia

MIT License — consulta el archivo [LICENSE](LICENSE) para más información.

---

<div align="center">
  <sub>Hecho con Ruby 🔴 · Sin dependencias · Solo librerías estándar</sub>
</div>