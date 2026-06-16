// ═══════════════════════════════════════════════════════════════════
// MANUAL DE USUARIO — Gestor de Contraseñas Seguro
// ───────────────────────────────────────────────────────────────────
// Compilar:  typst compile manual.typ
// Requiere:  Typst >= 0.11  (https://typst.app)
// ═══════════════════════════════════════════════════════════════════

// ── Configuración de página ─────────────────────────────────────────
#set page(
  paper:        "a4",
  margin:       (top: 2.5cm, bottom: 2.8cm, left: 3cm, right: 2.5cm),
  numbering:    "1",
  number-align: center,
  header: context {
    if counter(page).get().first() > 2 [
      #set text(size: 8.5pt, fill: rgb("#94a3b8"))
      Gestor de Contraseñas Seguro — Manual de Usuario
      #h(1fr)
      #counter(page).display("1")
    ]
  },
  footer: none,
)

// ── Tipografía ───────────────────────────────────────────────────────
#set text(size: 11pt, lang: "es")
#set par(justify: true, leading: 0.72em, spacing: 1.1em)
#set list(indent: 1.2em, body-indent: 0.5em)
#set enum(indent: 1.2em, body-indent: 0.5em)
#set heading(numbering: "1.1.")

// ── Paleta de colores ───────────────────────────────────────────────
#let c-accent   = rgb("#00c896")
#let c-dark     = rgb("#0f172a")
#let c-surface  = rgb("#f0fdf9")
#let c-muted    = rgb("#64748b")
#let c-border   = rgb("#cbd5e1")
#let c-code-bg  = rgb("#1e293b")
#let c-code-fg  = rgb("#e2e8f0")
#let c-danger   = rgb("#e05555")
#let c-warn-bg  = rgb("#fffbeb")
#let c-warn-bd  = rgb("#f59e0b")
#let c-danger-bg = rgb("#fff1f1")

// ── Estilo de títulos ───────────────────────────────────────────────
#show heading.where(level: 1): it => {
  pagebreak(weak: true)
  v(0.4em)
  block(
    width: 100%,
    fill:   c-accent.lighten(88%),
    stroke: (left: 4pt + c-accent),
    inset:  (left: 1em, right: 1em, top: 0.7em, bottom: 0.7em),
    radius: (right: 4pt),
    below:  1.2em,
  )[#text(weight: "bold", size: 13.5pt, fill: c-dark)[#it]]
}

#show heading.where(level: 2): it => {
  v(0.9em)
  text(weight: "bold", size: 11.5pt, fill: c-dark)[#it]
  v(0.25em)
  line(length: 100%, stroke: 0.5pt + c-accent.lighten(55%))
  v(0.6em)
}

#show heading.where(level: 3): it => {
  v(0.6em)
  text(size: 11pt, fill: c-muted, weight: "semibold")[▸ #it.body]
  v(0.35em)
}

// ── Componentes reutilizables ───────────────────────────────────────

// Bloque de terminal
#let terminal(body) = block(
  width:  100%,
  fill:   c-code-bg,
  inset:  (x: 1.3em, y: 1em),
  radius: 5pt,
  below:  1em,
)[#text(fill: c-code-fg, font: ("Courier New", "Courier"), size: 9pt)[#raw(body)]]

// Caja de información (verde)
#let info-box(body) = block(
  width:  100%,
  fill:   c-accent.lighten(90%),
  stroke: (left: 3pt + c-accent),
  inset:  (x: 1em, y: 0.8em),
  radius: (right: 4pt),
  below:  1em,
)[#text(size: 10.5pt)[💡 *Nota:* #body]]

// Caja de advertencia (ámbar)
#let warn-box(body) = block(
  width:  100%,
  fill:   c-warn-bg,
  stroke: (left: 3pt + c-warn-bd),
  inset:  (x: 1em, y: 0.8em),
  radius: (right: 4pt),
  below:  1em,
)[#text(size: 10.5pt, fill: rgb("#78350f"))[⚠ *Advertencia:* #body]]

// Caja de peligro (rojo)
#let danger-box(body) = block(
  width:  100%,
  fill:   c-danger-bg,
  stroke: (left: 3pt + c-danger),
  inset:  (x: 1em, y: 0.8em),
  radius: (right: 4pt),
  below:  1em,
)[#text(size: 10.5pt, fill: rgb("#7f1d1d"))[🔴 *Importante:* #body]]

// Tabla estilizada con cabecera oscura y filas alternadas
#let pm-table(columns: (), header: (), rows: ()) = table(
  columns:  columns,
  fill:     (x, y) => if y == 0 { c-dark } else if calc.odd(y) { c-accent.lighten(92%) } else { white },
  stroke:   0.5pt + c-border,
  inset:    (x: 0.8em, y: 0.6em),
  align:    left,
  ..header.map(h => [#text(fill: white, weight: "bold")[#h]]),
  ..rows.flatten(),
)

// ════════════════════════════════════════════════════════════════════
//  P O R T A D A
// ════════════════════════════════════════════════════════════════════
#page(numbering: none, header: none, footer: none, margin: 0cm)[

  // Franja superior oscura
  #block(width: 100%, height: 10.5cm, fill: c-dark)[

    #v(2cm)
    #align(center)[
      // Círculo con ícono
      #box(
        width:  3.8cm,
        height: 3.8cm,
        fill:   c-accent,
        radius: 50%,
      )[
        #align(center + horizon)[
          #text(size: 46pt, fill: white)[🔐]
        ]
      ]

      #v(1cm)
      #text(size: 30pt, weight: "bold", fill: white)[Gestor de Contraseñas]
      #v(0.2cm)
      #text(size: 13pt, fill: rgb("#94a3b8"))[Manual de Usuario]
    ]
  ]

  // Franja de datos técnicos
  #block(
    width:  100%,
    height: 2.2cm,
    fill:   c-accent,
  )[
    #align(center + horizon)[
      #grid(
        columns: (1fr, 1fr, 1fr, 1fr),
        gutter:  0em,
        align:   center,
        block(inset: (x: 0.5cm))[
          #text(fill: c-dark, size: 9pt)[VERSIÓN] \
          #text(fill: c-dark, weight: "bold", size: 12pt)[1.0]
        ],
        block(inset: (x: 0.5cm))[
          #text(fill: c-dark, size: 9pt)[CIFRADO] \
          #text(fill: c-dark, weight: "bold", size: 10pt)[AES-256-GCM]
        ],
        block(inset: (x: 0.5cm))[
          #text(fill: c-dark, size: 9pt)[KDF] \
          #text(fill: c-dark, weight: "bold", size: 10pt)[PBKDF2-SHA256]
        ],
        block(inset: (x: 0.5cm))[
          #text(fill: c-dark, size: 9pt)[TESTS] \
          #text(fill: c-dark, weight: "bold", size: 12pt)[66]
        ],
      )
    ]
  ]

  // Cuerpo blanco de la portada
  #block(width: 100%, fill: white, inset: (x: 3cm, y: 1.5cm))[
    #v(0.5cm)

    // Descripción corta
    #text(size: 12pt, fill: c-dark)[
      Gestor de contraseñas de línea de comandos escrito en Ruby puro,
      sin dependencias externas. Cifra tu almacén localmente con
      criptografía de grado militar.
    ]

    #v(1cm)

    // Grid de características
    #grid(
      columns: (1fr, 1fr),
      gutter: 1em,
      block(fill: c-surface, inset: 1em, radius: 6pt)[
        #text(weight: "bold", fill: c-accent)[✅ Lo que hace]\
        #v(0.4em)
        - Cifra tus contraseñas localmente\
        - Nunca se conecta a internet\
        - Solo librerías estándar de Ruby\
        - Código abierto y auditable
      ],
      block(fill: rgb("#f8fafc"), inset: 1em, radius: 6pt, stroke: 0.5pt + c-border)[
        #text(weight: "bold", fill: c-muted)[📋 Requisitos]\
        #v(0.4em)
        - Ruby >= 3.0\
        - Linux, macOS o Windows\
        - Sin instalación adicional\
        - Sin gemas ni bundler
      ],
    )

    #v(1fr)

    #align(center)[
      #text(size: 9pt, fill: c-muted)[
        Compilado con Typst · Ruby >= 3.0 requerido
      ]
    ]
  ]
]

// ════════════════════════════════════════════════════════════════════
//  Í N D I C E
// ════════════════════════════════════════════════════════════════════
#page(numbering: none, header: none)[
  #v(0.5em)
  #text(size: 18pt, weight: "bold", fill: c-dark)[Índice de contenidos]
  #v(0.4em)
  #line(length: 100%, stroke: 1.5pt + c-accent)
  #v(0.8em)
  #outline(
    title:  none,
    indent: 1.5em,
    depth:  2,
  )
]

#counter(page).update(1)

// ════════════════════════════════════════════════════════════════════
//  1. INTRODUCCIÓN
// ════════════════════════════════════════════════════════════════════
= Introducción

== ¿Qué es este programa?

El *Gestor de Contraseñas Seguro* es una aplicación de línea de comandos
(CLI) escrita en Ruby que te permite almacenar y gestionar contraseñas de
forma segura en tu propia máquina, sin depender de servicios en la nube.

A diferencia de los gestores online, tus datos *nunca salen de tu equipo*.
El almacén se cifra con algoritmos de grado militar y solo tú, con tu
contraseña maestra, puedes acceder a él.

== Características principales

#pm-table(
  columns: (2fr, 3fr),
  header:  ("Categoría", "Funcionalidad"),
  rows: (
    [*Seguridad*],   [AES-256-GCM · PBKDF2-SHA256 · Verificación SHA-256],
    [*Entradas*],    [Ver · Buscar · Añadir · Editar · Eliminar],
    [*Contraseñas*], [Generador personalizable · Validación de fortaleza · Historial],
    [*Sesión*],      [Autocierre por inactividad · Confirmación para ver contraseñas],
    [*Auditoría*],   [Registro de todos los accesos con purga automática cada 15 días],
    [*Backup*],      [Exportar e importar backups cifrados entre máquinas],
    [*Calidad*],     [Suite de 66 tests unitarios con Minitest],
  ),
)

== Cómo funciona el cifrado

#block(
  width:  100%,
  fill:   c-surface,
  stroke: 0.5pt + c-border,
  inset:  1.2em,
  radius: 6pt,
)[
  #align(center)[
    #text(font: ("Courier New", "Courier"), size: 10pt)[
      Contraseña maestra\
      ↓\
      PBKDF2-HMAC-SHA256 (100 000 iteraciones · salt 16 bytes)\
      ↓\
      Clave AES-256 (32 bytes)\
      ↓\
      AES-256-GCM (IV 12 bytes · auth_tag 16 bytes)\
      ↓\
      vault.json (todo cifrado: servicios, usuarios y contraseñas)
    ]
  ]
]

- *Salt e IV aleatorios* en cada escritura: dos cifrados del mismo texto producen resultados distintos.
- *Auth tag* de 128 bits: cualquier manipulación del archivo es detectada automáticamente al descifrar.
- La contraseña maestra *nunca se guarda en disco*, solo existe en memoria durante la sesión activa.

// ════════════════════════════════════════════════════════════════════
//  2. REQUISITOS E INSTALACIÓN
// ════════════════════════════════════════════════════════════════════
= Requisitos e instalación

== Requisitos del sistema

Solo se necesita *Ruby 3.0 o superior*. No hay que instalar gemas, bundler
ni ninguna dependencia adicional.

#pm-table(
  columns: (auto, 1fr, auto),
  header:  ("Librería", "Propósito", "Origen"),
  rows: (
    [`openssl`],      [Cifrado AES-256-GCM y PBKDF2],         [Ruby stdlib],
    [`json`],         [Serialización del almacén],             [Ruby stdlib],
    [`io/console`],   [Entrada de contraseña oculta],          [Ruby stdlib],
    [`securerandom`], [Aleatoriedad criptográfica],            [Ruby stdlib],
    [`time`],         [Timestamps del registro de auditoría],  [Ruby stdlib],
    [`timeout`],      [Autocierre por inactividad],            [Ruby stdlib],
  ),
)

Para verificar tu versión de Ruby:

#terminal("ruby --version\n# Resultado esperado: ruby 3.x.x o superior")

== Instalación

=== Desde GitHub

#terminal("git clone https://github.com/tu-usuario/gestor-contrasenas.git\ncd gestor-contrasenas")

=== Ejecución

No hay paso de instalación. Ejecuta directamente:

#terminal("ruby gestor_contrasenas.rb")

== Archivos que genera el programa

#pm-table(
  columns: (auto, 1fr, auto),
  header:  ("Archivo", "Contenido", "Subir a GitHub"),
  rows: (
    [`vault.json`],         [Almacén cifrado con todas las contraseñas], [❌ Nunca],
    [`vault.json.sha256`],  [Hash SHA-256 para verificar integridad],    [❌ Nunca],
    [`audit.log`],          [Registro de accesos y cambios],             [❌ Nunca],
    [`*.bak`],              [Archivos de backup cifrados],               [❌ Nunca],
  ),
)

#danger-box[
  *vault.json* contiene tus contraseñas cifradas. Aunque está cifrado,
  nunca lo subas a un repositorio público. El `.gitignore` del proyecto
  ya lo excluye, pero verifica que así sea antes de hacer `git push`.
]

== .gitignore recomendado

#terminal("# Almacén cifrado — NUNCA subir a GitHub\nvault.json\nvault.json.sha256\n\n# Registro de auditoría\naudit.log\n\n# Backups\n*.bak\n\n# Sistema operativo\n.DS_Store\nThumbs.db")

// ════════════════════════════════════════════════════════════════════
//  3. PRIMERA EJECUCIÓN
// ════════════════════════════════════════════════════════════════════
= Primera ejecución

== Crear el almacén

La primera vez que ejecutes el programa no existe `vault.json`. Se mostrará
el banner de bienvenida y se pedirá que elijas una contraseña maestra:

#terminal("  ╔═══════════════════════════════════════════════════════╗\n  ║             GESTOR DE CONTRASEÑAS SEGURAS             ║\n  ║  Cifrado    : AES-256-GCM                             ║\n  ║  KDF        : PBKDF2-HMAC-SHA256 · 100 000 iter.      ║\n  ║  Almacén    : vault.json                              ║\n  ║  Autocierre : 5 min                                   ║\n  ╚═══════════════════════════════════════════════════════╝\n\n  ⚪  Contraseña maestra: ****")

== Cómo elegir una buena contraseña maestra

La contraseña maestra protege *todo el almacén*. Si la olvidas, no hay
forma de recuperar los datos.

#grid(
  columns: (1fr, 1fr),
  gutter: 1em,
  block(fill: rgb("#f0fdf4"), inset: 1em, radius: 5pt, stroke: 0.5pt + c-accent)[
    *✅ Buena contraseña maestra*
    - Al menos 16 caracteres
    - Letras mayúsculas y minúsculas
    - Dígitos y símbolos
    - Fácil de recordar para ti
    - Ejemplo: `Mi#Gato$Duerme2024!`
  ],
  block(fill: rgb("#fef2f2"), inset: 1em, radius: 5pt, stroke: 0.5pt + c-danger)[
    *❌ Mala contraseña maestra*
    - Menos de 8 caracteres
    - Solo letras o solo números
    - Información personal obvia
    - Palabras del diccionario
    - Ejemplo: `password123`
  ],
)

#warn-box[
  Guarda tu contraseña maestra en un lugar físico seguro (papel en
  caja fuerte, por ejemplo). Si la pierdes, los datos son irrecuperables.
]

// ════════════════════════════════════════════════════════════════════
//  4. MENÚ PRINCIPAL
// ════════════════════════════════════════════════════════════════════
= Menú principal

Tras introducir la contraseña maestra correctamente, aparecerá el menú:

#terminal("  ┌─────────────────────────────────────────────────┐\n  │                MENÚ PRINCIPAL                   │\n  ├─────────────────────────────────────────────────┤\n  │   1. Ver entradas                               │\n  │   2. Buscar entradas                            │\n  │   3. Añadir entrada                             │\n  │   4. Editar entrada                             │\n  │   5. Eliminar entrada                           │\n  │   6. Cambiar contraseña maestra                 │\n  │   7. Ver registro de auditoría                  │\n  │   8. Historial de contraseñas                   │\n  │   9. Exportar backup                            │\n  │  10. Importar backup                            │\n  │   0. Salir                                      │\n  └─────────────────────────────────────────────────┘\n  Elige una opción: _")

Para elegir una opción, escribe el número y pulsa *Enter*. En las secciones
siguientes se explica cada opción en detalle.

// ════════════════════════════════════════════════════════════════════
//  5. GESTIÓN DE ENTRADAS
// ════════════════════════════════════════════════════════════════════
= Gestión de entradas

== Ver entradas (opción 1)

Muestra la tabla completa de entradas ordenadas *alfabéticamente* por nombre
de servicio (sin distinción de mayúsculas):

#terminal("  ────────────────────────────────────────────────────────────\n  N°       Servicio ↑ A–Z          Usuario\n  ────────────────────────────────────────────────────────────\n  0    *   GitHub                   dev@email.com\n  1        Gmail                    user@gmail.com\n  2    *   Netflix                  user@email.com\n       * = tiene historial de contraseñas\n  ────────────────────────────────────────────────────────────\n\n  Número de entrada para ver detalle de (Enter para cancelar):")

El asterisco (`*`) indica que esa entrada tiene historial de contraseñas anteriores.

Para ver la contraseña de una entrada, introduce su número. El programa
pedirá la *contraseña maestra* para confirmar tu identidad. Dispones de
3 intentos antes de que se deniegue el acceso.

== Buscar entradas (opción 2)

Busca en tiempo real con *autocompletado por prefijo* del nombre de servicio:

#terminal("  🔍 Buscar: git\n  ↳ Gitea  [GitHub]  GitLab")

#pm-table(
  columns: (auto, 1fr),
  header:  ("Tecla", "Acción"),
  rows: (
    [*Tab*],       [Cicla por las sugerencias · la activa aparece en \[verde\]],
    [*Enter*],     [Confirma el texto escrito y realiza la búsqueda],
    [*Backspace*], [Borra el último carácter],
    [*Esc*],       [Cancela y vuelve al menú principal],
  ),
)

La búsqueda cubre tanto el nombre del servicio como el usuario, y resalta
en cian los términos que coinciden en los resultados.

== Añadir entrada (opción 3)

El programa pide tres campos: servicio, usuario y contraseña.

#terminal("  Servicio: GitHub\n  Usuario:  dev@email.com\n  Contraseña [Enter para generador personalizable]: _")

Si pulsas *Enter* en el campo contraseña sin escribir nada, se abre el
*generador personalizable*:

#terminal("  ── Generador personalizable ─────────────────────────────\n  Longitud de la contraseña [16]: _\n\n  Mayúsculas  A–Z   [S/n]: s\n  Minúsculas  a–z   [S/n]: s\n  Dígitos     0–9   [S/n]: s\n  Símbolos    !@#$… [S/n]: n\n\n  Contraseña generada: Hy3RmZwK8NsVpT2Xd5Qb\n  Enter para aceptar  ·  r para regenerar  ·  q para cancelar: _")

Si escribes la contraseña manualmente, el programa evalúa su *fortaleza*:

#terminal("  Fortaleza : ██████████  Muy fuerte  (16 caracteres)\n  Criterios : ≥12 chars ✓  mayúsculas ✓  minúsculas ✓  dígitos ✓  símbolos ✓")

Si la contraseña es débil, aparecen tres opciones:

#terminal("  🟡  Contraseña débil.\n  (s) usar esta  ·  (g) generar segura  ·  (n / Enter) cancelar: _")

=== Niveles de fortaleza

#pm-table(
  columns: (auto, auto, 1fr),
  header:  ("Score", "Nivel", "Criterios cumplidos"),
  rows: (
    [0–1], [Muy débil],  [Ninguno o solo minúsculas],
    [2],   [Débil],      [Longitud ≥12 + un tipo más],
    [3],   [Moderada],   [Tres criterios de cinco],
    [4],   [Fuerte],     [Cuatro criterios de cinco],
    [5],   [Muy fuerte], [Longitud ≥12 + mayúsculas + minúsculas + dígitos + símbolos],
  ),
)

== Editar entrada (opción 4)

Muestra la tabla y permite modificar cualquier campo. Pulsar *Enter* sin
escribir nada conserva el valor actual:

#terminal("  Servicio    [GitHub]: _           ← Enter conserva el valor\n  Usuario     [dev@email.com]: _    ← Enter conserva el valor\n  Contraseña  [actual oculta — Enter conserva | 'g' generador]:\n  > _")

Antes de guardar se muestra un resumen de cambios y se pide confirmación.

#info-box[
  Si cambias la contraseña, la versión anterior se guarda automáticamente
  en el *historial* (opción 8). Se conservan hasta 5 versiones por entrada.
]

== Eliminar entrada (opción 5)

Selecciona una entrada de la tabla e introduce su número. El programa pide
*confirmación explícita* antes de eliminar:

#terminal("  ¿Eliminar 'GitHub' (dev@email.com)?\n  Esta acción es irreversible. (s/N): _")

#danger-box[
  La eliminación es *permanente*. Considera exportar un backup (opción 9)
  antes de borrar entradas importantes.
]

// ════════════════════════════════════════════════════════════════════
//  6. SEGURIDAD
// ════════════════════════════════════════════════════════════════════
= Seguridad

== Cambiar contraseña maestra (opción 6)

El proceso verifica la contraseña actual, pide la nueva dos veces para
confirmar, y *re-cifra todo el almacén* con la nueva clave:

#terminal("  Contraseña maestra actual: ****\n  Nueva contraseña maestra:  ****\n  Confirmar nueva contraseña: ****\n\n  🟢  Contraseña maestra actualizada. El almacén ha sido re-cifrado.")

La longitud mínima para la contraseña maestra es de *8 caracteres*.

== Autocierre por inactividad

Si el programa lleva *5 minutos* sin actividad en el menú principal, la
sesión se bloquea automáticamente y la contraseña maestra se elimina de
la memoria:

#terminal("  ─────────────────────────────────────────────────────────\n  SESIÓN BLOQUEADA\n  ─────────────────────────────────────────────────────────\n  Inactividad detectada (5 min).\n  Introduce tu contraseña maestra para continuar.")

Para reanudar, introduce la contraseña maestra. El programa re-descifra
el almacén completo (PBKDF2 + AES-256-GCM) antes de continuar.

#info-box[
  El tiempo de autocierre se puede cambiar modificando la constante
  `INACTIVITY_TIMEOUT` en el código. Por ejemplo: `10 * 60` para 10 minutos.
]

== Verificación de integridad SHA-256

Cada vez que se guarda el almacén, el programa calcula el *hash SHA-256*
de `vault.json` y lo guarda en `vault.json.sha256`. Al iniciar sesión,
verifica que el hash coincide:

#terminal("  ─────────────────────────────────────────────────────────\n  ADVERTENCIA: INTEGRIDAD DEL ALMACÉN COMPROMETIDA\n  ─────────────────────────────────────────────────────────\n  🟡  'vault.json' fue modificado fuera del programa.\n  🟡  El hash SHA-256 no coincide con el registrado.\n  🟡  Si no realizaste cambios manuales, investiga el origen.")

Esta verificación detecta modificaciones accidentales (corrupción de disco)
o manipulaciones externas. El cifrado AES-GCM ya protege el contenido:
cualquier manipulación del ciphertext produce un error de autenticación al descifrar.

// ════════════════════════════════════════════════════════════════════
//  7. AUDITORÍA E HISTORIAL
// ════════════════════════════════════════════════════════════════════
= Auditoría e historial

== Ver registro de auditoría (opción 7)

Muestra los últimos 20 eventos con fecha, hora y servicio afectado:

#terminal("  Fecha y hora          Acción                   Servicio\n  ────────────────────────────────────────────────────────────────────\n  14/06/2026 09:14:02   [OK] Inicio de sesion    —\n  14/06/2026 09:14:15   [+]  Nueva entrada       GitHub\n  14/06/2026 09:15:44   [!!] Fallo ver contrasena Netflix\n  14/06/2026 09:20:00   [!!] Bloqueo automatico  —\n  14/06/2026 09:21:33   [~]  Entrada editada     GitLab\n  ────────────────────────────────────────────────────────────────────\n\n  11 evento(s) en total.")

#pm-table(
  columns: (auto, 1fr),
  header:  ("Prefijo", "Significado"),
  rows: (
    [`[OK]`], [Operación realizada con éxito],
    [`[+]`],  [Elemento añadido (nueva entrada o backup importado)],
    [`[~]`],  [Elemento modificado (edición, restauración o mezcla)],
    [`[-]`],  [Elemento eliminado],
    [`[!!]`], [Evento de seguridad o acceso fallido],
  ),
)

Los eventos se purgan automáticamente al inicio de cada sesión cuando
tienen más de *15 días* de antigüedad.

== Historial de contraseñas (opción 8)

Muestra las contraseñas anteriores de cualquier entrada (hasta 5):

#terminal("  GitHub  ·  3 cambio(s) anteriores:\n\n  N°    Fecha del cambio       Contraseña\n  ─────────────────────────────────────────────────────\n  0     10/06/2026 09:14:00    ••••••••\n  1     05/06/2026 17:30:00    ••••••••\n  2     01/06/2026 11:00:00    ••••••••\n  ─────────────────────────────────────────────────────\n\n  N° para ver una contraseña histórica (Enter para omitir): _")

Para ver una contraseña histórica se requiere la *contraseña maestra*.
Después, el programa ofrece *restaurarla* como contraseña actual: la
contraseña actual pasa al historial y la seleccionada la reemplaza.

// ════════════════════════════════════════════════════════════════════
//  8. BACKUP Y MIGRACIÓN
// ════════════════════════════════════════════════════════════════════
= Backup y migración

== Exportar backup (opción 9)

Crea un archivo `.bak` con las entradas cifradas con *AES-256-GCM*:

#terminal("  Nombre del archivo [vault_backup_2026-06-14.bak]: [Enter]\n\n  🟢  Backup creado: vault_backup_2026-06-14.bak\n      Entradas  : 12\n      Tamaño    : 2.847 bytes\n      Cifrado   : AES-256-GCM (contraseña maestra actual)")

El archivo `.bak` es seguro para guardar en USB, Dropbox, Google Drive, etc.

== Importar backup (opción 10)

#terminal("  Ruta del archivo .bak: vault_backup_2026-06-14.bak\n\n  Creado    : 14/06/2026 09:30:00\n  Entradas  : 12\n\n  Contraseña del backup: ****\n\n  (r) Reemplazar todo el almacén actual\n  (m) Mezclar — añade nuevas, omite duplicados\n  (n) Cancelar\n  Elige: _")

=== Modo Reemplazar

Sustituye *todas* las entradas actuales por las del backup. Pide
confirmación explícita antes de proceder.

=== Modo Mezclar

Añade solo las entradas que *no existen* en el almacén actual. Se considera
duplicada una entrada con el mismo servicio Y el mismo usuario (sin distinción
de mayúsculas):

#terminal("  + Netflix       ← añadida (nueva)\n  + Amazon        ← añadida (nueva)\n  ↔ GitHub        ← omitida (ya existe)\n  ↔ Gmail         ← omitida (ya existe)\n\n  🟢  Mezcla completada: 2 añadida(s), 2 omitida(s).")

== Migrar a otra máquina

+ En la máquina *origen*: opción 9 → crea `vault_backup_YYYY-MM-DD.bak`
+ Copia el `.bak` a la nueva máquina (USB, correo, nube...)
+ En la máquina *destino*: opción 10 → introduce la contraseña → elige modo Mezclar

#info-box[
  La contraseña que se pide al importar es la que se usó para *crear* el
  backup, no necesariamente la del almacén destino. Esto permite migrar
  entre máquinas aunque uses contraseñas maestras distintas.
]

// ════════════════════════════════════════════════════════════════════
//  9. TESTS UNITARIOS
// ════════════════════════════════════════════════════════════════════
= Tests unitarios

El proyecto incluye una suite de *66 tests* para verificar el correcto
funcionamiento de todas las funcionalidades críticas:

#terminal("# Ejecutar todos los tests\nruby test_password_manager.rb\n\n# Modo detallado\nruby test_password_manager.rb --verbose\n\n# Solo un grupo\nruby test_password_manager.rb --name TestCrypto")

#pm-table(
  columns: (auto, 1fr),
  header:  ("Grupo", "Qué verifica"),
  rows: (
    [`TestPasswordGenerator`], [Longitud, tipos de caracteres, opciones, unicidad],
    [`TestCrypto`],            [Cifrado/descifrado, contraseña incorrecta, manipulación],
    [`TestPasswordStrength`],  [Los 6 niveles de fortaleza, criterios individuales],
    [`TestSearch`],            [Búsqueda parcial, case-insensitive, por usuario],
    [`TestHistory`],           [Prepend, límite MAX_HISTORY, timestamps],
    [`TestAuditLog`],          [Append, strip ANSI, purga automática],
    [`TestVaultIntegrity`],    [SHA-256, detección de manipulación, roundtrip],
    [`TestHelpers`],           [strip_ansi, truncate, sort, format_timeout],
  ),
)

// ════════════════════════════════════════════════════════════════════
//  10. CONFIGURACIÓN AVANZADA
// ════════════════════════════════════════════════════════════════════
= Configuración avanzada

Las siguientes constantes en `gestor_contrasenas.rb` permiten personalizar
el comportamiento sin modificar la lógica del programa:

#terminal("class PasswordManager\n  INACTIVITY_TIMEOUT   = 5 * 60  # Autocierre (segundos)\n  AUDIT_RETENTION_DAYS = 15      # Días que se conserva el log\n  MAX_HISTORY          = 5       # Versiones anteriores por entrada\n  MIN_MASTER_LEN       = 8       # Longitud mínima de la clave maestra\nend")

#pm-table(
  columns: (auto, auto, 1fr),
  header:  ("Constante", "Default", "Descripción"),
  rows: (
    [`INACTIVITY_TIMEOUT`],   [`300`], [Segundos sin actividad para bloquear la sesión],
    [`AUDIT_RETENTION_DAYS`], [`15`],  [Días que se conservan los eventos del log],
    [`MAX_HISTORY`],          [`5`],   [Número máximo de contraseñas anteriores por entrada],
    [`MIN_MASTER_LEN`],       [`8`],   [Longitud mínima de la contraseña maestra],
  ),
)

// ════════════════════════════════════════════════════════════════════
//  11. PREGUNTAS FRECUENTES
// ════════════════════════════════════════════════════════════════════
= Preguntas frecuentes

== ¿Qué pasa si olvido mi contraseña maestra?

No hay forma de recuperar los datos. La contraseña maestra *nunca se
almacena* en ningún lugar. Para prevenir esta situación:

+ Elige una contraseña que puedas recordar con facilidad
+ Escríbela en papel y guárdala en lugar físico seguro (no digital)
+ Haz backups regulares (opción 9) y guarda también la contraseña del backup

== ¿Es seguro guardar vault.json en la nube?

Sí, con matices. El contenido está cifrado con AES-256-GCM y sin tu
contraseña nadie puede leerlo. Sin embargo, el proveedor cloud sabe que
tienes el archivo (aunque no su contenido). Para máxima privacidad,
cifra el `.bak` adicionalmente con GPG antes de subirlo.

== ¿Puedo usar el programa en Windows?

Sí. Instala Ruby desde #link("https://rubyinstaller.org") y ejecuta desde
PowerShell. Ten en cuenta que:

- La carpeta del proyecto *no debe tener espacios ni caracteres especiales* (ñ, tildes)
- Nombre recomendado: `gestor-contrasenas`
- El autocompletado con Tab puede tener diferencias menores en CMD

== ¿Con qué frecuencia debo hacer backup?

- Uso diario → backup semanal
- Uso ocasional → backup tras cada sesión con cambios
- Cambio de máquina → backup inmediato antes de migrar

== ¿Qué significa la advertencia de "integridad comprometida"?

El hash SHA-256 del archivo `vault.json` no coincide con el guardado.
Posibles causas: edición manual accidental, corrupción de disco o
acceso no autorizado. El cifrado AES-GCM protege el contenido: si el
archivo fue manipulado, al descifrar se producirá un error de autenticación.

// ════════════════════════════════════════════════════════════════════
//  12. GLOSARIO
// ════════════════════════════════════════════════════════════════════
= Glosario

#pm-table(
  columns: (auto, 1fr),
  header:  ("Término", "Definición"),
  rows: (
    [*AES-256-GCM*],
    [Advanced Encryption Standard de 256 bits en modo Galois/Counter.
     Algoritmo de cifrado simétrico autenticado que garantiza
     confidencialidad e integridad simultáneamente.],

    [*PBKDF2*],
    [Password-Based Key Derivation Function 2. Convierte la contraseña
     maestra en una clave criptográfica usando 100 000 iteraciones de
     HMAC-SHA256, dificultando enormemente los ataques de fuerza bruta.],

    [*Salt*],
    [Valor aleatorio único generado al cifrar. Evita que dos almacenes
     con la misma contraseña produzcan la misma clave derivada.],

    [*IV*],
    [Vector de Inicialización. Valor aleatorio único para cada cifrado
     que garantiza que el mismo texto produce ciphertexts distintos.],

    [*Auth tag*],
    [Etiqueta de autenticación de 128 bits de AES-GCM. Permite detectar
     cualquier modificación del ciphertext, incluso de un solo byte.],

    [*SHA-256*],
    [Secure Hash Algorithm de 256 bits. Función de hash criptográfico
     usada para verificar la integridad del archivo vault.json.],

    [*CLI*],
    [Command Line Interface. Programa que se ejecuta y controla desde
     el terminal de comandos.],

    [*Almacén (vault)*],
    [El archivo vault.json que contiene todas las entradas cifradas:
     nombres de servicios, usuarios y contraseñas.],

    [*Contraseña maestra*],
    [La contraseña que protege todo el almacén. Nunca se guarda en disco.
     Su pérdida implica la pérdida irrecuperable de todos los datos.],
  ),
)

// ════════════════════════════════════════════════════════════════════
//  CONTRAPORTADA
// ════════════════════════════════════════════════════════════════════
#page(numbering: none, header: none, footer: none, margin: 0cm)[
  #v(1fr)

  #block(width: 100%, fill: c-dark, inset: (x: 3cm, y: 3cm))[
    #text(fill: c-accent, size: 20pt, weight: "bold")[
      Gestor de Contraseñas Seguro
    ]
    #v(0.4em)
    #text(fill: rgb("#94a3b8"), size: 11pt)[Manual de Usuario · v1.0]

    #v(1.5em)
    #line(length: 8cm, stroke: 0.5pt + rgb("#334155"))
    #v(1.5em)

    #grid(
      columns: (auto, 1fr),
      gutter: (0.5em, 0.6em),
      row-gutter: 0.6em,
      text(fill: c-accent)[🔐], text(fill: rgb("#94a3b8"))[Cifrado AES-256-GCM con autenticación GCM],
      text(fill: c-accent)[🔑], text(fill: rgb("#94a3b8"))[Derivación de clave PBKDF2-HMAC-SHA256 (100 000 iter.)],
      text(fill: c-accent)[🛡], text(fill: rgb("#94a3b8"))[Verificación de integridad SHA-256],
      text(fill: c-accent)[📋], text(fill: rgb("#94a3b8"))[Registro de auditoría con purga automática],
      text(fill: c-accent)[💾], text(fill: rgb("#94a3b8"))[Backup y migración cifrada entre máquinas],
      text(fill: c-accent)[🧪], text(fill: rgb("#94a3b8"))[66 tests unitarios con Minitest],
    )

    #v(2em)
    #text(fill: rgb("#475569"), size: 9pt)[
      Hecho con Ruby 🔴 · Sin dependencias · Solo librerías estándar \
      Compilado con Typst · https://typst.app
    ]
  ]
]
