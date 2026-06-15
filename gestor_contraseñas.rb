# encoding: utf-8
# frozen_string_literal: true

require 'securerandom'
require 'openssl'
require 'json'
require 'io/console'
require 'timeout'
require 'time'

module PasswordGenerator
  UPPERCASE = ('A'..'Z').to_a.freeze
  LOWERCASE = ('a'..'z').to_a.freeze
  DIGITS    = ('0'..'9').to_a.freeze
  SYMBOLS   = '!@#$%^&*()_+-=[]{}|;:,.<>?'.chars.freeze

  # Genera una contraseña criptográficamente segura.
  #
  # length — número de caracteres (mínimo: número de conjuntos activos)
  # opts   — hash con claves :uppercase, :lowercase, :digits, :symbols (true/false)
  #          Por defecto todos los conjuntos están activos.
  #
  # Garantiza al menos un carácter de cada conjunto activo y mezcla
  # el resultado con Fisher-Yates usando SecureRandom.
  def self.generate(length = 16, opts = {})
    use_upper   = opts.fetch(:uppercase, true)
    use_lower   = opts.fetch(:lowercase, true)
    use_digits  = opts.fetch(:digits,    true)
    use_symbols = opts.fetch(:symbols,   true)

    sets = []
    sets << UPPERCASE if use_upper
    sets << LOWERCASE if use_lower
    sets << DIGITS    if use_digits
    sets << SYMBOLS   if use_symbols

    raise ArgumentError, "Selecciona al menos un tipo de carácter" if sets.empty?

    all = sets.flatten
    min = sets.size
    raise ArgumentError, "Longitud mínima con los conjuntos seleccionados: #{min}" if length < min

    # Un carácter garantizado de cada conjunto activo
    password = sets.map { |s| s[SecureRandom.random_number(s.size)] }

    # Rellenar el resto
    (length - min).times do
      password << all[SecureRandom.random_number(all.size)]
    end

    # Fisher-Yates con valores criptográficos
    password.shuffle(random: SecureRandom).join
  end
end

module Crypto
  ITERATIONS = 100_000
  KEY_LENGTH = 32
  SALT_BYTES = 16
  IV_BYTES   = 12
  TAG_LENGTH = 16

  def self.derive_key(password, salt)
    OpenSSL::KDF.pbkdf2_hmac(
      password,
      salt:       salt,
      iterations: ITERATIONS,
      length:     KEY_LENGTH,
      hash:       'SHA256'
    )
  end

  def self.encrypt(plaintext, password)
    salt = SecureRandom.random_bytes(SALT_BYTES)
    iv   = SecureRandom.random_bytes(IV_BYTES)
    key  = derive_key(password, salt)

    cipher = OpenSSL::Cipher.new('AES-256-GCM')
    cipher.encrypt
    cipher.key = key
    cipher.iv  = iv

    ciphertext = cipher.update(plaintext) + cipher.final
    auth_tag   = cipher.auth_tag(TAG_LENGTH)

    {
      'salt'       => bin2hex(salt),
      'iv'         => bin2hex(iv),
      'auth_tag'   => bin2hex(auth_tag),
      'ciphertext' => bin2hex(ciphertext)
    }
  end

  def self.decrypt(data, password)
    salt       = hex2bin(data['salt'])
    iv         = hex2bin(data['iv'])
    auth_tag   = hex2bin(data['auth_tag'])
    ciphertext = hex2bin(data['ciphertext'])

    key = derive_key(password, salt)

    cipher = OpenSSL::Cipher.new('AES-256-GCM')
    cipher.decrypt
    cipher.key      = key
    cipher.iv       = iv
    cipher.auth_tag = auth_tag

    cipher.update(ciphertext) + cipher.final
  end

  def self.bin2hex(binary)
    binary.unpack1('H*')
  end

  def self.hex2bin(hex)
    [hex].pack('H*')
  end
end


class PasswordManager
  VAULT_FILE            = 'vault.json'
  AUDIT_FILE            = 'audit.log'
  CHECKSUM_FILE         = 'vault.json.sha256'   # hash de integridad del almacén
  AUDIT_RETENTION_DAYS  = 15
  MAX_HISTORY           = 5             # contraseñas anteriores que se conservan
  MIN_MASTER_LEN        = 8
  DEFAULT_PWD_LEN       = 16
  MIN_PWD_LEN           = 4
  MAX_PWD_LEN           = 128
  INACTIVITY_TIMEOUT    = 5 * 60        # segundos — ajusta aquí si lo deseas

  def initialize
    @master_password = nil
    @entries         = []
    @audit_log       = []
  end

  def run
    clear_screen
    show_banner
    authenticate
    load_vault
    load_audit_log
    verify_checksum   # advertir si vault.json fue modificado externamente
    log_event('login_ok')

    loop do
      show_menu
      begin
        option = Timeout.timeout(INACTIVITY_TIMEOUT) { $stdin.gets.chomp.strip }
      rescue Timeout::Error
        lock_session!
        next
      end
      dispatch(option)
    end
  end

  private

  def authenticate
    @master_password = prompt_secret("⚪  Contraseña maestra")
    if @master_password.empty?
      abort "\n    La contraseña maestra no puede estar vacía."
    end
  end

  def load_vault
    unless File.exist?(VAULT_FILE)
      info "Almacén no encontrado. Se creará al guardar la primera entrada."
      @entries = []
      return
    end

    print "\n    Derivando clave y descifrando almacén..."
    $stdout.flush

    begin
      encrypted_data = JSON.parse(File.read(VAULT_FILE))
      plaintext      = Crypto.decrypt(encrypted_data, @master_password)
      @entries       = JSON.parse(plaintext)
      sort_entries!
      print "\r" + (" " * 55) + "\r"
      ok "Almacén cargado — #{@entries.size} #{pluralize(@entries.size, 'entrada', 'entradas')}."
    rescue OpenSSL::Cipher::CipherError
      abort "\n\n    Contraseña maestra incorrecta o el archivo ha sido alterado."
    rescue JSON::ParserError
      abort "\n    El archivo del almacén está dañado y no puede leerse."
    rescue Errno::EACCES => e
      abort "\n    Sin permisos para leer '#{VAULT_FILE}': #{e.message}"
    end
  end

  def save_vault
    plaintext      = JSON.generate(@entries)
    encrypted_data = Crypto.encrypt(plaintext, @master_password)

    File.write(VAULT_FILE, JSON.pretty_generate(encrypted_data))
    File.chmod(0o600, VAULT_FILE)
    save_checksum   # actualizar el hash de integridad tras cada escritura
  rescue Errno::EACCES => e
    err "No se pudo guardar el almacén: #{e.message}"
  end

  # Calcula el SHA-256 del archivo vault.json cifrado y lo guarda en
  # CHECKSUM_FILE. Si falla (disco lleno, permisos…) no bloquea el guardado.
  def save_checksum
    digest = OpenSSL::Digest::SHA256.file(VAULT_FILE).hexdigest
    File.write(CHECKSUM_FILE, digest)
    File.chmod(0o600, CHECKSUM_FILE)
  rescue StandardError
    # No crítico — el vault ya se guardó correctamente
  end

  # Compara el SHA-256 actual de vault.json con el hash registrado.
  # Si no coinciden, muestra una advertencia, registra el evento en el
  # audit log y espera confirmación del usuario antes de continuar.
  # Llamar DESPUÉS de load_audit_log para que el log esté disponible.
  def verify_checksum
    return unless File.exist?(VAULT_FILE) && File.exist?(CHECKSUM_FILE)

    saved   = File.read(CHECKSUM_FILE).strip
    current = OpenSSL::Digest::SHA256.file(VAULT_FILE).hexdigest
    return if saved == current

    # ── Alerta de integridad ─────────────────────────────────────
    sep = '─' * 57
    puts "\n  #{sep}"
    puts "  ADVERTENCIA: INTEGRIDAD DEL ALMACEN COMPROMETIDA"
    puts "  #{sep}"
    warn_msg "'#{VAULT_FILE}' fue modificado fuera del programa."
    warn_msg "El hash SHA-256 registrado no coincide con el actual."
    warn_msg "Si no realizaste cambios manuales, investiga el origen."
    puts "  #{sep}\n"

    log_event('vault_tamper_detected')

    print "  Pulsa Enter para continuar de todas formas..."
    gets
  rescue StandardError
    # Error inesperado — no bloquear la sesión
  end

  # Carga el registro de auditoría desde disco y elimina los eventos
  # más antiguos que AUDIT_RETENTION_DAYS. Si el archivo no existe o
  # está dañado, arranca con un log vacío sin interrumpir el programa.
  def load_audit_log
    return unless File.exist?(AUDIT_FILE)
    @audit_log = JSON.parse(File.read(AUDIT_FILE))
    purge_old_audit_events
  rescue StandardError
    @audit_log = []
  end

  # Elimina de @audit_log los eventos anteriores al periodo de retención
  # y sobreescribe el archivo si se borró alguno.
  def purge_old_audit_events
    cutoff  = Time.now - (AUDIT_RETENTION_DAYS * 24 * 60 * 60)
    before  = @audit_log.size
    @audit_log.select! do |event|
      Time.iso8601(event['timestamp']) >= cutoff
    rescue StandardError
      true   # conservar el evento si el timestamp es ilegible
    end
    save_audit_log if @audit_log.size < before
  end

  # Persiste el registro de auditoría. Si falla (permisos, disco
  # lleno…) no interrumpe el flujo principal del programa.
  def save_audit_log
    File.write(AUDIT_FILE, JSON.pretty_generate(@audit_log))
    File.chmod(0o600, AUDIT_FILE)
  rescue StandardError
    # No crítico — el programa sigue funcionando sin el log
  end

  # Añade un evento al registro y lo guarda en disco inmediatamente.
  # action  — clave del evento (p.ej. 'entry_add', 'password_view')
  # detail  — contexto opcional (p.ej. nombre del servicio)
  # Los códigos ANSI se eliminan del detail antes de guardar para
  # que audit.log sea siempre texto plano legible.
  def log_event(action, detail = nil)
    @audit_log << {
      'timestamp' => Time.now.iso8601,
      'action'    => action,
      'detail'    => detail ? strip_ansi(detail) : nil
    }
    save_audit_log
  end

  def dispatch(option)
    clear_screen
    case option
    when '1'  then cmd_browse
    when '2'  then cmd_search
    when '3'  then cmd_add
    when '4'  then cmd_edit
    when '5'  then cmd_delete
    when '6'  then cmd_change_master
    when '7'  then cmd_audit
    when '8'  then cmd_history
    when '9'  then cmd_export_backup
    when '10' then cmd_import_backup
    when '0'  then cmd_exit
    else
      err "Opción '#{option}' no válida. Elige entre 0 y 10."
    end
  end


  # ── Opción 1: Ver servicios y detalle de una entrada ────────────

  def cmd_browse
    puts "  ── Servicios almacenados ───────────────────────────────"
    print_entries_table
    return pause if @entries.empty?

    idx = prompt_index("ver detalle de")
    return unless idx

    e   = @entries[idx]
    sep = '─' * 50

    # Servicio y usuario no son sensibles: se muestran sin restricción
    puts
    puts "  #{sep}"
    puts "  Servicio : #{e['service']}"
    puts "  Usuario  : #{e['username']}"
    puts "  #{sep}"

    # La contraseña requiere confirmación de identidad
    confirmed = confirm_and_show_password(e)
    pause unless confirmed   # si falló, pausa para que se lea el error
  end


  # ── Opción 2: Buscar y filtrar entradas ─────────────────────────
  # Búsqueda parcial, sin distinción de mayúsculas, en servicio Y usuario.
  # El prompt de búsqueda autocompleta por nombre de servicio (Tab).
  # Los términos que coincidan aparecen resaltados en cian.
  # Desde los resultados se puede ver el detalle de una entrada.
  # Al final se ofrece repetir la búsqueda sin volver al menú.

  def cmd_search
    return empty_vault_notice if @entries.empty?

    loop do
      puts "  ── Buscar entradas ─────────────────────────────────────"
      puts "  Autocompleta por nombre de servicio con Tab."
      puts "  La búsqueda también cubre el campo usuario.\n"

      candidates = @entries.map { |e| e['service'] }.uniq
      puts
      query = prompt_with_autocomplete("🔍 Buscar", candidates)

      if query.nil? || query.empty?
        info "Búsqueda cancelada."
        pause
        return
      end

      # Filtrar manteniendo el índice original de @entries
      results = @entries.each_with_index.select { |e, _i| entry_matches?(e, query) }

      clear_screen

      if results.empty?
        puts "  ── Sin resultados ──────────────────────────────────────"
        warn_msg "No se encontró ninguna entrada para \"#{query}\"."
      else
        total_str   = "#{@entries.size} #{pluralize(@entries.size, 'entrada', 'entradas')}"
        results_str = "#{results.size} #{pluralize(results.size, 'resultado', 'resultados')}"
        puts "  ── #{results_str} para \"#{query}\" (de #{total_str}) ──"
        print_search_table(results, query)

        # Ofrecer ver detalle de uno de los resultados
        idx = prompt_result_index(results)
        if idx
          e   = @entries[idx]
          sep = '─' * 50
          puts
          puts "  #{sep}"
          puts "  Servicio : #{e['service']}"
          puts "  Usuario  : #{e['username']}"
          puts "  #{sep}"
          confirm_and_show_password(e)
        end
      end

      print "\n  ¿Realizar otra búsqueda? (s/N): "
      break unless gets.chomp.strip.downcase == 's'
      clear_screen
    end

    pause
  end


  # ── Opción 3: Añadir entrada (manual o con contraseña generada) ─

  def cmd_add
    puts "  ── Añadir nueva entrada ────────────────────────────────"

    service  = prompt_required("Servicio")
    return unless service

    username = prompt_required("Usuario")
    return unless username

    password = prompt_password_or_generate
    return unless password

    append_and_save(service, username, password)
    ok "Entrada añadida y almacén guardado."
    pause
  end


  # ── Opción 4: Editar una entrada existente ──────────────────────
  # Muestra los valores actuales entre corchetes.
  # Pulsar Enter sin escribir nada conserva el valor original,
  # lo que permite editar solo los campos que necesites.

  def cmd_edit
    return empty_vault_notice if @entries.empty?

    puts "  ── Editar entrada ──────────────────────────────────────"
    print_entries_table

    idx = prompt_index("editar")
    return unless idx

    e = @entries[idx]

    puts "\n  Deja en blanco y pulsa Enter para conservar el valor actual.\n"

    # ── Servicio ────────────────────────────────────────────────
    print "  Servicio    [#{e['service']}]: "
    input_svc = gets.chomp.strip
    new_svc   = input_svc.empty? ? e['service'] : input_svc

    # ── Usuario ─────────────────────────────────────────────────
    print "  Usuario     [#{e['username']}]: "
    input_usr = gets.chomp.strip
    new_usr   = input_usr.empty? ? e['username'] : input_usr

    # ── Contraseña ──────────────────────────────────────────────
    puts "  Contraseña  [actual oculta — Enter conserva | 'g' generador personalizable]:"
    print "  > "
    input_pwd = gets.chomp.strip

    new_pwd = case input_pwd
              when ''
                # Conservar la contraseña actual sin mostrarla
                e['password']
              when 'g', 'G'
                # Abrir el generador personalizable
                puts
                result = prompt_generate_custom
                return unless result
                result
              else
                # Contraseña escrita a mano: validar fortaleza
                # show_password_strength devuelve la contraseña a usar o nil si canceló
                result = show_password_strength(input_pwd)
                return unless result
                result
              end

    # ── Confirmar cambios ───────────────────────────────────────
    puts
    puts "  ── Resumen de cambios ──────────────────────────────────"
    puts "  Servicio  : #{e['service']}  →  #{new_svc}"   if new_svc != e['service']
    puts "  Usuario   : #{e['username']}  →  #{new_usr}"  if new_usr != e['username']
    puts "  Contraseña: [cambiada]"                        if new_pwd != e['password']

    # Si no hubo ningún cambio real, avisamos y salimos
    if new_svc == e['service'] && new_usr == e['username'] && new_pwd == e['password']
      info "No se realizó ningún cambio."
      pause
      return
    end

    print "\n  ¿Guardar los cambios? (s/N): "
    confirm = gets.chomp.strip.downcase

    unless confirm == 's'
      info "Edición cancelada. No se guardó nada."
      pause
      return
    end

    # Guardar contraseña anterior en el historial si cambió
    add_to_history(@entries[idx], e['password']) if new_pwd != e['password']

    # Aplicar los cambios y persistir
    @entries[idx]['service']  = new_svc
    @entries[idx]['username'] = new_usr
    @entries[idx]['password'] = new_pwd
    sort_entries!
    save_vault
    log_event('entry_edit', new_svc)

    ok "Entrada actualizada y almacén guardado."
    pause
  end


  # ── Opción 5: Eliminar una entrada por índice ───────────────────

  def cmd_delete
    return empty_vault_notice if @entries.empty?

    puts "  ── Eliminar entrada ────────────────────────────────────"
    print_entries_table

    idx = prompt_index("eliminar")
    return unless idx

    e = @entries[idx]
    print "\n     ¿Eliminar '#{e['service']}' (#{e['username']})? "
    print "Esta acción es irreversible. (s/N): "
    input = gets.chomp.strip.downcase

    if input == 's'
      deleted_service = e['service']
      @entries.delete_at(idx)
      save_vault
      log_event('entry_delete', deleted_service)
      ok "Entrada eliminada y almacén guardado."
    else
      info "Operación cancelada."
    end
    pause
  end


  # ── Opción 6: Cambiar contraseña maestra ────────────────────────

  def cmd_change_master
    puts "  ── Cambiar contraseña maestra ──────────────────────────"

    if File.exist?(VAULT_FILE)
      current = prompt_secret("Contraseña maestra actual")
      begin
        Crypto.decrypt(JSON.parse(File.read(VAULT_FILE)), current)
      rescue OpenSSL::Cipher::CipherError
        err "Contraseña actual incorrecta."
        pause
        return
      end
    end

    new_pass    = prompt_secret("Nueva contraseña maestra")
    new_confirm = prompt_secret("Confirmar nueva contraseña")

    unless new_pass == new_confirm
      err "Las contraseñas no coinciden."
      pause
      return
    end

    if new_pass.length < MIN_MASTER_LEN
      err "La contraseña maestra debe tener al menos #{MIN_MASTER_LEN} caracteres."
      pause
      return
    end

    @master_password = new_pass
    save_vault
    ok "Contraseña maestra actualizada. El almacén ha sido completamente re-cifrado."
    pause
  end


  # ── Opción 7: Ver registro de auditoría ─────────────────────────
  # Muestra los últimos eventos del registro en una tabla.
  # Incluye: fecha/hora, tipo de acción y servicio afectado.

  def cmd_audit
    puts "  ── Registro de auditoría ───────────────────────────────"

    if @audit_log.empty?
      info "No hay eventos registrados todavía."
      pause
      return
    end

    page  = 20                         # eventos por pantalla
    total = @audit_log.size
    shown = @audit_log.last(page)
    sep   = '─' * 68

    puts "\n  #{sep}"
    puts "  #{"Fecha y hora".ljust(21)} #{"Acción".ljust(24)} Servicio"
    puts "  #{sep}"

    shown.each do |event|
      time    = format_audit_time(event['timestamp'])
      action  = translate_action(event['action']).ljust(24)
      detail  = truncate(strip_ansi(event['detail'] || '—'), 20)
      puts "  #{time.ljust(21)} #{action} #{detail}"
    end

    puts "  #{sep}"
    puts "\n  #{total} evento(s) en total." \
         "#{total > page ? " Mostrando los últimos #{page}." : ''}"
    pause
  end


  # ── Opción 8: Historial de contraseñas ─────────────────────────
  # Muestra las contraseñas anteriores de una entrada (hasta MAX_HISTORY).
  # Requiere contraseña maestra para ver cada contraseña histórica.
  # Permite restaurar una contraseña anterior como contraseña actual.

  def cmd_history
    return empty_vault_notice if @entries.empty?

    puts "  ── Historial de contraseñas ────────────────────────────"
    print_entries_table

    idx = prompt_index("ver historial de")
    return unless idx

    e       = @entries[idx]
    history = e['history'] || []

    if history.empty?
      info "'#{e['service']}' no tiene historial todavía.\n" \
           "  Se genera automáticamente cada vez que edites la contraseña."
      pause
      return
    end

    # ── Tabla de historial ──────────────────────────────────────
    sep = '─' * 55
    puts "\n  #{e['service']}  ·  #{history.size} cambio(s) anteriores:"
    puts "\n  #{sep}"
    puts "  #{"N°".ljust(5)} #{"Fecha del cambio".ljust(22)} Contraseña"
    puts "  #{sep}"
    history.each_with_index do |h, i|
      date = format_audit_time(h['changed_at'])
      puts "  #{i.to_s.ljust(5)} #{date.ljust(22)} ••••••••"
    end
    puts "  #{sep}\n"

    # ── Seleccionar entrada a ver ───────────────────────────────
    print "\n  N° para ver una contraseña histórica (Enter para omitir): "
    input = gets.chomp.strip
    return pause if input.empty?

    unless input.match?(/\A\d+\z/) && input.to_i < history.size
      err "Número fuera de rango. Rango válido: 0–#{history.size - 1}."
      pause
      return
    end

    hist_idx = input.to_i
    h        = history[hist_idx]
    date_str = format_audit_time(h['changed_at'])

    # Entry temporal: el campo Servicio incluye la fecha como contexto
    temp = {
      'service'  => "#{e['service']}  \e[90m(historial · #{date_str})\e[0m",
      'username' => e['username'],
      'password' => h['password']
    }
    confirmed = confirm_and_show_password(temp)
    return unless confirmed

    # ── Ofrecer restaurar ──────────────────────────────────────
    puts "  Servicio : #{e['service']}"
    print "  ¿Restaurar la contraseña del #{date_str} como contraseña actual? (s/N): "
    return unless gets.chomp.strip.downcase == 's'

    # 1. Eliminar la entrada seleccionada del historial
    # 2. Añadir la contraseña actual al historial
    # 3. Establecer la contraseña restaurada como actual
    @entries[idx]['history'].delete_at(hist_idx)
    add_to_history(@entries[idx], e['password'])
    @entries[idx]['password'] = h['password']

    save_vault
    log_event('password_restore', e['service'])
    ok "Contraseña restaurada. La anterior ha quedado en el historial."
    pause
  end


  # ── Opción 9: Exportar backup cifrado ───────────────────────────
  # Crea un archivo .bak con las entradas cifradas con la misma
  # contraseña maestra. Portable entre máquinas y sistemas operativos.

  def cmd_export_backup
    puts "  ── Exportar backup cifrado ─────────────────────────────"
    puts "  Crea un archivo .bak que puedes guardar en un USB,"
    puts "  nube, disco externo, etc.\n"

    default  = "vault_backup_#{Time.now.strftime('%Y-%m-%d')}.bak"
    filename = prompt_with_default("Nombre del archivo", default)

    if File.exist?(filename)
      print "\n  El archivo '#{filename}' ya existe. ¿Sobreescribir? (s/N): "
      unless gets.chomp.strip.downcase == 's'
        info "Exportación cancelada."
        pause
        return
      end
    end

    print "\n    Cifrando backup..."
    $stdout.flush

    encrypted = Crypto.encrypt(JSON.generate(@entries), @master_password)
    backup    = {
      'version'     => '1.0',
      'program'     => 'gestor-contrasenas',
      'created_at'  => Time.now.iso8601,
      'entry_count' => @entries.size
    }.merge(encrypted)

    File.write(filename, JSON.pretty_generate(backup))
    File.chmod(0o600, filename)
    print "\r#{' ' * 25}\r"

    log_event('backup_export', filename)

    ok "Backup creado: #{filename}"
    puts "  Entradas  : #{@entries.size}"
    puts "  Tamaño    : #{File.size(filename)} bytes"
    puts "  Cifrado   : AES-256-GCM (contraseña maestra actual)"
    pause
  rescue StandardError => e
    print "\r#{' ' * 25}\r"
    err "No se pudo crear el backup: #{e.message}"
    pause
  end


  # ── Opción 10: Importar backup cifrado ──────────────────────────
  # Lee un archivo .bak, lo descifra con la contraseña con la que
  # fue creado y ofrece dos modos:
  #   Reemplazar — sustituye todas las entradas actuales
  #   Mezclar    — añade solo las entradas nuevas, omite duplicados

  def cmd_import_backup
    puts "  ── Importar backup cifrado ─────────────────────────────"
    puts "  Restaura entradas desde un archivo .bak.\n"

    print "\n  Ruta del archivo .bak: "
    filename = gets.chomp.strip

    if filename.empty?
      info "Importación cancelada."
      pause
      return
    end

    unless File.exist?(filename)
      err "Archivo no encontrado: '#{filename}'"
      pause
      return
    end

    # ── Leer y validar estructura ──────────────────────────────────
    begin
      backup = JSON.parse(File.read(filename))
    rescue JSON::ParserError
      err "El archivo no tiene un formato JSON válido."
      pause
      return
    end

    unless backup['program'] == 'gestor-contrasenas' && backup['version']
      err "El archivo no es un backup de este programa."
      pause
      return
    end

    # ── Mostrar información del backup ────────────────────────────
    created = format_audit_time(backup['created_at'])
    puts "\n  Archivo   : #{filename}"
    puts "  Creado    : #{created}"
    puts "  Entradas  : #{backup['entry_count']}"
    puts "  Versión   : #{backup['version']}\n"

    # ── Descifrar ─────────────────────────────────────────────────
    password = prompt_secret("Contraseña del backup")

    print "\n    Descifrando..."
    $stdout.flush

    begin
      imported = JSON.parse(Crypto.decrypt(backup, password))
      print "\r#{' ' * 20}\r"
    rescue OpenSSL::Cipher::CipherError
      print "\r#{' ' * 20}\r"
      err "Contraseña incorrecta o archivo corrupto."
      pause
      return
    end

    # ── Elegir modo de importación ────────────────────────────────
    puts "\n  #{imported.size} entradas listas para importar.\n"
    puts "  (r) Reemplazar todo el almacén actual"
    puts "  (m) Mezclar  — añade nuevas, omite duplicados"
    puts "  (n) Cancelar\n"
    print "  Elige: "

    case gets.chomp.strip.downcase
    when 'r' then import_replace(imported)
    when 'm' then import_merge(imported)
    else
      info "Importación cancelada."
      pause
    end
  end


  # ── Helpers internos de importación ─────────────────────────────

  # Reemplaza TODAS las entradas actuales con las del backup.
  def import_replace(imported)
    print "\n  ¿Reemplazar todo el almacén? Esta acción es irreversible. (s/N): "
    unless gets.chomp.strip.downcase == 's'
      info "Importación cancelada."
      pause
      return
    end
    @entries = imported.map { |e| e.merge('history' => e['history'] || []) }
    sort_entries!
    save_vault
    log_event('backup_import_replace')
    ok "Almacén reemplazado. #{@entries.size} entradas importadas."
    pause
  end

  # Mezcla el backup con el almacén actual.
  # Duplicado = mismo servicio Y mismo usuario (sin distinción de mayúsculas).
  # Las entradas duplicadas se conservan tal como están en el almacén actual.
  def import_merge(imported)
    added   = []
    skipped = []

    imported.each do |imp|
      dup = @entries.any? do |e|
        e['service'].to_s.downcase  == imp['service'].to_s.downcase &&
        e['username'].to_s.downcase == imp['username'].to_s.downcase
      end

      if dup
        skipped << imp['service']
      else
        @entries << imp.merge('history' => imp['history'] || [])
        added    << imp['service']
      end
    end

    sort_entries!
    save_vault
    log_event('backup_import_merge')

    puts
    added.each   { |s| puts "  \e[32m+\e[0m #{s}" }
    skipped.each { |s| puts "  \e[90m↔ #{s}  (ya existe, omitida)\e[0m" }
    puts
    ok "Mezcla completada: #{added.size} añadida(s), #{skipped.size} omitida(s)."
    pause
  end


  # ── Opción 0: Salir del programa ────────────────────────────────

  def cmd_exit
    @master_password&.replace("\x00" * @master_password.bytesize)
    puts "\n  ⚪  ¡Hasta pronto! Tu almacén está protegido."
    exit(0)
  end


  # ── Autocierre por inactividad ───────────────────────────────────
  # Se activa cuando el usuario no escribe nada en el menú principal
  # durante INACTIVITY_TIMEOUT segundos.
  # Pasos: limpia datos sensibles → muestra pantalla de bloqueo →
  #        pide contraseña → re-descifra almacén → reanuda sesión.

  def lock_session!
    # 1. Registrar el bloqueo ANTES de limpiar la contraseña
    log_event('session_lock')

    # 2. Limpiar la contraseña maestra y las entradas de la memoria
    @master_password&.replace("\x00" * @master_password.bytesize)
    @master_password = nil
    @entries = []

    clear_screen
    show_lock_banner

    # 3. Pedir contraseña hasta acertar
    loop do
      password = prompt_secret("Contraseña maestra para desbloquear")

      print "\n    Verificando..."
      $stdout.flush

      begin
        if File.exist?(VAULT_FILE)
          encrypted_data = JSON.parse(File.read(VAULT_FILE))
          @entries       = JSON.parse(Crypto.decrypt(encrypted_data, password))
          sort_entries!
        end
        @master_password = password
        log_event('session_unlock_ok')
        print "\r#{' ' * 22}\r"
        ok "Sesión reanudada. Bienvenido de vuelta."
        sleep(1)
        clear_screen
        break
      rescue OpenSSL::Cipher::CipherError
        log_event('session_unlock_fail')
        print "\r#{' ' * 22}\r"
        err "Contraseña incorrecta. Inténtalo de nuevo."
      end
    end
  end


  # ── Helpers de entrada de usuario ───────────────────────────────

  def prompt_secret(label)
    print "\n  #{label}: "
    secret = if $stdin.respond_to?(:noecho)
               $stdin.noecho { |io| io.gets.to_s }.chomp
             else
               $stdin.gets.to_s.chomp
             end
    puts
    secret
  rescue IOError
    $stdin.gets.to_s.chomp
  end

  # Prompt interactivo con autocompletado en tiempo real.
  #
  # Mientras el usuario escribe, filtra 'candidates' por prefijo y
  # muestra hasta 6 coincidencias debajo del cursor (en gris).
  # La coincidencia seleccionada aparece resaltada en verde [entre corchetes].
  #
  #   Tab        → ciclar por las sugerencias
  #   Enter      → confirmar lo escrito (o la sugerencia seleccionada)
  #   Backspace  → borrar el último carácter
  #   Esc        → cancelar y devolver nil
  #
  # Si el terminal no soporta getch, cae a un prompt simple sin color.
  # Devuelve el texto introducido, o nil si el usuario pulsó Esc.
  def prompt_with_autocomplete(label, candidates)
    unless $stdin.respond_to?(:getch)
      print "\n  #{label}: "
      input = $stdin.gets.to_s.chomp.strip
      return input.empty? ? nil : input
    end

    buffer  = ''
    tab_idx = -1
    drawn   = false

    loop do
      # Coincidencias por prefijo, sin distinción de mayúsculas, máx. 6
      matches = buffer.empty? ? [] : candidates
        .select  { |c| c.downcase.start_with?(buffer.downcase) }
        .sort_by { |c| c.downcase }
        .first(6)

      # Borrar el área dibujada anteriormente (línea input + línea sugerencias)
      if drawn
        print "\r\e[2K"       # limpiar línea de sugerencias (línea actual)
        print "\e[1A\r\e[2K"  # subir y limpiar línea de input
      end
      drawn = true

      # ── Línea 1: prompt + texto actual ──────────────────────────
      print "  #{label}: #{buffer}"

      # ── Línea 2: sugerencias ────────────────────────────────────
      print "\n"
      if matches.any?
        parts = matches.each_with_index.map do |m, i|
          i == tab_idx ? "\e[1;32m[#{m}]\e[0m" : "\e[90m#{m}\e[0m"
        end
        print "  ↳ #{parts.join('  ')}"
      elsif buffer.empty?
        print "  \e[90m↳ escribe para ver sugerencias  ·  Tab  ·  Esc para cancelar\e[0m"
      else
        print "  \e[90m↳ sin coincidencias\e[0m"
      end
      $stdout.flush

      char = begin
        $stdin.getch
      rescue StandardError
        return nil
      end

      case char
      when "\r", "\n"          # Enter: confirmar
        print "\r\e[2K"
        print "\e[1A\r\e[2K"
        print "  #{label}: #{buffer}\n"
        return buffer.empty? ? nil : buffer

      when "\t"                # Tab: ciclar por coincidencias
        if matches.any?
          tab_idx = (tab_idx + 1) % matches.size
          buffer  = matches[tab_idx]
        end

      when "\x7f", "\b"        # Backspace: borrar último carácter
        buffer  = buffer[0..-2] unless buffer.empty?
        tab_idx = -1

      when "\e"                # Esc: cancelar
        # Consumir bytes adicionales (p.ej. flechas envían \e[A, \e[B…)
        begin
          $stdin.read_nonblock(3)
        rescue StandardError
          # Esc simple — no hay bytes extra
        end
        print "\r\e[2K"
        print "\e[1A\r\e[2K\n"
        return nil

      when /[\x20-\x7e]/       # ASCII imprimible
        buffer  += char
        tab_idx  = -1
        # Nota: caracteres UTF-8 multi-byte (é, ñ…) llegan en varios
        # bytes; se ignoran para no corromper el buffer.
      end
    end
  end

  def prompt_required(label)
    print "  #{label}: "
    value = gets.chomp.strip
    if value.empty?
      err "El campo '#{label}' no puede estar vacío."
      return nil
    end
    value
  end

  # Muestra un prompt con un valor por defecto entre corchetes.
  # Si el usuario pulsa Enter sin escribir nada, devuelve el default.
  def prompt_with_default(label, default)
    print "  #{label} [#{default}]: "
    input = gets.chomp.strip
    input.empty? ? default : input
  end

  def prompt_password_or_generate
    print "  Contraseña [Enter para generador personalizable]: "
    value = gets.chomp.strip

    unless value.empty?
      # Contraseña escrita a mano: validar fortaleza
      return show_password_strength(value)
    end

    # Enter vacío → abrir el generador personalizable
    puts
    prompt_generate_custom
  end

  # Muestra el generador personalizable: el usuario elige longitud,
  # conjuntos de caracteres y puede regenerar hasta quedar conforme.
  # Devuelve la contraseña elegida o nil si cancela con 'q'.
  def prompt_generate_custom
    puts "  ── Generador personalizable ────────────────────────────"
    puts "  Enter sin texto acepta el valor por defecto entre [corchetes].\n"

    length  = prompt_length
    puts
    upper   = prompt_yes_no("  Mayúsculas  A–Z  ", default: true)
    lower   = prompt_yes_no("  Minúsculas  a–z  ", default: true)
    digits  = prompt_yes_no("  Dígitos     0–9  ", default: true)
    symbols = prompt_yes_no("  Símbolos    !@#$…", default: true)

    unless upper || lower || digits || symbols
      err "Selecciona al menos un tipo de carácter."
      pause
      return nil
    end

    opts = { uppercase: upper, lowercase: lower,
             digits: digits, symbols: symbols }

    loop do
      begin
        password = PasswordGenerator.generate(length, opts)
      rescue ArgumentError => e
        err e.message
        pause
        return nil
      end

      puts "\n  Contraseña generada: \e[1;33m#{password}\e[0m"
      print "  Enter para aceptar  ·  r para regenerar  ·  q para cancelar: "

      case gets.chomp.strip.downcase
      when 'r' then next       # regenerar con los mismos parámetros
      when 'q' then return nil # cancelar
      else          return password  # Enter u otro → aceptar
      end
    end
  end

  # Muestra un prompt booleano con el valor por defecto entre corchetes.
  # Enter sin texto devuelve el valor por defecto.
  def prompt_yes_no(label, default: true)
    hint = default ? "[S/n]" : "[s/N]"
    print "#{label}  #{hint}: "
    input = gets.chomp.strip.downcase
    input.empty? ? default : input == 's'
  end

  def prompt_length
    print "  Longitud de la contraseña [#{DEFAULT_PWD_LEN}]: "
    input = gets.chomp.strip
    return DEFAULT_PWD_LEN if input.empty?

    n = input.to_i
    if input.match?(/\A\d+\z/) && n.between?(MIN_PWD_LEN, MAX_PWD_LEN)
      n
    else
      warn_msg "Valor fuera del rango #{MIN_PWD_LEN}–#{MAX_PWD_LEN}. Usando #{DEFAULT_PWD_LEN}."
      DEFAULT_PWD_LEN
    end
  end

  def prompt_index(action)
    print "\n  Número de entrada para #{action} (Enter para cancelar): "
    input = gets.chomp.strip
    return nil if input.empty?

    unless input.match?(/\A\d+\z/)
      err "Introduce un número entero válido."
      pause
      return nil
    end

    idx = input.to_i
    if idx >= @entries.size
      err "Índice #{idx} fuera de rango. " \
          "Rango válido: 0–#{@entries.size - 1}."
      pause
      return nil
    end

    idx
  end

  # ── Helpers de presentación ──────────────────────────────────────

  # Prepende old_password al historial de la entrada y recorta
  # a MAX_HISTORY entradas. Llamar ANTES de sobreescribir la contraseña.
  def add_to_history(entry, old_password)
    entry['history'] ||= []
    entry['history'].unshift({
      'password'   => old_password,
      'changed_at' => Time.now.iso8601
    })
    entry['history'] = entry['history'].first(MAX_HISTORY)
  end

  # ── Validación de fortaleza ──────────────────────────────────────

  # Evalúa cinco criterios de fortaleza y devuelve un hash con:
  #   score  — puntuación 0-5
  #   level  — texto ('Muy débil' … 'Muy fuerte')
  #   bar    — barra visual ANSI de 10 bloques
  #   color  — código ANSI del nivel
  #   checks — {length:, uppercase:, lowercase:, digits:, symbols:}
  def evaluate_password_strength(pwd)
    checks = {
      length:    pwd.length >= 12,
      uppercase: pwd.match?(/[A-Z]/),
      lowercase: pwd.match?(/[a-z]/),
      digits:    pwd.match?(/\d/),
      symbols:   pwd.match?(/[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]/)
    }
    score  = checks.values.count(true)
    color  = score >= 4 ? "\e[32m" : score == 3 ? "\e[33m" : "\e[31m"
    level  = ['Muy débil', 'Muy débil', 'Débil', 'Moderada', 'Fuerte', 'Muy fuerte'][score]
    filled = '█' * (score * 2)
    empty  = '░' * (10 - score * 2)
    {
      score:  score,
      checks: checks,
      length: pwd.length,
      level:  level,
      color:  color,
      bar:    "#{color}#{filled}\e[90m#{empty}\e[0m"
    }
  end

  # Muestra la fortaleza de una contraseña con barra visual y criterios.
  # Si score >= 3 retorna pwd directamente (sin interacción).
  # Si score <= 2 ofrece tres opciones al usuario:
  #   s → usar la contraseña débil tal cual
  #   g → generar una contraseña segura automáticamente (retorna la generada)
  #   n/Enter → cancelar (retorna nil)
  # Retorna siempre una String (la contraseña a usar) o nil si se canceló.
  def show_password_strength(pwd)
    s = evaluate_password_strength(pwd)
    puts
    puts "  Fortaleza : #{s[:bar]}  #{s[:color]}#{s[:level]}\e[0m  (#{s[:length]} caracteres)"
    puts "  Criterios : #{format_strength_checks(s[:checks])}"
    return pwd if s[:score] >= 3

    puts
    warn_msg "Contraseña débil."
    print "  (s) usar esta  ·  (g) generar segura  ·  (n / Enter) cancelar: "

    case gets.chomp.strip.downcase
    when 's'
      pwd                                        # usar la contraseña débil
    when 'g'
      generated = PasswordGenerator.generate(DEFAULT_PWD_LEN)
      puts "  Contraseña generada: \e[1;33m#{generated}\e[0m"
      generated                                  # usar la contraseña generada
    else
      nil                                        # cancelar
    end
  end

  # Elimina todos los códigos de escape ANSI (colores, estilos) de un string.
  def strip_ansi(str)
    str.to_s.gsub(/\e\[[0-9;]*m/, '')
  end

  # Formatea los cinco criterios como etiquetas coloreadas en una línea.
  def format_strength_checks(checks)
    { length: '≥12 chars', uppercase: 'mayúsculas',
      lowercase: 'minúsculas', digits: 'dígitos', symbols: 'símbolos' }
      .map { |k, label| checks[k] ? "\e[32m#{label} ✓\e[0m" : "\e[90m#{label} ✗\e[0m" }
      .join('  ')
  end

  # Pide la contraseña maestra y, si coincide, muestra la contraseña
  # de la entrada en pantalla. Protege contra accesos no autorizados
  # cuando alguien se acerca a una terminal ya desbloqueada.
  #
  # Comportamiento:
  #   · Hasta 3 intentos antes de denegar el acceso.
  #   · En cada intento fallido muestra cuántos quedan.
  #   · Si acierta: muestra la contraseña, espera Enter y limpia pantalla.
  #   · Retorna true si se mostró la contraseña, false si se denegó.
  def confirm_and_show_password(entry)
    max_attempts = 3

    max_attempts.times do |attempt|
      remaining = max_attempts - attempt
      hint      = attempt > 0 ? " (#{remaining} #{pluralize(remaining, 'intento', 'intentos')} restante(s))" : ""

      pwd = prompt_secret("Contraseña maestra para ver#{hint}")

      if pwd == @master_password
        log_event('password_view', entry['service'])
        sep = '─' * 50
        puts
        puts "  #{sep}"
        puts "  Servicio   : #{entry['service']}"
        puts "  Usuario    : #{entry['username']}"
        puts "  Contraseña : \e[1;33m#{entry['password']}\e[0m"
        puts "  #{sep}"
        print "\n  Pulsa Enter para ocultar la contraseña y limpiar la pantalla..."
        $stdin.gets
        clear_screen
        return true
      end

      log_event('password_view_fail', entry['service'])
      if attempt < max_attempts - 1
        err "Contraseña incorrecta. Inténtalo de nuevo."
      else
        err "Demasiados intentos fallidos. Acceso denegado."
      end
    end

    false
  end

  # Ordena @entries alfabéticamente por nombre de servicio
  # sin distinción de mayúsculas. Se llama al cargar, añadir y editar.
  def sort_entries!
    @entries.sort_by! { |e| e['service'].to_s.downcase }
  end

  def print_entries_table
    sep = '─' * 60

    puts "\n  #{sep}"
    puts "  #{"N°".ljust(5)}   #{"Servicio ↑ A–Z".ljust(24)} Usuario"
    puts "  #{sep}"

    if @entries.empty?
      puts "  (No hay entradas almacenadas)"
    else
      @entries.each_with_index do |e, i|
        has_hist = (e['history'] || []).any?
        marker   = has_hist ? "\e[90m*\e[0m" : ' '
        svc      = truncate(e['service'],  23)
        user     = truncate(e['username'], 25)
        puts "  #{i.to_s.ljust(5)} #{marker} #{svc.ljust(24)} #{user}"
      end
      if @entries.any? { |e| (e['history'] || []).any? }
        puts "  \e[90m      * = tiene historial de contraseñas\e[0m"
      end
    end

    puts "  #{sep}\n"
  end

  def truncate(str, max)
    s = str.to_s
    s.length > max ? "#{s[0, max - 1]}…" : s
  end

  def append_and_save(service, username, password)
    @entries << {
      'service'  => service,
      'username' => username,
      'password' => password,
      'history'  => []
    }
    sort_entries!
    save_vault
    log_event('entry_add', service)
  end

  # ── Helpers de búsqueda ──────────────────────────────────────────

  # Devuelve true si la query aparece (parcial, sin mayúsculas)
  # en el servicio O en el usuario de la entrada.
  # Devuelve false para query vacío (toda string contiene "").
  def entry_matches?(entry, query)
    return false if query.empty?
    q = query.downcase
    entry['service'].to_s.downcase.include?(q) ||
      entry['username'].to_s.downcase.include?(q)
  end

  # Envuelve la primera aparición de query en text con color cian+negrita.
  # Devuelve el text sin cambios si no hay coincidencia.
  def highlight(text, query)
    idx = text.downcase.index(query.downcase)
    return text unless idx
    before = text[0, idx]
    match  = text[idx, query.length]
    after  = text[(idx + query.length)..]
    "#{before}\e[1;36m#{match}\e[0m#{after}"
  end

  # Muestra la tabla de resultados con los términos resaltados.
  # results es un array de pares [entry, original_index].
  def print_search_table(results, query)
    sep = '─' * 60
    puts "\n  #{sep}"
    puts "  #{"N°".ljust(5)} #{"Servicio".ljust(27)} Usuario"
    puts "  #{sep}"
    results.each do |entry, orig_idx|
      svc  = truncate(entry['service'],  25).ljust(27)
      user = truncate(entry['username'], 25)
      puts "  #{orig_idx.to_s.ljust(5)} #{highlight(svc, query)} #{highlight(user, query)}"
    end
    puts "  #{sep}\n"
  end

  # Pide al usuario el N° original de una entrada de la lista de resultados.
  # Devuelve el índice si es válido, nil si el usuario pulsa Enter o el N° no existe.
  def prompt_result_index(results)
    valid = results.map { |_e, i| i }
    print "\n  Introduce el N° para ver detalle (Enter para omitir): "
    input = gets.chomp.strip
    return nil if input.empty?

    unless input.match?(/\A\d+\z/)
      err "Introduce un número entero válido."
      return nil
    end

    idx = input.to_i
    unless valid.include?(idx)
      err "El N° #{idx} no aparece en los resultados."
      return nil
    end

    idx
  end

  def empty_vault_notice
    info "El almacén está vacío. Añade entradas con la opción 3."
    pause
  end

  def info(msg)
    puts "\n  🔵   #{msg}"
  end

  def ok(msg)
    puts "\n  🟢  #{msg}"
  end

  def err(msg)
    puts "\n  🔴  #{msg}"
  end

  def warn_msg(msg)
    puts "\n  🟡   #{msg}"
  end

  def pluralize(n, singular, plural)
    n == 1 ? singular : plural
  end

  def pause
    print "\n  Pulsa Enter para continuar..."
    gets
  end

  def clear_screen
    system('clear') || system('cls')
  end

  # Convierte un timestamp ISO 8601 a formato legible dd/mm/aaaa HH:MM:SS.
  def format_audit_time(iso_string)
    Time.iso8601(iso_string).strftime('%d/%m/%Y %H:%M:%S')
  rescue StandardError
    iso_string.to_s[0, 19]
  end

  # Traduce la clave interna del evento a texto legible en español.
  def translate_action(action)
    {
      'login_ok'               => '[OK] Inicio de sesion',
      'session_lock'           => '[!!] Bloqueo automatico',
      'session_unlock_ok'      => '[OK] Desbloqueo',
      'session_unlock_fail'    => '[!!] Fallo desbloqueo',
      'password_view'          => '[OK] Ver contrasena',
      'password_view_fail'     => '[!!] Fallo ver contrasena',
      'password_restore'       => '[~]  Contrasena restaurada',
      'entry_add'              => '[+]  Nueva entrada',
      'entry_edit'             => '[~]  Entrada editada',
      'entry_delete'           => '[-]  Entrada eliminada',
      'vault_tamper_detected'  => '[!!] MODIFICACION EXTERNA',
      'backup_export'          => '[+]  Backup exportado',
      'backup_import_replace'  => '[~]  Backup importado (reemplazo)',
      'backup_import_merge'    => '[~]  Backup importado (mezcla)',
    }.fetch(action, action)
  end

  def show_banner
    puts <<~BANNER

      ╔═══════════════════════════════════════════════════════╗
      ║             GESTOR DE CONTRASEÑAS SEGURAS             ║
      ║                                                       ║
      ║  Cifrado    : AES-256-GCM                             ║
      ║  KDF        : PBKDF2-HMAC-SHA256 · 100 000 iter.      ║
      ║  Almacén    : #{VAULT_FILE.ljust(39)} ║
      ║  Permisos   : 0600                                    ║
      ║  Autocierre : #{format_timeout(INACTIVITY_TIMEOUT).ljust(39)} ║
      ╚═══════════════════════════════════════════════════════╝
    BANNER
  end

  # Pantalla que aparece cuando la sesión se bloquea por inactividad.
  def show_lock_banner
    sep      = '─' * 55
    time_str = format_timeout(INACTIVITY_TIMEOUT)
    puts <<~LOCK

      #{sep}

                       SESIÓN BLOQUEADA

        Inactividad detectada (#{time_str}).
        Introduce tu contraseña maestra para continuar.

      #{sep}

    LOCK
  end

  # Convierte segundos a texto legible, p.ej. 300 → "5 min".
  def format_timeout(seconds)
    mins = seconds / 60
    secs = seconds % 60
    secs.zero? ? "#{mins} min" : "#{mins} min #{secs} s"
  end

  def show_menu
    puts <<~MENU

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
    MENU
    print "  Elige una opción: "
  end
end

if __FILE__ == $PROGRAM_NAME
  begin
    PasswordManager.new.run
  rescue Interrupt
    puts "\n\n  🟡   Programa interrumpido. ¡Hasta pronto!"
    exit(0)
  rescue => e
    puts "\n  🔴  Error inesperado: #{e.message}"
    puts e.backtrace.first(5).map { |l| "     #{l}" }.join("\n") if $DEBUG
    exit(1)
  end
end