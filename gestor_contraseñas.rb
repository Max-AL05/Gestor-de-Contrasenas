require 'securerandom'
require 'openssl'
require 'json'
require 'io/console'
require 'timeout'

module PasswordGenerator
  UPPERCASE = ('A'..'Z').to_a.freeze
  LOWERCASE = ('a'..'z').to_a.freeze
  DIGITS    = ('0'..'9').to_a.freeze
  SYMBOLS   = '!@#$%^&*()_+-=[]{}|;:,.<>?'.chars.freeze
  ALL_CHARS = (UPPERCASE + LOWERCASE + DIGITS + SYMBOLS).freeze

  def self.generate(length = 16)
    raise ArgumentError, "La longitud mínima es 4 caracteres" if length < 4

    password = [
      UPPERCASE[SecureRandom.random_number(UPPERCASE.size)],
      LOWERCASE[SecureRandom.random_number(LOWERCASE.size)],
      DIGITS[SecureRandom.random_number(DIGITS.size)],
      SYMBOLS[SecureRandom.random_number(SYMBOLS.size)]
    ]

    (length - 4).times do
      password << ALL_CHARS[SecureRandom.random_number(ALL_CHARS.size)]
    end

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
  rescue Errno::EACCES => e
    err "No se pudo guardar el almacén: #{e.message}"
  end

  def load_audit_log
    return unless File.exist?(AUDIT_FILE)
    @audit_log = JSON.parse(File.read(AUDIT_FILE))
    purge_old_audit_events
  rescue StandardError
    @audit_log = []
  end

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

  def save_audit_log
    File.write(AUDIT_FILE, JSON.pretty_generate(@audit_log))
    File.chmod(0o600, AUDIT_FILE)
  rescue StandardError
  end

  def log_event(action, detail = nil)
    @audit_log << {
      'timestamp' => Time.now.iso8601,
      'action'    => action,
      'detail'    => detail
    }
    save_audit_log
  end

  def dispatch(option)
    clear_screen
    case option
    when '1' then cmd_browse
    when '2' then cmd_search
    when '3' then cmd_add
    when '4' then cmd_edit
    when '5' then cmd_delete
    when '6' then cmd_change_master
    when '7' then cmd_audit
    when '8' then cmd_history
    when '0' then cmd_exit
    else
      err "Opción '#{option}' no válida. Elige entre 0 y 8."
    end
  end


  def cmd_browse
    puts "  ── Servicios almacenados ───────────────────────────────"
    print_entries_table
    return pause if @entries.empty?

    idx = prompt_index("ver detalle de")
    return unless idx

    e   = @entries[idx]
    sep = '─' * 50
    puts
    puts "  #{sep}"
    puts "  Servicio : #{e['service']}"
    puts "  Usuario  : #{e['username']}"
    puts "  #{sep}"
    confirmed = confirm_and_show_password(e)
    pause unless confirmed   # si falló, pausa para que se lea el error
  end


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


  def cmd_edit
    return empty_vault_notice if @entries.empty?

    puts "  ── Editar entrada ──────────────────────────────────────"
    print_entries_table

    idx = prompt_index("editar")
    return unless idx

    e = @entries[idx]

    puts "\n  Deja en blanco y pulsa Enter para conservar el valor actual.\n"
    print "  Servicio    [#{e['service']}]: "
    input_svc = gets.chomp.strip
    new_svc   = input_svc.empty? ? e['service'] : input_svc
    print "  Usuario     [#{e['username']}]: "
    input_usr = gets.chomp.strip
    new_usr   = input_usr.empty? ? e['username'] : input_usr
    puts "  Contraseña  [actual oculta — Enter para conservar | 'g' para generar nueva]:"
    print "  > "
    input_pwd = gets.chomp.strip

    new_pwd = case input_pwd
              when ''
                e['password']
              when 'g', 'G'
                length    = prompt_length
                generated = PasswordGenerator.generate(length)
                puts "  Contraseña generada: \e[1;33m#{generated}\e[0m"
                generated
              else
                result = show_password_strength(input_pwd)
                return unless result
                result
              end
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
    add_to_history(@entries[idx], e['password']) if new_pwd != e['password']
    @entries[idx]['service']  = new_svc
    @entries[idx]['username'] = new_usr
    @entries[idx]['password'] = new_pwd
    sort_entries!
    save_vault
    log_event('entry_edit', new_svc)

    ok "Entrada actualizada y almacén guardado."
    pause
  end


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
      detail  = truncate(event['detail'] || '—', 20)
      puts "  #{time.ljust(21)} #{action} #{detail}"
    end

    puts "  #{sep}"
    puts "\n  #{total} evento(s) en total." \
         "#{total > page ? " Mostrando los últimos #{page}." : ''}"
    pause
  end


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
    temp = {
      'service'  => "#{e['service']}  \e[90m(historial · #{date_str})\e[0m",
      'username' => e['username'],
      'password' => h['password']
    }
    confirmed = confirm_and_show_password(temp)
    return unless confirmed
    puts "  Servicio : #{e['service']}"
    print "  ¿Restaurar la contraseña del #{date_str} como contraseña actual? (s/N): "
    return unless gets.chomp.strip.downcase == 's'
    @entries[idx]['history'].delete_at(hist_idx)
    add_to_history(@entries[idx], e['password'])
    @entries[idx]['password'] = h['password']

    save_vault
    log_event('password_restore', e['service'])
    ok "Contraseña restaurada. La anterior ha quedado en el historial."
    pause
  end


  def cmd_exit
    @master_password&.replace("\x00" * @master_password.bytesize)
    puts "\n  ⚪  ¡Hasta pronto! Tu almacén está protegido."
    exit(0)
  end


  def lock_session!
    log_event('session_lock')
    @master_password&.replace("\x00" * @master_password.bytesize)
    @master_password = nil
    @entries = []
    clear_screen
    show_lock_banner
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
      matches = buffer.empty? ? [] : candidates
        .select  { |c| c.downcase.start_with?(buffer.downcase) }
        .sort_by { |c| c.downcase }
        .first(6)
      if drawn
        print "\r\e[2K"
        print "\e[1A\r\e[2K"
      end
      drawn = true
      print "  #{label}: #{buffer}"
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
      when "\r", "\n"
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
      when /[\x20-\x7e]/
        buffer  += char
        tab_idx  = -1
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

  def prompt_password_or_generate
    print "  Contraseña [Enter para generar automáticamente]: "
    value = gets.chomp.strip
    unless value.empty?
      return show_password_strength(value)
    end
    length   = prompt_length
    password = PasswordGenerator.generate(length)
    puts "    Contraseña generada: \e[1;33m#{password}\e[0m"
    password
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

  def add_to_history(entry, old_password)
    entry['history'] ||= []
    entry['history'].unshift({
      'password'   => old_password,
      'changed_at' => Time.now.iso8601
    })
    entry['history'] = entry['history'].first(MAX_HISTORY)
  end

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

  def show_password_strength(pwd)
    s = evaluate_password_strength(pwd)
    puts
    puts "  Fortaleza : #{s[:bar]}  #{s[:color]}#{s[:level]}\e[0m  (#{s[:length]} caracteres)"
    puts "  Criterios : #{format_strength_checks(s[:checks])}"
    return pwd if s[:score] >= 3
    puts
    warn_msg "Contraseña débil."
    print "  (s) usar esta  ·  (g) generar segura  ·  (n) cancelar: "
    case gets.chomp.strip.downcase
    when 's'
      pwd
    when 'g'
      generated = PasswordGenerator.generate(DEFAULT_PWD_LEN)
      puts "  Contraseña generada: \e[1;33m#{generated}\e[0m"
      generated
    else
      nil
    end
  end
  def format_strength_checks(checks)
    { length: '≥12 chars', uppercase: 'mayúsculas',
      lowercase: 'minúsculas', digits: 'dígitos', symbols: 'símbolos' }
      .map { |k, label| checks[k] ? "\e[32m#{label} ✓\e[0m" : "\e[90m#{label} ✗\e[0m" }
      .join('  ')
  end

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

  def entry_matches?(entry, query)
    q = query.downcase
    entry['service'].to_s.downcase.include?(q) ||
      entry['username'].to_s.downcase.include?(q)
  end

  def highlight(text, query)
    idx = text.downcase.index(query.downcase)
    return text unless idx
    before = text[0, idx]
    match  = text[idx, query.length]
    after  = text[(idx + query.length)..]
    "#{before}\e[1;36m#{match}\e[0m#{after}"
  end

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

  def format_audit_time(iso_string)
    Time.iso8601(iso_string).strftime('%d/%m/%Y %H:%M:%S')
  rescue StandardError
    iso_string.to_s[0, 19]
  end

  def translate_action(action)
    {
      'login_ok'             => '[OK] Inicio de sesion',
      'session_lock'         => '[!!] Bloqueo automatico',
      'session_unlock_ok'    => '[OK] Desbloqueo',
      'session_unlock_fail'  => '[!!] Fallo desbloqueo',
      'password_view'        => '[OK] Ver contrasena',
      'password_view_fail'   => '[!!] Fallo ver contrasena',
      'password_restore'     => '[~]  Contrasena restaurada',
      'entry_add'            => '[+]  Nueva entrada',
      'entry_edit'           => '[~]  Entrada editada',
      'entry_delete'         => '[-]  Entrada eliminada',
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
      │  1. Ver entradas                                │
      │  2. Buscar entradas                             │
      │  3. Añadir entrada                              │
      │  4. Editar entrada                              │
      │  5. Eliminar entrada                            │
      │  6. Cambiar contraseña maestra                  │
      │  7. Ver registro de auditoría                   │
      │  8. Historial de contraseñas                    │
      │  0. Salir                                       │
      └─────────────────────────────────────────────────┘
    MENU
    print "  Elige una opción: "
  end
end

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