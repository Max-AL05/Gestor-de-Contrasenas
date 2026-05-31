require 'securerandom'
require 'openssl'
require 'json'
require 'io/console'

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
  VAULT_FILE      = 'vault.json'
  MIN_MASTER_LEN  = 8
  DEFAULT_PWD_LEN = 16
  MIN_PWD_LEN     = 4
  MAX_PWD_LEN     = 128

  def initialize
    @master_password = nil
    @entries = []
  end

  def run
    clear_screen
    show_banner
    authenticate
    load_vault

    loop do
      show_menu
      dispatch(gets.chomp.strip)
    end
  end

  private

  def authenticate
    @master_password = prompt_secret("🔑  Contraseña maestra")
    if @master_password.empty?
      abort "\n  ❌  La contraseña maestra no puede estar vacía."
    end
  end

  def load_vault
    unless File.exist?(VAULT_FILE)
      info "Almacén no encontrado. Se creará al guardar la primera entrada."
      @entries = []
      return
    end

    print "\n  ⏳  Derivando clave y descifrando almacén..."
    $stdout.flush

    begin
      encrypted_data = JSON.parse(File.read(VAULT_FILE))
      plaintext      = Crypto.decrypt(encrypted_data, @master_password)
      @entries       = JSON.parse(plaintext)
      print "\r" + (" " * 55) + "\r"
      ok "Almacén cargado — #{@entries.size} #{pluralize(@entries.size, 'entrada', 'entradas')}."
    rescue OpenSSL::Cipher::CipherError
      abort "\n\n  ❌  Contraseña maestra incorrecta o el archivo ha sido alterado."
    rescue JSON::ParserError
      abort "\n  ❌  El archivo del almacén está dañado y no puede leerse."
    rescue Errno::EACCES => e
      abort "\n  ❌  Sin permisos para leer '#{VAULT_FILE}': #{e.message}"
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

  def dispatch(option)
    clear_screen
    case option
    when '1' then cmd_browse
    when '2' then cmd_add
    when '3' then cmd_delete
    when '4' then cmd_change_master
    when '0' then cmd_exit
    else
      err "Opción '#{option}' no válida. Elige entre 0 y 4."
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
    puts
    puts "  #{sep}"
    puts "  Servicio   : #{e['service']}"
    puts "  Usuario    : #{e['username']}"
    puts "  Contraseña : \e[1;33m#{e['password']}\e[0m"
    puts "  #{sep}"
    pause
  end


  # ── Opción 2: Añadir entrada (manual o con contraseña generada) ─
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


  # ── Opción 3: Eliminar una entrada por índice ───────────────────

  def cmd_delete
    return empty_vault_notice if @entries.empty?

    puts "  ── Eliminar entrada ────────────────────────────────────"
    print_entries_table

    idx = prompt_index("eliminar")
    return unless idx

    e = @entries[idx]
    print "\n  ⚠️   ¿Eliminar '#{e['service']}' (#{e['username']})? "
    print "Esta acción es irreversible. (s/N): "
    input = gets.chomp.strip.downcase

    if input == 's'
      @entries.delete_at(idx)
      save_vault
      ok "Entrada eliminada y almacén guardado."
    else
      info "Operación cancelada."
    end
    pause
  end


  # ── Opción 4: Cambiar contraseña maestra ────────────────────────

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


  # ── Opción 0: Salir del programa ────────────────────────────────

  def cmd_exit
    @master_password&.replace("\x00" * @master_password.bytesize)
    puts "\n  👋  ¡Hasta pronto! Tu almacén está protegido."
    exit(0)
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
    return value unless value.empty?

    length   = prompt_length
    password = PasswordGenerator.generate(length)
    puts "  🔐  Contraseña generada: \e[1;33m#{password}\e[0m"
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

  def print_entries_table
    sep = '─' * 60

    puts "\n  #{sep}"
    puts "  #{"N°".ljust(5)} #{"Servicio".ljust(27)} Usuario"
    puts "  #{sep}"

    if @entries.empty?
      puts "  (No hay entradas almacenadas)"
    else
      @entries.each_with_index do |e, i|
        svc  = truncate(e['service'],  25)
        user = truncate(e['username'], 25)
        puts "  #{i.to_s.ljust(5)} #{svc.ljust(27)} #{user}"
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
      'password' => password
    }
    save_vault
  end

  def empty_vault_notice
    info "El almacén está vacío. Añade entradas con la opción 2."
    pause
  end

  def info(msg)
    puts "\n  ℹ️   #{msg}"
  end

  def ok(msg)
    puts "\n  ✅  #{msg}"
  end

  def err(msg)
    puts "\n  ❌  #{msg}"
  end

  def warn_msg(msg)
    puts "\n  ⚠️   #{msg}"
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

  def show_banner
    puts <<~BANNER

      ╔═══════════════════════════════════════════════════════╗
      ║             GESTOR DE CONTRASEÑAS SEGURAS             ║
      ║                                                       ║
      ║  Cifrado    : AES-256-GCM (cifrado autenticado)       ║
      ║  KDF        : PBKDF2-HMAC-SHA256 · 100 000 iter.      ║
      ║  Almacén    : #{VAULT_FILE.ljust(39)} ║
      ║  Permisos   : 0600 (solo el propietario)              ║
      ╚═══════════════════════════════════════════════════════╝
    BANNER
  end

  def show_menu
    puts <<~MENU

      ┌─────────────────────────────────────────────────┐
      │                MENÚ PRINCIPAL                   │
      ├─────────────────────────────────────────────────┤
      │  1. Ver entradas                                │
      │  2. Añadir entrada                              │
      │  3. Eliminar entrada                            │
      │  4. Cambiar contraseña maestra                  │
      │  0. Salir                                       │
      └─────────────────────────────────────────────────┘
    MENU
    print "  Elige una opción: "
  end
end

begin
  PasswordManager.new.run
rescue Interrupt
  puts "\n\n  ⚠️   Programa interrumpido. ¡Hasta pronto!"
  exit(0)
rescue => e
  puts "\n  ❌  Error inesperado: #{e.message}"
  puts e.backtrace.first(5).map { |l| "     #{l}" }.join("\n") if $DEBUG
  exit(1)
end