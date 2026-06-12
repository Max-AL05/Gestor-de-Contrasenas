# encoding: utf-8
# frozen_string_literal: true
#
# Suite de tests unitarios — Gestor de Contraseñas
# ─────────────────────────────────────────────────
# Ejecutar:   ruby test_password_manager.rb
# Verboso:    ruby test_password_manager.rb --verbose
# Un grupo:   ruby test_password_manager.rb --name TestCrypto
#
# Requisitos: Ruby >= 3.0 (solo librería estándar + minitest)

require 'minitest/autorun'
require 'fileutils'
require 'tmpdir'
require_relative 'gestor_contraseñas'

# ════════════════════════════════════════════════════════════════════
# Base común para los tests que necesitan una instancia de la clase
# ════════════════════════════════════════════════════════════════════
class PasswordManagerTest < Minitest::Test
  MASTER = 'MasterTest123!'

  # Crea un directorio temporal y cambia a él para que vault.json,
  # audit.log, etc. se creen ahí y no ensucien el proyecto.
  def setup
    @tmpdir      = Dir.mktmpdir('pm_test_')
    @original_dir = Dir.pwd
    Dir.chdir(@tmpdir)

    @pm = PasswordManager.new
    @pm.instance_variable_set(:@master_password, MASTER)
    @pm.instance_variable_set(:@audit_log,       [])
    @pm.instance_variable_set(:@entries,         sample_entries)
  end

  def teardown
    Dir.chdir(@original_dir)
    FileUtils.rm_rf(@tmpdir)
  end

  private

  # Llama a un método privado de PasswordManager.
  def pm(method, *args)
    @pm.send(method, *args)
  end

  def sample_entries
    [
      { 'service' => 'GitHub',  'username' => 'dev@email.com',  'password' => 'OldPass1!', 'history' => [] },
      { 'service' => 'Gmail',   'username' => 'user@gmail.com', 'password' => 'OldPass2!', 'history' => [] },
      { 'service' => 'Netflix', 'username' => 'user@email.com', 'password' => 'OldPass3!', 'history' => [] },
    ]
  end
end


# ════════════════════════════════════════════════════════════════════
# 1. PasswordGenerator
# ════════════════════════════════════════════════════════════════════
class TestPasswordGenerator < Minitest::Test

  def test_default_length_is_16
    assert_equal 16, PasswordGenerator.generate.length
  end

  def test_custom_length
    [8, 12, 24, 32, 64].each do |n|
      assert_equal n, PasswordGenerator.generate(n).length, "Longitud #{n}"
    end
  end

  def test_includes_all_types_by_default
    # Generamos varias para descartar falsos negativos por azar
    samples = Array.new(5) { PasswordGenerator.generate(20) }
    assert samples.any? { |p| p.match?(/[A-Z]/) },          'Debe haber mayúsculas'
    assert samples.any? { |p| p.match?(/[a-z]/) },          'Debe haber minúsculas'
    assert samples.any? { |p| p.match?(/[0-9]/) },          'Debe haber dígitos'
    assert samples.any? { |p| p.match?(/[!@#$%^&*()]/) },   'Debe haber símbolos'
  end

  def test_uppercase_only
    pwd = PasswordGenerator.generate(10,
      uppercase: true, lowercase: false, digits: false, symbols: false)
    assert_match(/\A[A-Z]{10}\z/, pwd)
  end

  def test_digits_only
    pwd = PasswordGenerator.generate(8,
      uppercase: false, lowercase: false, digits: true, symbols: false)
    assert_match(/\A[0-9]{8}\z/, pwd)
  end

  def test_no_symbols_when_disabled
    100.times do
      pwd = PasswordGenerator.generate(12, symbols: false)
      refute_match(/[!@#$%^&*()]/, pwd, 'No debe tener símbolos')
    end
  end

  def test_no_digits_when_disabled
    100.times do
      pwd = PasswordGenerator.generate(12, digits: false)
      refute_match(/[0-9]/, pwd, 'No debe tener dígitos')
    end
  end

  def test_raises_when_no_sets_selected
    assert_raises(ArgumentError) do
      PasswordGenerator.generate(8,
        uppercase: false, lowercase: false, digits: false, symbols: false)
    end
  end

  def test_raises_when_length_less_than_active_sets
    # 3 conjuntos activos → longitud mínima 3
    assert_raises(ArgumentError) do
      PasswordGenerator.generate(2,
        uppercase: true, lowercase: true, digits: true, symbols: false)
    end
  end

  def test_generates_unique_passwords
    pwds = Array.new(20) { PasswordGenerator.generate(16) }
    # Con 20 contraseñas de 16 chars, la probabilidad de duplicado es ínfima
    assert_equal 20, pwds.uniq.size, 'Cada contraseña debe ser única'
  end

  def test_guarantees_at_least_one_of_each_active_set
    # Con longitud = número de conjuntos, la única solución es uno de cada uno
    100.times do
      pwd = PasswordGenerator.generate(4)   # 4 conjuntos, longitud 4
      assert_match(/[A-Z]/, pwd, 'Debe incluir mayúscula')
      assert_match(/[a-z]/, pwd, 'Debe incluir minúscula')
      assert_match(/[0-9]/, pwd, 'Debe incluir dígito')
      assert_match(/[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]/, pwd, 'Debe incluir símbolo')
    end
  end
end


# ════════════════════════════════════════════════════════════════════
# 2. Crypto  (cifrado AES-256-GCM + PBKDF2)
# ════════════════════════════════════════════════════════════════════
class TestCrypto < Minitest::Test
  PASS  = 'CryptoTest123!'
  PLAIN = '{"service":"GitHub","password":"xK9#mP2!"}'

  def test_encrypt_decrypt_roundtrip
    enc = Crypto.encrypt(PLAIN, PASS)
    assert_equal PLAIN, Crypto.decrypt(enc, PASS)
  end

  def test_wrong_password_raises_cipher_error
    enc = Crypto.encrypt(PLAIN, PASS)
    assert_raises(OpenSSL::Cipher::CipherError) do
      Crypto.decrypt(enc, 'wrongPassword')
    end
  end

  def test_tampered_auth_tag_raises_error
    enc = Crypto.encrypt(PLAIN, PASS)
    bad = enc.merge('auth_tag' => ('ab' * 16))
    assert_raises(OpenSSL::Cipher::CipherError) do
      Crypto.decrypt(bad, PASS)
    end
  end

  def test_tampered_ciphertext_raises_error
    enc = Crypto.encrypt(PLAIN, PASS)
    bad = enc.merge('ciphertext' => enc['ciphertext'].sub(/../, '00'))
    assert_raises(OpenSSL::Cipher::CipherError) do
      Crypto.decrypt(bad, PASS)
    end
  end

  def test_each_encryption_uses_unique_salt_and_iv
    e1 = Crypto.encrypt(PLAIN, PASS)
    e2 = Crypto.encrypt(PLAIN, PASS)
    refute_equal e1['salt'],       e2['salt'],       'Salt debe ser único'
    refute_equal e1['iv'],         e2['iv'],         'IV debe ser único'
    refute_equal e1['ciphertext'], e2['ciphertext'], 'Ciphertext debe ser distinto'
  end

  def test_output_contains_required_keys
    enc = Crypto.encrypt(PLAIN, PASS)
    %w[salt iv auth_tag ciphertext].each do |key|
      assert enc.key?(key),        "Debe tener la clave '#{key}'"
      refute enc[key].empty?,      "'#{key}' no puede estar vacío"
    end
  end

  def test_output_values_are_hex_strings
    enc = Crypto.encrypt(PLAIN, PASS)
    %w[salt iv auth_tag ciphertext].each do |key|
      assert_match(/\A[0-9a-f]+\z/, enc[key], "'#{key}' debe ser hex")
    end
  end
end


# ════════════════════════════════════════════════════════════════════
# 3. Validación de fortaleza de contraseña
# ════════════════════════════════════════════════════════════════════
class TestPasswordStrength < PasswordManagerTest

  def test_empty_password_scores_zero
    r = pm(:evaluate_password_strength, '')
    assert_equal 0, r[:score]
    assert_equal 'Muy débil', r[:level]
  end

  def test_only_lowercase_scores_one
    r = pm(:evaluate_password_strength, 'abc')
    assert_equal 1, r[:score]
  end

  def test_lowercase_and_length_scores_two
    r = pm(:evaluate_password_strength, 'abcdefghijkl')
    assert_equal 2, r[:score]
    assert_equal 'Débil', r[:level]
  end

  def test_three_criteria_is_moderada
    r = pm(:evaluate_password_strength, 'Abcdefghijkl')
    assert_equal 3, r[:score]
    assert_equal 'Moderada', r[:level]
  end

  def test_four_criteria_is_fuerte
    r = pm(:evaluate_password_strength, 'Abcdefghijk1')
    assert_equal 4, r[:score]
    assert_equal 'Fuerte', r[:level]
  end

  def test_all_five_criteria_is_muy_fuerte
    r = pm(:evaluate_password_strength, 'Abcdefghijk1!')
    assert_equal 5, r[:score]
    assert_equal 'Muy fuerte', r[:level]
  end

  def test_length_criterion_requires_12_chars
    short = pm(:evaluate_password_strength, 'Abc1!')
    long  = pm(:evaluate_password_strength, 'Abcdefghij1!')
    refute short[:checks][:length], 'Menos de 12 no cumple el criterio de longitud'
    assert long[:checks][:length],  '12 o más cumple el criterio de longitud'
  end

  def test_result_includes_bar_and_color
    r = pm(:evaluate_password_strength, 'SomePass1!')
    assert r[:bar],   'Debe devolver barra visual'
    assert r[:color], 'Debe devolver código de color ANSI'
  end

  def test_weak_password_color_is_red
    r = pm(:evaluate_password_strength, 'abc')
    assert_includes r[:color], "\e[31", 'Contraseña débil debe ser roja'
  end

  def test_strong_password_color_is_green
    r = pm(:evaluate_password_strength, 'Abcdefghijk1!')
    assert_includes r[:color], "\e[32", 'Contraseña fuerte debe ser verde'
  end
end


# ════════════════════════════════════════════════════════════════════
# 4. Búsqueda y filtrado
# ════════════════════════════════════════════════════════════════════
class TestSearch < PasswordManagerTest

  def test_matches_exact_service_name
    assert pm(:entry_matches?, sample_entries[0], 'GitHub')
  end

  def test_matches_partial_service_name
    assert pm(:entry_matches?, sample_entries[0], 'it')    # g[it]hub
    assert pm(:entry_matches?, sample_entries[0], 'Hub')   # Git[Hub]
  end

  def test_matches_by_username
    assert pm(:entry_matches?, sample_entries[1], 'gmail.com')
    assert pm(:entry_matches?, sample_entries[2], 'user@email')
  end

  def test_no_match_returns_false
    refute pm(:entry_matches?, sample_entries[0], 'netflix')
    refute pm(:entry_matches?, sample_entries[0], 'xyz999')
  end

  def test_case_insensitive_service
    assert pm(:entry_matches?, sample_entries[0], 'GITHUB')
    assert pm(:entry_matches?, sample_entries[0], 'github')
    assert pm(:entry_matches?, sample_entries[0], 'GiThUb')
  end

  def test_case_insensitive_username
    assert pm(:entry_matches?, sample_entries[0], 'DEV@EMAIL')
    assert pm(:entry_matches?, sample_entries[0], 'dev@email')
  end

  def test_empty_query_returns_false
    refute pm(:entry_matches?, sample_entries[0], '')
  end
end


# ════════════════════════════════════════════════════════════════════
# 5. Historial de contraseñas
# ════════════════════════════════════════════════════════════════════
class TestHistory < PasswordManagerTest

  def test_adds_password_to_empty_history
    entry = { 'service' => 'Test', 'password' => 'v1', 'history' => [] }
    pm(:add_to_history, entry, 'v0')
    assert_equal 1, entry['history'].size
    assert_equal 'v0', entry['history'].first['password']
  end

  def test_most_recent_goes_first
    entry = { 'service' => 'Test', 'password' => 'v3', 'history' => [] }
    pm(:add_to_history, entry, 'v1')
    pm(:add_to_history, entry, 'v2')
    pm(:add_to_history, entry, 'v3')
    assert_equal 'v3', entry['history'].first['password'], 'Más reciente al principio'
    assert_equal 'v1', entry['history'].last['password'],  'Más antigua al final'
  end

  def test_respects_max_history_limit
    entry = { 'service' => 'Test', 'password' => 'v0', 'history' => [] }
    7.times { |i| pm(:add_to_history, entry, "v#{i}") }
    assert_equal PasswordManager::MAX_HISTORY, entry['history'].size
  end

  def test_oldest_entry_removed_when_full
    entry = { 'service' => 'Test', 'password' => 'v0', 'history' => [] }
    (PasswordManager::MAX_HISTORY + 1).times { |i| pm(:add_to_history, entry, "pass#{i}") }
    passwords = entry['history'].map { |h| h['password'] }
    refute_includes passwords, 'pass0', 'La entrada más antigua debe eliminarse'
  end

  def test_history_entry_has_valid_timestamp
    entry  = { 'service' => 'Test', 'password' => 'v1', 'history' => [] }
    pm(:add_to_history, entry, 'v0')
    ts = Time.iso8601(entry['history'].first['changed_at'])
    # Tolerancia de 2 s: iso8601 trunca decimales y puede quedar 1 s atrás
    assert (Time.now - ts).abs < 2, "Timestamp debe estar a menos de 2 s del momento actual"
  end

  def test_creates_history_key_if_missing
    entry = { 'service' => 'Test', 'password' => 'v1' }   # sin 'history'
    pm(:add_to_history, entry, 'v0')
    assert entry.key?('history'), "Debe crear la clave 'history'"
    assert_equal 1, entry['history'].size
  end
end


# ════════════════════════════════════════════════════════════════════
# 6. Registro de auditoría
# ════════════════════════════════════════════════════════════════════
class TestAuditLog < PasswordManagerTest

  def test_log_event_appends_entry
    pm(:log_event, 'login_ok')
    log = @pm.instance_variable_get(:@audit_log)
    assert_equal 1,          log.size
    assert_equal 'login_ok', log.first['action']
    refute_nil               log.first['timestamp']
  end

  def test_log_event_strips_ansi_from_detail
    pm(:log_event, 'password_view', "GitHub  \e[90m(historial · 01/01/2026)\e[0m")
    detail = @pm.instance_variable_get(:@audit_log).first['detail']
    refute_includes detail, "\e[",   'No debe contener códigos ANSI'
    assert_includes detail, 'GitHub','Debe conservar el texto'
  end

  def test_log_event_accepts_nil_detail
    pm(:log_event, 'session_lock', nil)
    assert_nil @pm.instance_variable_get(:@audit_log).first['detail']
  end

  def test_purge_removes_events_older_than_retention
    old_ts   = (Time.now - (PasswordManager::AUDIT_RETENTION_DAYS + 1) * 86400).iso8601
    fresh_ts = Time.now.iso8601
    @pm.instance_variable_set(:@audit_log, [
      { 'timestamp' => old_ts,   'action' => 'login_ok', 'detail' => nil },
      { 'timestamp' => fresh_ts, 'action' => 'entry_add','detail' => 'X' },
    ])
    pm(:purge_old_audit_events)
    log = @pm.instance_variable_get(:@audit_log)
    assert_equal 1,          log.size
    assert_equal 'entry_add',log.first['action']
  end

  def test_purge_keeps_all_recent_events
    log = 5.times.map { { 'timestamp' => Time.now.iso8601, 'action' => 'x', 'detail' => nil } }
    @pm.instance_variable_set(:@audit_log, log)
    pm(:purge_old_audit_events)
    assert_equal 5, @pm.instance_variable_get(:@audit_log).size
  end

  def test_purge_preserves_entries_with_bad_timestamp
    @pm.instance_variable_set(:@audit_log, [
      { 'timestamp' => 'FECHA_INVALIDA', 'action' => 'login_ok', 'detail' => nil },
    ])
    pm(:purge_old_audit_events)
    # Un timestamp ilegible debe conservarse (no se puede saber si es viejo)
    assert_equal 1, @pm.instance_variable_get(:@audit_log).size
  end
end


# ════════════════════════════════════════════════════════════════════
# 7. Integridad del almacén (SHA-256)
# ════════════════════════════════════════════════════════════════════
class TestVaultIntegrity < PasswordManagerTest

  def test_save_vault_creates_checksum_file
    pm(:save_vault)
    assert File.exist?(PasswordManager::CHECKSUM_FILE), 'Debe crear vault.json.sha256'
  end

  def test_checksum_is_valid_sha256_hex
    pm(:save_vault)
    digest = File.read(PasswordManager::CHECKSUM_FILE).strip
    assert_match(/\A[0-9a-f]{64}\z/, digest, 'Debe ser SHA-256 en hexadecimal')
  end

  def test_checksum_matches_vault_file
    pm(:save_vault)
    saved   = File.read(PasswordManager::CHECKSUM_FILE).strip
    current = OpenSSL::Digest::SHA256.file(PasswordManager::VAULT_FILE).hexdigest
    assert_equal saved, current
  end

  def test_tampered_vault_produces_different_checksum
    pm(:save_vault)
    original = File.read(PasswordManager::CHECKSUM_FILE).strip

    # Modificar el vault sin actualizar el checksum
    File.write(PasswordManager::VAULT_FILE, File.read(PasswordManager::VAULT_FILE) + 'X')

    current = OpenSSL::Digest::SHA256.file(PasswordManager::VAULT_FILE).hexdigest
    refute_equal original, current, 'La modificación debe cambiar el hash'
  end

  def test_vault_save_load_roundtrip
    entries = [{ 'service' => 'RoundTrip', 'username' => 'u', 'password' => 'P@ss1!', 'history' => [] }]
    @pm.instance_variable_set(:@entries, entries)
    pm(:save_vault)

    # Cargar con una nueva instancia
    pm2 = PasswordManager.new
    pm2.instance_variable_set(:@master_password, MASTER)
    pm2.instance_variable_set(:@entries,         [])
    pm2.instance_variable_set(:@audit_log,       [])
    pm2.send(:load_vault)

    loaded = pm2.instance_variable_get(:@entries)
    assert_equal 1,            loaded.size
    assert_equal 'RoundTrip',  loaded.first['service']
    assert_equal 'u',          loaded.first['username']
  end
end


# ════════════════════════════════════════════════════════════════════
# 8. Helpers de utilidad
# ════════════════════════════════════════════════════════════════════
class TestHelpers < PasswordManagerTest

  def test_strip_ansi_removes_single_color_code
    assert_equal 'hola',  pm(:strip_ansi, "\e[32mhola\e[0m")
  end

  def test_strip_ansi_removes_compound_color_code
    assert_equal 'text',  pm(:strip_ansi, "\e[1;33mtext\e[0m")
  end

  def test_strip_ansi_removes_dim_code
    assert_equal '(gris)', pm(:strip_ansi, "\e[90m(gris)\e[0m")
  end

  def test_strip_ansi_leaves_plain_string_unchanged
    assert_equal 'sin codigos', pm(:strip_ansi, 'sin codigos')
  end

  def test_strip_ansi_returns_empty_for_only_codes
    assert_equal '', pm(:strip_ansi, "\e[0m")
  end

  def test_strip_ansi_handles_nested_codes
    assert_equal 'doble', pm(:strip_ansi, "\e[31m\e[1mdoble\e[0m")
  end

  def test_truncate_shortens_long_strings
    result = pm(:truncate, 'a' * 30, 10)
    assert result.length <= 10
    assert result.end_with?('…')
  end

  def test_truncate_leaves_short_strings_unchanged
    assert_equal 'hola', pm(:truncate, 'hola', 10)
  end

  def test_truncate_at_exact_limit
    assert_equal 'abcde', pm(:truncate, 'abcde', 5)
  end

  def test_sort_entries_alphabetical_case_insensitive
    entries = [
      { 'service' => 'Zoom',   'username' => 'a', 'password' => '1', 'history' => [] },
      { 'service' => 'amazon', 'username' => 'b', 'password' => '2', 'history' => [] },
      { 'service' => 'GitHub', 'username' => 'c', 'password' => '3', 'history' => [] },
      { 'service' => 'Apple',  'username' => 'd', 'password' => '4', 'history' => [] },
    ]
    @pm.instance_variable_set(:@entries, entries)
    pm(:sort_entries!)
    names = @pm.instance_variable_get(:@entries).map { |e| e['service'] }
    assert_equal %w[amazon Apple GitHub Zoom], names
  end

  def test_format_timeout_minutes_only
    assert_equal '5 min',  pm(:format_timeout, 300)
    assert_equal '60 min', pm(:format_timeout, 3600)
    assert_equal '1 min',  pm(:format_timeout, 60)
  end

  def test_format_timeout_minutes_and_seconds
    assert_equal '1 min 30 s', pm(:format_timeout, 90)
    assert_equal '0 min 45 s', pm(:format_timeout, 45)
  end

  def test_format_audit_time_output_format
    result = pm(:format_audit_time, '2026-06-11T14:30:00+00:00')
    assert_match(/\A\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}:\d{2}\z/, result)
  end

  def test_format_audit_time_invalid_returns_substring
    result = pm(:format_audit_time, 'FECHA_INVALIDA')
    assert_kind_of String, result
    refute_nil result
  end
end