-- ══════════════════════════════════════════════════════════════
--  PET-PROJECT — Audit Log Setup (v2 — blockchain-style chaining)
--  Run this ONCE, AFTER stored_procedures.sql (and role_migration.sql
--  if you used it). WARNING: DROP TABLE wipes existing audit data.
-- ══════════════════════════════════════════════════════════════

USE petdb;

-- ──────────────────────────────────────────────────────────────
--  STEP 1 — audit_logs table (+ prev_hash, curr_hash added)
-- ──────────────────────────────────────────────────────────────

DROP TABLE IF EXISTS audit_logs;

CREATE TABLE audit_logs (
  log_id       INT AUTO_INCREMENT PRIMARY KEY,
  user_id      INT          DEFAULT NULL,
  username     VARCHAR(255) DEFAULT NULL,
  action_type  VARCHAR(50)  NOT NULL,
  table_name   VARCHAR(100) DEFAULT 'users',
  record_id    INT          DEFAULT NULL,
  old_data     TEXT         DEFAULT NULL,
  new_data     TEXT         DEFAULT NULL,
  performed_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
  ip_address   VARCHAR(100) DEFAULT NULL,
  device_info  TEXT         DEFAULT NULL,
  prev_hash    CHAR(64)     DEFAULT NULL,
  curr_hash    CHAR(64)     DEFAULT NULL,
  UNIQUE KEY uq_curr_hash (curr_hash)
);

-- ──────────────────────────────────────────────────────────────
--  STEP 2 — DML triggers on `users` (INSERT / UPDATE / DELETE)
--  These fire automatically and log straight into audit_logs.
-- ──────────────────────────────────────────────────────────────

DROP TRIGGER IF EXISTS trg_after_user_insert;
DROP TRIGGER IF EXISTS trg_after_user_update;
DROP TRIGGER IF EXISTS trg_before_user_delete;

DELIMITER //

CREATE TRIGGER trg_after_user_insert
AFTER INSERT ON users
FOR EACH ROW
BEGIN
  INSERT INTO audit_logs (
    user_id, username, action_type, table_name, record_id,
    old_data, new_data, performed_at, ip_address, device_info
  ) VALUES (
    NEW.id, NEW.userid, 'INSERT', 'users', NEW.id,
    NULL,
    JSON_OBJECT(
      'userid', NEW.userid,
      'role', NEW.role,
      'name_enc', HEX(NEW.name),
      'mobile_enc', HEX(NEW.mobile),
      'address_enc', HEX(NEW.address),
      'email_enc', HEX(NEW.email)
    ),
    NOW(), @audit_ip, @audit_device
  );
END //

CREATE TRIGGER trg_after_user_update
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
  INSERT INTO audit_logs (
    user_id, username, action_type, table_name, record_id,
    old_data, new_data, performed_at, ip_address, device_info
  ) VALUES (
    OLD.id, OLD.userid, 'UPDATE', 'users', OLD.id,
    JSON_OBJECT(
      'userid', OLD.userid, 'role', OLD.role, 'name_enc', HEX(OLD.name),
      'mobile_enc', HEX(OLD.mobile), 'address_enc', HEX(OLD.address),
      'email_enc', HEX(OLD.email)
    ),
    JSON_OBJECT(
      'userid', NEW.userid, 'role', NEW.role, 'name_enc', HEX(NEW.name),
      'mobile_enc', HEX(NEW.mobile), 'address_enc', HEX(NEW.address),
      'email_enc', HEX(NEW.email)
    ),
    NOW(), @audit_ip, @audit_device
  );
END //

CREATE TRIGGER trg_before_user_delete
BEFORE DELETE ON users
FOR EACH ROW
BEGIN
  INSERT INTO audit_logs (
    user_id, username, action_type, table_name, record_id,
    old_data, new_data, performed_at, ip_address, device_info
  ) VALUES (
    OLD.id, OLD.userid, 'DELETE', 'users', OLD.id,
    JSON_OBJECT(
      'userid', OLD.userid, 'role', OLD.role, 'name_enc', HEX(OLD.name),
      'mobile_enc', HEX(OLD.mobile), 'address_enc', HEX(OLD.address),
      'email_enc', HEX(OLD.email)
    ),
    NULL, NOW(), @audit_ip, @audit_device
  );
END //

DELIMITER ;

-- ──────────────────────────────────────────────────────────────
--  STEP 3 — user_activity_log + its cascading trigger
--  SELECT-type events (login, profile view, grade view, blocked
--  attempts...) can't be caught by DML triggers, so server.js
--  inserts a plain row here — this trigger then formats it into
--  audit_logs automatically, so all events end up in one place.
-- ──────────────────────────────────────────────────────────────

DROP TABLE IF EXISTS user_activity_log;

CREATE TABLE user_activity_log (
  activity_id  INT AUTO_INCREMENT PRIMARY KEY,
  user_id      INT          DEFAULT NULL,
  username     VARCHAR(255) DEFAULT NULL,
  action_type  VARCHAR(50)  NOT NULL,
  record_id    INT          DEFAULT NULL,
  old_data     TEXT         DEFAULT NULL,
  new_data     TEXT         DEFAULT NULL,
  ip_address   VARCHAR(100) DEFAULT NULL,
  device_info  TEXT         DEFAULT NULL,
  logged_at    TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);

DROP TRIGGER IF EXISTS trg_after_activity_insert;

DELIMITER //

CREATE TRIGGER trg_after_activity_insert
AFTER INSERT ON user_activity_log
FOR EACH ROW
BEGIN
  INSERT INTO audit_logs (
    user_id, username, action_type, table_name, record_id,
    old_data, new_data, performed_at, ip_address, device_info
  ) VALUES (
    NEW.user_id, NEW.username, NEW.action_type, 'users', NEW.record_id,
    NEW.old_data, NEW.new_data, NOW(), NEW.ip_address, NEW.device_info
  );
END //

DELIMITER ;

-- ══════════════════════════════════════════════════════════════
--  STEP 4 — THE BLOCKCHAIN PART
--  (a) BEFORE INSERT: chain this row to the previous row's hash
--  (b) BEFORE UPDATE / DELETE: hard-block, table becomes append-only
-- ══════════════════════════════════════════════════════════════

DROP TRIGGER IF EXISTS trg_audit_logs_hash_chain;
DROP TRIGGER IF EXISTS trg_block_audit_update;
DROP TRIGGER IF EXISTS trg_block_audit_delete;

DELIMITER //

CREATE TRIGGER trg_audit_logs_hash_chain
BEFORE INSERT ON audit_logs
FOR EACH ROW
BEGIN
  DECLARE last_hash CHAR(64);

  SELECT curr_hash INTO last_hash
  FROM audit_logs
  ORDER BY log_id DESC
  LIMIT 1;

  IF last_hash IS NULL THEN
    SET last_hash = REPEAT('0', 64);   -- genesis block
  END IF;

  SET NEW.prev_hash = last_hash;

  SET NEW.curr_hash = SHA2(
    CONCAT_WS('|',
      last_hash,
      IFNULL(NEW.user_id, ''),
      IFNULL(NEW.username, ''),
      NEW.action_type,
      IFNULL(NEW.table_name, ''),
      IFNULL(NEW.record_id, ''),
      IFNULL(NEW.old_data, ''),
      IFNULL(NEW.new_data, ''),
      NEW.performed_at,
      IFNULL(NEW.ip_address, ''),
      IFNULL(NEW.device_info, '')
    ),
    256
  );
END //

CREATE TRIGGER trg_block_audit_update
BEFORE UPDATE ON audit_logs
FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000'
  SET MESSAGE_TEXT = 'audit_logs is append-only — UPDATE is not permitted.';
END //

CREATE TRIGGER trg_block_audit_delete
BEFORE DELETE ON audit_logs
FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000'
  SET MESSAGE_TEXT = 'audit_logs is append-only — DELETE is not permitted.';
END //

DELIMITER ;

-- ──────────────────────────────────────────────────────────────
--  STEP 5 — sp_GetAuditLogs (hash columns bhi return karo ab)
-- ──────────────────────────────────────────────────────────────

DROP PROCEDURE IF EXISTS sp_GetAuditLogs;

DELIMITER //

CREATE PROCEDURE sp_GetAuditLogs()
BEGIN
  SELECT
    log_id, user_id, username, action_type, table_name, record_id,
    old_data, new_data, performed_at, ip_address, device_info,
    prev_hash, curr_hash
  FROM audit_logs
  ORDER BY log_id ASC;   -- ASC zaroori hai chain-order verification ke liye
END //

DELIMITER ;

-- VERIFY:
-- SHOW TRIGGERS FROM petdb;
-- DESCRIBE audit_logs;