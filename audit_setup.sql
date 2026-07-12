-- ══════════════════════════════════════════════════════════════
--  PET-PROJECT — Audit Log Setup
--  File: audit_setup.sql
--  Run this ONCE in MySQL after your existing stored_procedures.sql
--
--  What this file does:
--  1. Creates audit_logs table
--  2. Creates AFTER INSERT trigger on users  → logs new registrations
--  3. Creates AFTER UPDATE trigger on users  → logs profile changes (old + new encrypted values)
--  4. Creates BEFORE DELETE trigger on users → logs deleted record before it's gone
--  5. Creates sp_GetAuditLogs procedure      → admin panel ke liye
-- ══════════════════════════════════════════════════════════════

USE petdb;

-- ──────────────────────────────────────────────────────────────
--  STEP 1 — audit_logs table
--
--  Columns explained:
--  log_id       → auto increment primary key
--  user_id      → which user's record was affected (users.id)
--  username     → email of affected user (plain text — login id hai)
--  action_type  → INSERT / UPDATE / DELETE / LOGIN / PROFILE_VIEW / REGISTER
--  table_name   → which table was touched (always 'users' for now)
--  record_id    → id of the affected row in that table
--  old_data     → JSON of values BEFORE the change (UPDATE/DELETE ke liye)
--  new_data     → JSON of values AFTER the change  (INSERT/UPDATE ke liye)
--  performed_at → exact timestamp
--  ip_address   → captured from Node.js (triggers cannot get IP)
--  device_info  → user agent string from browser (Node.js se aata hai)
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
  device_info  TEXT         DEFAULT NULL
);

-- ──────────────────────────────────────────────────────────────
--  STEP 2 — Triggers
--
--  WHY TRIGGERS and NOT Node.js for INSERT/UPDATE/DELETE?
--  ─────────────────────────────────────────────────────
--  Triggers fire AUTOMATICALLY inside MySQL whenever a row
--  changes — even if someone directly queries the DB via
--  MySQL Workbench or another tool, the log still gets created.
--  Node.js logging only catches API calls — direct DB access
--  would be invisible. Triggers close that gap.
--
--  WHY TRIGGERS CANNOT LOG SELECT (profile views / logins)?
--  ─────────────────────────────────────────────────────
--  MySQL triggers only fire on: INSERT, UPDATE, DELETE.
--  SELECT reads data but changes nothing — MySQL provides
--  no hook for it. That's why LOGIN and PROFILE_VIEW are
--  logged manually inside Node.js Express routes.
-- ──────────────────────────────────────────────────────────────

DROP TRIGGER IF EXISTS trg_after_user_insert;
DROP TRIGGER IF EXISTS trg_after_user_update;
DROP TRIGGER IF EXISTS trg_before_user_delete;

DELIMITER //

-- ── TRIGGER 1: AFTER INSERT ──────────────────────────────────
--  Fires after a new user row is inserted (registration)
--  NEW.column = the values just inserted
--  We store HEX of encrypted fields so the log is readable JSON
-- ─────────────────────────────────────────────────────────────
CREATE TRIGGER trg_after_user_insert
AFTER INSERT ON users
FOR EACH ROW
BEGIN
  INSERT INTO audit_logs (
    user_id,
    username,
    action_type,
    table_name,
    record_id,
    old_data,
    new_data,
    performed_at
  ) VALUES (
    NEW.id,
    NEW.userid,
    'INSERT',
    'users',
    NEW.id,
    NULL,
    JSON_OBJECT(
      'userid',   NEW.userid,
      'name_enc', HEX(NEW.name),
      'mobile_enc', HEX(NEW.mobile),
      'address_enc', HEX(NEW.address),
      'email_enc', HEX(NEW.email)
    ),
    NOW()
  );
END //

-- ── TRIGGER 2: AFTER UPDATE ──────────────────────────────────
--  Fires after any column is updated on a user row
--  OLD.column = values before update
--  NEW.column = values after update
--  Stores both so admin can compare what changed
-- ─────────────────────────────────────────────────────────────
CREATE TRIGGER trg_after_user_update
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
  INSERT INTO audit_logs (
    user_id,
    username,
    action_type,
    table_name,
    record_id,
    old_data,
    new_data,
    performed_at
  ) VALUES (
    OLD.id,
    OLD.userid,
    'UPDATE',
    'users',
    OLD.id,
    JSON_OBJECT(
      'userid',      OLD.userid,
      'name_enc',    HEX(OLD.name),
      'mobile_enc',  HEX(OLD.mobile),
      'address_enc', HEX(OLD.address),
      'email_enc',   HEX(OLD.email)
    ),
    JSON_OBJECT(
      'userid',      NEW.userid,
      'name_enc',    HEX(NEW.name),
      'mobile_enc',  HEX(NEW.mobile),
      'address_enc', HEX(NEW.address),
      'email_enc',   HEX(NEW.email)
    ),
    NOW()
  );
END //

-- ── TRIGGER 3: BEFORE DELETE ─────────────────────────────────
--  Fires BEFORE the row is deleted — AFTER DELETE would mean
--  the row is already gone and we cannot read OLD values
--  This captures the full record before it disappears
-- ─────────────────────────────────────────────────────────────
CREATE TRIGGER trg_before_user_delete
BEFORE DELETE ON users
FOR EACH ROW
BEGIN
  INSERT INTO audit_logs (
    user_id,
    username,
    action_type,
    table_name,
    record_id,
    old_data,
    new_data,
    performed_at
  ) VALUES (
    OLD.id,
    OLD.userid,
    'DELETE',
    'users',
    OLD.id,
    JSON_OBJECT(
      'userid',      OLD.userid,
      'name_enc',    HEX(OLD.name),
      'mobile_enc',  HEX(OLD.mobile),
      'address_enc', HEX(OLD.address),
      'email_enc',   HEX(OLD.email)
    ),
    NULL,
    NOW()
  );
END //

DELIMITER ;

-- ──────────────────────────────────────────────────────────────
--  STEP 3 — Stored Procedure for Admin: get all audit logs
--  Admin panel will call GET /api/admin/audit-logs
--  which calls this procedure
-- ──────────────────────────────────────────────────────────────

DROP PROCEDURE IF EXISTS sp_GetAuditLogs;

DELIMITER //

CREATE PROCEDURE sp_GetAuditLogs()
BEGIN
  SELECT
    log_id,
    user_id,
    username,
    action_type,
    table_name,
    record_id,
    old_data,
    new_data,
    performed_at,
    ip_address,
    device_info
  FROM audit_logs
  ORDER BY performed_at DESC;
END //

DELIMITER ;

-- ──────────────────────────────────────────────────────────────
--  VERIFY — run these after the script to confirm everything created
-- ──────────────────────────────────────────────────────────────
-- SHOW TRIGGERS FROM petdb;
-- SHOW PROCEDURE STATUS WHERE Db = 'petdb';
-- DESCRIBE audit_logs;