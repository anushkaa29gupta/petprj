-- ══════════════════════════════════════════════════════════════
--  PET-PROJECT — Role Migration
--  File: role_migration.sql
--
--  ONLY run this if you already have an OLDER petdb (created
--  before role support existed) and don't want to drop your data.
--  If you're setting up fresh, just run stored_procedures.sql —
--  the role column is already included there and this file is
--  not needed.
--
--  What this does:
--  1. Adds 'role' column to users table (skipped if it already exists)
--  2. Recreates sp_RegisterUser to accept + store role
--  3. Recreates sp_LoginUser to return role
--  4. Recreates sp_GetProfile to return role
--  5. Recreates sp_GetAllUsersAdmin to return role
--  6. Adds sp_UpdateUserRole for admin to change roles
--  (sp_GetAuditLogs is defined separately in audit_setup.sql)
-- ══════════════════════════════════════════════════════════════

USE petdb;

-- ──────────────────────────────────────────────────────────────
--  STEP 1 — Add role column to users table (idempotent)
--  Default = 'student' so existing users are not affected.
--  Guarded with information_schema check so re-running this
--  script never throws "Duplicate column name".
-- ──────────────────────────────────────────────────────────────
SET @col_exists := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME   = 'users'
    AND COLUMN_NAME  = 'role'
);

SET @ddl := IF(
  @col_exists = 0,
  "ALTER TABLE users ADD COLUMN role ENUM('student','teacher','accountant','admin') NOT NULL DEFAULT 'student' AFTER userid",
  "SELECT 'role column already exists — skipped' AS status"
);

PREPARE stmt FROM @ddl;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ──────────────────────────────────────────────────────────────
--  STEP 2 — Drop and recreate stored procedures
--  (MySQL does not support ALTER PROCEDURE for param changes)
-- ──────────────────────────────────────────────────────────────
DROP PROCEDURE IF EXISTS sp_RegisterUser;
DROP PROCEDURE IF EXISTS sp_LoginUser;
DROP PROCEDURE IF EXISTS sp_GetProfile;
DROP PROCEDURE IF EXISTS sp_GetAllUsersAdmin;
DROP PROCEDURE IF EXISTS sp_UpdateUserRole;

DELIMITER //

-- ══════════════════════════════════════════════════════════════
--  REGISTER — now accepts role parameter
--  Node.js always sends 'student' — admin changes it later
-- ══════════════════════════════════════════════════════════════
CREATE PROCEDURE sp_RegisterUser(
  IN p_userid   VARCHAR(255),
  IN p_role     VARCHAR(20),
  IN p_name     VARCHAR(255),
  IN p_mobile   VARCHAR(255),
  IN p_address  VARCHAR(255),
  IN p_email    VARCHAR(255),
  IN p_password VARCHAR(255),
  IN p_key      VARCHAR(255)
)
BEGIN
  INSERT INTO users (userid, role, name, mobile, address, email, password)
  VALUES (
    p_userid,
    p_role,
    AES_ENCRYPT(p_name,    p_key),
    AES_ENCRYPT(p_mobile,  p_key),
    AES_ENCRYPT(p_address, p_key),
    AES_ENCRYPT(p_email,   p_key),
    p_password
  );
END //

-- ══════════════════════════════════════════════════════════════
--  LOGIN — returns role so frontend knows which dashboard to show
-- ══════════════════════════════════════════════════════════════
CREATE PROCEDURE sp_LoginUser(
  IN p_userid VARCHAR(255),
  IN p_key    VARCHAR(255)
)
BEGIN
  SELECT
    id,
    userid,
    role,
    CAST(AES_DECRYPT(name,    p_key) AS CHAR(255)) AS name,
    CAST(AES_DECRYPT(mobile,  p_key) AS CHAR(255)) AS mobile,
    CAST(AES_DECRYPT(address, p_key) AS CHAR(255)) AS address,
    CAST(AES_DECRYPT(email,   p_key) AS CHAR(255)) AS email,
    password
  FROM users
  WHERE userid = p_userid;
END //

-- ══════════════════════════════════════════════════════════════
--  GET PROFILE — returns role for dashboard rendering
-- ══════════════════════════════════════════════════════════════
CREATE PROCEDURE sp_GetProfile(
  IN p_userid VARCHAR(255),
  IN p_key    VARCHAR(255)
)
BEGIN
  SELECT
    userid,
    role,
    CAST(AES_DECRYPT(name,    p_key) AS CHAR(255)) AS name,
    CAST(AES_DECRYPT(mobile,  p_key) AS CHAR(255)) AS mobile,
    CAST(AES_DECRYPT(address, p_key) AS CHAR(255)) AS address,
    CAST(AES_DECRYPT(email,   p_key) AS CHAR(255)) AS email
  FROM users
  WHERE userid = p_userid;
END //

-- ══════════════════════════════════════════════════════════════
--  GET ALL USERS ADMIN — returns role column
--  (fixed: original script was missing the opening "(" here,
--  which would have failed to compile — corrected below)
-- ══════════════════════════════════════════════════════════════
CREATE PROCEDURE sp_GetAllUsersAdmin(
  IN p_key VARCHAR(255)
)
BEGIN
  SELECT
    id,
    userid,
    role,
    CAST(AES_DECRYPT(name,    p_key) AS CHAR(255)) AS name_plain,
    CAST(AES_DECRYPT(mobile,  p_key) AS CHAR(255)) AS mobile_plain,
    CAST(AES_DECRYPT(address, p_key) AS CHAR(255)) AS address_plain,
    HEX(name)    AS name_encrypted_hex,
    HEX(mobile)  AS mobile_encrypted_hex,
    HEX(address) AS address_encrypted_hex,
    password,
    created_at
  FROM users
  ORDER BY id ASC;
END //

-- ══════════════════════════════════════════════════════════════
--  UPDATE USER ROLE — admin only
--  Changes a user's role by their id
-- ══════════════════════════════════════════════════════════════
CREATE PROCEDURE sp_UpdateUserRole(
  IN p_id   INT,
  IN p_role VARCHAR(20)
)
BEGIN
  UPDATE users
  SET role = p_role
  WHERE id = p_id;
END //

DELIMITER ;

-- ──────────────────────────────────────────────────────────────
--  VERIFY
-- ──────────────────────────────────────────────────────────────
-- SHOW PROCEDURE STATUS WHERE Db = 'petdb';
-- DESCRIBE users;