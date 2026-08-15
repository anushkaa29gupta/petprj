-- ══════════════════════════════════════════════════════════════
--  PET-PROJECT — stored_procedures.sql
--  Fresh-install schema + procedures for a NEW database.
--  Already includes the `role` column baked in, so you do NOT
--  need to run role_migration.sql after this on a fresh DB.
--  (role_migration.sql is only for upgrading an EXISTING DB that
--  was created before role support existed.)
-- ══════════════════════════════════════════════════════════════

USE petdb;

DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  userid     VARCHAR(255) UNIQUE NOT NULL,
  role       ENUM('student','teacher','accountant','admin') NOT NULL DEFAULT 'student',
  name       VARBINARY(255),
  mobile     VARBINARY(255),
  address    VARBINARY(255),
  email      VARBINARY(255),
  password   VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ──────────────────────────────────────────────────────
--  To clean
-- ──────────────────────────────────────────────────────
DROP PROCEDURE IF EXISTS sp_RegisterUser;
DROP PROCEDURE IF EXISTS sp_LoginUser;
DROP PROCEDURE IF EXISTS sp_GetProfile;
DROP PROCEDURE IF EXISTS sp_GetAllUsersAdmin;
DROP PROCEDURE IF EXISTS sp_UpdateUserRole;
DROP PROCEDURE IF EXISTS sp_DeleteUser;

DELIMITER //

-- ══════════════════════════════════════════════════════
--  PROCEDURE 1: REGISTER
--  Plain text leta hai → AES_ENCRYPT karta hai → INSERT
--  Password already bcrypt-hashed aata hai Node.js se
--  Role bhi ab yahin store hota hai (server.js hamesha
--  'student' bhejta hai; admin baad mein change karta hai)
-- ══════════════════════════════════════════════════════
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

-- ══════════════════════════════════════════════════════
--  PROCEDURE 2: LOGIN
--  userid se row fetch karta hai, AES_DECRYPT karke return
--  Role bhi return hota hai — frontend isse dashboard choose
--  karta hai. Password check Node.js mein hota hai (bcrypt.compare)
-- ══════════════════════════════════════════════════════
CREATE PROCEDURE sp_LoginUser(
  IN p_userid VARCHAR(255),
  IN p_key    VARCHAR(255)
)
BEGIN
  SELECT
    id,
    userid,
    role,
    CAST(AES_DECRYPT(name,    p_key) AS CHAR(255))  AS name,
    CAST(AES_DECRYPT(mobile,  p_key) AS CHAR(255))  AS mobile,
    CAST(AES_DECRYPT(address, p_key) AS CHAR(255))  AS address,
    CAST(AES_DECRYPT(email,   p_key) AS CHAR(255))  AS email,
    password
  FROM users
  WHERE userid = p_userid;
END //

-- ══════════════════════════════════════════════════════
--  PROCEDURE 3: GET PROFILE (single user, after login)
-- ══════════════════════════════════════════════════════
CREATE PROCEDURE sp_GetProfile(
  IN p_userid VARCHAR(255),
  IN p_key    VARCHAR(255)
)
BEGIN
  SELECT
    userid,
    role,
    CAST(AES_DECRYPT(name,    p_key) AS CHAR(255))  AS name,
    CAST(AES_DECRYPT(mobile,  p_key) AS CHAR(255))  AS mobile,
    CAST(AES_DECRYPT(address, p_key) AS CHAR(255))  AS address,
    CAST(AES_DECRYPT(email,   p_key) AS CHAR(255))  AS email
  FROM users
  WHERE userid = p_userid;
END //

-- ══════════════════════════════════════════════════════
--  PROCEDURE 4: ADMIN — saare users (plain + encrypted dono)
-- ══════════════════════════════════════════════════════
CREATE PROCEDURE sp_GetAllUsersAdmin(
  IN p_key VARCHAR(255)
)
BEGIN
  SELECT
    id,
    userid,
    role,
    CAST(AES_DECRYPT(name,    p_key) AS CHAR(255))  AS name_plain,
    CAST(AES_DECRYPT(mobile,  p_key) AS CHAR(255))  AS mobile_plain,
    CAST(AES_DECRYPT(address, p_key) AS CHAR(255))  AS address_plain,
    HEX(name)     AS name_encrypted_hex,
    HEX(mobile)   AS mobile_encrypted_hex,
    HEX(address)  AS address_encrypted_hex,
    password,
    created_at
  FROM users
  ORDER BY id ASC;
END //

-- ══════════════════════════════════════════════════════
--  PROCEDURE 5: ADMIN — update a user's role
-- ══════════════════════════════════════════════════════
CREATE PROCEDURE sp_UpdateUserRole(
  IN p_id   INT,
  IN p_role VARCHAR(20)
)
BEGIN
  UPDATE users
  SET role = p_role
  WHERE id = p_id;
END //

-- ══════════════════════════════════════════════════════
--  PROCEDURE 6: ADMIN — delete user
-- ══════════════════════════════════════════════════════
CREATE PROCEDURE sp_DeleteUser(
  IN p_id INT
)
BEGIN
  DELETE FROM users WHERE id = p_id;
END //

DELIMITER ;

-- ══════════════════════════════════════════════════════
--  Test karne ke liye (optional — manually try kar sakte ho)
-- ══════════════════════════════════════════════════════
-- CALL sp_RegisterUser('test@gmail.com','student','Test User','9999999999','Test Address','test@gmail.com','$2b$12$dummyhash','0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
-- CALL sp_LoginUser('test@gmail.com', '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
-- CALL sp_GetAllUsersAdmin('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');