process.on("uncaughtException",  (err) => { console.error("💥 UNCAUGHT:", err.message); });
process.on("unhandledRejection", (err) => { console.error("💥 PROMISE:",  err.message); });

require("dotenv").config();
const express = require("express");
const cors    = require("cors");
const bcrypt  = require("bcrypt");
const jwt     = require("jsonwebtoken");
const crypto  = require("crypto");
const db      = require("./db");

function withAuditContext(ip, device, useConnection) {
  if (typeof db.getConnection === "function") {
    db.getConnection((err, conn) => {
      if (err) return useConnection(err);
      conn.query("SET @audit_ip = ?, @audit_device = ?", [ip, device], (err2) => {
        if (err2) { conn.release(); return useConnection(err2); }
        useConnection(null, conn, () => conn.release());
      });
    });
  } else {
    db.query("SET @audit_ip = ?, @audit_device = ?", [ip, device], (err2) => {
      useConnection(err2, db, () => {});
    });
  }
}

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.static("public"));

const DB_AES_KEY = process.env.AES_KEY;

// ── CMD logger ─────────────────────────────────────────────
function logTable(title, rows) {
  console.log("\n" + "─".repeat(68));
  console.log("  " + title);
  console.log("─".repeat(68));
  rows.forEach(([k, v]) => console.log(`  ${(k + ":").padEnd(18)} ${v}`));
  console.log("─".repeat(68) + "\n");
}

// ══════════════════════════════════════════════════════════════
//  AUDIT LOGGER — ab yeh audit_logs mein DIRECTLY nahi likhta.
//  Sirf user_activity_log mein ek simple row daalta hai.
//  trg_after_activity_insert trigger automatically audit_logs
//  mein poora formatted entry bana deta hai.
// ══════════════════════════════════════════════════════════════
function auditLog(userId, username, actionType, recordId, oldData, newData, ip, device) {
  db.query(
    `INSERT INTO user_activity_log
     (user_id, username, action_type, record_id, old_data, new_data, ip_address, device_info)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      userId   || null,
      username || null,
      actionType,
      recordId || null,
      oldData  ? JSON.stringify(oldData)  : null,
      newData  ? JSON.stringify(newData)  : null,
      ip       || null,
      device   || null
    ],
    (err) => { if (err) console.error("⚠️  Activity log failed:", err.message); }
  );
}

function getClientInfo(req) {
  const ip     = req.headers["x-forwarded-for"]?.split(",")[0]?.trim()
               || req.socket?.remoteAddress || "unknown";
  const device = req.headers["user-agent"] || "unknown";
  return { ip, device };
}

// ══════════════════════════════════════════════════════════════
//  REGISTER — always registers as 'student'
//  Admin changes role from admin panel later
// ══════════════════════════════════════════════════════════════
app.post("/api/register", async (req, res) => {
  const { name, mobile, address, email, password } = req.body;
  const { ip, device } = getClientInfo(req);

  if (!name || !mobile || !address || !email || !password)
    return res.status(400).json({ success: false, message: "All fields are required" });

  db.query("SELECT id FROM users WHERE userid = ?", [email], async (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: "DB error" });

    if (rows.length > 0) {
      auditLog(null, email, "REGISTER_FAILED", null, null,
        { reason: "Email already exists" }, ip, device);
      return res.status(409).json({ success: false, message: "Email already registered. Please login." });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    withAuditContext(ip, device, (ctxErr, conn, release) => {
      if (ctxErr) return res.status(500).json({ success: false, message: "Audit context failed" });

      conn.query(
        "CALL sp_RegisterUser(?, ?, ?, ?, ?, ?, ?, ?)",
        [email, "student", name, mobile, address, email, hashedPassword, DB_AES_KEY],
        (err) => {
          release();
          if (err) {
            console.error("❌ PROCEDURE ERROR:", err.message);
            return res.status(500).json({ success: false, message: "Registration failed" });
          }
          logTable("✅ USER REGISTERED (role: student)", [["Email", email], ["IP", ip]]);
          res.json({ success: true, message: "Registered successfully! Please login." });
        }
      );
    });
  });
});

// ══════════════════════════════════════════════════════════════
//  LOGIN — returns role, JWT contains role
// ══════════════════════════════════════════════════════════════
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  const { ip, device } = getClientInfo(req);

  if (!email || !password)
    return res.status(400).json({ success: false, message: "Email and password required" });

  db.query("CALL sp_LoginUser(?, ?)", [email, DB_AES_KEY], async (err, results) => {
    if (err) return res.status(500).json({ success: false, message: "DB error: " + err.message });

    const rows = results[0];
    if (!rows || rows.length === 0) {
      auditLog(null, email, "LOGIN_FAILED", null, null,
        { reason: "Email not found" }, ip, device);
      return res.status(401).json({ success: false, message: "Invalid email or password" });
    }

    const user  = rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      auditLog(user.id, email, "LOGIN_FAILED", user.id, null,
        { reason: "Wrong password", role: user.role }, ip, device);
      return res.status(401).json({ success: false, message: "Invalid email or password" });
    }

    // JWT includes role — used in auth middleware for role checks
    const token = jwt.sign(
      { userid: user.userid, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );

    auditLog(user.id, email, "LOGIN", user.id, null,
      { status: "success", role: user.role }, ip, device);

    logTable("✅ LOGIN SUCCESS", [
      ["Email", email], ["Role", user.role], ["IP", ip]
    ]);

    res.json({
      success: true, token,
      user: {
        userid:  user.userid,
        role:    user.role,
        name:    user.name,
        mobile:  user.mobile,
        address: user.address,
        email:   user.email,
      }
    });
  });
});

// ══════════════════════════════════════════════════════════════
//  AUTH MIDDLEWARE — verifies JWT, attaches user to req
// ══════════════════════════════════════════════════════════════
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ success: false, message: "No token" });
  try {
    req.user = jwt.verify(header.split(" ")[1], process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ success: false, message: "Token expired or invalid" });
  }
}

// ══════════════════════════════════════════════════════════════
//  ROLE MIDDLEWARE — checks if user has required role
//  Usage: roleOnly('teacher', 'accountant')
//         means: only teacher OR accountant can access
// ══════════════════════════════════════════════════════════════
function roleOnly(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      const { ip, device } = getClientInfo(req);

      // Log the unauthorized role-based access attempt
      auditLog(null, req.user.userid, "UNAUTHORIZED_ACCESS", null, null, {
        attempted_resource: req.path,
        user_role:          req.user.role,
        required_roles:     allowedRoles,
        result:             "BLOCKED"
      }, ip, device);

      logTable("🚨 ROLE ACCESS BLOCKED", [
        ["User",     req.user.userid],
        ["Has role", req.user.role],
        ["Needs",    allowedRoles.join(" or ")],
        ["Path",     req.path],
      ]);

      return res.status(403).json({
        success: false,
        message: `Access denied. Your role (${req.user.role}) cannot access this resource. This attempt has been logged.`
      });
    }
    next();
  };
}

// ── ADMIN MIDDLEWARE ───────────────────────────────────────
function adminAuth(req, res, next) {
  const key = req.headers["x-admin-key"];
  if (key !== process.env.ADMIN_KEY)
    return res.status(403).json({ success: false, message: "Forbidden" });
  next();
}

// ══════════════════════════════════════════════════════════════
//  PROFILE — all roles can view own profile
// ══════════════════════════════════════════════════════════════
app.get("/api/profile", auth, (req, res) => {
  const { ip, device } = getClientInfo(req);

  db.query("CALL sp_GetProfile(?, ?)", [req.user.userid, DB_AES_KEY], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    const rows = results[0];
    if (!rows || rows.length === 0) return res.status(404).json({ success: false });
    const u = rows[0];

    db.query("SELECT id FROM users WHERE userid=?", [req.user.userid], (e, idRows) => {
      const uid = idRows?.[0]?.id || null;
      auditLog(uid, req.user.userid, "PROFILE_VIEW", uid,
        null, { fields_accessed: ["name","mobile","address","email"] }, ip, device);
    });

    res.json({
      success: true,
      user: { userid: u.userid, role: u.role, name: u.name, mobile: u.mobile, address: u.address, email: u.email }
    });
  });
});

// ══════════════════════════════════════════════════════════════
//  STUDENT — view own grades
//  Allowed roles: student only
// ══════════════════════════════════════════════════════════════
app.get("/api/college/my-grades", auth, roleOnly("student"), (req, res) => {
  const { ip, device } = getClientInfo(req);

  const grades = {
    student: req.user.userid, semester: "Semester 5",
    subjects: [
      { code:"CS501", name:"Data Structures",      marks:78, grade:"B+" },
      { code:"CS502", name:"Operating Systems",    marks:85, grade:"A"  },
      { code:"CS503", name:"Database Management",  marks:91, grade:"A+" },
      { code:"CS504", name:"Computer Networks",    marks:72, grade:"B"  },
      { code:"CS505", name:"Software Engineering", marks:88, grade:"A"  },
    ],
    cgpa: "8.4"
  };

  db.query("SELECT id FROM users WHERE userid=?", [req.user.userid], (e, r) => {
    const uid = r?.[0]?.id || null;
    auditLog(uid, req.user.userid, "VIEW_OWN_GRADES", uid,
      null, { section: "My Grades", semester: "Semester 5", result: "ALLOWED" }, ip, device);
  });

  res.json({ success: true, grades });
});

// ══════════════════════════════════════════════════════════════
//  TEACHER — view all student records and grades
//  Allowed roles: teacher only
//  Students blocked — logged as UNAUTHORIZED_ACCESS
// ══════════════════════════════════════════════════════════════
app.get("/api/college/student-records", auth, roleOnly("teacher"), (req, res) => {
  const { ip, device } = getClientInfo(req);

  // Simulated student list — in real system: DB query
  const students = [
    { id:1, name:"Priya Sharma",  email:"priya.sharma@gmail.com",  semester:"Sem 5", cgpa:"8.4" },
    { id:2, name:"Rohit Verma",   email:"rohit.verma@gmail.com",   semester:"Sem 5", cgpa:"7.8" },
    { id:3, name:"Kavya Nair",    email:"kavya.nair@gmail.com",    semester:"Sem 5", cgpa:"9.1" },
    { id:4, name:"Arjun Mehta",   email:"arjun.mehta@gmail.com",   semester:"Sem 5", cgpa:"8.0" },
    { id:5, name:"Sneha Patil",   email:"sneha.patil@gmail.com",   semester:"Sem 5", cgpa:"8.7" },
  ];

  db.query("SELECT id FROM users WHERE userid=?", [req.user.userid], (e, r) => {
    const uid = r?.[0]?.id || null;
    auditLog(uid, req.user.userid, "VIEW_STUDENT_RECORDS", uid,
      null, { records_accessed: students.length, result: "ALLOWED", role: "teacher" }, ip, device);
  });

  logTable("📋 STUDENT RECORDS ACCESSED (teacher)", [["Teacher", req.user.userid]]);
  res.json({ success: true, students });
});

// ══════════════════════════════════════════════════════════════
//  TEACHER — view own salary only
//  Allowed roles: teacher only
// ══════════════════════════════════════════════════════════════
app.get("/api/college/my-salary", auth, roleOnly("teacher"), (req, res) => {
  const { ip, device } = getClientInfo(req);

  const salary = {
    teacher:     req.user.userid,
    month:       "June 2024",
    basic:       45000,
    allowances:  8000,
    deductions:  3500,
    net:         49500,
    status:      "Paid",
    paid_on:     "2024-06-30"
  };

  db.query("SELECT id FROM users WHERE userid=?", [req.user.userid], (e, r) => {
    const uid = r?.[0]?.id || null;
    auditLog(uid, req.user.userid, "VIEW_OWN_SALARY", uid,
      null, { section: "My Salary", month: "June 2024", result: "ALLOWED" }, ip, device);
  });

  res.json({ success: true, salary });
});

// ══════════════════════════════════════════════════════════════
//  TEACHER — view exam papers (allowed for teachers)
//  Students blocked by roleOnly middleware
// ══════════════════════════════════════════════════════════════
app.get("/api/college/exam-papers", auth, roleOnly("teacher"), (req, res) => {
  const { ip, device } = getClientInfo(req);

  const papers = [
    { code:"CS601", name:"Data Science",      date:"2024-11-15", status:"Ready" },
    { code:"CS602", name:"Machine Learning",  date:"2024-11-17", status:"Ready" },
    { code:"CS603", name:"Cloud Computing",   date:"2024-11-19", status:"Draft" },
    { code:"CS604", name:"Cybersecurity",     date:"2024-11-21", status:"Ready" },
  ];

  db.query("SELECT id FROM users WHERE userid=?", [req.user.userid], (e, r) => {
    const uid = r?.[0]?.id || null;
    auditLog(uid, req.user.userid, "VIEW_EXAM_PAPERS", uid,
      null, { papers_accessed: papers.length, result: "ALLOWED", role: "teacher" }, ip, device);
  });

  res.json({ success: true, papers });
});

// ══════════════════════════════════════════════════════════════
//  ACCOUNTANT — view all teacher salaries
//  Allowed roles: accountant only
//  Teachers and students blocked
// ══════════════════════════════════════════════════════════════
app.get("/api/college/all-salaries", auth, roleOnly("accountant"), (req, res) => {
  const { ip, device } = getClientInfo(req);

  const salaries = [
    { id:1, name:"Dr. Ananya Roy",    subject:"Mathematics",   basic:48000, net:52000, status:"Paid"    },
    { id:2, name:"Prof. Karan Singh", subject:"Physics",       basic:46000, net:50000, status:"Paid"    },
    { id:3, name:"Ms. Reena Shah",    subject:"Chemistry",     basic:44000, net:48000, status:"Pending" },
    { id:4, name:"Mr. Vivek Nair",    subject:"CS Theory",     basic:50000, net:54000, status:"Paid"    },
    { id:5, name:"Dr. Priti Das",     subject:"Data Science",  basic:52000, net:56000, status:"Paid"    },
  ];

  db.query("SELECT id FROM users WHERE userid=?", [req.user.userid], (e, r) => {
    const uid = r?.[0]?.id || null;
    auditLog(uid, req.user.userid, "VIEW_ALL_SALARIES", uid,
      null, { records_accessed: salaries.length, result: "ALLOWED", role: "accountant" }, ip, device);
  });

  logTable("💰 ALL SALARIES ACCESSED (accountant)", [["Accountant", req.user.userid]]);
  res.json({ success: true, salaries });
});

// ══════════════════════════════════════════════════════════════
//  BLOCKED ROUTES — explicit blocks with logging
//  Students trying teacher/accountant routes
// ══════════════════════════════════════════════════════════════

// Student tries to access exam papers — blocked
app.get("/api/college/student-exam-attempt", auth, (req, res) => {
  const { ip, device } = getClientInfo(req);
  db.query("SELECT id FROM users WHERE userid=?", [req.user.userid], (e, r) => {
    const uid = r?.[0]?.id || null;
    auditLog(uid, req.user.userid, "EXAM_PAPER_ACCESS_ATTEMPT", uid, null, {
      attempted_resource: "Sealed Exam Papers",
      user_role: req.user.role, result: "BLOCKED",
      reason: "Students cannot access exam papers"
    }, ip, device);
  });
  res.status(403).json({ success:false, message:"Access Denied. Exam papers are sealed for students. Attempt logged." });
});

// Any role tries to access all student records without teacher role
app.get("/api/college/student-records-attempt", auth, (req, res) => {
  const { ip, device } = getClientInfo(req);
  db.query("SELECT id FROM users WHERE userid=?", [req.user.userid], (e, r) => {
    const uid = r?.[0]?.id || null;
    auditLog(uid, req.user.userid, "UNAUTHORIZED_ACCESS", uid, null, {
      attempted_resource: "All Student Records",
      user_role: req.user.role, result: "BLOCKED",
      reason: `Role '${req.user.role}' cannot access all student records`
    }, ip, device);
  });
  res.status(403).json({ success:false, message:"Access Denied. Your role cannot view all student records. Attempt logged." });
});

// Any role tries teacher salary without accountant role
app.get("/api/college/salary-attempt", auth, (req, res) => {
  const { ip, device } = getClientInfo(req);
  db.query("SELECT id FROM users WHERE userid=?", [req.user.userid], (e, r) => {
    const uid = r?.[0]?.id || null;
    auditLog(uid, req.user.userid, "UNAUTHORIZED_ACCESS", uid, null, {
      attempted_resource: "All Teacher Salaries",
      user_role: req.user.role, result: "BLOCKED",
      reason: `Role '${req.user.role}' cannot access salary records of others`
    }, ip, device);
  });
  res.status(403).json({ success:false, message:"Access Denied. Only accountants can view salary records. Attempt logged." });
});

// Admin panel access attempt from portal
app.post("/api/college/admin-access-attempt", auth, (req, res) => {
  const { ip, device } = getClientInfo(req);
  db.query("SELECT id FROM users WHERE userid=?", [req.user.userid], (e, r) => {
    const uid = r?.[0]?.id || null;
    auditLog(uid, req.user.userid, "ADMIN_ACCESS_ATTEMPT", uid, null, {
      attempted_resource: "Admin Control Panel",
      user_role: req.user.role,
      result: "BLOCKED", severity: "HIGH",
      reason: "Unauthorized admin panel access attempt"
    }, ip, device);
  });
  logTable("🚨🚨 ADMIN PANEL ATTEMPT", [["User", req.user.userid], ["Role", req.user.role]]);
  res.status(403).json({ success:false, message:"Access Denied. Admin panel is strictly restricted. High-severity incident logged." });
});

// ══════════════════════════════════════════════════════════════
//  ADMIN — GET ALL USERS (with roles)
// ══════════════════════════════════════════════════════════════
app.get("/api/admin/users", adminAuth, (req, res) => {
  const { ip, device } = getClientInfo(req);

  db.query("CALL sp_GetAllUsersAdmin(?)", [DB_AES_KEY], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });

    const rows  = results[0];
    const users = rows.map(u => ({
      id: u.id, userid: u.userid, role: u.role, created_at: u.created_at,
      plain:     { name: u.name_plain, mobile: u.mobile_plain, address: u.address_plain, password: u.password },
      encrypted: { name: u.name_encrypted_hex, mobile: u.mobile_encrypted_hex, address: u.address_encrypted_hex, password: u.password }
    }));

    auditLog(null, "ADMIN", "ADMIN_VIEW_USERS", null,
      null, { total: users.length }, ip, device);

    res.json({ success: true, total: users.length, users });
  });
});

// ══════════════════════════════════════════════════════════════
//  ADMIN — UPDATE USER ROLE
//  Admin assigns teacher/accountant roles from admin panel
// ══════════════════════════════════════════════════════════════
app.put("/api/admin/users/:id/role", adminAuth, (req, res) => {
  const { ip, device } = getClientInfo(req);
  const { role }  = req.body;
  const validRoles = ["student", "teacher", "accountant"];

  if (!validRoles.includes(role))
    return res.status(400).json({ success: false, message: "Invalid role. Must be student, teacher, or accountant." });

  // Get old role before updating
  db.query("SELECT userid, role FROM users WHERE id=?", [req.params.id], (err, rows) => {
    if (err || !rows.length)
      return res.status(404).json({ success: false, message: "User not found" });

    const oldRole = rows[0].role;
    const email   = rows[0].userid;

    withAuditContext(ip, device, (ctxErr, conn, release) => {
      if (ctxErr) return res.status(500).json({ success: false, message: "Audit context failed" });

      conn.query("CALL sp_UpdateUserRole(?, ?)", [req.params.id, role], (err2) => {
        release();
        if (err2) return res.status(500).json({ success: false, message: err2.message });

        auditLog(null, "ADMIN", "ROLE_CHANGED", req.params.id,
          { role: oldRole }, { role: role, changed_by: "ADMIN" }, ip, device);

        logTable("🔄 ROLE UPDATED", [["User", email], ["Old", oldRole], ["New", role]]);
        res.json({ success: true, message: `Role updated to ${role}` });
      });
    });
  });
});

// ══════════════════════════════════════════════════════════════
//  ADMIN — DELETE USER
// ══════════════════════════════════════════════════════════════
app.delete("/api/admin/users/:id", adminAuth, (req, res) => {
  const { ip, device } = getClientInfo(req);

  db.query("SELECT userid, role FROM users WHERE id=?", [req.params.id], (err, rows) => {
    const email = rows?.[0]?.userid || "unknown";
    const role  = rows?.[0]?.role  || "unknown";

    withAuditContext(ip, device, (ctxErr, conn, release) => {
      if (ctxErr) return res.status(500).json({ success: false, message: "Audit context failed" });

      conn.query("CALL sp_DeleteUser(?)", [req.params.id], (err2) => {
        release();
        if (err2) return res.status(500).json({ success: false, message: err2.message });

        auditLog(null, "ADMIN", "USER_DELETED", req.params.id,
          null, { deleted_user: email, deleted_role: role }, ip, device);

        logTable("🗑️  USER DELETED", [["Email", email], ["Role", role], ["IP", ip]]);
        res.json({ success: true, message: `User ${req.params.id} deleted` });
      });
    });
  });
});

// ══════════════════════════════════════════════════════════════
//  ADMIN — GET AUDIT LOGS
// ══════════════════════════════════════════════════════════════
app.get("/api/admin/audit-logs", adminAuth, (req, res) => {
  const { ip, device } = getClientInfo(req);

  db.query("CALL sp_GetAuditLogs()", (err, results) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    const logs = results[0];
    auditLog(null, "ADMIN", "ADMIN_VIEW_LOGS", null,
      null, { logs_accessed: logs.length }, ip, device);
    res.json({ success: true, total: logs.length, logs });
  });
});

// ══════════════════════════════════════════════════════════════
//  ADMIN — VERIFY BLOCKCHAIN INTEGRITY OF AUDIT LOGS
//  Recomputes every row's hash and compares to stored curr_hash
//  Any mismatch = someone tampered the DB directly
// ══════════════════════════════════════════════════════════════
app.get("/api/admin/verify-chain", adminAuth, (req, res) => {
  db.query("CALL sp_GetAuditLogs()", (err, results) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    const logs = results[0];

    let expectedPrev = "0".repeat(64);
    let brokenAt = null;

    for (const row of logs) {
      const raw = [
        expectedPrev,
        row.user_id ?? "",
        row.username ?? "",
        row.action_type,
        row.table_name ?? "",
        row.record_id ?? "",
        row.old_data ?? "",
        row.new_data ?? "",
        row.performed_at instanceof Date ? row.performed_at.toISOString().slice(0, 19).replace("T", " ") : row.performed_at,
        row.ip_address ?? "",
        row.device_info ?? ""
      ].join("|");

      const recomputed = crypto.createHash("sha256").update(raw).digest("hex");

      if (row.prev_hash !== expectedPrev || row.curr_hash !== recomputed) {
        brokenAt = row.log_id;
        break;
      }
      expectedPrev = row.curr_hash;
    }

    if (brokenAt) {
      logTable("🚨 CHAIN BROKEN", [["log_id", brokenAt]]);
      return res.json({ success: true, valid: false, brokenAtLogId: brokenAt,
        message: `Tampering detected at log_id ${brokenAt}` });
    }

    res.json({ success: true, valid: true, totalChecked: logs.length,
      message: "Chain intact — no tampering detected" });
  });
});

// ── ADMIN PAGE ROUTE ───────────────────────────────────────
app.get("/admin", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

// ─────────────────────────────────────────────────────────
app.listen(3000, () => {
  logTable("🚀 COLLEGE PORTAL — ROLE-BASED ACCESS ACTIVE", [
    ["Port",        "3000"],
    ["App",         "http://localhost:3000"],
    ["Admin",       "http://localhost:3000/admin"],
    ["Roles",       "student | teacher | accountant"],
    ["Encryption",  "AES inside MySQL stored procedures"],
    ["Password",    "BCrypt (rounds: 12)"],
    ["Session",     "JWT with role (2h expiry)"],
    ["Audit",       "MySQL triggers + Node.js hash-chain (append-only)"],
  ]);
});