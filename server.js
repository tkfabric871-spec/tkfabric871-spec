require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 4000);

/* =========================================================
   BASIC SETTINGS
========================================================= */

app.use(cors());
app.use(express.json({ limit: '1mb' }));

/* =========================================================
   FRONTEND
   server.js is in the project ROOT
   index.html is also in the project ROOT
========================================================= */

const frontendDir = __dirname;

app.use(express.static(frontendDir));

app.get('/', (req, res) => {
  res.sendFile(path.join(frontendDir, 'index.html'));
});

app.get('/index.html', (req, res) => {
  res.sendFile(path.join(frontendDir, 'index.html'));
});

/* =========================================================
   UPLOADS
========================================================= */

const uploadDir = path.join(frontendDir, 'uploads');

fs.mkdirSync(uploadDir, {
  recursive: true
});

const upload = multer({
  dest: uploadDir,
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    cb(null, /^image\//.test(file.mimetype));
  }
});

app.use('/uploads', express.static(uploadDir));

/* =========================================================
   MYSQL
========================================================= */

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'smart_invest',
  waitForConnections: true,
  connectionLimit: 10,
  decimalNumbers: true
});

/* =========================================================
   SETTINGS
========================================================= */

const JWT_SECRET =
  process.env.JWT_SECRET || 'CHANGE_ME';

const REFERRAL_RATE =
  Number(process.env.REFERRAL_RATE || 0.05);

/* =========================================================
   REFERRAL CODE
========================================================= */

function makeReferralCode(username) {
  return (
    String(username)
      .replace(/[^a-z0-9]/gi, '')
      .slice(0, 6)
      .toUpperCase() +
    Math.floor(1000 + Math.random() * 9000)
  );
}

/* =========================================================
   JWT
========================================================= */

function sign(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username
    },
    JWT_SECRET,
    {
      expiresIn: '7d'
    }
  );
}

/* =========================================================
   USER AUTH
========================================================= */

function auth(req, res, next) {
  const token = (req.headers.authorization || '')
    .replace(/^Bearer /, '');

  if (!token) {
    return res.status(401).json({
      error: 'Authentication required.'
    });
  }

  try {
    req.user = jwt.verify(
      token,
      JWT_SECRET
    );

    next();
  } catch {
    return res.status(401).json({
      error: 'Invalid or expired token.'
    });
  }
}

/* =========================================================
   ADMIN AUTH
========================================================= */

function adminAuth(req, res, next) {
  if (
    req.headers['x-admin-username'] !==
      process.env.ADMIN_USERNAME ||
    req.headers['x-admin-password'] !==
      process.env.ADMIN_PASSWORD
  ) {
    return res.status(401).json({
      error: 'Admin authentication required.'
    });
  }

  next();
}

/* =========================================================
   DATABASE MIGRATION
========================================================= */

async function migrate() {
  try {
    await pool.query(
      "ALTER TABLE users ADD COLUMN status ENUM('active','suspended') NOT NULL DEFAULT 'active'"
    );
  } catch (e) {
    if (e.code !== 'ER_DUP_FIELDNAME') {
      console.warn(
        'users migration:',
        e.message
      );
    }
  }

  try {
    await pool.query(
      'ALTER TABLE payment_requests ADD COLUMN payment_screenshot VARCHAR(255) NULL'
    );
  } catch (e) {
    if (e.code !== 'ER_DUP_FIELDNAME') {
      console.warn(
        'payment screenshot migration:',
        e.message
      );
    }
  }
}

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');

    res.json({
      ok: true,
      database: true
    });
  } catch (e) {
    res.status(500).json({
      ok: false,
      database: false,
      error: e.message
    });
  }
});

/* =========================================================
   SIGNUP
========================================================= */

app.post(
  '/api/auth/signup',
  async (req, res) => {
    try {
      const username = String(
        req.body.username || ''
      ).trim();

      const password = String(
        req.body.password || ''
      );

      const referralCode = String(
        req.body.referralCode || ''
      )
        .trim()
        .toUpperCase();

      if (
        username.length < 3 ||
        username.length > 50
      ) {
        return res.status(400).json({
          error:
            'Username must be 3-50 characters.'
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          error:
            'Password must be at least 6 characters.'
        });
      }

      const [existing] =
        await pool.query(
          'SELECT id FROM users WHERE LOWER(username)=LOWER(?)',
          [username]
        );

      if (existing.length) {
        return res.status(409).json({
          error:
            'Username already exists.'
        });
      }

      let referrer = null;

      if (referralCode) {
        const [r] =
          await pool.query(
            'SELECT id, username FROM users WHERE referral_code=? AND status="active"',
            [referralCode]
          );

        if (!r.length) {
          return res.status(400).json({
            error:
              'Invalid referral code.'
          });
        }

        referrer = r[0];
      }

      let code = null;

      for (let i = 0; i < 20; i++) {
        const candidate =
          makeReferralCode(username);

        const [c] =
          await pool.query(
            'SELECT id FROM users WHERE referral_code=?',
            [candidate]
          );

        if (!c.length) {
          code = candidate;
          break;
        }
      }

      if (!code) {
        throw new Error(
          'Could not create referral code.'
        );
      }

      const hash =
        await bcrypt.hash(
          password,
          12
        );

      const [result] =
        await pool.query(
          'INSERT INTO users(username,password_hash,referral_code,referred_by_user_id) VALUES(?,?,?,?)',
          [
            username,
            hash,
            code,
            referrer
              ? referrer.id
              : null
          ]
        );

      const [rows] =
        await pool.query(
          'SELECT id,username,referral_code,balance,referral_earnings,created_at,status FROM users WHERE id=?',
          [result.insertId]
        );

      res.status(201).json({
        token: sign(rows[0]),
        user: rows[0]
      });
    } catch (e) {
      console.error('Signup error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   LOGIN
========================================================= */

app.post(
  '/api/auth/login',
  async (req, res) => {
    try {
      const username = String(
        req.body.username || ''
      ).trim();

      const password = String(
        req.body.password || ''
      );

      const [rows] =
        await pool.query(
          'SELECT * FROM users WHERE username=?',
          [username]
        );

      if (
        !rows.length ||
        !(await bcrypt.compare(
          password,
          rows[0].password_hash
        ))
      ) {
        return res.status(401).json({
          error:
            'Invalid username or password.'
        });
      }

      if (
        rows[0].status ===
        'suspended'
      ) {
        return res.status(403).json({
          error:
            'This account is suspended.'
        });
      }

      const u = rows[0];

      res.json({
        token: sign(u),

        user: {
          id: u.id,
          username: u.username,
          referral_code:
            u.referral_code,
          balance: u.balance,
          referral_earnings:
            u.referral_earnings,
          created_at:
            u.created_at
        }
      });
    } catch (e) {
      console.error('Login error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   CHANGE PASSWORD
========================================================= */

app.post(
  '/api/auth/change-password',
  auth,
  async (req, res) => {
    try {
      const currentPassword =
        String(
          req.body.currentPassword ||
            ''
        );

      const newPassword =
        String(
          req.body.newPassword || ''
        );

      if (newPassword.length < 6) {
        return res.status(400).json({
          error:
            'New password must be at least 6 characters.'
        });
      }

      const [rows] =
        await pool.query(
          'SELECT password_hash FROM users WHERE id=?',
          [req.user.id]
        );

      if (
        !rows.length ||
        !(await bcrypt.compare(
          currentPassword,
          rows[0].password_hash
        ))
      ) {
        return res.status(401).json({
          error:
            'Current password is incorrect.'
        });
      }

      const hash =
        await bcrypt.hash(
          newPassword,
          12
        );

      await pool.query(
        'UPDATE users SET password_hash=? WHERE id=?',
        [
          hash,
          req.user.id
        ]
      );

      res.json({
        message:
          'Password changed successfully.'
      });
    } catch (e) {
      console.error('Change password error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   PLANS
========================================================= */

app.get(
  '/api/plans',
  async (req, res) => {
    try {
      const [rows] =
        await pool.query(
          'SELECT id,name,amount,daily_rate,duration_days FROM plans WHERE active=1 ORDER BY id'
        );

      res.json(rows);
    } catch (e) {
      console.error('Plans error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   PROFILE
========================================================= */

app.get(
  '/api/profile',
  auth,
  async (req, res) => {
    try {
      const [rows] =
        await pool.query(
          'SELECT id,username,referral_code,referred_by_user_id,balance,referral_earnings,created_at,status FROM users WHERE id=?',
          [req.user.id]
        );

      if (!rows.length) {
        return res.status(404).json({
          error:
            'User not found.'
        });
      }

      const [ref] =
        await pool.query(
          'SELECT username FROM users WHERE id=?',
          [rows[0].referred_by_user_id]
        );

      res.json({
        ...rows[0],
        referred_by:
          ref[0]?.username ||
          null
      });
    } catch (e) {
      console.error('Profile error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   PAYMENT REQUEST
========================================================= */

app.post(
  '/api/payments',
  auth,
  upload.single(
    'paymentScreenshot'
  ),
  async (req, res) => {
    try {
      const planId = Number(
        req.body.planId
      );

      const transactionId =
        String(
          req.body.transactionId ||
            ''
        ).trim();

      const [plans] =
        await pool.query(
          'SELECT * FROM plans WHERE id=? AND active=1',
          [planId]
        );

      if (!plans.length) {
        return res.status(400).json({
          error:
            'Invalid plan.'
        });
      }

      if (
        !transactionId &&
        !req.file
      ) {
        return res.status(400).json({
          error:
            'Transaction ID or payment screenshot is required.'
        });
      }

      if (transactionId) {
        const [existing] =
          await pool.query(
            'SELECT id FROM payment_requests WHERE transaction_id=?',
            [transactionId]
          );

        if (existing.length) {
          return res.status(409).json({
            error:
              'Transaction ID already exists.'
          });
        }
      }

      const screenshot =
        req.file
          ? '/uploads/' +
            path.basename(
              req.file.path
            )
          : null;

      await pool.query(
        'INSERT INTO payment_requests(user_id,plan_id,amount,transaction_id,payment_screenshot) VALUES(?,?,?,?,?)',
        [
          req.user.id,
          planId,
          plans[0].amount,
          transactionId ||
            null,
          screenshot
        ]
      );

      res.status(201).json({
        message:
          'Payment request submitted for admin review.'
      });
    } catch (e) {
      console.error('Payment error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   USER PAYMENTS
========================================================= */

app.get(
  '/api/payments',
  auth,
  async (req, res) => {
    try {
      const [rows] =
        await pool.query(
          'SELECT id,plan_id,amount,transaction_id,payment_screenshot,status,created_at,reviewed_at FROM payment_requests WHERE user_id=? ORDER BY id DESC',
          [req.user.id]
        );

      res.json(rows);
    } catch (e) {
      console.error('User payments error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   INVESTMENTS
========================================================= */

app.get(
  '/api/investments',
  auth,
  async (req, res) => {
    try {
      const [rows] =
        await pool.query(
          'SELECT i.*,p.name AS plan_name FROM investments i JOIN plans p ON p.id=i.plan_id WHERE i.user_id=? ORDER BY i.id DESC',
          [req.user.id]
        );

      res.json(rows);
    } catch (e) {
      console.error('Investments error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   WITHDRAWAL REQUEST
========================================================= */

app.post(
  '/api/withdrawals',
  auth,
  async (req, res) => {
    try {
      const amount = Number(
        req.body.amount
      );

      const method = String(
        req.body.method || ''
      ).trim();

      const account = String(
        req.body.account || ''
      ).trim();

      if (
        !(amount > 0) ||
        !method ||
        !account
      ) {
        return res.status(400).json({
          error:
            'Valid amount, method and account are required.'
        });
      }

      const [users] =
        await pool.query(
          'SELECT balance,status FROM users WHERE id=?',
          [req.user.id]
        );

      if (
        !users.length ||
        users[0].status !==
          'active'
      ) {
        return res.status(403).json({
          error:
            'Account is not active.'
        });
      }

      const [pending] =
        await pool.query(
          'SELECT COALESCE(SUM(amount),0) pending FROM withdrawals WHERE user_id=? AND status="pending"',
          [req.user.id]
        );

      const available =
        Number(users[0].balance) -
        Number(
          pending[0].pending
        );

      if (amount > available) {
        return res.status(400).json({
          error:
            'Insufficient available balance.'
        });
      }

      await pool.query(
        'INSERT INTO withdrawals(user_id,amount,method,account) VALUES(?,?,?,?)',
        [
          req.user.id,
          amount,
          method,
          account
        ]
      );

      res.status(201).json({
        message:
          'Withdrawal request submitted.',
        availableBalance:
          available - amount
      });
    } catch (e) {
      console.error('Withdrawal error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   USER WITHDRAWALS
========================================================= */

app.get(
  '/api/withdrawals',
  auth,
  async (req, res) => {
    try {
      const [rows] =
        await pool.query(
          'SELECT id,amount,method,account,status,created_at,reviewed_at FROM withdrawals WHERE user_id=? ORDER BY id DESC',
          [req.user.id]
        );

      res.json(rows);
    } catch (e) {
      console.error('User withdrawals error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   ADMIN STATS
========================================================= */

app.get(
  '/api/admin/stats',
  adminAuth,
  async (req, res) => {
    try {
      const [[users]] =
        await pool.query(
          'SELECT COUNT(*) count FROM users'
        );

      const [[payments]] =
        await pool.query(
          'SELECT COUNT(*) count FROM payment_requests WHERE status="pending"'
        );

      const [[withdrawals]] =
        await pool.query(
          'SELECT COUNT(*) count FROM withdrawals WHERE status="pending"'
        );

      const [[investments]] =
        await pool.query(
          'SELECT COUNT(*) count FROM investments WHERE status="active"'
        );

      const [[balance]] =
        await pool.query(
          'SELECT COALESCE(SUM(balance),0) total FROM users'
        );

      res.json({
        users: users.count,
        pendingPayments:
          payments.count,
        pendingWithdrawals:
          withdrawals.count,
        activeInvestments:
          investments.count,
        totalUserBalance:
          balance.total
      });
    } catch (e) {
      console.error('Admin stats error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   ADMIN PAYMENTS
========================================================= */

app.get(
  '/api/admin/payments',
  adminAuth,
  async (req, res) => {
    try {
      const [rows] =
        await pool.query(
          'SELECT pr.*,u.username,p.name plan_name FROM payment_requests pr JOIN users u ON u.id=pr.user_id JOIN plans p ON p.id=pr.plan_id ORDER BY pr.id DESC'
        );

      res.json(rows);
    } catch (e) {
      console.error('Admin payments error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   ADMIN APPROVE PAYMENT
========================================================= */

app.post(
  '/api/admin/payments/:id/approve',
  adminAuth,
  async (req, res) => {
    const conn =
      await pool.getConnection();

    try {
      await conn.beginTransaction();

      const [requests] =
        await conn.query(
          'SELECT * FROM payment_requests WHERE id=? FOR UPDATE',
          [req.params.id]
        );

      if (
        !requests.length ||
        requests[0].status !==
          'pending'
      ) {
        throw new Error(
          'Payment request is not pending.'
        );
      }

      const [plans] =
        await conn.query(
          'SELECT * FROM plans WHERE id=?',
          [requests[0].plan_id]
        );

      if (!plans.length) {
        throw new Error(
          'Plan not found.'
        );
      }

      const start =
        new Date();

      const end =
        new Date(
          start.getTime() +
            plans[0]
              .duration_days *
              86400000
        );

      await conn.query(
        'INSERT INTO investments(user_id,plan_id,amount,daily_rate,duration_days,status,start_at,end_at) VALUES(?,?,?,?,?,?,?,?)',
        [
          requests[0]
            .user_id,
          plans[0].id,
          plans[0].amount,
          plans[0]
            .daily_rate,
          plans[0]
            .duration_days,
          'active',
          start,
          end
        ]
      );

      await conn.query(
        'UPDATE users SET balance=balance+? WHERE id=?',
        [
          requests[0].amount,
          requests[0]
            .user_id
        ]
      );

      await conn.query(
        'UPDATE payment_requests SET status="approved",reviewed_at=NOW() WHERE id=?',
        [requests[0].id]
      );

      const [users] =
        await conn.query(
          'SELECT referred_by_user_id FROM users WHERE id=?',
          [requests[0].user_id]
        );

      if (
        users[0]
          ?.referred_by_user_id
      ) {
        const commission =
          Number(
            requests[0].amount
          ) *
          REFERRAL_RATE;

        await conn.query(
          'UPDATE users SET balance=balance+?,referral_earnings=referral_earnings+? WHERE id=?',
          [
            commission,
            commission,
            users[0]
              .referred_by_user_id
          ]
        );
      }

      await conn.commit();

      res.json({
        message:
          'Payment approved.'
      });
    } catch (e) {
      await conn.rollback();

      console.error('Approve payment error:', e);

      res.status(400).json({
        error: e.message
      });
    } finally {
      conn.release();
    }
  }
);

/* =========================================================
   ADMIN REJECT PAYMENT
========================================================= */

app.post(
  '/api/admin/payments/:id/reject',
  adminAuth,
  async (req, res) => {
    try {
      await pool.query(
        'UPDATE payment_requests SET status="rejected",reviewed_at=NOW() WHERE id=? AND status="pending"',
        [req.params.id]
      );

      res.json({
        message:
          'Payment rejected.'
      });
    } catch (e) {
      console.error('Reject payment error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   ADMIN WITHDRAWALS
========================================================= */

app.get(
  '/api/admin/withdrawals',
  adminAuth,
  async (req, res) => {
    try {
      const [rows] =
        await pool.query(
          'SELECT w.*,u.username FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.id DESC'
        );

      res.json(rows);
    } catch (e) {
      console.error('Admin withdrawals error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   ADMIN APPROVE WITHDRAWAL
========================================================= */

app.post(
  '/api/admin/withdrawals/:id/approve',
  adminAuth,
  async (req, res) => {
    const conn =
      await pool.getConnection();

    try {
      await conn.beginTransaction();

      const [withdrawals] =
        await conn.query(
          'SELECT * FROM withdrawals WHERE id=? FOR UPDATE',
          [req.params.id]
        );

      if (
        !withdrawals.length ||
        withdrawals[0].status !==
          'pending'
      ) {
        throw new Error(
          'Withdrawal is not pending.'
        );
      }

      const [users] =
        await conn.query(
          'SELECT balance FROM users WHERE id=? FOR UPDATE',
          [
            withdrawals[0]
              .user_id
          ]
        );

      if (
        !users.length ||
        Number(
          users[0].balance
        ) <
          Number(
            withdrawals[0]
              .amount
          )
      ) {
        throw new Error(
          'Insufficient balance.'
        );
      }

      await conn.query(
        'UPDATE users SET balance=balance-? WHERE id=?',
        [
          withdrawals[0]
            .amount,
          withdrawals[0]
            .user_id
        ]
      );

      await conn.query(
        'UPDATE withdrawals SET status="completed",reviewed_at=NOW() WHERE id=?',
        [req.params.id]
      );

      await conn.commit();

      res.json({
        message:
          'Withdrawal approved.'
      });
    } catch (e) {
      await conn.rollback();

      console.error('Approve withdrawal error:', e);

      res.status(400).json({
        error: e.message
      });
    } finally {
      conn.release();
    }
  }
);

/* =========================================================
   ADMIN REJECT WITHDRAWAL
========================================================= */

app.post(
  '/api/admin/withdrawals/:id/reject',
  adminAuth,
  async (req, res) => {
    try {
      await pool.query(
        'UPDATE withdrawals SET status="rejected",reviewed_at=NOW() WHERE id=? AND status="pending"',
        [req.params.id]
      );

      res.json({
        message:
          'Withdrawal rejected.'
      });
    } catch (e) {
      console.error('Reject withdrawal error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   ADMIN USERS
========================================================= */

app.get(
  '/api/admin/users',
  adminAuth,
  async (req, res) => {
    try {
      const [rows] =
        await pool.query(
          'SELECT id,username,referral_code,referred_by_user_id,balance,referral_earnings,created_at,status FROM users ORDER BY id DESC'
        );

      res.json(rows);
    } catch (e) {
      console.error('Admin users error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   ADMIN INVESTMENTS
========================================================= */

app.get(
  '/api/admin/investments',
  adminAuth,
  async (req, res) => {
    try {
      const [rows] =
        await pool.query(
          'SELECT i.*,u.username,p.name plan_name FROM investments i JOIN users u ON u.id=i.user_id JOIN plans p ON p.id=i.plan_id ORDER BY i.id DESC'
        );

      res.json(rows);
    } catch (e) {
      console.error('Admin investments error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   ADMIN PLANS
========================================================= */

app.get(
  '/api/admin/plans',
  adminAuth,
  async (req, res) => {
    try {
      const [rows] =
        await pool.query(
          'SELECT id,name,amount,daily_rate,duration_days,active FROM plans ORDER BY id'
        );

      res.json(rows);
    } catch (e) {
      console.error('Admin plans error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   ADMIN UPDATE PLAN
========================================================= */

app.put(
  '/api/admin/plans/:id',
  adminAuth,
  async (req, res) => {
    try {
      const name = String(
        req.body.name || ''
      ).trim();

      const amount = Number(
        req.body.amount
      );

      const dailyRate = Number(
        req.body.dailyRate
      );

      const durationDays =
        Number(
          req.body.durationDays
        );

      const active =
        req.body.active ? 1 : 0;

      if (
        !name ||
        !(amount > 0) ||
        !(dailyRate >= 0) ||
        !(durationDays > 0)
      ) {
        return res.status(400).json({
          error:
            'Valid plan fields are required.'
        });
      }

      await pool.query(
        'UPDATE plans SET name=?,amount=?,daily_rate=?,duration_days=?,active=? WHERE id=?',
        [
          name,
          amount,
          dailyRate,
          durationDays,
          active,
          req.params.id
        ]
      );

      res.json({
        message:
          'Plan updated.'
      });
    } catch (e) {
      console.error('Update plan error:', e);

      res.status(500).json({
        error: e.message
      });
    }
  }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (err, req, res, next) => {
    console.error(err);

    res.status(500).json({
      error:
        'Server error.'
    });
  }
);

/* =========================================================
   START SERVER
========================================================= */

migrate()
  .then(() => {
    app.listen(
      PORT,
      '0.0.0.0',
      () => {
        console.log(
          `Smart Invest API running on port ${PORT}`
        );

        console.log(
          `Frontend directory: ${frontendDir}`
        );

        console.log(
          `Frontend file: ${path.join(
            frontendDir,
            'index.html'
          )}`
        );

        console.log(
          `Frontend exists: ${fs.existsSync(
            path.join(
              frontendDir,
              'index.html'
            )
          )}`
        );
      }
    );
  })
  .catch(e => {
    console.error(
      'Server startup failed:',
      e
    );

    process.exit(1);
  });