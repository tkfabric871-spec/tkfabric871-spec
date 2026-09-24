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

app.use(cors());
app.use(express.json({ limit: '1mb' }));

// Serve frontend files from the parent smart_work folder
app.use(express.static(path.join(__dirname, '..')));

// Upload directory
const uploadDir = path.join(__dirname, '..', 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });

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

// MySQL
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

const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME';
const REFERRAL_RATE = Number(process.env.REFERRAL_RATE || 0.05);

// Referral code
function code(u) {
  return String(u)
    .replace(/[^a-z0-9]/gi, '')
    .slice(0, 6)
    .toUpperCase() +
    Math.floor(1000 + Math.random() * 9000);
}

// JWT
function sign(u) {
  return jwt.sign(
    {
      id: u.id,
      username: u.username
    },
    JWT_SECRET,
    {
      expiresIn: '7d'
    }
  );
}

// User authentication
function auth(req, res, next) {
  const t = (req.headers.authorization || '').replace(/^Bearer /, '');

  if (!t) {
    return res.status(401).json({
      error: 'Authentication required.'
    });
  }

  try {
    req.user = jwt.verify(t, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: 'Invalid or expired token.'
    });
  }
}

// Admin authentication
function adminAuth(req, res, next) {
  if (
    req.headers['x-admin-username'] !== process.env.ADMIN_USERNAME ||
    req.headers['x-admin-password'] !== process.env.ADMIN_PASSWORD
  ) {
    return res.status(401).json({
      error: 'Admin authentication required.'
    });
  }

  next();
}

// Database migration
async function migrate() {
  try {
    await pool.query(
      "ALTER TABLE users ADD COLUMN status ENUM('active','suspended') NOT NULL DEFAULT 'active'"
    );
  } catch (e) {
    if (e.code !== 'ER_DUP_FIELDNAME') {
      console.warn('users migration:', e.message);
    }
  }

  try {
    await pool.query(
      "ALTER TABLE payment_requests ADD COLUMN payment_screenshot VARCHAR(255) NULL"
    );
  } catch (e) {
    if (e.code !== 'ER_DUP_FIELDNAME') {
      console.warn('payment screenshot migration:', e.message);
    }
  }
}

// Health check
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

// Signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    const ref = String(req.body.referralCode || '')
      .trim()
      .toUpperCase();

    if (username.length < 3 || username.length > 50) {
      return res.status(400).json({
        error: 'Username must be 3-50 characters.'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: 'Password must be at least 6 characters.'
      });
    }

    const [e] = await pool.query(
      'SELECT id FROM users WHERE LOWER(username)=LOWER(?)',
      [username]
    );

    if (e.length) {
      return res.status(409).json({
        error: 'Username already exists.'
      });
    }

    let referrer = null;

    if (ref) {
      const [r] = await pool.query(
        'SELECT id,username FROM users WHERE referral_code=? AND status="active"',
        [ref]
      );

      if (!r.length) {
        return res.status(400).json({
          error: 'Invalid referral code.'
        });
      }

      referrer = r[0];
    }

    let referralCode;

    for (let i = 0; i < 20; i++) {
      const c = code(username);

      const [cx] = await pool.query(
        'SELECT id FROM users WHERE referral_code=?',
        [c]
      );

      if (!cx.length) {
        referralCode = c;
        break;
      }
    }

    if (!referralCode) {
      throw Error('Could not create referral code.');
    }

    const hash = await bcrypt.hash(password, 12);

    const [r] = await pool.query(
      'INSERT INTO users(username,password_hash,referral_code,referred_by_user_id) VALUES(?,?,?,?)',
      [
        username,
        hash,
        referralCode,
        referrer?.id || null
      ]
    );

    const [u] = await pool.query(
      'SELECT id,username,referral_code,balance,referral_earnings,created_at,status FROM users WHERE id=?',
      [r.insertId]
    );

    res.status(201).json({
      token: sign(u[0]),
      user: u[0]
    });
  } catch (e) {
    res.status(500).json({
      error: e.message
    });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');

    const [r] = await pool.query(
      'SELECT * FROM users WHERE username=?',
      [username]
    );

    if (
      !r.length ||
      !(await bcrypt.compare(password, r[0].password_hash))
    ) {
      return res.status(401).json({
        error: 'Invalid username or password.'
      });
    }

    if (r[0].status === 'suspended') {
      return res.status(403).json({
        error: 'This account is suspended.'
      });
    }

    const u = r[0];

    res.json({
      token: sign(u),
      user: {
        id: u.id,
        username: u.username,
        referral_code: u.referral_code,
        balance: u.balance,
        referral_earnings: u.referral_earnings,
        created_at: u.created_at
      }
    });
  } catch (e) {
    res.status(500).json({
      error: e.message
    });
  }
});

// Change password
app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const cur = String(req.body.currentPassword || '');
    const next = String(req.body.newPassword || '');

    if (next.length < 6) {
      return res.status(400).json({
        error: 'New password must be at least 6 characters.'
      });
    }

    const [r] = await pool.query(
      'SELECT password_hash FROM users WHERE id=?',
      [req.user.id]
    );

    if (
      !r.length ||
      !(await bcrypt.compare(cur, r[0].password_hash))
    ) {
      return res.status(401).json({
        error: 'Current password is incorrect.'
      });
    }

    const h = await bcrypt.hash(next, 12);

    await pool.query(
      'UPDATE users SET password_hash=? WHERE id=?',
      [h, req.user.id]
    );

    res.json({
      message: 'Password changed successfully.'
    });
  } catch (e) {
    res.status(500).json({
      error: e.message
    });
  }
});

// Plans
app.get('/api/plans', async (req, res) => {
  try {
    const [r] = await pool.query(
      'SELECT id,name,amount,daily_rate,duration_days FROM plans WHERE active=1 ORDER BY id'
    );

    res.json(r);
  } catch (e) {
    res.status(500).json({
      error: e.message
    });
  }
});

// Profile
app.get('/api/profile', auth, async (req, res) => {
  try {
    const [r] = await pool.query(
      'SELECT id,username,referral_code,referred_by_user_id,balance,referral_earnings,created_at,status FROM users WHERE id=?',
      [req.user.id]
    );

    if (!r.length) {
      return res.status(404).json({
        error: 'User not found.'
      });
    }

    const [ref] = await pool.query(
      'SELECT username FROM users WHERE id=?',
      [r[0].referred_by_user_id]
    );

    res.json({
      ...r[0],
      referred_by: ref[0]?.username || null
    });
  } catch (e) {
    res.status(500).json({
      error: e.message
    });
  }
});

// Payment request
app.post(
  '/api/payments',
  auth,
  upload.single('paymentScreenshot'),
  async (req, res) => {
    try {
      const planId = Number(req.body.planId);
      const tx = String(req.body.transactionId || '').trim();

      const [p] = await pool.query(
        'SELECT * FROM plans WHERE id=? AND active=1',
        [planId]
      );

      if (!p.length) {
        return res.status(400).json({
          error: 'Invalid plan.'
        });
      }

      if (!tx && !req.file) {
        return res.status(400).json({
          error: 'Transaction ID or payment screenshot is required.'
        });
      }

      if (tx) {
        const [e] = await pool.query(
          'SELECT id FROM payment_requests WHERE transaction_id=?',
          [tx]
        );

        if (e.length) {
          return res.status(409).json({
            error: 'Transaction ID already exists.'
          });
        }
      }

      const shot = req.file
        ? '/uploads/' + path.basename(req.file.path)
        : null;

      await pool.query(
        'INSERT INTO payment_requests(user_id,plan_id,amount,transaction_id,payment_screenshot) VALUES(?,?,?,?,?)',
        [
          req.user.id,
          planId,
          p[0].amount,
          tx || null,
          shot
        ]
      );

      res.status(201).json({
        message: 'Payment request submitted for admin review.'
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// Payment history
app.get('/api/payments', auth, async (req, res) => {
  try {
    const [r] = await pool.query(
      'SELECT id,plan_id,amount,transaction_id,payment_screenshot,status,created_at,reviewed_at FROM payment_requests WHERE user_id=? ORDER BY id DESC',
      [req.user.id]
    );

    res.json(r);
  } catch (e) {
    res.status(500).json({
      error: e.message
    });
  }
});

// Investments
app.get('/api/investments', auth, async (req, res) => {
  try {
    const [r] = await pool.query(
      'SELECT i.*,p.name AS plan_name FROM investments i JOIN plans p ON p.id=i.plan_id WHERE i.user_id=? ORDER BY i.id DESC',
      [req.user.id]
    );

    res.json(r);
  } catch (e) {
    res.status(500).json({
      error: e.message
    });
  }
});

// Withdrawals
app.post('/api/withdrawals', auth, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    const method = String(req.body.method || '').trim();
    const account = String(req.body.account || '').trim();

    if (!(amount > 0) || !method || !account) {
      return res.status(400).json({
        error: 'Valid amount, method and account are required.'
      });
    }

    const [u] = await pool.query(
      'SELECT balance,status FROM users WHERE id=?',
      [req.user.id]
    );

    if (!u.length || u[0].status !== 'active') {
      return res.status(403).json({
        error: 'Account is not active.'
      });
    }

    const [w] = await pool.query(
      'SELECT COALESCE(SUM(amount),0) pending FROM withdrawals WHERE user_id=? AND status="pending"',
      [req.user.id]
    );

    const available =
      Number(u[0].balance) - Number(w[0].pending);

    if (amount > available) {
      return res.status(400).json({
        error: 'Insufficient available balance.'
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
      message: 'Withdrawal request submitted.',
      availableBalance: available - amount
    });
  } catch (e) {
    res.status(500).json({
      error: e.message
    });
  }
});

// Withdrawal history
app.get('/api/withdrawals', auth, async (req, res) => {
  try {
    const [r] = await pool.query(
      'SELECT id,amount,method,account,status,created_at,reviewed_at FROM withdrawals WHERE user_id=? ORDER BY id DESC',
      [req.user.id]
    );

    res.json(r);
  } catch (e) {
    res.status(500).json({
      error: e.message
    });
  }
});

// Admin stats
app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const [[users]] = await pool.query(
      'SELECT COUNT(*) count FROM users'
    );

    const [[payments]] = await pool.query(
      'SELECT COUNT(*) count FROM payment_requests WHERE status="pending"'
    );

    const [[withdrawals]] = await pool.query(
      'SELECT COUNT(*) count FROM withdrawals WHERE status="pending"'
    );

    const [[investments]] = await pool.query(
      'SELECT COUNT(*) count FROM investments WHERE status="active"'
    );

    const [[balance]] = await pool.query(
      'SELECT COALESCE(SUM(balance),0) total FROM users'
    );

    res.json({
      users: users.count,
      pendingPayments: payments.count,
      pendingWithdrawals: withdrawals.count,
      activeInvestments: investments.count,
      totalUserBalance: balance.total
    });
  } catch (e) {
    res.status(500).json({
      error: e.message
    });
  }
});

// Admin payments
app.get('/api/admin/payments', adminAuth, async (req, res) => {
  try {
    const [r] = await pool.query(
      'SELECT pr.*,u.username,p.name plan_name FROM payment_requests pr JOIN users u ON u.id=pr.user_id JOIN plans p ON p.id=pr.plan_id ORDER BY pr.id DESC'
    );

    res.json(r);
  } catch (e) {
    res.status(500).json({
      error: e.message
    });
  }
});

// Admin approve payment
app.post(
  '/api/admin/payments/:id/approve',
  adminAuth,
  async (req, res) => {
    const c = await pool.getConnection();

    try {
      await c.beginTransaction();

      const [r] = await c.query(
        'SELECT * FROM payment_requests WHERE id=? FOR UPDATE',
        [req.params.id]
      );

      if (!r.length || r[0].status !== 'pending') {
        throw Error('Payment request is not pending.');
      }

      const [p] = await c.query(
        'SELECT * FROM plans WHERE id=?',
        [r[0].plan_id]
      );

      const start = new Date();
      const end = new Date(
        start.getTime() +
        p[0].duration_days * 86400000
      );

      await c.query(
        'INSERT INTO investments(user_id,plan_id,amount,daily_rate,duration_days,status,start_at,end_at) VALUES(?,?,?,?,?,?,?,?)',
        [
          r[0].user_id,
          p[0].id,
          p[0].amount,
          p[0].daily_rate,
          p[0].duration_days,
          'active',
          start,
          end
        ]
      );

      await c.query(
        'UPDATE users SET balance=balance+? WHERE id=?',
        [
          r[0].amount,
          r[0].user_id
        ]
      );

      await c.query(
        'UPDATE payment_requests SET status="approved",reviewed_at=NOW() WHERE id=?',
        [r[0].id]
      );

      const [u] = await c.query(
        'SELECT referred_by_user_id FROM users WHERE id=?',
        [r[0].user_id]
      );

      if (u[0]?.referred_by_user_id) {
        const commission =
          Number(r[0].amount) * REFERRAL_RATE;

        await c.query(
          'UPDATE users SET balance=balance+?,referral_earnings=referral_earnings+? WHERE id=?',
          [
            commission,
            commission,
            u[0].referred_by_user_id
          ]
        );
      }

      await c.commit();

      res.json({
        message: 'Payment approved.'
      });
    } catch (e) {
      await c.rollback();

      res.status(400).json({
        error: e.message
      });
    } finally {
      c.release();
    }
  }
);

// Admin reject payment
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
        message: 'Payment rejected.'
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// Admin withdrawals
app.get(
  '/api/admin/withdrawals',
  adminAuth,
  async (req, res) => {
    try {
      const [r] = await pool.query(
        'SELECT w.*,u.username FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.id DESC'
      );

      res.json(r);
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// Admin approve withdrawal
app.post(
  '/api/admin/withdrawals/:id/approve',
  adminAuth,
  async (req, res) => {
    const c = await pool.getConnection();

    try {
      await c.beginTransaction();

      const [r] = await c.query(
        'SELECT * FROM withdrawals WHERE id=? FOR UPDATE',
        [req.params.id]
      );

      if (!r.length || r[0].status !== 'pending') {
        throw Error('Withdrawal is not pending.');
      }

      const [u] = await c.query(
        'SELECT balance FROM users WHERE id=? FOR UPDATE',
        [r[0].user_id]
      );

      if (
        Number(u[0].balance) <
        Number(r[0].amount)
      ) {
        throw Error('Insufficient balance.');
      }

      await c.query(
        'UPDATE users SET balance=balance-? WHERE id=?',
        [
          r[0].amount,
          r[0].user_id
        ]
      );

      await c.query(
        'UPDATE withdrawals SET status="completed",reviewed_at=NOW() WHERE id=?',
        [req.params.id]
      );

      await c.commit();

      res.json({
        message: 'Withdrawal approved.'
      });
    } catch (e) {
      await c.rollback();

      res.status(400).json({
        error: e.message
      });
    } finally {
      c.release();
    }
  }
);

// Admin reject withdrawal
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
        message: 'Withdrawal rejected.'
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// Admin users
app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const [r] = await pool.query(
      'SELECT id,username,referral_code,referred_by_user_id,balance,referral_earnings,created_at,status FROM users ORDER BY id DESC'
    );

    res.json(r);
  } catch (e) {
    res.status(500).json({
      error: e.message
    });
  }
});

// Admin investments
app.get(
  '/api/admin/investments',
  adminAuth,
  async (req, res) => {
    try {
      const [r] = await pool.query(
        'SELECT i.*,u.username,p.name plan_name FROM investments i JOIN users u ON u.id=i.user_id JOIN plans p ON p.id=i.plan_id ORDER BY i.id DESC'
      );

      res.json(r);
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// Admin plans
app.get('/api/admin/plans', adminAuth, async (req, res) => {
  try {
    const [r] = await pool.query(
      'SELECT id,name,amount,daily_rate,duration_days,active FROM plans ORDER BY id'
    );

    res.json(r);
  } catch (e) {
    res.status(500).json({
      error: e.message
    });
  }
});

// Admin update plan
app.put(
  '/api/admin/plans/:id',
  adminAuth,
  async (req, res) => {
    try {
      const name = String(req.body.name || '').trim();
      const amount = Number(req.body.amount);
      const dailyRate = Number(req.body.dailyRate);
      const durationDays = Number(req.body.durationDays);
      const active = req.body.active ? 1 : 0;

      if (
        !name ||
        !(amount > 0) ||
        !(dailyRate >= 0) ||
        !(durationDays > 0)
      ) {
        return res.status(400).json({
          error: 'Valid plan fields are required.'
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
        message: 'Plan updated.'
      });
    } catch (e) {
      res.status(500).json({
        error: e.message
      });
    }
  }
);

// Error handler
app.use((err, req, res, next) => {
  console.error(err);

  res.status(500).json({
    error: 'Server error.'
  });
});

// Start server
migrate()
  .then(() => {
    app.listen(PORT, () => {
      console.log(
        `Smart Invest API running on http://localhost:${PORT}`
      );
    });
  })
  .catch(e => {
    console.error(e);
    process.exit(1);
  });