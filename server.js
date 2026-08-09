require('dotenv').config();

const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const passport = require('passport');
const session = require('express-session');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

const toUserResponse = (row) => ({
  id: row.id,
  firstName: row.first_name,
  lastName: row.last_name,
  email: row.email,
  role: row.role,
  position: row.position,
  department: row.department,
  education: row.education,
  bio: row.bio,
  location: row.location,
  phone: row.phone,
  profilePhoto: row.profile_photo,
  coverPhoto: row.cover_photo,
});

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'No token provided.' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
};

const requireRole = (...allowedRoles) => async (req, res, next) => {
  try {
    const [rows] = await pool.query('SELECT role FROM users WHERE id = ?', [req.userId]);
    if (rows.length === 0 || !allowedRoles.includes(rows[0].role)) {
      return res.status(403).json({ message: 'You do not have permission to perform this action.' });
    }
    next();
  } catch (err) {
    res.status(500).json({ message: 'Failed to verify role.' });
  }
};

// ===================== PASSPORT / GOOGLE OAUTH SETUP =====================

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

const findOrCreateOAuthUser = async (provider, profile) => {
  const oauthId = profile.id;
  const email = profile.emails?.[0]?.value || `${provider}_${oauthId}@noemail.local`;
  const displayName = profile.displayName || 'User';
  const [firstName, ...rest] = displayName.split(' ');
  const lastName = rest.join(' ') || '';
  const photo = profile.photos?.[0]?.value || null;

  const [existing] = await pool.query(
    'SELECT * FROM users WHERE oauth_provider = ? AND oauth_id = ?',
    [provider, oauthId]
  );
  if (existing.length > 0) return existing[0];

  const [byEmail] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
  if (byEmail.length > 0) {
    await pool.query(
      'UPDATE users SET oauth_provider = ?, oauth_id = ? WHERE id = ?',
      [provider, oauthId, byEmail[0].id]
    );
    return byEmail[0];
  }

  const [result] = await pool.query(
    `INSERT INTO users (first_name, last_name, email, profile_photo, oauth_provider, oauth_id, role)
     VALUES (?, ?, ?, ?, ?, ?, 'student')`,
    [firstName, lastName, email, photo, provider, oauthId]
  );
  const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [result.insertId]);
  return rows[0];
};

passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:5000/api/auth/google/callback',
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const user = await findOrCreateOAuthUser('google', profile);
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }
));

// ===================== AUTH =====================

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }
    const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(409).json({ message: 'An account with this email already exists.' });
    }
    const [firstName, ...rest] = name.trim().split(' ');
    const lastName = rest.join(' ') || '';
    const passwordHash = await bcrypt.hash(password, 10);
    const validRoles = ['student', 'manager', 'hr'];
    const finalRole = validRoles.includes(role) ? role : 'student';

    const [result] = await pool.query(
      'INSERT INTO users (first_name, last_name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)',
      [firstName, lastName, email, passwordHash, finalRole]
    );
    const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [result.insertId]);
    const user = toUserResponse(rows[0]);
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during signup.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) return res.status(401).json({ message: 'Invalid email or password.' });
    if (!rows[0].password_hash) {
      return res.status(401).json({ message: 'This account uses social sign-in. Please continue with Google.' });
    }
    const match = await bcrypt.compare(password, rows[0].password_hash);
    if (!match) return res.status(401).json({ message: 'Invalid email or password.' });
    const user = toUserResponse(rows[0]);
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during login.' });
  }
});

// ===================== GOOGLE OAUTH ROUTES =====================

app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/api/auth/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: `${process.env.FRONTEND_URL}/auth` }),
  (req, res) => {
    const user = toUserResponse(req.user);
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.redirect(`${process.env.FRONTEND_URL}/oauth-success?token=${token}&user=${encodeURIComponent(JSON.stringify(user))}`);
  }
);

// ===================== PROFILE =====================

app.put('/api/users/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    if (parseInt(id) !== req.userId) {
      return res.status(403).json({ message: 'Not authorized to update this profile.' });
    }
    const {
      firstName, lastName, position, department,
      education, bio, location, phone, profilePhoto, coverPhoto
    } = req.body;

    await pool.query(
      `UPDATE users SET
        first_name = ?, last_name = ?, position = ?, department = ?,
        education = ?, bio = ?, location = ?, phone = ?, profile_photo = ?, cover_photo = ?
       WHERE id = ?`,
      [firstName, lastName, position, department, education, bio, location, phone, profilePhoto, coverPhoto, id]
    );

    const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [id]);
    res.json({ user: toUserResponse(rows[0]) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error updating profile.' });
  }
});

// ===================== SKILLS =====================

app.get('/api/skills/:userId', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM skills WHERE user_id = ?', [req.params.userId]);
    res.json({ skills: rows.map(r => ({ id: r.id, name: r.skill_name })) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch skills.' });
  }
});

app.post('/api/skills', authMiddleware, async (req, res) => {
  try {
    const { skillName } = req.body;
    if (!skillName?.trim()) return res.status(400).json({ message: 'Skill name required.' });
    const [result] = await pool.query(
      'INSERT INTO skills (user_id, skill_name) VALUES (?, ?)',
      [req.userId, skillName.trim()]
    );
    res.status(201).json({ id: result.insertId, name: skillName.trim() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to add skill.' });
  }
});

app.delete('/api/skills/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM skills WHERE id = ? AND user_id = ?', [req.params.id, req.userId]);
    res.json({ deleted: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to delete skill.' });
  }
});

// ===================== CERTIFICATES =====================

app.get('/api/certificates/:userId', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM certificates WHERE user_id = ?', [req.params.userId]);
    res.json({ certificates: rows.map(r => ({ id: r.id, name: r.certificate_name })) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch certificates.' });
  }
});

app.post('/api/certificates', authMiddleware, async (req, res) => {
  try {
    const { certificateName } = req.body;
    if (!certificateName?.trim()) return res.status(400).json({ message: 'Certificate name required.' });
    const [result] = await pool.query(
      'INSERT INTO certificates (user_id, certificate_name) VALUES (?, ?)',
      [req.userId, certificateName.trim()]
    );
    res.status(201).json({ id: result.insertId, name: certificateName.trim() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to add certificate.' });
  }
});

app.delete('/api/certificates/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM certificates WHERE id = ? AND user_id = ?', [req.params.id, req.userId]);
    res.json({ deleted: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to delete certificate.' });
  }
});

// ===================== TEAMS =====================

app.get('/api/teams', authMiddleware, async (req, res) => {
  try {
    const [teams] = await pool.query('SELECT * FROM teams ORDER BY created_at ASC');

    const fullTeams = await Promise.all(
      teams.map(async (team) => {
        const [members] = await pool.query(
          'SELECT * FROM team_members WHERE team_id = ? ORDER BY joined_at ASC',
          [team.id]
        );

        const membersWithSkills = await Promise.all(
          members.map(async (m) => {
            const [skills] = await pool.query(
              'SELECT skill_name FROM team_member_skills WHERE team_member_id = ?',
              [m.id]
            );
            return {
              id: m.id,
              name: m.member_name,
              avatar: m.member_avatar,
              role: m.member_role,
              rating: m.rating,
              feedback: m.feedback,
              completedTrainings: m.completed_trainings,
              skills: skills.map((s) => s.skill_name),
            };
          })
        );

        return {
          id: team.id,
          name: team.name,
          manager: {
            name: team.manager_name,
            role: team.manager_role,
            avatar: team.manager_avatar,
          },
          employees: membersWithSkills,
        };
      })
    );

    res.json({ teams: fullTeams });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch teams.' });
  }
});

app.post('/api/teams', authMiddleware, requireRole('manager', 'hr', 'admin'), async (req, res) => {
  try {
    const { name, managerName, managerRole, managerAvatar } = req.body;
    if (!name || !managerName) {
      return res.status(400).json({ message: 'Team name and manager name are required.' });
    }

    const [result] = await pool.query(
      'INSERT INTO teams (name, manager_name, manager_role, manager_avatar) VALUES (?, ?, ?, ?)',
      [name, managerName, managerRole || 'Manager', managerAvatar || null]
    );

    res.status(201).json({
      id: result.insertId,
      name,
      manager: { name: managerName, role: managerRole || 'Manager', avatar: managerAvatar || null },
      employees: [],
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to create team.' });
  }
});

app.post('/api/teams/:teamId/members', authMiddleware, requireRole('manager', 'hr', 'admin'), async (req, res) => {
  try {
    const { teamId } = req.params;
    const { name, avatar, role, rating, feedback, completedTrainings, skills } = req.body;

    if (!name) return res.status(400).json({ message: 'Member name is required.' });

    const [result] = await pool.query(
      `INSERT INTO team_members (team_id, member_name, member_avatar, member_role, rating, feedback, completed_trainings)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [teamId, name, avatar || null, role || null, rating || null, feedback || null, completedTrainings || 0]
    );

    const memberId = result.insertId;

    if (Array.isArray(skills) && skills.length > 0) {
      const skillValues = skills.map((s) => [memberId, s]);
      await pool.query('INSERT INTO team_member_skills (team_member_id, skill_name) VALUES ?', [skillValues]);
    }

    res.status(201).json({
      id: memberId,
      name,
      avatar,
      role,
      rating,
      feedback,
      completedTrainings: completedTrainings || 0,
      skills: skills || [],
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to add member.' });
  }
});

app.put('/api/teams/members/:memberId/feedback', authMiddleware, requireRole('manager', 'hr', 'admin'), async (req, res) => {
  try {
    const { memberId } = req.params;
    const { rating, feedback } = req.body;

    await pool.query(
      'UPDATE team_members SET rating = ?, feedback = ? WHERE id = ?',
      [rating, feedback, memberId]
    );

    res.json({ id: memberId, rating, feedback });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to update feedback.' });
  }
});

// ===================== CHAT MESSAGES =====================

app.get('/api/chat-messages', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM chat_messages WHERE user_id = ? ORDER BY sent_at ASC',
      [req.userId]
    );

    const grouped = {};
    rows.forEach((row) => {
      if (!grouped[row.contact_id]) grouped[row.contact_id] = [];
      grouped[row.contact_id].push({
        id: row.id,
        text: row.text,
        sender: row.sender,
        time: new Date(row.sent_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      });
    });

    res.json({ messages: grouped });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch messages.' });
  }
});

app.post('/api/chat-messages', authMiddleware, async (req, res) => {
  try {
    const { contactId, text } = req.body;
    if (!contactId || !text?.trim()) {
      return res.status(400).json({ message: 'contactId and text are required.' });
    }

    const [result] = await pool.query(
      'INSERT INTO chat_messages (user_id, contact_id, text, sender) VALUES (?, ?, ?, ?)',
      [req.userId, contactId, text.trim(), 'me']
    );

    const [rows] = await pool.query('SELECT * FROM chat_messages WHERE id = ?', [result.insertId]);
    const row = rows[0];

    res.status(201).json({
      id: row.id,
      contactId: row.contact_id,
      text: row.text,
      sender: row.sender,
      time: new Date(row.sent_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to send message.' });
  }
});

// ===================== EMPLOYEES (reuses users table) =====================

app.get('/api/employees', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, first_name, last_name, position, department, profile_photo,
              experience, current_salary, performance_rating
       FROM users`
    );
    const employees = rows.map((r) => ({
      id: r.id,
      name: `${r.first_name} ${r.last_name}`,
      currentPosition: r.position || 'Unassigned',
      currentSalary: parseFloat(r.current_salary) || 0,
      avatar: r.profile_photo,
      department: r.department || 'General',
      experience: r.experience || 'N/A',
      performance: parseFloat(r.performance_rating) || 0,
    }));
    res.json({ employees });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch employees.' });
  }
});

// ===================== PROMOTION REQUESTS (HR reviews first, Manager confirms) =====================

app.get('/api/promotion-requests', authMiddleware, async (req, res) => {
  try {
    const [requests] = await pool.query('SELECT * FROM promotion_requests ORDER BY created_at DESC');

    const fullRequests = await Promise.all(
      requests.map(async (r) => {
        const [skills] = await pool.query(
          'SELECT skill_name FROM promotion_request_skills WHERE promotion_request_id = ?',
          [r.id]
        );
        const [certs] = await pool.query(
          'SELECT certificate_name FROM promotion_request_certificates WHERE promotion_request_id = ?',
          [r.id]
        );

        return {
          id: r.id,
          employeeId: r.user_id,
          currentPosition: r.current_position,
          requestedPosition: r.requested_position,
          currentSalary: parseFloat(r.current_salary) || 0,
          requestedSalary: parseFloat(r.requested_salary) || 0,
          reason: r.justification,
          submittedDate: r.submitted_date,
          status: r.status,
          achievements: r.achievements ? r.achievements.split('\n').filter(Boolean) : [],
          certificates: certs.map((c) => c.certificate_name),
          skills: skills.map((s) => s.skill_name),
          hrApproval: r.hr_approved !== null
            ? {
                approved: !!r.hr_approved,
                approvedBy: r.hr_approved_by,
                approvedDate: r.hr_approved_date,
                comments: r.hr_comments,
              }
            : null,
          managerApproval: r.manager_approved !== null
            ? {
                approved: !!r.manager_approved,
                approvedBy: r.manager_approved_by,
                approvedDate: r.manager_approved_date,
                approvedPosition: r.manager_approved_position,
                approvedSalary: parseFloat(r.manager_approved_salary) || 0,
                approvedRating: parseFloat(r.manager_rating) || 0,
                comments: r.manager_comments,
              }
            : null,
          approvedPosition: r.manager_approved_position,
          approvedSalary: parseFloat(r.manager_approved_salary) || 0,
          approvedRating: parseFloat(r.manager_rating) || 0,
        };
      })
    );

    res.json({ requests: fullRequests });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch promotion requests.' });
  }
});

app.post('/api/promotion-requests', authMiddleware, async (req, res) => {
  try {
    const {
      currentPosition, requestedPosition, department,
      currentSalary, requestedSalary, justification,
      achievements, timeline, skills
    } = req.body;

    if (!requestedPosition || !justification) {
      return res.status(400).json({ message: 'Requested position and justification are required.' });
    }

    const [result] = await pool.query(
      `INSERT INTO promotion_requests
        (user_id, current_position, requested_position, department, current_salary, requested_salary, justification, achievements, timeline)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [req.userId, currentPosition || '', requestedPosition, department || null, currentSalary || 0, requestedSalary || 0, justification, achievements || '', timeline || null]
    );

    const requestId = result.insertId;

    if (Array.isArray(skills) && skills.length > 0) {
      const skillValues = skills.map((s) => [requestId, s]);
      await pool.query('INSERT INTO promotion_request_skills (promotion_request_id, skill_name) VALUES ?', [skillValues]);
    }

    res.status(201).json({ id: requestId, message: 'Promotion request submitted.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to submit promotion request.' });
  }
});

app.put('/api/promotion-requests/:id/hr-review', authMiddleware, requireRole('hr', 'admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const { comments } = req.body;

    await pool.query(
      `UPDATE promotion_requests SET
        status = 'on-hold',
        hr_approved = TRUE,
        hr_approved_by = 'HR Director',
        hr_approved_date = CURRENT_DATE,
        hr_comments = ?
       WHERE id = ? AND status = 'pending'`,
      [comments, id]
    );

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to review request.' });
  }
});

app.put('/api/promotion-requests/:id/manager-final-approve', authMiddleware, requireRole('manager', 'admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const { approvedPosition, approvedSalary, approvedRating, comments } = req.body;

    const [rows] = await pool.query('SELECT * FROM promotion_requests WHERE id = ?', [id]);
    if (rows.length === 0) return res.status(404).json({ message: 'Request not found.' });
    const request = rows[0];

    await pool.query(
      `UPDATE promotion_requests SET
        status = 'approved',
        manager_approved = TRUE,
        manager_approved_by = 'Manager',
        manager_approved_date = CURRENT_DATE,
        manager_approved_position = ?,
        manager_approved_salary = ?,
        manager_rating = ?,
        manager_comments = ?
       WHERE id = ? AND status = 'on-hold'`,
      [approvedPosition, approvedSalary, approvedRating, comments, id]
    );

    await pool.query(
      `UPDATE users SET position = ?, current_salary = ?, performance_rating = ? WHERE id = ?`,
      [approvedPosition, approvedSalary, approvedRating, request.user_id]
    );

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to finalize approval.' });
  }
});

app.put('/api/promotion-requests/:id/reject', authMiddleware, requireRole('hr', 'manager', 'admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const { comments } = req.body;
    const [userRows] = await pool.query('SELECT role FROM users WHERE id = ?', [req.userId]);
    const rejectorRole = userRows[0]?.role;

    if (rejectorRole === 'hr') {
      await pool.query(
        `UPDATE promotion_requests SET status = 'rejected', hr_approved = FALSE, hr_approved_by = 'HR Director', hr_approved_date = CURRENT_DATE, hr_comments = ? WHERE id = ?`,
        [comments || null, id]
      );
    } else {
      await pool.query(
        `UPDATE promotion_requests SET status = 'rejected', manager_approved = FALSE, manager_approved_by = 'Manager', manager_approved_date = CURRENT_DATE, manager_comments = ? WHERE id = ?`,
        [comments || null, id]
      );
    }

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to reject request.' });
  }
});

// ===================== FORMATIONS =====================

app.get('/api/formations', authMiddleware, async (req, res) => {
  try {
    const [formations] = await pool.query('SELECT * FROM formations ORDER BY created_at DESC');
    const full = await Promise.all(
      formations.map(async (f) => {
        const [skills] = await pool.query('SELECT skill_name FROM formation_skills WHERE formation_id = ?', [f.id]);
        return {
          id: f.id,
          title: f.title,
          description: f.description,
          duration: f.duration,
          instructor: f.instructor,
          level: f.level,
          category: f.category,
          available: !!f.available,
          iconUrl: f.icon_url,
          skills: skills.map((s) => s.skill_name),
        };
      })
    );
    res.json({ formations: full });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch formations.' });
  }
});

app.post('/api/formations', authMiddleware, requireRole('manager', 'hr', 'admin'), async (req, res) => {
  try {
    const { title, description, duration, instructor, level, category, iconUrl, skills } = req.body;
    if (!title) return res.status(400).json({ message: 'Title is required.' });

    const [result] = await pool.query(
      `INSERT INTO formations (title, description, duration, instructor, level, category, icon_url)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [title, description || '', duration || '', instructor || '', level || 'Intermédiaire', category || '', iconUrl || null]
    );

    const formationId = result.insertId;
    if (Array.isArray(skills) && skills.length > 0) {
      const values = skills.map((s) => [formationId, s]);
      await pool.query('INSERT INTO formation_skills (formation_id, skill_name) VALUES ?', [values]);
    }

    res.status(201).json({ id: formationId, message: 'Formation created.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to create formation.' });
  }
});

app.post('/api/formations/:formationId/assign', authMiddleware, requireRole('manager', 'hr', 'admin'), async (req, res) => {
  try {
    const { formationId } = req.params;
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ message: 'userId is required.' });

    const [existing] = await pool.query(
      'SELECT id FROM user_formation_progress WHERE user_id = ? AND formation_id = ?',
      [userId, formationId]
    );
    if (existing.length > 0) {
      return res.status(409).json({ message: 'This employee is already assigned to this formation.' });
    }

    await pool.query(
      `INSERT INTO user_formation_progress (user_id, formation_id, status, progress, started_at)
       VALUES (?, ?, 'En cours', 0, CURRENT_DATE)`,
      [userId, formationId]
    );

    res.status(201).json({ message: 'Formation assigned successfully.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to assign formation.' });
  }
});

app.get('/api/my-formations', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT ufp.*, f.title, f.description, f.duration, f.instructor, f.level, f.icon_url
       FROM user_formation_progress ufp
       JOIN formations f ON f.id = ufp.formation_id
       WHERE ufp.user_id = ?`,
      [req.userId]
    );
    const myFormations = rows.map((r) => ({
      id: r.id,
      formationId: r.formation_id,
      title: r.title,
      description: r.description,
      duration: r.duration,
      instructor: r.instructor,
      level: r.level,
      iconUrl: r.icon_url,
      status: r.status,
      progress: r.progress,
      startedAt: r.started_at,
    }));
    res.json({ formations: myFormations });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch your formations.' });
  }
});

app.put('/api/my-formations/:id/progress', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { progress } = req.body;
    const status = progress >= 100 ? 'Terminée' : 'En cours';

    await pool.query(
      'UPDATE user_formation_progress SET progress = ?, status = ? WHERE id = ? AND user_id = ?',
      [progress, status, id, req.userId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to update progress.' });
  }
});

// ===================== FORMATION ENROLLMENT REQUESTS (HR reviews first, Manager confirms) =====================

app.post('/api/formation-requests', authMiddleware, async (req, res) => {
  try {
    const { formationId, motivation } = req.body;
    if (!formationId || !motivation?.trim()) {
      return res.status(400).json({ message: 'Formation and motivation are required.' });
    }

    const [result] = await pool.query(
      `INSERT INTO formation_requests (formation_id, user_id, motivation, status)
       VALUES (?, ?, ?, 'pending')`,
      [formationId, req.userId, motivation.trim()]
    );

    res.status(201).json({ id: result.insertId, message: 'Request submitted.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to submit request.' });
  }
});

app.get('/api/formation-requests', authMiddleware, requireRole('manager', 'hr', 'admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT fr.*, f.title AS formation_title, u.first_name, u.last_name, u.profile_photo
       FROM formation_requests fr
       JOIN formations f ON f.id = fr.formation_id
       JOIN users u ON u.id = fr.user_id
       ORDER BY fr.requested_at DESC`
    );
    const requests = rows.map((r) => ({
      id: r.id,
      formationId: r.formation_id,
      formationTitle: r.formation_title,
      userId: r.user_id,
      employeeName: `${r.first_name} ${r.last_name}`,
      employeeAvatar: r.profile_photo,
      motivation: r.motivation,
      status: r.status,
      requestedAt: r.requested_at,
    }));
    res.json({ requests });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch formation requests.' });
  }
});

app.put('/api/formation-requests/:id/hr-review', authMiddleware, requireRole('hr', 'admin'), async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query(
      `UPDATE formation_requests SET status = 'on-hold' WHERE id = ? AND status = 'pending'`,
      [id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to review request.' });
  }
});

app.put('/api/formation-requests/:id/manager-confirm', authMiddleware, requireRole('manager', 'admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await pool.query('SELECT * FROM formation_requests WHERE id = ? AND status = ?', [id, 'on-hold']);
    if (rows.length === 0) return res.status(404).json({ message: 'Request not found or not ready for confirmation.' });
    const request = rows[0];

    await pool.query(`UPDATE formation_requests SET status = 'approved' WHERE id = ?`, [id]);

    const [existing] = await pool.query(
      'SELECT id FROM user_formation_progress WHERE user_id = ? AND formation_id = ?',
      [request.user_id, request.formation_id]
    );
    if (existing.length === 0) {
      await pool.query(
        `INSERT INTO user_formation_progress (user_id, formation_id, status, progress, started_at)
         VALUES (?, ?, 'En cours', 0, CURRENT_DATE)`,
        [request.user_id, request.formation_id]
      );
    }

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to confirm request.' });
  }
});

app.put('/api/formation-requests/:id/reject', authMiddleware, requireRole('manager', 'hr', 'admin'), async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query(`UPDATE formation_requests SET status = 'rejected' WHERE id = ?`, [id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to reject request.' });
  }
});

// Always return JSON on error, never HTML
app.use((err, req, res, next) => {
  console.error(err);
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ message: 'Image is too large. Please use a smaller photo.' });
  }
  res.status(500).json({ message: 'Something went wrong on the server.' });
});

app.listen(process.env.PORT, () => {
  console.log(`CareerHive API running on port ${process.env.PORT}`);
});