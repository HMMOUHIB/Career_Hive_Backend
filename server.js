require('dotenv').config();
console.log('CLIENT_ID length:', process.env.GOOGLE_CLIENT_ID?.length);
console.log('CLIENT_ID:', JSON.stringify(process.env.GOOGLE_CLIENT_ID));
console.log('CLIENT_SECRET length:', process.env.GOOGLE_CLIENT_SECRET?.length);
console.log('CLIENT_SECRET:', JSON.stringify(process.env.GOOGLE_CLIENT_SECRET));
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
    `INSERT INTO users (first_name, last_name, email, profile_photo, oauth_provider, oauth_id)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [firstName, lastName, email, photo, provider, oauthId]
  );
  const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [result.insertId]);
  return rows[0];
};

passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:5000/api/auth/google/callback',
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
    const { name, email, password } = req.body;
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
    const [result] = await pool.query(
      'INSERT INTO users (first_name, last_name, email, password_hash) VALUES (?, ?, ?, ?)',
      [firstName, lastName, email, passwordHash]
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

app.get('/api/auth/google/callback', (req, res, next) => {
  passport.authenticate('google', { session: false }, (err, user, info) => {
    if (err) {
      console.log('=== FULL OAUTH ERROR DUMP ===');
      console.log('Error message:', err.message);
      console.log('OAuth error body:', err.oauthError?.data || err.oauthError);
      console.log('Full error object:', JSON.stringify(err, Object.getOwnPropertyNames(err)));
      return res.status(500).json({ message: 'OAuth failed', details: err.message });
    }
    if (!user) {
      return res.status(401).json({ message: 'No user returned', info });
    }
    const userResponse = toUserResponse(user);
    const token = jwt.sign({ id: userResponse.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.redirect(`${process.env.FRONTEND_URL}/oauth-success?token=${token}&user=${encodeURIComponent(JSON.stringify(userResponse))}`);
  })(req, res, next);
});

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

app.post('/api/teams', authMiddleware, async (req, res) => {
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

app.post('/api/teams/:teamId/members', authMiddleware, async (req, res) => {
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

app.put('/api/teams/members/:memberId/feedback', authMiddleware, async (req, res) => {
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