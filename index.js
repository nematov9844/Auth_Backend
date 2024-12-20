const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const dotenv = require('dotenv');
const morgan = require('morgan');
const helmet = require('helmet');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.SECRET_KEY;
const DB_FILE = './db.json';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(morgan('dev'));
app.use(helmet());

// Helper functions
const readDB = () => JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
const writeDB = (data) => fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));

// Initialize DB if not exists
const initializeDB = () => {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], posts: {} }, null, 2));
    console.log('db.json created');
  }
};
initializeDB();

// Middleware for token authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded; // Store decoded user info in request
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token.' });
  }
};

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({ message: err.message || 'Internal server error' });
});

// 1. Register
app.post('/register', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const db = readDB();

    if (db.users.find(user => user.email === email)) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { id: Date.now(), email, password: hashedPassword };
    db.users.push(newUser);
    writeDB(db);

    const token = jwt.sign({ id: newUser.id, email: newUser.email }, SECRET_KEY, { expiresIn: '1h' });

    res.status(201).json({
      message: 'User registered successfully',
      token,
    });
  } catch (err) {
    next(err);
  }
});

// 2. Login
app.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const db = readDB();
    const user = db.users.find(user => user.email === email);

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    next(err);
  }
});

// 3. Get User Data (Protected)
app.get('/user', authenticateToken, (req, res, next) => {
  try {
    const db = readDB();
    const user = db.users.find(u => u.id === req.user.id);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ id: user.id, email: user.email });
  } catch (err) {
    next(err);
  }
});

// 4. Get All Posts with Pagination
app.get('/posts', (req, res, next) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const db = readDB();
    const postsArray = Object.values(db.posts);

    const start = (page - 1) * limit;
    const end = start + parseInt(limit);

    res.json({
      page: parseInt(page),
      limit: parseInt(limit),
      total: postsArray.length,
      data: postsArray.slice(start, end),
    });
  } catch (err) {
    next(err);
  }
});

// 5. Create a Post (Protected)
app.post('/posts', authenticateToken, (req, res, next) => {
  try {
    const db = readDB();
    const id = Date.now().toString(); // Unique ID as a string
    const newPost = { id, userId: req.user.id, ...req.body };

    db.posts[id] = newPost;
    writeDB(db);

    res.status(201).json(newPost);
  } catch (err) {
    next(err);
  }
});

// 6. Update a Post (Protected)
app.patch('/posts/:id', authenticateToken, (req, res, next) => {
  try {
    const { id } = req.params;
    const db = readDB();

    if (!db.posts[id]) {
      return res.status(404).json({ message: 'Post not found' });
    }

    if (db.posts[id].userId !== req.user.id) {
      return res.status(403).json({ message: 'Access denied.' });
    }

    db.posts[id] = { ...db.posts[id], ...req.body };
    writeDB(db);

    res.json(db.posts[id]);
  } catch (err) {
    next(err);
  }
});

// 7. Delete a Post (Protected)
app.delete('/posts/:id', authenticateToken, (req, res, next) => {
  try {
    const { id } = req.params;
    const db = readDB();

    if (!db.posts[id]) {
      return res.status(404).json({ message: 'Post not found' });
    }

    if (db.posts[id].userId !== req.user.id) {
      return res.status(403).json({ message: 'Access denied.' });
    }

    const deletedPost = db.posts[id];
    delete db.posts[id];
    writeDB(db);

    res.json({ message: 'Post deleted successfully', deletedPost });
  } catch (err) {
    next(err);
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
