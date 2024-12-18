const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');

const app = express();
const PORT = 5000;
const SECRET_KEY = "your_secret_key";
const DB_FILE = './db.json';

app.use(cors());
app.use(bodyParser.json());

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

// 1. Register
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const db = readDB();

  if (db.users.find(user => user.email === email)) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: Date.now(), email, password: hashedPassword };
  db.users.push(newUser);
  writeDB(db);

  res.status(201).json({ message: 'User registered successfully' });
});

// 2. Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const db = readDB();
  const user = db.users.find(user => user.email === email);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: 'Invalid email or password' });
  }

  const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});

// 3. Get User Data (Protected)
app.get('/user', (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const db = readDB();
    const user = db.users.find(u => u.id === decoded.id);
    if (!user) throw new Error();
    res.json(user);
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
});

// 4. Get All Posts
app.get('/posts', (req, res) => {
  const db = readDB();
  res.json(db.posts); // Returns posts as an object
});

// 5. Create a Post
app.post('/posts', (req, res) => {
  const db = readDB();
  const id = Date.now().toString(); // Unique ID as a string
  const newPost = { id, ...req.body };

  db.posts[id] = newPost; // Add to posts object
  writeDB(db);

  res.status(201).json(newPost);
});

// 6. Update a Post
app.put('/posts/:id', (req, res) => {
  const { id } = req.params;
  const db = readDB();

  if (!db.posts[id]) {
    return res.status(404).json({ message: 'Post not found' });
  }

  db.posts[id] = { ...db.posts[id], ...req.body }; // Update post
  writeDB(db);

  res.json(db.posts[id]);
});

// 7. Delete a Post
app.delete('/posts/:id', (req, res) => {
  const { id } = req.params;
  const db = readDB();

  if (!db.posts[id]) {
    return res.status(404).json({ message: 'Post not found' });
  }

  const deletedPost = db.posts[id];
  delete db.posts[id]; // Remove post from object
  writeDB(db);

  res.json(deletedPost);
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
