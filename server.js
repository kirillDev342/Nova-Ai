const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, './')));

// База данных
const db = new sqlite3.Database('./database.sqlite');

// Создаем таблицы
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

// Регистрация
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
            [name, email, hashedPassword],
            function(err) {
                if (err) {
                    res.status(400).json({ error: 'Email уже используется' });
                    return;
                }
                res.json({ success: true, message: 'Регистрация успешна!' });
            });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Вход
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (!user) {
            res.status(401).json({ error: 'Неверный email или пароль' });
            return;
        }
        
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            res.status(401).json({ error: 'Неверный email или пароль' });
            return;
        }
        
        res.json({ 
            success: true, 
            user: { name: user.name, email: user.email }
        });
    });
});

app.listen(PORT, () => {
    console.log(`🚀 NOVA AI работает на http://localhost:${PORT}`);
});