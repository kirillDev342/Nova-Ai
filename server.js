const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

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

// РЕГИСТРАЦИЯ
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Все поля обязательны' });
    }
    
    try {
        // Проверяем существует ли пользователь
        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
            if (user) {
                return res.status(400).json({ error: 'Email уже используется' });
            }
            
            // Хешируем пароль
            const hashedPassword = await bcrypt.hash(password, 10);
            
            // Сохраняем в базу
            db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
                [name, email, hashedPassword],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: 'Ошибка базы данных' });
                    }
                    
                    res.json({ 
                        success: true, 
                        user: { 
                            id: this.lastID, 
                            name, 
                            email 
                        }
                    });
                });
        });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ВХОД
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email и пароль обязательны' });
    }
    
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка базы данных' });
        }
        
        if (!user) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }
        
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }
        
        res.json({ 
            success: true, 
            user: { 
                id: user.id, 
                name: user.name, 
                email: user.email 
            }
        });
    });
});

app.listen(PORT, () => {
    console.log(`🚀 NOVA AI работает на http://localhost:${PORT}`);
});
