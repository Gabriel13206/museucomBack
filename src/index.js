import express from "express";
import cors from "cors";
import os from 'os';
import dotenv from "dotenv";
import mysql from "mysql2/promise";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb' }));

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Middleware de autenticação
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// ===== ROTAS DE AUTENTICAÇÃO =====

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const connection = await pool.getConnection();
    
    const [users] = await connection.query('SELECT * FROM users WHERE email = ?', [email]);
    connection.release();

    if (users.length === 0) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    const user = users[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET || 'your_secret_key',
      { expiresIn: '24h' }
    );

    res.json({ token, user: { id: user.id, email: user.email, nome: user.nome } });
  } catch (error) {
    res.status(500).json({ message: 'Erro no servidor', error: error.message });
  }
});

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, nome } = req.body;
    const connection = await pool.getConnection();

    const [existingUsers] = await connection.query('SELECT * FROM users WHERE email = ?', [email]);

    if (existingUsers.length > 0) {
      connection.release();
      return res.status(400).json({ message: 'Email já registado' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await connection.query(
      'INSERT INTO users (email, password, nome) VALUES (?, ?, ?)',
      [email, hashedPassword, nome]
    );

    connection.release();
    res.status(201).json({ message: 'Utilizador registado com sucesso' });
  } catch (error) {
    res.status(500).json({ message: 'Erro no servidor', error: error.message });
  }
});

// ===== ROTAS DE MATERIAIS (COM PLACA_DESCRITIVA) =====

// GET todos os materiais
app.get('/api/materiais', authenticateToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [materiais] = await connection.query('SELECT * FROM materiais ORDER BY id DESC');
    connection.release();
    res.json(materiais);
  } catch (error) {
    res.status(500).json({ message: 'Erro ao buscar materiais', error: error.message });
  }
});

// GET material por ID
app.get('/api/materiais/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const connection = await pool.getConnection();
    const [materiais] = await connection.query('SELECT * FROM materiais WHERE id = ?', [id]);
    connection.release();

    if (materiais.length === 0) {
      return res.status(404).json({ message: 'Material não encontrado' });
    }

    res.json(materiais[0]);
  } catch (error) {
    res.status(500).json({ message: 'Erro ao buscar material', error: error.message });
  }
});

// POST - Criar novo material (COM PLACA_DESCRITIVA)
app.post('/api/materiais', authenticateToken, async (req, res) => {
  try {
    const {
      nome,
      descricao,
      categoria,
      estado,
      localizacao,
      data_aquisicao,
      numero_serie,
      modelo,
      fabricante,
      placa_descritiva // ✅ NOVO CAMPO
    } = req.body;

    const connection = await pool.getConnection();

    await connection.query(
      'INSERT INTO materiais (nome, descricao, categoria, estado, localizacao, data_aquisicao, numero_serie, modelo, fabricante, placa_descritiva, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [nome, descricao, categoria, estado, localizacao, data_aquisicao, numero_serie, modelo, fabricante, placa_descritiva, req.user.id]
    );

    connection.release();
    res.status(201).json({ message: 'Material criado com sucesso' });
  } catch (error) {
    res.status(500).json({ message: 'Erro ao criar material', error: error.message });
  }
});

// PUT - Atualizar material (COM PLACA_DESCRITIVA)
app.put('/api/materiais/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      nome,
      descricao,
      categoria,
      estado,
      localizacao,
      data_aquisicao,
      numero_serie,
      modelo,
      fabricante,
      placa_descritiva // ✅ NOVO CAMPO
    } = req.body;

    const connection = await pool.getConnection();

    await connection.query(
      'UPDATE materiais SET nome = ?, descricao = ?, categoria = ?, estado = ?, localizacao = ?, data_aquisicao = ?, numero_serie = ?, modelo = ?, fabricante = ?, placa_descritiva = ? WHERE id = ?',
      [nome, descricao, categoria, estado, localizacao, data_aquisicao, numero_serie, modelo, fabricante, placa_descritiva, id]
    );

    connection.release();
    res.json({ message: 'Material atualizado com sucesso' });
  } catch (error) {
    res.status(500).json({ message: 'Erro ao atualizar material', error: error.message });
  }
});

// DELETE material
app.delete('/api/materiais/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const connection = await pool.getConnection();

    await connection.query('DELETE FROM materiais WHERE id = ?', [id]);
    connection.release();

    res.json({ message: 'Material eliminado com sucesso' });
  } catch (error) {
    res.status(500).json({ message: 'Erro ao eliminar material', error: error.message });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK' });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor a correr na porta ${PORT}`);
});
