const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = 3000;

app.use(bodyParser.json());
app.use(cors());

const SECRET_KEY = "codelab_secret_key_123";
const TOKEN_EXPIRATION = "30m";

// Simulação de banco de dados
const fakeUsersDB = {
    user1: {
        username: "user1",
        full_name: "User One",
        email: "user1@example.com",
        password: "password", // Senha original (não hashada)
        hashed_password: "", // Vamos gerar o hash
        disabled: false
    }
};

// Função para gerar o hash da senha e armazená-lo
const generatePasswordHash = async () => {
    const saltRounds = 12;
    for (const user in fakeUsersDB) {
        if (fakeUsersDB[user].password) {
            const hashedPassword = await bcrypt.hash(fakeUsersDB[user].password, saltRounds);
            fakeUsersDB[user].hashed_password = hashedPassword;
            console.log(`Hash gerado para ${user}: ${hashedPassword}`);
        }
    }
};

generatePasswordHash(); // Gerar o hash da senha de todos os usuários na inicialização

// Função para verificar a senha
const verifyPassword = async (plainPassword, hashedPassword) => {
    return await bcrypt.compare(plainPassword, hashedPassword);
};

// Função para autenticar o usuário
const authenticateUser = async (username, password) => {
    const user = fakeUsersDB[username];
    if (!user || !(await verifyPassword(password, user.hashed_password))) {
        return null;
    }
    return user;
};

// Função para criar o token JWT
const createAccessToken = (data) => {
    return jwt.sign(data, SECRET_KEY, { expiresIn: TOKEN_EXPIRATION });
};

// Rota de login para gerar o token
app.post("/token", async (req, res) => {
    const { username, password } = req.body;
    const user = await authenticateUser(username, password);
    if (!user) {
        return res.status(401).json({ detail: "Incorrect username or password" });
    }
    const accessToken = createAccessToken({ sub: user.username });
    res.json({ access_token: accessToken, token_type: "bearer" });
});

// Middleware para autenticação do token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) {
        return res.status(401).json({ detail: "Token not provided" });
    }
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ detail: "Invalid token" });
        }
        req.user = user;
        next();
    });
};

// Rota para acessar informações do usuário logado
app.get("/users/me", authenticateToken, (req, res) => {
    const user = fakeUsersDB[req.user.sub];
    if (!user) {
        return res.status(404).json({ detail: "User not found" });
    }
    res.json(user);
});

// Iniciar o servidor
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
