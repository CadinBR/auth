const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

app.use(express.json());

const PORT = 3000;


// BANCO SIMULADO

let usuarios = [];


// INICIAR SERVIDOR

async function iniciar() {

    const senhaHash = await bcrypt.hash("123456", 10);

    usuarios.push({
        id: 1,
        nome: "Ricardo",
        email: "ricardo@email.com",
        senha: senhaHash
    });

    app.listen(PORT, () => {
        console.log(`Servidor rodando na porta ${PORT}`);
    });
}

//ROTA TESTE
app.get("/", (req, res) => {
    res.json({
        mensagem: "Servidor funcionando!"
    });
});

// =====================================
// LOGIN
// =====================================

app.post("/auth/login", async (req, res) => {

    const { email, senha } = req.body;

    const usuario = usuarios.find(
        usuario => usuario.email === email
    );

    if (!usuario) {
        return res.status(401).json({
            mensagem: "Email ou senha inválidos"
        });
    }

    const senhaValida = await bcrypt.compare(
        senha,
        usuario.senha
    );

    if (!senhaValida) {
        return res.status(401).json({
            mensagem: "Email ou senha inválidos"
        });
    }

    const token = jwt.sign(
        {
            id: usuario.id,
            email: usuario.email
        },
        process.env.JWT_SECRET,
        {
            expiresIn: "1h"
        }
    );

    return res.json({
        mensagem: "Login realizado com sucesso",
        token
    });
});


// =====================================
// MIDDLEWARE
// =====================================

function authMiddleware(req, res, next) {

    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({
            mensagem: "Token não informado"
        });
    }

    const token = authHeader.split(" ")[1];

    try {

        const usuario = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        req.usuario = usuario;

        next();

    } catch (error) {

        return res.status(401).json({
            mensagem: "Token inválido ou expirado"
        });
    }
}


// =====================================
// ROTA PROTEGIDA
// =====================================

app.get("/usuario/perfil", authMiddleware, (req, res) => {

    res.json({
        mensagem: "Você está autenticado!",
        usuario: req.usuario
    });

});


// =====================================
// EXECUTAR
// =====================================

iniciar();