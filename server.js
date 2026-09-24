const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

app.use(express.json());

const PORT = 3000;


// BANCO 
const mysql = require("mysql2/promise");

const db = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "",
    database: "auth"
});


// INICIAR SERVIDOR

async function iniciar() {
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

// LOGIN

app.post("/auth/login", async (req, res) => {

    const { email, senha } = req.body;

    try {

        // Buscar usuário no banco
        const [usuarios] = await db.execute(
            "SELECT * FROM usuarios WHERE email = ?",
            [email]
        );

        // Verificar se encontrou o usuário
        if (usuarios.length === 0) {
            return res.status(401).json({
                mensagem: "Email ou senha inválidos"
            });
        }

        const usuario = usuarios[0];

        // Comparar senha informada com a senha criptografada
        const senhaValida = await bcrypt.compare(
            senha,
            usuario.senha
        );

        if (!senhaValida) {
            return res.status(401).json({
                mensagem: "Email ou senha inválidos"
            });
        }

        // Gerar novo token
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

    } catch (error) {

        console.error(error);

        return res.status(500).json({
            mensagem: "Erro interno do servidor"
        });

    }

});

// MIDDLEWARE

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


// ROTA PROTEGIDA

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