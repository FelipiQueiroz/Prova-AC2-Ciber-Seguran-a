const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = 3000;

// Chave e IV para AES
const key = crypto.randomBytes(32); // 256 bits
const iv = crypto.randomBytes(16);  // 128 bits

// Funções de criptografia e descriptografia AES
function encrypt(text) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf-8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decrypt(encrypted) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');
    return decrypted;
}

// Dados na memória
const mensagens = [];

app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());
app.use(bodyParser.json());

const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

// Middleware para enviar token CSRF no cookie
app.use((req, res, next) => {
    res.cookie('csrfToken', req.csrfToken());
    next();
});

// Enviar mensagem (com criptografia)
app.post('/send', (req, res) => {
    const { from, to, message } = req.body;
    const encryptedMessage = encrypt(message);

    mensagens.push({
        from,
        to,
        encrypted: encryptedMessage
    });

    console.log(`Mensagem recebida de ${from} para ${to}`);
    console.log('Mensagem criptografada:', encryptedMessage);

    res.status(200).json({ success: true });
});

// Listar mensagens recebidas por um usuário
app.get('/messages/:user', (req, res) => {
    const user = req.params.user;
    const msgs = mensagens
        .filter(m => m.to === user)
        .map(m => ({
            from: m.from,
            to: m.to,
            encrypted: m.encrypted,
            decrypted: decrypt(m.encrypted)
        }));

    console.log(`Mensagens para ${user}:`, msgs);
    res.json(msgs);
});

app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});
