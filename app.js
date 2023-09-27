require('dotenv').config()
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

//Json response
app.use(express.json());

//Models
const User = require('./models/User');

//Rota pública
app.get('/', (req, res) => {
    res.status(200).json({msg: 'Bem vindo a api' })
})

//Rota Privada
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id;
    
    const user = await User.findById(id, '-password');

    if(!user){
        return res.status(404).json({msg: 'Usuário não encontrado'})
    }

    res.status(200).json({ user })
})

//Checar token

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.spli(" ") [1]

    if(!token){
        return res.status(401).json({msg: 'Acesso negado'})
    }

    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()

    } catch (error) {
        res.status(400).json({msg: "Token invalido"})
    }
}

//Registro
app.post('/auth/register', async (req, res) => {

    const{name, email, password, confirmpassword} = req.body;
    
    //validações
    if(!name) {
        return res.status(422).json({msg: 'O nome é obrigatório'})
    }
    if(!email) {
        return res.status(422).json({msg: 'O email é obrigatório'})
    }
    if(!password) {
        return res.status(422).json({msg: 'A senha é obrigatória'})
    }
    if(password !== confirmpassword) {
        return res.status(422).json({msg: 'As senhas não são iguais'})
    }


//Checar se usuário existe
 const userExists = await User.findOne ({email: email})

 if(userExists) {
    return res.status(422).json({msg: 'Email já utilizado, recupere sua senha!'})
 }

 //Criar Password
 const salt = await bcrypt.genSalt(12)
 const passwordHash = await bcrypt.hash(password, salt)

 //Criar Usuario
 const user = new User({
    name,
    password: passwordHash,
    email,
 })

 try {
    await user.save()

    res.status(201).json({msg: 'Usuário criado com sucesso'})
    
 } catch (error) {
    console.log(error)

    res.status(500).json({msg: "Erro no servidor, tente novamente!"})
 }
})

//Login
app.post("/auth/login", async (req, res) => {
    const {email, password} = req.body

    //validate
    if(!email) {
        return res.status(422).json({msg: 'O email é obrigatório'})
    }
    if(!password) {
        return res.status(422).json({msg: 'A senha é obrigatória'})
    }

    //Checar se usuário existe
 const user = await User.findOne ({email: email})

 if(!user) {
    return res.status(422).json({msg: 'Usuário não encontrado'})
 }

 //checar password
 const checkPassword = await bcrypt.compare(password, user.password)

 if(!checkPassword) {
    return res.status(422).json({msg:'Senha está inválida'})
 }

 try {
    const secret = process.env.SECRET

    const token = jwt.sign({
        id: user.id,

    },
    secret,
    )

    res.status(200).json({msg: 'Usuário logado com sucesso', token})
    
 } catch (error) {
    console.log(error)

    res.status(500).json({msg: "Erro no servidor, tente novamente!"})
 }
})

//Credenciais
const dbUser = process.env.DB_USER
const dbPassorwd = process.env.DB_PASS
mongoose.connect(
    `mongodb+srv://${dbUser}:${dbPassorwd}@cluster0.z1he7zj.mongodb.net/?retryWrites=true&w=majority`)
.then(() => {
    app.listen(3000);
    console.log('Banco conectado')
})
.catch((error) => console.log(error));