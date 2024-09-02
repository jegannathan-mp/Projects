const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const env = require('dotenv').config;

const JWT_SECRET = "26813f71dc2eceb164b7d74c922d1794e065d266a7a94d94b6e607ae16f53860";
const port = 3000;



const app = express();
app.use(express.json());

const users = [];



app.post('/register', async (req,res)=>{
    const {username, password} = req.body;
    const hashpassword = await bcrypt.hash(password,10);
    users.push({username:username,password:hashpassword});
    res.status(200).json({message:"Success"})
})

app.post('/login', async (req,res)=>{
    const {username, password} = req.body;
    const user = users.find(u=>u.username===username);
    if(!user){
        return res.status(400).json({message : "User Does not exist"});
    }

    const isPassword = await bcrypt.compare(password,user.password);
    if(!isPassword){
        return res.status(400).json({message:"Password invalid"});
    }

    const token = jwt.sign({username:user.username},JWT_SECRET, {expiresIn:'1h'});
    res.json({token});
})


app.get('/secured', async (req,res)=>{
    const authHeader = req.headers.authorization;
    console.log(req.headers);
    
    if(!authHeader){
        return res.status(405).json({message : "Authentication header missing"});
    }
    const token = authHeader.split(' ')[1];
    try {
        const decode = jwt.verify(token, JWT_SECRET)
        res.json({message:`Welcome ${decode.username}`});
    } catch (error) {
        res.status(404).json({message:"Token expired"});
    }
})


app.listen(port,()=>{
    console.log("Server is running at "+port);
})