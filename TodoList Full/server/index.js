const express = require('express')
const mongoose = require('mongoose')
const cors = require('cors')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const {todoModel} = require('./model/schema')
const {loginModel} = require('./model/edschema')

const SECRETKEY = 'KEYKEY'
let app = express()
let port = 3100;
app.use(express.json())

app.use(cors())

// 
let middlewarePoints=['/todo','/todoget/:email','/todoupd/:id','/tododlt/:id']

const mongoconnect = async()=>{
    try {
        let connection = mongoose.connect("mongodb+srv://Jegan:%40Jegan123@cluster0.lhjs2jt.mongodb.net/",{
            useNewUrlParser:true,
            useUnifiedTopology:true
        })
        console.log("Mongo db successfully connected", (await connection).Connection.host)
    } catch (error) {
        console.log(error);
    }   
}
mongoconnect()


// Middleware
let middlewares = (req,res,next)=>{
    try {
        let {authorization} = req.headers
        if(authorization){
            jwt.verify(authorization.split(' ')[1], SECRETKEY,(error)=>{
                if(error){
                    res.status(401).send({message:error, statusCode:401})
                    return 
                }
                next()
            })
        } else{
            res.status(401).send({message:"Unauthroized",statusCode:401})
            return
        }
        
    } catch (error) {
        console.log("From middleware : ",error)
    }
}

app.use(middlewarePoints,middlewares)



// Input data
app.post('/todo',async (req,res)=>{
    try {
        let {email, Todo} = req.body
        let todo = new todoModel({email, Todo})
        let response = await todo.save()
        res.status(200).send({data:response, message:"Success",statusCode:200})
        // console.log('saved');
    } catch (error) {
        console.log("Todo Post : ",error)
        if(error.code === 11000){
            res.status(400).send({ message: "Email already exists", statusCode: 400 });
        } else {
            res.status(500).send({message:"Message not send",statusCode:500})
        }
    }
})


// Get data
app.get('/todoget/:email',async(req,res)=>{
    try {
        let email = req.params.email
        const todo = await todoModel.find({email});
        res.status(200).send({data:todo, message:"success", statusCode : 200})
    } catch (error) {
        console.log(error)
        res.status(500).send({message : "Message can't see", statusCode:500})
    }
})

// Update data
app.put('/todoupd/:id', async(req,res)=>{
    try {
        let param = req.params.id;
        let body = req.body;
        let result = await todoModel.findByIdAndUpdate(param, {Todo:body.Todo}, {new:true})
        res.send({data:result, message:'success', statucCode:200}).status(200)
    } catch (error) {
        console.log(error)
        res.status(500).send({message:"Message can't update", statusCode:500})
    }
})

// Delete data  
app.delete('/tododlt/:id', async(req,res)=>{
    try {
        // let body = req.body
        let param = req.params.id
        let result = await todoModel.findByIdAndDelete(param)
        res.send({data:result, message:"Successfully deleted", statusCode:200}).status(200)
    } catch (error) {
        console.log(error)
        res.status(500).send({message:"Can't delete",statusCode:500})
        
    }
})







// Signup
app.post('/mongoencrypt', async(req,res)=>{
    try {
        let {name,email, password} = req.body
        let salt = await bcrypt.genSalt(10)
        let change = await bcrypt.hash(password,salt)
        let login = new loginModel({name:name,email:email, password:change})
        let response = await login.save()

        // Generate jwt token
        const token = jwt.sign({email},SECRETKEY,{expiresIn:'1h'})

        res.send({encrypt:response,token:token,statusCode:200, message:"Sign Up successful"}).status(200)
    } catch (error) {
        console.log(error)
        res.status(500).send({message:"Can't delete",statusCode:500})
    }
})


// Signin
app.post('/mongodecrypt', async (req,res)=>{
    try {
        let {name, email,password} = req.body
        let getData = await loginModel.find({name:name, email:email})
        if (!getData){
            return res.status(200).send({message:"User Not Found", statusCode:400})
        }
        let compare = await bcrypt.compare(password, getData[0].password)

        // Generate jwt token
        const token = jwt.sign({email:email},SECRETKEY,{expiresIn:'1h'})

        res.send({compare, token:token,statusCode:200, message:"Sign In successful"}).status(200)
    } catch (error) {
        console.log(error)
        res.status(500).send({message:"Can't getdata",statusCode:500})
    }
})


// Forgot password
app.get('/bcryptget/:id', async (req,res) =>{
    try {
        const findData = await loginModel.findOne({email:req.params.id})
        if (!findData) {
            return res.status(200).send({ message: "Email not found", statusCode: 404 });
        }
        res.status(200).send({data:findData, message:"Success", statusCode:200})

    } catch (error) {
        console.log(error)
        res.status(500).send({message : "Message can't see", statusCode:500})
    }
})


// Change password
app.put('/bcryptput/:id', async(req,res)=>{
    try {
        const {password} = req.body
        let param = req.params.id
        let salt = await bcrypt.genSalt(10)
        let change = await bcrypt.hash(password, salt)
        let result = await loginModel.findOneAndUpdate({_id:param},{password:change},{new:true})
        res.send({data:result, statusCode:200, message:'Success'}).status(200)
    } catch (error) {
        console.log("Bcrypt Put : ",error)
        res.status(500).send({message : "Message can't see", statusCode:500})
        
    }
})



app.listen(port, ()=>{
    console.log(`Server running at ${port}`);
})