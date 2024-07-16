const mongoose = require('mongoose')

let schema = mongoose.Schema

let login = new schema({
    name : String,
    email:{
        type:String,
        unique:true,
        required:true
    },
    password : {
        type:String, 
        required:true
    }
})

let loginModel = mongoose.model('bcrypt',login)

module.exports = {
    loginModel
}