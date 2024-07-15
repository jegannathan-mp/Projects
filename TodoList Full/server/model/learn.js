const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
    email:String,
    password:String,
    restPasswordToken:String,
    restPasswordExpires:Date,
});

const User = mongoose.model("User",userSchema)

module.exports = User;