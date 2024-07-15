const mongoose = require('mongoose')

let schema = mongoose.Schema;

let todoForm = new schema({
    email:{
        type:String,
        unique:true
    },
    Todo : {
        type:String
    }

})

let todoModel = mongoose.model('Todo',todoForm)

module.exports = {
    todoModel
}