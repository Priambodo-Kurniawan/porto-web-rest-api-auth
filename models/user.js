var mongoose = require('mongoose');
var Schema = mongoose.Schema;
const validator = require('validator');

var userSchema = new Schema({
  username: {
    type: String,
    unique: [true, 'username is already used'],
    required: [true, 'Please enter your name.'],
    minlength: [3, 'Username must be at least 3 letters long.']
  },
  password: {
    type: String,
    required: [true, 'Please enter your password.']
  },
  email: {
    type: String,
    unique: [true, 'email is already used'],
    required: [true, 'Please enter your email.'],
    validate: {
      validator: function(value) {
        return validator.isEmail(value)
      },
      message: '{VALUE} is not a valid email.'
    }
  }
})

var User = mongoose.model('User', userSchema);

module.exports = User;
