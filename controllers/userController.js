require('dotenv').config();
const saltRounds = 10;

var User = require('../models/user');
var bcrypt = require('bcrypt');
var methods = {}

methods.findAll = (req, res) => {
  User.find({})
  .then((users)=>{
    res.send(users)
  })
  .catch(err => console.log(err))
}

methods.getOne = (req, res) => {
  User.find({_id: req.params.id})
  .then(user => {
    res.send(user)
  })
  .catch(err => console.log(err))
}

methods.update = (req, res) => {
  if(req.body.password){
    var salt = bcrypt.genSaltSync(saltRounds);
    var hash = bcrypt.hashSync(req.body.password, salt);
    req.body.password = hash
  }
  User.findByIdAndUpdate(req.params.id, { $set: req.body }, { runValidators: true }, (err, user) => {
    if(err) res.send(err.errors)
    res.send('Data berhasil diupdate')
  })
}

methods.remove = (req, res) => {
  User.findOneAndRemove({_id: req.params.id})
  .then (() => {
    res.send('user has been deleted')
  })
  .catch(err => console.log(err))
}

module.exports = methods
