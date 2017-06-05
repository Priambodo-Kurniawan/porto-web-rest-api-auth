var Memo = require('../models/memo');
var util = require('../helpers/util');
var methods = {}

methods.getAll = (req, res) => {
  Memo.find({}, (err, memos) => {
    res.send(memos)
  })
}

methods.get = (req, res) => {
  util.userInfo(req.headers.token, function(user){
    Memo.find({creator: user.id}, (err, memos) => {
      res.send(memos)
    })
  })
}

methods.create = (req, res) => {
  var content = req.body.content;
  var tags = req.body.tags;
  if (req.headers.token) {
    util.userInfo(req.headers.token, function(user){
      Memo.create({
        content: content,
        tags: tags,
        creator: user.id
      })
      .then(response => {
        console.log(response);
        res.send('Task added')
      })
      .catch(err => console.log(err))
    })
  } else {
    res.send('Please login first')
  }
}

methods.getOne = (req, res) => {
  if(req.headers.token) {
    util.userInfo(req.headers.token, function(user) {
      Memo.find({_id: req.params.id, })
      .then(memo => {
        if(memo.creator == user._id){
          res.send(memo)
        } else {
          res.send('not authorized')
        }
        res.send(memo)
      })
      .catch(err => console.log(err))
    })
  } else {
    res.send('please login first')
  }
}

methods.update = (req, res) => {
  util.userInfo(req.headers.token, function(user) {
    Memo.findById(req.params.id)
    .then(memo =>{
      console.log(user.id);
      if(memo.creator == user.id){
        Memo.update({_id:req.params.id}, req.body)
        .then(()=>{
          res.send('memo has been updated')
        })
      } else {
        res.send('not authorized')
      }
    })
    .catch(err => console.log(err))
  })
}

methods.delete = (req, res) => {
  util.userInfo(req.headers.token, function(user){
    Memo.findById(req.params.id)
    .then(memo => {
      if(memo.creator == user.id){
        memo.remove()
        .then(()=>{
          res.send('memo has been deleted')
        })
        .catch(err => console.log(err))
      } else {
        res.send('not authorized')
      }
    })
  })
}

module.exports = methods
