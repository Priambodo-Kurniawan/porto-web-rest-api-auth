const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
mongoose.Promise = global.Promise;
mongoose.connect('mongodb://localhost/memo');

var app = express();
var users = require('./routes/users');
var memos = require('./routes/memos');
var index = require('./routes/index');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false}));

app.use('/api/users', users);
app.use('/api/memos', memos);
app.use('/', index);

app.listen(7000, () => {
  console.log('Listening on port 7000');
})
