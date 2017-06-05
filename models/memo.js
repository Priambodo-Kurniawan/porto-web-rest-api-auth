var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var memoSchema = new Schema ({
  content: {
    type: String,
    required: [true, 'Please enter your memo\'s content']
  },
  tags: [{
    type: String
  }],
  creator: {
    type: Schema.Types.ObjectId, ref: 'User'
  }
})

var Memo = mongoose.model('Memo', memoSchema);

module.exports = Memo;
