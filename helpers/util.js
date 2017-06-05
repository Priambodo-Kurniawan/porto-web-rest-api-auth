require('dotenv').config();
const secret = process.env.TOKEN_SECRET;
var jwt = require('jsonwebtoken')
var methods = {}

methods.userInfo = (token, callback) => {
  if(token){
    jwt.verify(token, secret, (err, decoded) => {
      if(decoded){
        callback(decoded)
      } else {
        return 'No Information'
      }
    })
  } else {
    return 'No Access'
  }
}

module.exports = methods
