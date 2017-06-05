var express = require('express');
var router = express.Router();
var memo = require('../controllers/memoController')

router.get('/', memo.getAll);

router.get('/memo', memo.get);

// create new memo
router.post('/create', memo.create)

// get memo by id
router.get('/:id', memo.getOne)

// update memo
router.put('/:id', memo.update)

// delete memo
router.delete('/:id', memo.delete)



module.exports = router;
