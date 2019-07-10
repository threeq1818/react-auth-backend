// chracter.js

const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const passport = require('passport');

const validateCharacterInput = require('../validation/character');
const Character = require('../models/Character');

router.post('/', function (req, res) {
    const { errors, isValid } = validateCharacterInput(req.body);

    if (!isValid) {
        return res.status(400).json(errors);
    }

    const newCharacter = new Character({
        name: req.body.name,
        job: req.body.job
    });

    newCharacter.save()
        .then(character => {
            res.json(character);
        });
});

router.delete('/:id', function (req, res) {
    const id = req.params.id;

}

module.exports = router;