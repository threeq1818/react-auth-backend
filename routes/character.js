// chracter.js

const express = require('express');
const router = express.Router();

const validateCharacterInput = require('../validation/character');
const Character = require('../models/Character');

router.get('/id/:id', function (req, res) {
    if (!req.user)
        return res.status(401).json({ message: "not auth" });

    const id = req.params.id;
    Character.findById(id)
        .then(character => {
            res.json(character);
        })
        .catch(err => {
            res.status(400).json(err);
        })
});

router.get('/all', function (req, res) {
    if (!req.user)
        return res.status(401).json({ message: "not auth" });
    Character.find({})
        .then(characters => {
            res.json(characters);
        })
        .catch(err => {
            res.status(400).json(err);
        })
})

router.post('/', function (req, res) {
    if (!req.user)
        return res.status(401).json({ message: "not auth" });

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
    if (!req.user)
        return res.status(401).json({ message: "not auth" });

    const id = req.params.id;

    Character.deleteOne({ _id: id })
        .then(() => {
            res.json({ _id: id });
        })
        .catch(errors => {
            res.status(400).json(errors);
        });
});

module.exports = router;