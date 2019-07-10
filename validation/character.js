// character.js

const Validator = require('validator');
const isEmpty = require('./is-empty');

module.exports = function validateCharacerInput(data) {
    let errors = {};
    data.name = !isEmpty(data.name) ? data.name : '';
    data.job = !isEmpty(data.job) ? data.job : '';

    if (Validator.isEmpty(data.name)) {
        errors.name = 'Name is required';
    }

    if (Validator.isEmpty(data.job)) {
        errors.job = 'Job is required';
    }

    return {
        errors,
        isValid: isEmpty(errors)
    }
}