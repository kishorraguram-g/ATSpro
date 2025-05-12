// errorController.js

exports.default=handleJWTError = (res) => {
    return res.status(400).json({
        status: 'fail',
        message: "Invalid token. Please log in again!",
    });
};

exports.default=handleJWTExpiredError = (res) => {
    return res.status(400).json({
        status: 'fail',
        message: "Your token has expired! Please log in again.",
    });
}


module.exports = {
    handleJWTError,
    handleJWTExpiredError
}

