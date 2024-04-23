// connection.js

const mongoose = require("mongoose");

mongoose.connect("mongodb://127.0.0.1:27017/IDE", {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log("Connection to MongoDB is successful");
}).catch((error) => {
    console.error("Error connecting to MongoDB:", error);
});

module.exports = mongoose.connection;
