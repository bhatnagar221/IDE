const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const flash = require('express-flash');
const path = require("path");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const User = require("./models/user");
const mongooseConnection = require("./db/connection");
const { exec } = require('child_process');
const fs = require('fs');
const bcrypt = require('bcrypt'); // Added bcrypt dependency

const app = express();
const port = process.env.PORT || 3001;

// Secret key for session management
const secretKey = crypto.randomBytes(6).toString("hex");

// Function to compile and run C/C++ code
function compileAndRun(language, code, res) {
    let command;
    let extension;
    let compiledFilename;
  
    // Determine the compilation command and file extension based on the selected language
    if (language === 'c') {
      command = 'gcc';
      extension = 'c';
      compiledFilename = 'a.exe'; // Assuming Windows environment, adjust if needed
    } else if (language === 'cpp') {
      command = 'g++';
      extension = 'cpp';
      compiledFilename = 'a.exe'; // Assuming Windows environment, adjust if needed
    } else {
      res.status(400).send('Unsupported language');
      return;
    }
  
    // Write the code to a temporary file
    const filename = `temp.${extension}`;
    const filepath = path.join(__dirname, filename);
    fs.writeFileSync(filepath, code);
  
    // Execute the compilation command
  // Execute the compilation command
  exec(`${command} ${filename} -o ${compiledFilename}`, (error, stdout, stderr) => {
    if (error) {
      res.status(500).send(stderr);
    } else {
      // If compilation succeeded, execute the compiled program
      exec(`${compiledFilename}`, (runError, runStdout, runStderr) => {
        if (runError) {
          res.status(500).send(runStderr);
        } else {
          res.send(runStdout);
        }
  
        // Clean up temporary files after execution
        cleanupFiles(filepath, compiledFilename);
      });
    }
  });
  
  function cleanupFiles(filepath, compiledFilename) {
    // Using asynchronous functions for file operations
    fs.unlink(filepath, (err) => {
      if (err) {
        console.error('Error deleting temporary file:', err);
      } else {
        console.log('Temporary file deleted successfully:', filepath);
      }
    });
  
    fs.unlink(compiledFilename, (err) => {
      if (err) {
        console.error('Error deleting compiled file:', err);
      } else {
        console.log('Compiled file deleted successfully:', compiledFilename);
      }
    });
  }
  }
  app.post('/compile', (req, res) => {
    const { language, code } = req.body;
  
    if (language === 'python') {
      // Write the Python code to a temporary file
      const filename = path.join(__dirname, 'temp.py');
      fs.writeFileSync(filename, code);
  
      // Execute the Python code using child_process
      exec(`python ${filename}`, (error, stdout, stderr) => {
        if (error) {
          res.status(500).send(stderr);
        } else {
          res.send(stdout);
        }
        // Delete the temporary file after execution
        fs.unlinkSync(filename);
      });
    } else {
      // Call the compileAndRun function for C and C++ code
      compileAndRun(language, code, res);
    }
  });
  
  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
  });
  
// Middleware
app.use(express.static(path.join(__dirname, 'views')));
app.use(bodyParser.json());
app.use(session({
    secret: secretKey,
    resave: false,
    saveUninitialized: true,
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// Passport configuration
passport.use(new LocalStrategy({
    usernameField: "email",
    passwordField: "password",
}, async (email, password, done) => {
    try {
        const user = await User.findOne({ email });

        if (user) {
            // Replace password comparison with bcrypt comparison for enhanced security
            const passwordMatch = await bcrypt.compare(password, user.password);
            if (passwordMatch) {
                console.log(`User ${user.email} logged in successfully.`);
                return done(null, user);
            } else {
                console.log(`Login attempt failed for user ${user.email}. Incorrect password.`);
                return done(null, false, { message: "Incorrect password" });
            }
        } else {
            console.log(`Login attempt failed. User with email ${email} not found.`);
            return done(null, false, { message: "User not found" });
        }
    } catch (error) {
        console.error(`Error during login: ${error}`);
        return done(error);
    }
}));
passport.serializeUser((user, done) => {
    done(null, user.id);
});
passport.deserializeUser((id, done) => {
    User.findById(id).exec()
        .then(user => {
            if (!user) {
                return done(null, false);
            }
            return done(null, user);
        })
        .catch(err => {
            return done(err);
        });
});

// IDE Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.post('/compile', (req, res) => {
    const { language, code } = req.body;

    if (language === 'python') {
        // Write the Python code to a temporary file
        const filename = path.join(__dirname, 'temp.py');
        fs.writeFileSync(filename, code);

        // Execute the Python code using child_process
        exec(`python ${filename}`, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send(stderr);
            } else {
                res.send(stdout);
            }
            // Delete the temporary file after execution
            fs.unlinkSync(filename);
        });
    } else {
        // Call the compileAndRun function for C and C++ code
        compileAndRun(language, code, res);
    }
});

// Login Routes
app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true,
}));

// Signup Routes
app.get("/signup", (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'signup.html'));
});

app.post("/usersignup", async (req, res) => {
    const { name, email, password } = req.body;

    // Validate user input (e.g., check if required fields are provided)

    // Hash the user's password for security
    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user document in the database
        const newUser = new User({
            name,
            email,
            password: hashedPassword,
        });
        await newUser.save();
        res.status(201).json({ message: "User created successfully" });
    } catch (error) {
        console.error("Error creating user:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Listen on port
app.listen(port, () => {
    console.log(`Server is running at port ${port}`);
});