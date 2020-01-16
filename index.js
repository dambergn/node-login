'use strict';

// NPM Modules
const fs = require('fs');
var nodemon = require('nodemon');
try {
  if (!fs.existsSync('.env')) {
    console.log('***************************************************');
    console.log('***Please run ./setup.sh or configure .env file!***');
    console.log('***************************************************');
    nodemon.emit('quit');
  }
} catch (err) { console.error(err) }
require('dotenv').config();
const http = require('http');
const https = require('https');
const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const Base64 = require('js-base64').Base64;
const readline = require('readline');
const cmd = require('node-cmd');

// Self Managed Modules
const sha256 = require('./modules/sha256.js');
const sha512 = require('./modules/sha512.js');

// Configurations
const PORT = process.env.PORT || 3000;
const PORTS = process.env.PORTS || 8080;
const options = {
  key: fs.readFileSync(process.env.KEY),
  cert: fs.readFileSync(process.env.CERT),
};
const tokenExperation = '1d'

const app = express();
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.enable('trust proxy');

let users = JSON.parse(fs.readFileSync('database/0users.json'));

// Web Front End
app.use(function (req, res, next) {// This function re-directs http to https
  if (req.secure) {// request was via https, so do no special handling
    next();
  } else {// request was via http, so redirect to https
    res.redirect('https://' + req.headers.host.split(':')[0] + ':' + PORTS + req.url);
  }
});
app.use(express.static('./public'));

app.get('/', (req, res) => {
  res.sendFile('index.html', { root: './public' });
});

app.get('/api', (req, res) => {
  res.json({
    message: 'Welcome to the API'
  })
})

app.post('/api/login', (req, res) => {
  let loginInfoBase64 = Object.keys(req.body)[0];
  let loginInfoDecoded = Base64.decode(loginInfoBase64);
  let loginInfo = JSON.parse(loginInfoDecoded);
  let userName = loginInfo.username;
  let password = sha512.hex(loginInfo.password);
  let authentication = checkUsers(userName, password);
  if (authentication != 'not authenticated') {
    console.log("User is authenticated");
    jwt.sign(authentication, options.key, { expiresIn: tokenExperation }, (err, token) => {
      if (err) {
        console.log("error:", err)
      }
      res.json({
        jwToken: token
      })
    });
  } else {
    console.log("Incorrect username or password");
    res.json({ jwToken: 'Not Authenticated' });
  }
});

app.post('/api/user', verifyToken, (req, res) => {
  res.json({ jwToken: 'User Authenticated' });
})

app.post('/api/admin', verifyTokenAdmin, (req, res) => {
  res.json({ jwToken: 'Admin Authenticated' });
})

// Format of token
// Authorization: Bearer <access_token>

function applicationVersion() {// Pulls application version from package.json
  let nodePackage = JSON.parse(fs.readFileSync('package.json'));
  return nodePackage.version
}

app.listen(PORT, () => {// Server for http calls
  console.log('HTTP Listening on port:', PORT, 'use CTRL+C to close.')
});

const server = https.createServer(options, app).listen(PORTS, function () {// https server
  console.log('HTTPS Listening on port:', PORTS, 'use CTRL+C to close.')
  console.log('Server started:', new Date());
  console.log('Currently running on Version', applicationVersion());
  console.log('Type man to see a list of available CLI commands.');
});

// Admin console commands
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

rl.on('line', (input) => {
  if (input.split(' ')[0] === 'man') {
    manual();
  } else if (input.split(' ')[0] === 'status') {
    const used = process.memoryUsage();
    for (let key in used) {
      console.log(`${key} ${Math.round(used[key] / 1024 / 1024 * 100) / 100} MB`);
    }
  } else if (input.split(' ')[0] === 'sha256') {
    console.log("sha256:", sha256.hex(input.substr(input.indexOf(' ') + 1)));
  } else if (input.split(' ')[0] === 'sha512') {
    console.log("sha512:", sha512.hex(input.substr(input.indexOf(' ') + 1)));
  } else if (input.split(' ')[0] === 'users') {
    console.log("Users:", users);
  } else {
    console.log(input, 'is not a valid input')
  };
});

function manual(){
  console.log('Put list of commands here')
  console.log('status - prints out usage data')
}

function checkUsers(userName, password) {
  let userNameFound = false;
  let passwordMatches = false;
  for (let i = 0; i < users.length; i++) {
    if (userName === users[i].userName) {
      userNameFound = true;
      if (password === users[i].password) {
        passwordMatches = true;
        return users[i];
      } else {
        console.log('incorrect password')
      }
    } else {
      console.log('username not found')
    }
  }
  if (userNameFound != true || passwordMatches != true) {
    return 'not authenticated';
  }
};

// Verify Token
function verifyToken(req, res, next) {
  console.log("Verifying Token")
  // Get auth header value
  let bearerHeader = req.headers['authorization'];
  // Check if bearer is undefied
  if (typeof bearerHeader !== 'undefined') {
    // Split at the space
    let bearer = bearerHeader.split(' ');
    // Get toekn from array
    let bearerToken = bearer[1];
    // set the token
    req.token = JSON.parse(bearerToken)
    // Next middleware
    jwt.verify(req.token, options.key, (err, authData) => {
      if (err) {
        console.log('token error:', err)
        res.sendStatus(403);
      } else {
        // console.log("data:", authData.permissions)
        next();
      }
    })
  } else {
    // Forbidden
    console.log('Not Authorized')
    res.sendStatus(403);
  }
};

// Verify Token Admin
function verifyTokenAdmin(req, res, next) {
  console.log("Verifying Token")
  // Get auth header value
  let bearerHeader = req.headers['authorization'];
  // Check if bearer is undefied
  if (typeof bearerHeader !== 'undefined') {
    // Split at the space
    let bearer = bearerHeader.split(' ');
    // Get toekn from array
    let bearerToken = bearer[1];
    // set the token
    req.token = JSON.parse(bearerToken) 
    // Next middleware
    jwt.verify(req.token, options.key, (err, authData) => {
      if (err) {
        console.log('token error:', err)
        res.sendStatus(403);
      } else {
        if (authData.permissions === "admin") {
          next();
        } else {
          console.log('Not Authorized')
          res.sendStatus(403);
        }
      }
    })
  } else {
    // Forbidden
    console.log('Not Authorized')
    res.sendStatus(403);
  }
};