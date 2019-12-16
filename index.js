'use strict';

const serverVersion = '0.3';
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
const cors = require('cors');
const bodyParser = require('body-parser');
const Base64 = require('js-base64').Base64;
const PORT = process.env.PORT || 3001;
const tokenExperation = '1d'
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

let users = [
  {userName: 'user1', password: 'Password!1'},
  {userName: 'user2', password: 'Password!2'},
  {userName: 'user3', password: 'Password!3'},
]

app.use(express.static('./public'));
app.use(express.static('./admin'));

app.get('/', (req, res) => {
  res.sendFile('index.html', { root: './public' });
});

app.get('/admin', verifyToken, (req, res) => {
  jwt.verify(req.token, 'secretkey', (err, authData) => {
    if(err){
      console.log('User does not have access to admin')
      res.sendStatus(403);
    } else {
      console.log('Directing user to admin page');
      // res.json({
      //   message: 'Welcome to the Admin route'
      // })
      res.sendFile('index.html', { root: './admin' });
    }
  })
});

app.get('/api', (req, res) => {
  res.json({
    message: 'Welcome to the API'
  })
})

app.post('/api/posts', verifyToken, (req, res) => {
  jwt.verify(req.token, 'secretkey', (err, authData) => {
    if(err){
      res.sendStatus(403);
    } else {
      res.json({
        message: 'Post created...',
        authData
      })
      console.log('post sucessfull')
    }
  })
})

app.post('/api/login', (req, res) => {
  let loginInfoBase64 = Object.keys(req.body)[0]
  let loginInfoDecoded = Base64.decode(loginInfoBase64);
  let loginInfo = JSON.parse(loginInfoDecoded)
  console.log('Login API hit: ', loginInfo);
  let authentication = checkUsers(loginInfo.username, loginInfo.password);
  console.log('Authentication :', authentication);

  if(authentication === 'not authenticated'){
    // res.json({message: 'not authenticated'});
    res.status(403);
  } else {
    jwt.sign(authentication, 'secretkey', {expiresIn: tokenExperation}, (err, token) => {
      res.json({
        token: token
      })
    });
  } 
})

// Format of token
// Authorization: Bearer <access_token>

// verify token
function verifyToken(req, res, next) {
  // Get auth header value
  const bearerHeader = req.headers['authorization'];
  // Check if bearer is undefined
  if(typeof bearerHeader !== 'undefined'){
    // Split at the space
    const bearer = bearerHeader.split(' ');
    // Get token from array
    const bearerToken = bearer[1];
    // Set the token
    req.token = bearerToken;
    // Next middleware
    next();
  } else {
    // Forbidden
    res.sendStatus(403);
  }
}

app.listen(PORT, () => {
  console.log('Listening on port:', PORT, 'use CTRL+C to close.');
  console.log('Server started:', new Date());
  console.log('Currently running on', serverVersion);
});

function checkUsers(userName, password){
  console.log('Username: ', userName, 'Password: ', password);
  let userNameFound = false;
  let passwordMatches = false;
  for(let i = 0; i < users.length; i++){
    console.log('Traverse: ', users[i]);
    if(userName === users[i].userName){
      console.log('user found');
      if(users[i].password === password){
        passwordMatches = true;
        console.log('Passwords match:', users[i].password, password)
        return users[i]
      } else {
        console.log('Passwords do not match:', users[i].password, password);
      }
    }
  }
  if(userNameFound != true && passwordMatches != true){
    console.log('Username or Password not found');
    return 'not authenticated';
  }
}
