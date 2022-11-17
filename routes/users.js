var express = require('express');
var router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { db } = require("../mongo");
const { uuid } = require("uuidv4")
let user = {};

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

router.post('/register', async (req, res) => {
  try {
    const email = req.body.email;
    const password = req.body.password;

    const saltRounds = 5;
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(password, salt);
    
    user = {
      email,
      password: hash,
      id: uuid()
    };

    const insertUser = db().collection('users').insertOne(user);

    res.json({
      success: true
    });

  } catch (err){
    console.error(err);
    res.json({
      success: false,
      error: err.toString()
    });
  }
})

router.post('/login', async (req, res) => {
  try {
    const email = req.body.email;
    const password = req.body.password;

    const foundUser = await db().collection('users').findOne({
      email: email
    });

      if (!foundUser){
        res.json({
          success: false,
          message: "Could not find user."
        }).status(204);
        return;
      };
      // password match?
      const match = await bcrypt.compare(password, user.password);
      
      if (match === false){
        res.json({
          success: false,
          message: "Incorrect password."
        }).status(204);
        return;
      };
    // if email includes this then make userType = admin, else = user.
      const userType = email.includes("codeimmersives.com") ? "admin" : "user";
      const userData = {
        date: new Date(),
        userID: foundUser.id,
        scope: userType
      }
      // create JSON webtoken:
      /* The JWT_SECRET_KEY is the passphrase that will be used to encrypt our tokens. This key should always be stored server-side and never exposed to users. If a third party had access to your server's secret key, they could decrypt a user's idToken and gain access to their user data. Or they could create their own fake tokens and immitate a user on your platform. Thus, this key should always be stored server-side and will be the only place that a jwt for your application can be encrypted/decrypted. */
     const exp = Math.floor(Date.now() / 1000) + (60 * 60)
      const payload = {
        userData,
        exp // expires in 24 hrs
      };
      const jwtSecretKey = process.env.JWT_SECRET_KEY;
      console.log(jwtSecretKey)
      const token = jwt.sign(payload, jwtSecretKey)

      res.json({
        success: true,
        token: token,
        email: foundUser.email
      })

  } catch (err) {
    console.error(err);
    res.json({
      success: false,
      error: err.toString()
    });
  }
})

router.get('/message', (req, res) => {
  try {
    //Get the user's token from the request headers and assign it to a new variable.
    const tokenHeaderKey = process.env.TOKEN_HEADER_KEY;
    const token = req.header(tokenHeaderKey);
    // use the jwt.verify method to decode and verify the token. 
    const jwtSecretKey = process.env.JWT_SECRET_KEY;
    const verified = jwt.verify(token, jwtSecretKey);
    console.log(verified.header)
    if (!verified) {
      return res.json({
        success: false,
        message: "ID Token could not be verified."
      })
    };

    if (verified.userData && verified.userData.scope === "user") {
      return res.json({
        success: true,
        message: "I am a normal user",
      });
    }
    
    if (verified.userData && verified.userData.scope === "admin") {
      return res.json({
        success: true,
        message: "I am an admin user",
      });
    }

    throw Error("Access Denied");
  } catch (err) {
    console.error(err);
    res.json({
      success: false,
      error: err.toString()
    });
  }
})
module.exports = router;
