const express = require('express');
const morgan = require('morgan');
const helmet = require('helmet');
const cors = require('cors');
const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const jwtAuthz = require('express-jwt-authz');

const authConfig = require('./auth_config.json');
const { retryWhen } = require('rxjs');

const app = express();

if (
  !process.env.DOMAIN ||
  !process.env.AUDIENCE ||
  process.env.AUDIENCE === "YOUR_API_IDENTIFIER"
) {
  console.log(
    "Exiting: Please make sure that auth_config.json is in place and populated with valid domain and audience values"
  );

  process.exit();
}

app.use(morgan('dev'));
app.use(helmet());
// app.use(
//   cors({
//     origin: process.env.appUri,
//   })
// );

app.use(cors({credentials: true, origin: '*'}) );
app.options('*', cors({credentials: true, origin: true}));

app.use(express.json());
app.use(express.urlencoded());

const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${process.env.DOMAIN}/.well-known/jwks.json`,
  }),

  audience: process.env.AUDIENCE,
  issuer: `https://${process.env.DOMAIN}/`,
  algorithms: ['RS256'],
});

const checkScopes = jwtAuthz(['update:current_user_metadata']);

app.get('/api/external', checkJwt, checkScopes, (req, res) => {
  res.send({
    msg: 'Your access token was successfully validated!',
  });
});

app.post('/api/:user_id/order/', checkJwt, checkScopes, (req, res) => {

  // Complete the order after checkJwt and checkScopes (could also do the email verification check here as well)

  res.send(req.body)

  // Could send request to Management API here but I chose to do it in frontend

  // var axios = require("axios").default;

  // var options = {
  //   method: 'PATCH',
  //   url: 'https://dev-49fsv0cc.us.auth0.com/api/v2/users/' + req.params.user_id,
  //   headers: { authorization: req.headers.authorization, 'content-type': 'application/json' },
  //   data: {
  //     user_metadata: { orders: req.body },
  //   }
  // };

  // axios.request(options).then(function (response) {
  //   res.send('Success');

  // }).catch(function (error) {
  //   console.error(error);
  // });

});

app.listen(process.env.PORT || 3001, () => console.log(`Api started...`));

