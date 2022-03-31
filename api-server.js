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
  !authConfig.domain ||
  !authConfig.audience ||
  authConfig.audience === "YOUR_API_IDENTIFIER"
) {
  console.log(
    "Exiting: Please make sure that auth_config.json is in place and populated with valid domain and audience values"
  );

  process.exit();
}

app.use(morgan('dev'));
app.use(helmet());
app.use(
  cors({
    origin: authConfig.appUri,
  })
);
app.use(express.json());
app.use(express.urlencoded());

const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${authConfig.domain}/.well-known/jwks.json`,
  }),

  audience: authConfig.audience,
  issuer: `https://${authConfig.domain}/`,
  algorithms: ['RS256'],
});

const checkScopes = jwtAuthz(['update:current_user_metadata']);

app.get('/api/external', checkJwt, checkScopes, (req, res) => {
  res.send({
    msg: 'Your access token was successfully validated!',
  });
});

app.post('/api/:user_id/order/', checkJwt, checkScopes, (req, res) => {
  var axios = require("axios").default;

  var options = {
    method: 'PATCH',
    url: 'https://dev-49fsv0cc.us.auth0.com/api/v2/users/' + req.params.user_id,
    headers: { authorization: req.headers.authorization, 'content-type': 'application/json' },
    data: {
      user_metadata: { orders: req.body },
    }
  };

  axios.request(options).then(function (response) {
    res.send('Success');

  }).catch(function (error) {
    console.error(error);
  });

});

// const port = process.env.API_SERVER_PORT || 3001;

app.listen(process.env.API_SERVER_PORT || 3001, () => console.log(`Api started...`));

