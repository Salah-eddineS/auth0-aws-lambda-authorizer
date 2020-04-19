const jwt = require("jsonwebtoken");
const jwks = require("jwks-rsa");

// Set in `environment` of serverless.yml
const { AUTH0_AUDIENCE, AUTH0_DOMAIN } = process.env;

const options = {
  audience: AUTH0_AUDIENCE,
  issuer: AUTH0_DOMAIN,
};

// Policy helper function
const generatePolicy = (principalId, effect, resource) => {
  const authResponse = {};
  authResponse.principalId = principalId;
  if (effect && resource) {
    const policyDocument = {};
    policyDocument.Version = "2012-10-17";
    policyDocument.Statement = [];
    const statementOne = {};
    statementOne.Action = "execute-api:Invoke";
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }
  return authResponse;
};

// Reusable Authorizer function, set on `authorizer` field in serverless.yml
module.exports.handler = (event, context, callback) => {
  try {
    console.log("event", JSON.stringify(event, null, 2));
    const tokenString = event.authorizationToken;
    if (!tokenString) {
      return callback("Unauthorized");
    }

    const match = tokenString.match(/^Bearer (.*)$/);

    if (!match || match.length < 2) {
      return callback("Unauthorized");
    }

    const token = match[1];

    const decoded = jwt.decode(token, { complete: true });

    const client = jwks({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `${AUTH0_DOMAIN}.well-known/jwks.json`,
    });

    client.getSigningKey(decoded.header.kid, (err, key) => {
      if (err) {
        return callback("Unauthorized");
      }

      jwt.verify(
        token,
        key.publicKey || key.rsaPublicKey,
        options,
        (verifyError, decoded) => {
          if (verifyError) {
            console.log("verifyError", verifyError);
            // 401 Unauthorized
            console.log(`Token invalid. ${verifyError}`);
            return callback("Unauthorized");
          }
          // is custom authorizer function
          console.log("valid from customAuthorizer", decoded);
          return callback(
            null,
            generatePolicy(decoded.sub, "Allow", event.methodArn)
          );
        }
      );
    });
  } catch (error) {
    console.log("Unexpected error", error);
    callback("Unauthorized");
  }
};
