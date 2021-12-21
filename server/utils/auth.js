const jwt = require('jsonwebtoken');
const secret = 'mysecrethdhdhdhdh';
const expiration = '24h';

module.exports = {
   //* The signToken() function expects a user object and will add that user's username, email, and _id properties
   //* to the token. Optionally, tokens can be given an expiration date and a secret to sign the token with. Note
   //* that the secret has nothing to do with encoding. The secret merely enables the server to verify whether
   //* it recognizes this token
   //! ENSURE THAT 'secret' IS STORED IN AN ENVIRONMENT VARIABLE NOT THE js FILE
   //! DO NOT INCLUDE SENSITIVE INFORMATION IN THE PAYLOAD (passwords, etc.)
   signToken: function ({ username, email, _id }) {
      const payload = { username, email, _id };
      return jwt.sign({ data: payload }, secret, { expiresIn: expiration });
   },

   authMiddleware: function ({ req }) {
      //* allows token to be sent via req.body, req.query, or headers (PREFERRED)
      let token = req.body.token || req.query.token || req.headers.authorization;

      //* Authorization: "Bearer <tokenvalue>"
      if (req.headers.authorization) {
         token = token.split(' ').pop().trim();
      }

      //* if no token, return request object as is
      if (!token) {
         return req;
      }

      try {
         //! decode and attach user data to request object
         //* This is where the secret becomes important. If the secret on jwt.verify() doesn't match the secret
         //* that was used with jwt.sign(), the object won't be decoded. When the JWT verification fails, an error
         //* is thrown.
         //* We don't want an error thrown on every request, though. Users with an invalid token should still be
         //* able to request and see all thoughts.Thus, we wrapped the verify() method in a try...catch statement
         //* to mute the error. We'll manually throw an authentication error on the resolver side when the need arises.
         const { data } = jwt.verify(token, secret, { maxAge: expiration });

         req.user = data;
      } catch {
         console.log('Invalid token');
      }

      return req; //* return updated request object
   },
};
