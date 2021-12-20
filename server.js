const express = require('express');

// import path module for express
const path = require('path');

// import ApolloServer
const { ApolloServer } = require('apollo-server-express');

// import our typeDefs and resolvers
const { typeDefs, resolvers } = require('./schemas');
const db = require('./config/connection');

// import supposed middleware function...
const { authMiddleware } = require('./utils/auth');

const PORT = process.env.PORT || 3001;
const app = express();

const startServer = async () => {
   // create a new Apollo server and pass in our schema data
   const server = new ApolloServer({
      typeDefs,
      resolvers,
      context: authMiddleware,
   });

   //* Start the Apollo server
   await server.start();

   // Integrate our Apollo server with the Express application as middleware
   server.applyMiddleware({ app });

   // log where we can go to test oue GWL API
   console.log(`Use GrapgQL at http://localhost:${PORT}${server.graphqlPath}`);
};

//* Initialize the Apollo server
startServer();

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

//* Serve up static assets
if (process.env.NODE_ENV !== 'production') {
   app.use(express.static(path.join(__dirname, '../client/build')));
}

app.get('*', (req, res) => {
   res.sendFile(path.join(__dirname, '../client/build/index.html'));
});

db.once('open', () => {
   app.listen(PORT, () => {
      console.log(`API server running on port ${PORT}!`);
   });
});
