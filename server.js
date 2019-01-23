// Set up
var express  = require('express');
var app      = express();                               // create our app w/ express
var mongoose = require('mongoose');                     // mongoose for mongodb
var morgan = require('morgan');             // log requests to the console (express4)
var bodyParser = require('body-parser');    // pull information from HTML POST (express4)
var methodOverride = require('method-override'); // simulate DELETE and PUT (express4)
var cors = require('cors');

const util = require('util');
 


var databaseConfig = require('./config/database');
//var router = require('./app/routes');
 
// Configuration
var promise = mongoose.connect(databaseConfig.url, {
  useMongoClient: true,
});
 
app.use(morgan('dev'));                                         // log every request to the console
app.use(bodyParser.urlencoded({'extended':'false'}));            // parse application/x-www-form-urlencoded
app.use(bodyParser.json());                                     // parse application/json
app.use(bodyParser.json({ type: 'application/vnd.api+json' })); // parse application/vnd.api+json as json
app.use(methodOverride());
app.use(cors());
 
app.use(function(req, res, next) {
   res.header("Access-Control-Allow-Origin", "*");
   res.header('Access-Control-Allow-Methods', 'DELETE, PUT');
   res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
   next();
});
 
// Models
var Villes = mongoose.model('Villes', {
    id: String,
    ville: String,
    avatar: String,
    image: String,
    favoris: String
});
var Pays = mongoose.model('Pays', {
    pays: String,
    plu: String,
    favoris: String
});
var Bieres = mongoose.model('Bieres', {
    nom: String,
    marque: String,
    volume: Number,
    degret: String,
    favoris: String,
    plu: String,
    description: String,
    image: String,
    rating: String,
    pays: String
});
var Commentaires = mongoose.model('Commentaires', {
    ladescription: String,
    lenote: String,
    auteur: String,
    pseudo: String,
    letype: String,
    laref: String
});

var Users = mongoose.model('Users', {
    email: String,
    pseudo: String
});
/*var Classement = mongoose.model('Classement', {
    nom: String,
    score: Number
});
var Classements = mongoose.model('Classements', {
    nom: String,
    score: Number
});
var MeilleurScore = mongoose.model('MeilleurScore', {
    nom: String,
    score: Number
});*/

var Events = mongoose.model('Events', {
    date: String,
    auteur: String,
    title: String,
    description: String,
    nbr_like: Number
});

var Scores = mongoose.model('Scores', {
    user: String,
    nom: String,
    score: Number
});


 
// Routes

    var AuthenticationController = require('./app/controllers/authentication');
    var passportService = require('./config/passport');
    var passport = require('passport');

    var requireAuth = passport.authenticate('jwt', {session: false});
    var requireLogin = passport.authenticate('local', {session: false});

    app.post('/api/register', AuthenticationController.register);
    app.post('/api/login', requireLogin, AuthenticationController.login);
    app.get('/api/protected', requireAuth, function(req, res){
        res.send({ content: 'Success'});
    });


    


    // Get events
    app.get('/api/events', function(req, res) {
 
        console.log("fetching events");
 
        // use mongoose to get all reviews in the database
        Events.find(function(err, events) {
 
            // if there is an error retrieving, send the error. nothing after res.send(err) will execute
            if (err)
                res.send(err)
 
            res.json(events); // return all reviews in JSON format
        });
    });
 
 
    // Get villes
    app.get('/api/villes', function(req, res) {
 
        console.log("fetching villes");
 
        // use mongoose to get all villes in the database
        Villes.find(function(err, villes) {
 
            // if there is an error retrieving, send the error. nothing after res.send(err) will execute
            if (err)
                res.send(err)
 
            res.json(villes); // return all reviews in JSON format
        });
    });

    // Get users
    app.get('/api/users', function(req, res) {
 
        console.log("fetching users");
 
        // use mongoose to get all villes in the database
        Users.find(function(err, users) {
 
            // if there is an error retrieving, send the error. nothing after res.send(err) will execute
            if (err)
                res.send(err)
 
            res.json(users); // return all reviews in JSON format
        });
    });


 
    // Get pays
    app.get('/api/pays', function(req, res) {
 
        console.log("fetching pays");
 
        // use mongoose to get all villes in the database
        Pays.find(function(err, pays) {
 
            // if there is an error retrieving, send the error. nothing after res.send(err) will execute
            if (err)
                res.send(err)
 
            res.json(pays); // return all reviews in JSON format
        });
    });

    // Post bières
    app.post('/api/bieres', function(req, res) {

        const util = require('util');
        console.log("OK 4 "+util.inspect(req.body.params.pays, false, null));
        Bieres.find({"pays":req.body.params.pays},function(err, bieres) {
            if (err)
                res.send(err)
 
            res.json(bieres); 
        });
    });


    // Get bières
    app.get('/api/bieres', function(req, res) {

        Bieres.find(function(err, bieres) {
            if (err)
                res.send(err)
 
            res.json(bieres);
        });
    });


    // Get commentaires
    app.get('/api/commentaires', function(req, res) {
 
        console.log("fetching commentaires");
 
        // use mongoose to get all reviews in the database
        Commentaires.find(function(err, commentaires) {
 
            // if there is an error retrieving, send the error. nothing after res.send(err) will execute
            if (err)
                res.send(err)
 
            res.json(commentaires); // return all reviews in JSON format
        });
    });/**/

     // Get scores
    app.get('/api/scores', function(req, res) {
 
        console.log("fetching scores");
 
        // use mongoose to get all reviews in the database
        Scores.find(function(err, scores) {
 
            // if there is an error retrieving, send the error. nothing after res.send(err) will execute
            if (err)
                res.send(err)
 
            res.json(scores); // return all reviews in JSON format
        });
    });

    app.post('/api/scores', function(req, res) {
 
        console.log("creating score " + util.inspect(req.body));
 
        // create a review, information comes from request from Ionic
        Scores.create({
            user : req.body.user,
            nom : req.body.nom,
            score : req.body.score
        }, function(err, review) {
            if (err)
                res.send(err);
 
            // get and return all the reviews after you create another
            Scores.find(function(err, scores) {
                if (err)
                    res.send(err)
                res.json(scores);
            });
        });
 
    });

    app.put('/api/scores', function(req, res) {

        console.log("villePUT " + util.inspect(req.body));

        Scores.findOneAndUpdate(
            { user : req.body.user }, 
            { $set: { score:req.body.score } }, 
            function (err, post) {
                if (err)
                res.send(err);
 
                Scores.find(function(err, scores) {
                    if (err)
                        res.send(err)
                    res.json(scores);
                });
          });


        /*Villes.findOneAndUpdate(
            req.params.ville_id, 
            { favoris:"favoris" }, 
            function (err, post) {
            res.json(post);
          });*/
 
    });

    /*/ Get meilleurscore
    app.get('/api/meilleurscore', function(req, res) {
 
        console.log("fetching meilleurscore");
 
        // use mongoose to get all reviews in the database
        MeilleurScore.find(function(err, meilleurscore) {
 
            // if there is an error retrieving, send the error. nothing after res.send(err) will execute
            if (err)
                res.send(err)
 
            res.json(meilleurscore); // return all reviews in JSON format
        });
    });

    // Get Classements
    app.get('/api/classements', function(req, res) {
 
        console.log("fetching classements");
 
        // use mongoose to get all reviews in the database
        Classements.find(function(err, classements) {
 
            // if there is an error retrieving, send the error. nothing after res.send(err) will execute
            if (err)
                res.send(err)
 
            res.json(classements); // return all reviews in JSON format
        });
    });

    // Get classement
    app.get('/api/classement', function(req, res) {
 
        console.log("fetching classement");
 
        // use mongoose to get all villes in the database
        Classement.find(function(err, classement) {
 
            // if there is an error retrieving, send the error. nothing after res.send(err) will execute
            if (err)
                res.send(err)
 
            res.json(classement); // return all reviews in JSON format
        });
    }); */
 
    // create review 

    app.put('/api/commentaires', function(req, res) {

        console.log("commentaires " + util.inspect(req.body));

        Commentaires.findOneAndUpdate(
            { _id : req.body._id }, 
            { $set: { lenote:req.body.manote,ladescription:req.body.madescription } }, 
            function (err, post) {
                if (err)
                res.send(err);
 
                Commentaires.find(function(err, commentaires) {
                    if (err)
                        res.send(err)
                    res.json(commentaires);
                });
          });
 
    });




    app.post('/api/commentaires', function(req, res) {
 
        console.log("creating commentaires " + util.inspect(req.body));
 
        // create a review, information comes from request from Ionic
        Commentaires.create({
            ladescription: req.body.madescription,
            lenote: req.body.manote,
            auteur: req.body.auteur,
            pseudo: req.body.pseudo,
            letype: req.body.montype,
            laref: req.body.maref
        }, function(err, review) {
            if (err)
                res.send(err);
 
            // get and return all the reviews after you create another
            Commentaires.find(function(err, commentaires) {
                if (err)
                    res.send(err)
                res.json(commentaires);
            });
        });
 
    });


    // update ville
    app.put('/api/villes', function(req, res) {

        console.log("villePUT " + util.inspect(req.body));

        Villes.findOneAndUpdate(
            { _id : req.body._id }, 
            { $set: { favoris:req.body.favoris } }, 
            function (err, post) {
                if (err)
                res.send(err);
 
                Villes.find(function(err, villes) {
                    if (err)
                        res.send(err)
                    res.json(villes);
                });
          });


        /*Villes.findOneAndUpdate(
            req.params.ville_id, 
            { favoris:"favoris" }, 
            function (err, post) {
            res.json(post);
          });*/
 
    });

    // update pays
    app.put('/api/pays', function(req, res) {

        console.log("paysPUT " + util.inspect(req.body));

        Pays.findOneAndUpdate(
            { pays : req.body.pays }, 
            { $set: { favoris:req.body.favoris }}, 
            function (err, post) {
                if (err)
                res.send(err);
 
                Pays.find(function(err, pays) {
                    if (err)
                        res.send(err)
                    res.json(pays);
                });
          });
 
    });

    // update bieres
    app.put('/api/bieres', function(req, res) {

        console.log("bierePUT " + util.inspect(req.body));

        Bieres.findOneAndUpdate(
            { _id : req.body._id }, 
            { $set: { favoris:req.body.favoris }}, 
            function (err, post) {
                if (err)
                res.send(err);
 
                Bieres.find(function(err, bieres) {
                    if (err)
                        res.send(err)
                    res.json(bieres);
                });
          });
    });
 
    // delete a review
    /*app.delete('/api/commentaires/:commentaire_id', function(req, res) {
        Commentaires.remove({
            _id : req.params.commentaire_id
        }, function(err, commentaire) {
 
        });
    });*/
 
 //router(app);
 
// listen (start app with node server.js) ======================================
app.listen(8080);
console.log("App listening on port 8080");  

