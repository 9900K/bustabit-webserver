var admin = require('./admin');
var assert = require('better-assert');
var lib = require('./lib');
var database = require('./database');
var user = require('./user');
var games = require('./games');
var sendEmail = require('./sendEmail');
var stats = require('./stats');
var config = require('../config/config');
var recaptchaValidator = require('recaptcha-validator');


var production = process.env.NODE_ENV === 'production';

function staticPageLogged(page, loggedGoTo) {

    return function(req, res) {
        var user = req.user;
        if (!user){
            return res.render(page);
        }
        if (loggedGoTo) return res.redirect(loggedGoTo);

        res.render(page, {
            user: user
        });
    }
}
 
function contact(origin) {
    assert(typeof origin == 'string');

    return function(req, res, next) {
        var user = req.user;
        var from = req.body.email;
        var message = req.body.message;

        if (!from ) return res.render(origin, { user: user, warning: 'email required' });

        if (!message) return res.render(origin, { user: user, warning: 'message required' });

        if (user) message = 'user_id: ' + req.user.id + '\n' + message;

        sendEmail.contact(from, message, null, function(err) {
            if (err)
                return next(new Error('Error sending email: \n' + err ));

            return res.render(origin, { user: user, success: 'Thank you for writing, one of my humans will write you back very soon :) ' });
        });
    }
}

function restrict(req, res, next) {
    if (!req.user) {
       res.status(401);
       if (req.header('Accept') === 'text/plain')
          res.send('Not authorized');
       else
          res.render('401');
       return;
    } else
        next();
}

function restrictRedirectToHome(req, res, next) {
    if(!req.user) {
        res.redirect('/');
        return;
    }
    next();
}

function adminRestrict(req, res, next) {

    if (!req.user || !req.user.admin) {
        res.status(401);
        if (req.header('Accept') === 'text/plain')
            res.send('Not authorized');
        else
            res.render('401'); //Not authorized page.
        return;
    }
    next();
}

function recaptchaRestrict(req, res, next) {
  var recaptcha = lib.removeNullsAndTrim(req.body['g-recaptcha-response']);
  if (!recaptcha) {
    return res.send('No recaptcha submitted, go back and try again');
  }

  recaptchaValidator.callback(config.RECAPTCHA_PRIV_KEY, recaptcha, req.ip, function(err) {
    if (err) {
      if (typeof err === 'string')
        res.send('Got recaptcha error: ' + err + ' please go back and try again');
      else {
        console.error('[INTERNAL_ERROR] Recaptcha failure: ', err);
        res.render('error');
      }
      return;
    }

    next();
  });
}


function table() {
    return function(req, res) {
        res.render('table_old', {
            user: req.user,
            table: true
        });
    }
}

function tableNew() {
    return function(req, res) {
        res.render('table_new', {
            user: req.user,
            buildConfig: config.BUILD,
            table: true
        });
    }
}

function tableDev() {
    return function(req, res) {
        if(config.PRODUCTION)
            return res.status(401);
        requestDevOtt(req.params.id, function(devOtt) {
            res.render('table_new', {
                user: req.user,
                devOtt: devOtt,
                table: true
            });
        });
    }
}
function requestDevOtt(id, callback) {
    var curl = require('curlrequest');
    var options = {
        url: 'https://www.bustabit.com/ott',
        include: true ,
        method: 'POST',
        'cookie': 'id='+id
    };

    var ott=null;
    curl.request(options, function (err, parts) {
        parts = parts.split('\r\n');
        var data = parts.pop()
            , head = parts.pop();
        ott = data.trim();
        console.log('DEV OTT: ', ott);
        callback(ott);
    });
}

let router = require('express').router(),

    router.get('/', tableNew()); // Changed the default index page to play page {staticPageLogged('index')}
    router.get('/register', staticPageLogged('register', '/play'));
    router.get('/login', staticPageLogged('login', '/play'));
    router.get('/reset/:recoverId', user.validateResetPassword);
    router.get('/faq', staticPageLogged('faq'));
    router.get('/contact', staticPageLogged('contact'));
    router.get('/request', restrict, user.request);
    router.get('/deposit', restrict, user.deposit);
    router.get('/withdraw', restrict, user.withdraw);
    router.get('/withdraw/request', restrict, user.withdrawRequest);
    router.get('/support', restrict, user.contact);
    router.get('/account', restrict, user.account);
    router.get('/security', restrict, user.security);
    router.get('/forgot-password', staticPageLogged('forgot-password'));
    router.get('/calculator', staticPageLogged('calculator'));
    router.get('/guide', staticPageLogged('guide'));


    router.get('/play-old', table());
    router.get('/play', tableNew());
    router.get('/play-id/:id', tableDev());

    router.get('/leaderboard', games.getLeaderBoard);
    router.get('/game/:id', games.show);
    router.get('/user/:name', user.profile);

    router.get('/error', function(req, res, next) { // Sometimes we redirect people to /error
      return res.render('error');
    });

    router.post('/request', restrict, recaptchaRestrict, user.giveawayRequest);
    router.post('/sent-reset', user.resetPasswordRecovery);
    router.post('/sent-recover', recaptchaRestrict, user.sendPasswordRecover);
    router.post('/reset-password', restrict, user.resetPassword);
    router.post('/edit-email', restrict, user.editEmail);
    router.post('/enable-2fa', restrict, user.enableMfa);
    router.post('/disable-2fa', restrict, user.disableMfa);
    router.post('/withdraw-request', restrict, user.handleWithdrawRequest);
    router.post('/support', restrict, contact('support'));
    router.post('/contact', contact('contact'));
    router.post('/logout', restrictRedirectToHome, user.logout);
    router.post('/login', recaptchaRestrict, user.login);
    router.post('/register', recaptchaRestrict, user.register);

    router.post('/ott', restrict, function(req, res, next) {
        var user = req.user;
        var ipAddress = req.ip;
        var userAgent = req.get('user-agent');
        assert(user);
        database.createOneTimeToken(user.id, ipAddress, userAgent, function(err, token) {
            if (err) {
                console.error('[INTERNAL_ERROR] unable to get OTT got ' + err);
                res.status(500);
                return res.send('Server internal error');
            }
            res.send(token);
        });
    });
    router.get('/stats', stats.index);


    // Admin stuff
    router.get('/admin-giveaway', restrict, admin.giveAway);
    router.post('/admin-giveaway', restrict, admin.giveAwayHandle);

    router.get('*', function(req, res) {
        res.status(404);
        res.render('404');
    module.exports = router;
    });
};
