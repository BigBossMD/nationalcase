/**
 * INIT
 * Include modules
 */

var passport = require('passport');
var util = require('util');
var fs = require('fs');
var VkStrategy = require('passport-vkontakte').Strategy;
var mysql = require('mysql');
var crypto = require('crypto');
var Random = require('random-js');
var random = new Random(Random.engines.mt19937().autoSeed());
var Base64 = require('js-base64').Base64;

/**
 * Configure
 * Global variables
 */
// Config
var config = JSON.parse(fs.readFileSync('config.json'));
var cases = JSON.parse(fs.readFileSync('cases.json'));

var salt = generateToken(16);

var sockethost = 'http://' + config.url + ':' + config.socket.port;
var render_title = 'UPCASH.PRO - Удача за тобой!';

var socket_connections = {};
var pool;

var mysqlQueue = [];

var mysqlQueueInterval; // Clear it to stop sending queries to mysql
var default_user = {
  id: 0,
  vkid: 0,
  banned: 0,
  username: 0,
  balance: 0,
  accesstoken: '',
  regdate: 0,
  ip: 0,
  ref: null,
  chance: 0,
  won: 0,
  rolls: 0
};

var VK_APP_ID = config.vk.appid;
var VK_APP_SECRET = config.vk.secret;

var app = require('express')(),
bodyParser = require('body-parser'),
express = require('express');

app.use(require('body-parser').urlencoded({extended: true}));
app.use(require('body-parser').json());

app.set('views', __dirname + '/views');
app.use(express.static(__dirname + '/views'));
app.set('view engine', 'ejs');

app.use(require('cookie-parser')());
app.use(require('express-session')({ 
  secret: config.express.secret,
  resave: true,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

/************
 *** Cache ***
 ************/

var stat_users = 0;
var stat_online = 0;
var stat_opened = 0;
var live = [];
var userlist = {};
var transactions = {};
var rolls = [];
var withdrawal = [];
var top3 = [];

// Extra functional
String.prototype.removescript = function() {
  return this.replace(/[<>]/ig, "");
}
String.prototype.removequots = function() {
  return this.replace(/['"\\\0]/ig, "");
}

function remoteAddr(req) {
  return (req.connection.remoteAddress || req.ip ||
    req.headers["X-Forwarded-For"] ||
    req.headers["x-forwarded-for"] ||
    req.client.remoteAddress || req.ips[0] || '127.0.0.1');
}

function round(i, x) {
  i = i || 0;
  x = x || 0;
  return Math.round(parseFloat(i) * Math.pow(10, parseInt(x))) / Math.pow(10, parseInt(x));
}

function update_salt() {
  return salt = generateToken(16);
}

function sha(string) {
  return crypto.createHash('sha1').update(string).digest("hex");
}

function md5(string) {
  return crypto.createHash('md5').update(string).digest("hex");
}


function generateToken(length) {
  var symbols = '1234567890abcdefghijklmnopqrstuvwxyz'.split('');
  var token = '';
  for (var i = 0; i < length; i++) {
    token += symbols[random.integer(0, symbols.length - 1)];
  }
  return token;
}

function isAdmin(vkid) {
  return (config.admin.admins.indexOf(vkid.toString()) > -1);
}

function getCaseKeyById(id) {
  for (var key in cases.cases) {
    if (cases.cases[key].id == id) return key;
  }
  return null;
}

function getCaseById(id) {
  for (var key in cases.cases) {
    if (cases.cases[key].id == id) return Object.assign({}, cases.cases[key]);
  }
  return null;
}

function getTransaction(id) {
  for (var i = transactions.length; i > 0; i--) {
    if (transactions[i - 1].id == id) {
      return Object.assign({}, transactions[i - 1], {
        ___key: (i - 1)
      });
    }
  }
  return null;
}

function getWithdraw(id) {
  for (var i = withdrawal.length; i > 0; i--) {
    if (withdrawal[i - 1].id == id) {
      return Object.assign({}, withdrawal[i - 1], {
        ___key: (i - 1)
      });
    }
  }
  return null;
}

function getUser(vkid) {
  var params = [...arguments];
  params.shift();
  if (vkid in userlist) {
    var usr = Object.assign({}, userlist[''+vkid]);
    if (params.indexOf('opened') >= 0) {
      usr.opened = [];
      for (var i = rolls.length; i > 0 && usr.opened.length < 30; i--) {
        if (rolls[i - 1].vkid == vkid) usr.opened.push(Object.assign({}, rolls[i - 1]));
      }
    }
    if (params.indexOf('transactions') >= 0 || params.indexOf('finances') >= 0) {
      var f = (params.indexOf('finances') >= 0);
      var t = (params.indexOf('transactions') >= 0);
      if (f) {
        usr.income = usr.withdraw = usr.withdrawing = usr.refsum = 0;
      }
      if (t) {
        usr.transactions = [];
      }
      for (var i = transactions.length; i > 0; i--) {
        var tr = Object.assign({}, transactions[i - 1]);
        if (transactions[i - 1].vkid == vkid) {
          if (t) {
            usr.transactions.push(tr);
          }
          if (f) {
            if (tr.type == 'deposit' && tr.status == 'success') usr.income += tr.amount;
            if (tr.type == 'withdraw' && tr.status == 'success') usr.withdraw += tr.amount;
            if (tr.type == 'withdraw' && tr.status == 'waiting') usr.withdrawing += tr.amount;
            if (tr.type == 'ref' && tr.status == 'success') usr.refsum += tr.amount;
          }
        }
      }
    }
    if (params.indexOf('referal') >= 0) {
      usr.refcount = 0;
      usr.referals = [];
      for (var key in userlist) {
        if (userlist[''+key].ref == vkid) {
          usr.refcount++;
          usr.referals.push(key);
        }
      }
    }
    return usr;
  }
  return null;
}

function roll_map(a) {
  var x = Object.assign({}, a);
  var c = getCaseById(a.caseid);
  var pid = parseInt(a.prizeid);
  a.userimg = userlist[''+a.vkid].userimg || '/assets/img/avatar.jpg';
  if (c && 'prizes' in c && pid in c.prizes) {
    a.live = c.prizes[pid].live;
    a.img = c.prizes[pid].img;
  } else {
    a.live = cases.defaultCase.prizes[0].live;
    a.img = cases.defaultCase.prizes[0].img;
  }
  return a;
}

function saveuser(profile, accesstoken, req) {
  var existent = getUser(profile.id);
  var usr = {
    vkid: profile.id,
    username: profile.displayName.removequots().removescript(),
    userimg: profile._json.photo_max_orig,
    accesstoken: accesstoken,
    regdate: round(new Date / 1000),
    ip: remoteAddr(req)
  };
  if (existent) {
    mysqlQueue.push('UPDATE users SET `username`=\'' + usr.username + '\',`userimg`=\'' + usr.userimg + '\',`accesstoken`=\'' + usr.accesstoken + '\'  WHERE vkid=' + profile.id);
    userlist[''+profile.id].username = usr.username;
    userlist[''+profile.id].userimg = usr.userimg;
    userlist[''+profile.id].accesstoken = usr.accesstoken;
  } else {
    mysqlQueue.push('INSERT INTO users (' + Object.keys(usr).map(k => '`' + k + '`').join(',') + ') VALUES (' + Object.keys(usr).map(k => '\'' + usr[k] + '\'').join(',') + ')');
    stat_users++;
    userlist[''+profile.id] = Object.assign({}, default_user, usr);
  }
}

function query(q) {
  var x = [...arguments];
  var a = null;
  var done = error = always = function() {};
  while (a = x.shift()) {
    if ("function" == typeof a) {
      if (a.name == 'done') done = a;
      else if (a.name == 'error') error = a;
      else if (a.name == 'always') always = a;
    }
  }
  pool.query(q, function(a, b, c) {
    return function always(err, result, fields) {
      if (err && (err.code === 'PROTOCOL_CONNECTION_LOST' || err.code == 'ECONNRESET')) {
        handleDisconnect();
        a(err, result, fields);
      } else {
        b(err, result, fields);
      }
      c(err, result, fields);
    };
  }(done, error, always));
}

function handleDisconnect() {
  pool = mysql.createConnection({
    host: config.mysql.host,
    user: config.mysql.user,
    password: config.mysql.pass,
    database: config.mysql.db,
    charset: 'utf8_general_ci'
  });

  pool.connect(function(err) {
    if (err) {
      if (config.debug) console.log('[ERROR] Connecting to db:', err);
      setTimeout(handleDisconnect, 2000);
    } else {
      if (config.debug) console.log('connected to db');

      query('SELECT u.*, (SELECT SUM(prize) FROM rolls WHERE rolls.vkid = u.vkid) as won, (SELECT COUNT(*) FROM rolls WHERE rolls.vkid = u.vkid) as rolls  FROM `users` as u WHERE 1', function always(err, result, fields) {
        stat_users = result.length;
        userlist = {};
        for (var key in result) {
          result[key].won = result[key].won || 0;
          result[key].rolls = result[key].rolls || 0;
          userlist[''+result[key].vkid] = Object.assign({}, result[key]);
        }
        update_top3();
        if (config.debug) console.log('Пользователей зарегистрированно: ', stat_users);
        query('SELECT * FROM rolls WHERE 1', function always(err, result, fields) {
          stat_opened = result.length;
          rolls = result.map(roll_map);
          if (config.debug) console.log('Кейсов открыто: ', stat_opened);
          query('SELECT * FROM transactions WHERE 1', function always(err, result, fields) {
            transactions = result;
            query('SELECT * FROM withdraw WHERE 1', function always(err, result, fields) {
              withdrawal = result;
              query('SELECT * FROM rolls ORDER BY id DESC LIMIT 0, 15', function always(err, result, fields) {
                live = result.map(roll_map);
                console.log('Server run!');
              });
            });
          });
        });
      });

      update_salt();
    }
  });

  pool.on('error', function(err) {
    if (config.debug) console.log('DB error', err);
    if (err.code === 'PROTOCOL_CONNECTION_LOST' || err.code === 'ECONNRESET') {
      handleDisconnect();
    } else {
      throw err;
    }
  });
}

function checksalt(a, b) {
  return (b == sha(salt + ":" + a));
}

function saveconf() {
  fs.writeFileSync('config.json', JSON.stringify(config, null, "\t"));
}

function savecases() {
  fs.writeFileSync('cases.json', JSON.stringify(cases, null, "\t"));
}

function opencase(id, user_chance, extra_chance, extra_price) {
  var caseinfo = getCaseById(id);
  var potential_prize;
  var real_prize;
  var sum_probability = 0;
  var payment = parseFloat(caseinfo.price) + extra_price;
  cases.balance += payment;
  for (var key in caseinfo.prizes) {
    sum_probability += parseFloat(caseinfo.prizes[key].probability);
  }
  var randomval = round(sum_probability * (user_chance + Math.random() + extra_chance));
  randomval = Math.min(sum_probability, Math.max(0, randomval));
  var win_ticket = randomval;
  for (var key in caseinfo.prizes) {
    caseinfo.prizes[key].id = key;
    var prize = caseinfo.prizes[key];
    if (config.debug) console.log('Тикет:', randomval, 'Вероятность приза:', parseFloat(prize.probability));
	update_top3();
    if (randomval <= parseFloat(prize.probability)) {
      potential_prize = prize;
      if (cases.balance < parseFloat(prize.value)) {
        real_prize = caseinfo.prizes[0];
      } else {
        real_prize = potential_prize;
      }
      break;
    } else {
      randomval -= parseFloat(prize.probability);
    }
  }
  if (config.debug) console.log('Выигрышный билет:', win_ticket, 'Шанс:', extra_chance, 'Приз:', real_prize);
  cases.cases[getCaseKeyById(id)].won += parseFloat(real_prize.value);
  cases.balance -= parseFloat(real_prize.value);
  var profit = Math.max(0, payment - parseFloat(real_prize.value)) * parseFloat(config.profitperc) || 0;
  update_top3();
  cases.balance -= profit;
  cases.profit += profit;
  cases.balance = round(cases.balance, 2);
  cases.profit = round(cases.profit, 2);
  stat_opened++;
  io.emit('stats_update', {
    opened: stat_opened
  });
  savecases();
  return {
    id: id,
    user_chance: user_chance,
    extra_chance: extra_chance,
    extra_price: extra_price,
    prize: real_prize,
    profit: profit,
    randomval: randomval,
    potential_prize: potential_prize,
    win_ticket: win_ticket
  };
}

function updatebalance(vkid, change) {
  if (vkid in userlist) userlist[''+vkid].balance += parseFloat(change);
  mysqlQueue.push('UPDATE users SET balance = balance + ' + change + ' WHERE vkid = ' + vkid);
}

function sendidemit(vkid, emit, data) {
  for (var key in socket_connections) {
    if (socket_connections[key] == vkid) {
      io.to(key).emit(emit, data);
      if (config.debug) console.log('sending ' + emit + '(' + JSON.stringify(data) + ') to ' + key + '(' + vkid + ')');
    }
  }
}

function sendbalance(vkid) {
  sendidemit(vkid, "balance", getUser(vkid).balance);
}

function sendprize(vkid, prize) {
  sendidemit(vkid, "prize", prize);
  setTimeout(function() {
    sendlive(vkid, prize)
  }, 6500);
}

function sendlive(vkid, prize) {
  io.emit('liveprize', {
    prize: prize,
    vkid: vkid,
    img: userlist[''+vkid].userimg
  });
}

function update_top3() {
  var top_1 = userlist[''+Object.keys(userlist)[0]] || default_user;
  var top_2 = userlist[''+Object.keys(userlist)[1]] || default_user;
  var top_3 = userlist[''+Object.keys(userlist)[2]] || default_user;
  for (var key in userlist) {
    var usr = getUser(key);
    if (usr.won > top_1.won) top_1 = Object.assign({}, usr);
    else if (usr.won > top_2.won) top_2 = Object.assign({}, usr);
    else if (usr.won > top_3.won) top_3 = Object.assign({}, usr);
  }
  top3 = [];
  if (top_1.vkid) top3.push(top_1);
  if (top_2.vkid) top3.push(top_2);
  if (top_3.vkid) top3.push(top_3);
}

function pushroll(vkid, prize, caseid, profit) {
  var roll = {
    vkid: vkid,
    caseid: caseid,
    prizeid: prize.id,
    prize: prize.value,
    time: round(new Date / 1000),
    profit: profit
  };
  mysqlQueue.push('INSERT INTO rolls (' + Object.keys(roll).map(k => '`' + k + '`').join(',') + ') VALUES (' + Object.keys(roll).map(k => '\'' + roll[k] + '\'').join(',') + ')');
  roll = roll_map(roll);
  rolls.push(roll);
  live.splice(0, 0, roll);
  while (live.length > 15) live.pop();
}

function handleMysqlQueue() {
  if (mysqlQueue.length) {
    var q = mysqlQueue.shift();
    if(config.debug) console.log(q);
    query(q, function always(err) {
      handleMysqlQueue();
      if (err) console.log('[MYSQL ERROR]', err);
    });
  }
}

if (!VK_APP_ID || !VK_APP_SECRET) {
  throw new Error('Set VK_APP_ID and VK_APP_SECRET');
}

passport.serializeUser(function(user, done) {
  done(null, user);
});
passport.deserializeUser(function(obj, done) {
  done(null, obj);
});
passport.use(
  new VkStrategy({
    clientID: VK_APP_ID,
    clientSecret: VK_APP_SECRET,
    callbackURL: "http://" + config.url + "/auth/vk/callback",
    scope: ['email', 'photos'],
    profileFields: ['email', 'photo_max_orig'],
    passReqToCallback: true
  }, function verify(req, accessToken, refreshToken, params, profile, done) {
    if (config.debug) console.log(accessToken + ' for ' + profile.id);
    profile.displayName = profile.displayName.removequots();
    saveuser(profile, accessToken, req);
    process.nextTick(function() {
      return done(null, profile);
    });
  }));
handleDisconnect();

mysqlQueueInterval = setInterval(handleMysqlQueue, 2000);

app.get('/', function(req, res) {
  var vkid = 1;
  var hash = 1;
  var isadmin = false;
  if (req.isAuthenticated()) {
    vkid = req.user.id;
    hash = sha(salt + ":" + vkid);
    if (isAdmin(req.user.id)) {
      isadmin = true;
    }
  }
  res.render('index', {
    curpage: 'index',
    title: render_title,
    user: (('user' in req && 'id' in req.user) ? getUser(req.user.id) : false),
    vkid: vkid,
    salt: hash,
    sockethost: sockethost,
    cases: cases.cases,
    users: top3,
    rolls: live,
    stat_: [stat_users,stat_online,stat_opened],
    isadmin: isadmin
  });
});
app.get('/success', function(req, res) {
  var vkid = 1;
  var hash = 1;
  var isadmin = false
  
  if (req.isAuthenticated()) {
    vkid = req.user.id;
    hash = sha(salt + ":" + vkid);
    if (isAdmin(req.user.id)) {
      isadmin = true;
    }
  }
  res.render('success', {
    curpage: 'success',
    title: render_title,
    user: (('user' in req && 'id' in req.user) ? getUser(req.user.id) : false),
    vkid: vkid,
    salt: hash,
    sockethost: sockethost,
    cases: cases.cases,
    users: top3,
    rolls: live,
    stat_: [stat_users,stat_online,stat_opened],
    isadmin: isadmin
  });
});
app.get('/error', function(req, res) {
  var vkid = 1;
  var hash = 1;
  var isadmin = false;
  if (req.isAuthenticated()) {
    vkid = req.user.id;
    hash = sha(salt + ":" + vkid);
    if (isAdmin(req.user.id)) {
      isadmin = true;
    }
  }
  res.render('error', {
    curpage: 'error',
    title: render_title,
    user: (('user' in req && 'id' in req.user) ? getUser(req.user.id) : false),
    vkid: vkid,
    salt: hash,
    sockethost: sockethost,
    cases: cases.cases,
    users: top3,
    rolls: live,
    stat_: [stat_users,stat_online,stat_opened],
    isadmin: isadmin
  });
});
app.get('/faq', function(req, res) {
  var vkid = 1;
  var hash = 1;
  var isadmin = false;
  if (req.isAuthenticated()) {
    vkid = req.user.id;
    hash = sha(salt + ":" + vkid);
    if (isAdmin(req.user.id)) {
      isadmin = true;
    }
  }
  res.render('faq', {
    curpage: 'faq',
    title: render_title,
    user: (('user' in req && 'id' in req.user) ? getUser(req.user.id) : false),
    vkid: vkid,
    salt: hash,
    sockethost: sockethost,
    cases: cases.cases,
    users: top3,
    rolls: live,
    stat_: [stat_users,stat_online,stat_opened],
    isadmin: isadmin
  });
});
app.get('/contests', function(req, res) {
  var vkid = 1;
  var hash = 1;
  var isadmin = false;
  if (req.isAuthenticated()) {
    vkid = req.user.id;
    hash = sha(salt + ":" + vkid);
    if (isAdmin(req.user.id)) {
      isadmin = true;
    }
  }
  res.render('contests', {
    curpage: 'contests',
    title: render_title,
    user: (('user' in req && 'id' in req.user) ? getUser(req.user.id) : false),
    vkid: vkid,
    salt: hash,
    sockethost: sockethost,
    cases: cases.cases,
    users: top3,
    rolls: live,
    stat_: [stat_users,stat_online,stat_opened],
    isadmin: isadmin
  });
});
app.get('/terms', function(req, res) {
  var vkid = 1;
  var hash = 1;
  var isadmin = false;
  if (req.isAuthenticated()) {
    vkid = req.user.id;
    hash = sha(salt + ":" + vkid);
    if (isAdmin(req.user.id)) {
      isadmin = true;
    }
  }
  res.render('terms', {
    curpage: 'terms',
    title: render_title,
    user: (('user' in req && 'id' in req.user) ? getUser(req.user.id) : false),
    vkid: vkid,
    salt: hash,
    sockethost: sockethost,
    cases: cases.cases,
    users: top3,
    rolls: live,
    stat_: [stat_users,stat_online,stat_opened],
    isadmin: isadmin
  });
});
app.get('/guaranties', function(req, res) {
  var vkid = 1;
  var hash = 1;
  var isadmin = false;
  if (req.isAuthenticated()) {
    vkid = req.user.id;
    hash = sha(salt + ":" + vkid);
    if (isAdmin(req.user.id)) {
      isadmin = true;
    }
  }
  res.render('guaranties', {
    curpage: 'guaranties',
    title: render_title,
    user: (('user' in req && 'id' in req.user) ? getUser(req.user.id) : false),
    vkid: vkid,
    salt: hash,
    sockethost: sockethost,
    cases: cases.cases,
    users: top3,
    rolls: live,
    stat_: [stat_users,stat_online,stat_opened],
    isadmin: isadmin
  });
});

app.get('/bonuses', function(req, res) {
  var vkid = 1;
  var hash = 1;
  var isadmin = false;
  if (req.isAuthenticated()) {
    vkid = req.user.id;
    hash = sha(salt + ":" + vkid);
    if (isAdmin(req.user.id)) {
      isadmin = true;
    }
  }
  res.render('bonuses', {
    curpage: 'bonuses',
    title: render_title,
    user: (('user' in req && 'id' in req.user) ? getUser(req.user.id) : false),
    vkid: vkid,
    salt: hash,
    sockethost: sockethost,
    cases: cases.cases,
    users: top3,
    rolls: live,
    stat_: [stat_users,stat_online,stat_opened],
    isadmin: isadmin
  });
});
app.get('/profile/:vkid', function(req, res) {
  var reqvkid = req.params.vkid;
  var vkid = 1;
  var hash = 1;
  var isadmin = false;
  if (req.isAuthenticated()) {
    vkid = req.user.id;
    hash = sha(salt + ":" + vkid);
    if (isAdmin(req.user.id)) {
      isadmin = true;
    }
  }
  if (!(reqvkid in userlist)) return res.redirect('/');
  var requser = getUser(reqvkid, 'opened');
  res.render('profile', {
    curpage: 'profile',
    title: render_title,
    user: (('user' in req && 'id' in req.user) ? getUser(req.user.id) : false),
    vkid: vkid,
    salt: hash,
    sockethost: sockethost,
    cases: cases.cases,
	
    users: top3,
    rolls: live,
	 opened: requser.opened,
    stat_: [stat_users,stat_online,stat_opened],
    rollss: requser.opened,
    requser: requser,
    isadmin: isadmin
  });
});
app.get('/account', function(req, res) {
  var vkid = 1;
  var hash = 1;
  var isadmin = false;
  if (req.isAuthenticated()) {
    vkid = req.user.id;
    hash = sha(salt + ":" + vkid);
    var isadmin = isAdmin(req.user.id);
    var info = getUser(vkid, 'referal', 'finance', 'opened', 'transactions');
    res.render('account', {
      curpage: 'account',
      title: render_title,
      user: (('user' in req && 'id' in req.user) ? getUser(req.user.id) : false),
      vkid: vkid,
      salt: hash,
      sockethost: sockethost,
      cases: cases.cases,
      users: top3,
      rolls: live,
      info: info,
      opened: info.opened,
      transactions: info.transactions,
      stat_: [stat_users,stat_online,stat_opened],
      isadmin: isadmin,
      ref: Base64.encode(vkid),
      refer: Base64.encode(info.ref || ''),
      refcfg: config.ref,
      refsum: info.refsum,
      refcount: info.refcount
    });
  } else {
    res.redirect('/');
  }
});
app.get('/case/:caseid', function(req, res) {
  var paramid = req.params.caseid;
  var vkid = 1;
  var hash = 1;
  var isadmin = false;
  if (req.isAuthenticated()) {
    vkid = req.user.id;
    hash = sha(salt + ":" + vkid);
    if (isAdmin(req.user.id)) {
      isadmin = true;
    }
  }
  var caseinfo = getCaseById(paramid);
  if (!caseinfo) {
    res.json({
      success: false,
      error: "no such caseid"
    });
    return;
  } else if (!caseinfo.prizes.length) {
    res.redirect('/');
  }
  var withdrawed = 0;
  var minprize = maxprize = (caseinfo.prizes.length ? caseinfo.prizes[0].value || 0 : 0);
  for (var key in caseinfo.prizes) {
    var x = parseFloat(caseinfo.prizes[key].value);
    if(x!=x) continue;
    minprize = Math.min(minprize, x);
    maxprize = Math.max(maxprize, x);
  };
  var i = rolls.length;
  while (i--)
    if (rolls[i].caseid == paramid) withdrawed += parseFloat(rolls[i].prize);
  res.render('case', {
    curpage: 'case',
    title: render_title,
    user: (('user' in req && 'id' in req.user) ? getUser(req.user.id) : false),
    vkid: vkid,
    salt: hash,
    sockethost: sockethost,
    caseinfo: caseinfo,
    minprize: minprize,
    maxprize: maxprize,
    users: top3,
    rolls: live,
    stat_: [stat_users,stat_online,stat_opened],
    isadmin: isadmin,
    extrachance: config.extra,
    withdrawed: withdrawed
  });
});
app.get('/deposit', function(req, res) {
  var vkid = 1;
  var hash = 1;
  var isadmin = false;
  if (req.isAuthenticated()) {
    vkid = req.user.id;
    hash = sha(salt + ":" + vkid);
    var b = parseFloat(req.query.b || 0);
    b = round(b, 2);
    if(config.debug) console.log('DEPOSIT: ', vkid, salt, b);
    if (b < 10 || b > 15000) return res.redirect('/?error=deposit:invalid');
   var methods = "1,2,3,45,60,61,62,63,64,67,69,74,79,80,81,82,84,87,94,98,100,102,103,106,109,110,112,113,114,115,116,117,118,123,124,125,130,131,132,133,136,137,138,139,140,141,142,143,146,147,150".split(',');
   var tid = ((typeof transactions[transactions.length - 1] === 'undefined') ? 1 : (transactions[transactions.length - 1].id + 1));
   var tr = {
	  id: tid,
      type: 'deposit',
      status: 'waiting',
      amount: b,
      timestamp: round(new Date / 1000),
      vkid: vkid
    };
    mysqlQueue.push('INSERT INTO transactions (' + Object.keys(tr).map(k => '`' + k + '`').join(',') + ') VALUES (' + Object.keys(tr).map(k => '\'' + tr[k] + '\'').join(',') + ')');
    transactions.push(tr);
    var sig = md5(config.merchant.id + ':' + b + ':' + config.merchant.secret + ':' + tr.id);
    var url = 'https://www.free-kassa.ru/merchant/cash.php?m=' + config.merchant.id + '&oa=' + b + '&o=' + tr.id + '&s=' + sig + '&us_d=' + vkid;
    if ('i' in req.query && methods.indexOf('' + req.query.i) >= 0) url += '&i=' + req.query.i;
    res.redirect(url);
  } else {
    res.redirect('/?error=?deposit:auth');
  }
});
app.get('/ref/:ref', function(req, res) {
  var ref = req.params.ref;
  var vkid = 1;
  var hash = 1;
  if (req.isAuthenticated()) {
    vkid = req.user.id;
    hash = sha(salt + ":" + vkid);
    var usr = getUser(vkid);
    var refvkid = parseInt(Base64.decode(ref));
    if (refvkid == vkid);
    if (usr.vkid == refvkid) return res.json({
      success: false,
      done: true,
      error: 'Вы вводите свой код'
    });
	if (usr.ref && usr.ref != '') return res.json({
      success: false,
      done: true,
      error: 'Вы уже ввели код'
    });
    if (!(refvkid in userlist)) return res.json({
      success: false,
      done: true,
      error: 'Код недействителен'
    });
    // Изменяем рефера у реферала
    mysqlQueue.push('UPDATE users SET ref=' + refvkid + ' WHERE vkid=' + vkid);
    userlist[''+vkid].ref = refvkid;
    // Пополняем баланс реферала
    mysqlQueue.push('UPDATE users SET balance=balance+' + config.ref.guest.value + ' WHERE vkid=' + vkid);
    userlist[''+vkid].balance += parseFloat(config.ref.guest.value);
    sendbalance(vkid);
	var tid = ((typeof transactions[transactions.length - 1] === 'undefined') ? 1 : (transactions[transactions.length - 1].id + 1));
    // Создаём транзакцию реферального начисления
    var tr = {
      id: tid,
      type: 'ref',
      status: 'done',
      amount: config.ref.guest.value,
      timestamp: round(new Date / 1000),
      vkid: vkid
    };
	
    mysqlQueue.push('INSERT INTO transactions (' + Object.keys(tr).map(k => '`' + k + '`').join(',') + ') VALUES (' + Object.keys(tr).map(k => '\'' + tr[k] + '\'').join(',') + ')');
    transactions.push(tr);
    // Если реферальный бонус рефера статичный за каждого реферала
    if (config.ref.ref.type == 'stat') {
      // Пополняем баланс рефера
      mysqlQueue.push('UPDATE users SET balance=balance+' + config.ref.ref.value + ' WHERE vkid=' + refvkid);
      userlist[''+refvkid].balance += parseFloat(config.ref.ref.value);
      sendbalance(refvkid);
      // Добавляем транзакцию реферального начисления для рефера
      mysqlQueue.push('INSERT INTO transactions (`type`, `status`, `amount`, `timestamp`, `vkid`) VALUES (\'ref\', \'done\', ' + config.ref.ref.value + ', ' + round(new Date / 1000) + ' ,' + refvkid + ')');
      var tid = ((typeof transactions[transactions.length - 1] === 'undefined') ? 1 : (transactions[transactions.length - 1].id + 1));
	  transactions.push({
        id: tid,
        type: 'ref',
        status: 'done',
        amount: config.ref.ref.value,
        timestamp: round(new Date / 1000),
        vkid: refvkid
      });
    }
    res.json({
      success: true,
      done: true
    });
  } else {
    res.json({
      success: false,
      error: 'Ошибка авторизации'
    });
  }
});
app.get('/login', function(req, res) {
  res.render('login', {
    curpage: 'login',
    title: render_title,
    user: (('user' in req && 'id' in req.user) ? getUser(req.user.id) : false)
  });
});
app.get('/auth/vk', passport.authenticate('vkontakte'), function(req, res) {});
app.get('/auth/vk/callback', passport.authenticate('vkontakte', {
  failureRedirect: '/login'
}), function(req, res) {
  res.redirect('/');
});
app.get('/logout', function(req, res) {
  req.logout();
  res.redirect('/');
});
app.get('/admin', function(req, res) {
  if (req.isAuthenticated()) {
    if (config.debug) console.log(req.user.id + ' is trying to access admin');
    if (isAdmin(req.user.id)) {
      var vkid = req.user.id;
      var hash = sha(salt + ":" + vkid);
      var output = {
        title: render_title,
        user: (('user' in req && 'id' in req.user) ? getUser(req.user.id) : false),
        vkid: vkid,
        salt: hash,
        sockethost: sockethost,
        settings: cases,
        profitperc: config.profitperc,
        stats: {
          income: {
            today: 0,
            total: 0
          },
          profit: {
            today: 0,
            total: cases.profit
          },
          withdraw: {
            today: 0,
            total: 0
          },
          users: {
            today: 0,
            total: stat_users
          }
        },
        charts: {
          profit: [],
		  deposit: [],
		  withdraw: []
        },
        chartsorder: []
      };
      var today = new Date;
      var month_to_string = ['Янв', 'Фев', 'Мар', 'Апр', 'Май', 'Июн', 'Июл', 'Авг', 'Сен', 'Окт', 'Ноя', 'Дек'];
      today = round(new Date(today.toDateString()) / 1000);
      var monthAgo = new Date;
      monthAgo.setDate(monthAgo.getDate() - 30);
      monthAgo = new Date(monthAgo.toDateString());
      var profitstat = withdrawstat = depositstat = [];
      for (var i = rolls.length - 1; i >= 0; i--) {
        var roll = Object.assign({}, rolls[i]);
        if (roll.time > today) output.stats.profit.today += parseFloat(roll.profit);
        if (roll.time > round(monthAgo / 1000)) {
          profitstat.push(roll);
        } else {
          break;
        }
      }
      for (var i = transactions.length; i > 0; i--) {
        var tr = Object.assign({}, transactions[i - 1]);
          if (tr.type == 'deposit' && tr.status == 'done') {
            if (tr.timestamp > today) output.stats.income.today += parseFloat(tr.amount);
            if (tr.timestamp > round(monthAgo / 1000)) depositstat.push(tr);
            output.stats.income.total += parseFloat(tr.amount);
		  } else if (tr.type == 'withdraw' && tr.status == 'done') {
            if (tr.timestamp > today) output.stats.withdraw.today += parseFloat(tr.amount);
            if (tr.timestamp > round(monthAgo / 1000)) withdrawstat.push(tr);
            output.stats.withdraw.total += parseFloat(tr.amount);
          }
      }
      for (var key in userlist) {
        if (userlist[''+key].regdate > today) output.stats.users.today++;
      }

      var profit_by_days = {};
	  var deposit_by_days = {};
	  var withdraw_by_days = {};
      var daytime = new Date();
      daytime = new Date(daytime.toDateString());
       while (daytime > monthAgo) {
        var date = daytime.getDate() + ' ' + month_to_string[daytime.getMonth()];
        output.chartsorder.splice(0, 0, date);
        if (!(date in profit_by_days)) profit_by_days[date] = 0;
        if (!(date in deposit_by_days)) deposit_by_days[date] = 0;
        if (!(date in withdraw_by_days)) withdraw_by_days[date] = 0;
		
        while ( profitstat.length) { 
          if (profitstat[0].time < (daytime / 1000)) break;  
     profit_by_days[date] += parseFloat(profitstat[0].profit);        
     profitstat.splice(0, 1);
        }
        for (var i = depositstat.length - 1 ; i>=0; i--) {
          if (depositstat[i].timestamp < (daytime / 1000)) break;
          deposit_by_days[date] += parseInt(depositstat[i].amount);            
          depositstat.splice(0, 1);     
   
        }
  
        for (var i = withdrawstat.length - 1 ; i>=0; i--) {  
          if (withdrawstat[i].timestamp < (daytime / 1000)) break;
          withdraw_by_days[date] += parseInt(withdrawstat[i].amount);     
          withdrawstat.splice(0, 1);
        }
        daytime.setDate(daytime.getDate() - 1);
      }
      output.charts.profit = profit_by_days;
      output.charts.deposit = deposit_by_days;
      output.charts.withdraw = withdraw_by_days;
      res.render('admin/admin', output);
    }
  } else {
    res.redirect('/');
  }
});
app.get('/admin/cases', function(req, res) {
  if (req.isAuthenticated()) {
    if (isAdmin(req.user.id)) {
      var vkid = req.user.id;
      var hash = sha(salt + ":" + vkid);
      res.render('admin/cases', {
        title: render_title,
        user: (('user' in req && 'id' in req.user) ? getUser(req.user.id) : false),
        vkid: vkid,
        salt: hash,
        sockethost: sockethost,
        settings: cases
      });
    } else {
      if (config.debug) console.log(req.user.id + ' tried to access admin panel');
      res.redirect('/');
    }
  } else {
    res.redirect('/');
  }
});
app.get('/admin/payments', function(req, res) {
  if (req.isAuthenticated()) {
    if (isAdmin(req.user.id)) {
      var vkid = req.user.id;
      var hash = sha(salt + ":" + vkid);
      var payments = [];
      for (var i = withdrawal.length - 1; i >= 0; i--) {
        if(withdrawal[i].status != 'waiting') continue;
        var payment = Object.assign({}, withdrawal[i], {
          income: 0,
          withdraw: 0,
          withdrawing: 0,
          refsum: 0
        });
        payment.username = userlist[''+payment.vkid].username;
        payment.userimg = userlist[''+payment.vkid].userimg;
        payment.balance = userlist[''+payment.vkid].balance;
        for (var key in transactions) {
          var tr = transactions[key];
          if (tr.type == 'deposit' && tr.vkid == payment.vkid && tr.status == 'done') payment.income += tr.amount;
          if (tr.type == 'withdraw' && tr.vkid == payment.vkid && tr.status == 'done') payment.withdraw += tr.amount;
          if (tr.type == 'withdraw' && tr.vkid == payment.vkid && tr.status == 'done') payment.withdrawing += tr.amount;
          if (tr.type == 'ref' && tr.vkid == payment.vkid && tr.status == 'done') payment.refsum += tr.amount;
        }
        payments.push(payment);
      }
      res.render('admin/payments', {
        title: render_title,
        user: (('user' in req && 'id' in req.user) ? getUser(req.user.id) : false),
        vkid: vkid,
        salt: hash,
        sockethost: sockethost,
        settings: cases,
        payments: payments
      });
    } else {
      if (config.debug) console.log(req.user.id + ' tried to access admin panel');
      res.redirect('/');
    }
  } else {
    res.redirect('/');
  }
});
app.get('/admin/payment/:action/:pid', function(req, res) {
  if (req.isAuthenticated()) {
    if (isAdmin(req.user.id)) {
      var vkid = req.user.id;
      var hash = sha(salt + ":" + vkid);
      var action = req.params.action;
      var pid = req.params.pid;
      var payment;
      if (payment = getWithdraw(pid)) {
        if (action == 'ban') {
          action = 'reject';
          mysqlQueue.push('UPDATE users SET banned = 1 WHERE vkid=' + payment.vkid);
          userlist[''+payment.vkid].banned = true;
        }
        if (action == 'reject') {
          mysqlQueue.push('UPDATE users SET balance = balance + ' + payment.amount + ' WHERE vkid=' + payment.vkid);
          userlist[''+payment.vkid].balance += parseFloat(payment.amount);
          sendbalance(payment.vkid);
        }
        mysqlQueue.push('UPDATE withdraw SET status=\'' + (action == 'reject' ? 'reject' : 'done') + '\' WHERE id=' + pid);
        mysqlQueue.push('UPDATE transactions SET status=\'' + (action == 'reject' ? 'reject' : 'done') + '\' WHERE id=' + payment.tid);
        for (var i = transactions.length - 1; i >= 0; i--) {
          if (transactions[i].id == payment.tid) {
            transactions[i].status = (action == 'reject' ? 'reject' : 'done');
            break;
          }
        }
        for (var i = withdrawal.length - 1; i >= 0; i--) {
          if (withdrawal[i].id == pid) {
            withdrawal[i].status = (action == 'reject' ? 'reject' : 'done');
            break;
          }
        }
        res.json({
          success: true
        });
      } else {
        res.json({
          success: false,
          error: 'Указаная выплата не существует'
        });
      }
    } else {
      if (config.debug) console.log(req.user.id + ' tried to access admin panel');
      res.json({
        success: false,
        error: 'Ошибка авторизации'
      });
    }
  } else {
    res.json({
      success: false,
      error: 'Ошибка авторизации'
    });
  }
});
app.get('/admin/users', function(req, res) {
  if (req.isAuthenticated()) {
    if (isAdmin(req.user.id)) {
      var vkid = req.user.id;
      var hash = sha(salt + ":" + vkid);
      res.render('admin/users', {
        title: render_title,
        user: (('user' in req && 'id' in req.user) ? getUser(req.user.id) : false),
        vkid: vkid,
        salt: hash,
        sockethost: sockethost,
        settings: cases,
        users: Object.keys(userlist).map(a => Object.assign({}, userlist[''+a]))
      });
    } else {
      if (config.debug) console.log(req.user.id + ' tried to access admin panel');
      res.redirect('/');
    }
  } else {
    res.redirect('/');
  }
});
app.get('/admin/user/:vkid', function(req, res) {
  if (req.isAuthenticated()) {
    if (isAdmin(req.user.id)) {
      var vkid = req.user.id;
      var hash = sha(salt + ":" + vkid);
      if (!(req.params.vkid in userlist)) return res.redirect('/admin/users');
      var requser = getUser(req.params.vkid, 'finances', 'referals');
      var referals = [];
      for (var key in requser.referals) {
        referals.push(getUser(requser.referals[key], 'finances'));
      }

      var info = {
        id: requser.id || 0,
        vkid: requser.vkid || 0,
        banned: requser.banned || 0,
        username: requser.username || '',
        userimg: requser.userimg || '',
        balance: requser.balance || 0,
        chance: requser.chance || 0,
        accesstoken: requser.accesstoken || '',
        regdate: requser.regdate || 0,
        ip: requser.ip || '127.0.0.1',
        won: requser.won || 0,
        income: requser.income || 0,
        withdraw: requser.withdraw || 0,
        withdrawing: requser.withdrawing || 0,
        refsum: requser.refsum || 0,
        refcount: requser.refcount || 0,
        rolls: requser.rolls || 0
      };
      res.render('admin/user', {
        title: render_title,
        user: (('user' in req && 'id' in req.user) ? getUser(req.user.id) : false),
        vkid: vkid,
        salt: hash,
        sockethost: sockethost,
        settings: cases,
        info: info,
        refcode: Base64.encode(req.params.vkid),
        referals: (referals && referals.length) ? referals : []
      });
    } else {
      if (config.debug) console.log(req.user.id + ' tried to access admin panel');
      res.redirect('/');
    }
  } else {
    res.redirect('/');
  }
});
app.get('/admin/toggleban/:vkid', function(req, res) {
  if (req.isAuthenticated()) {
    if (isAdmin(req.user.id)) {
      var vkid = req.user.id;
      var hash = sha(salt + ":" + vkid);
      if (req.params.vkid in userlist) {
        mysqlQueue.push('UPDATE users SET banned = 1 - banned WHERE vkid = ' + req.params.vkid);
        userlist[''+req.params.vkid].banned = !userlist[''+req.params.vkid].banned;
      }
      res.json({
        success: true
      });
    } else {
      if (config.debug) console.log(req.user.id + ' tried to access admin panel');
      res.redirect('/');
    }
  } else {
    res.redirect('/');
  }
});
app.get('/admin/updateconf', function(req, res) {
  if (req.isAuthenticated()) {
    if (isAdmin(req.user.id)) {
      var vkid = req.user.id;
      var hash = sha(salt + ":" + vkid);
      var bal = req.query.balance || cases.balance;
      var prof = req.query.profit || cases.profit;
      var profitperc = req.query.profitperc || config.profitperc;
      config.profitperc = profitperc;
      cases.balance = bal;
      cases.profit = prof;
      savecases();
      saveconf();
      res.json({
        success: true
      });
    } else {
      if (config.debug) console.log(req.user.id + ' tried to access admin panel');
      res.redirect('/');
    }
  } else {
    res.redirect('/');
  }
});
app.get('/admin/updatebalance/:vkid', function(req, res) {
  if (req.isAuthenticated()) {
    if (isAdmin(req.user.id)) {
      var vkid = req.user.id;
      var hash = sha(salt + ":" + vkid);
      if (req.params.vkid in userlist) {
        mysqlQueue.push('UPDATE users SET balance = ' + req.query.balance + ' WHERE vkid = ' + req.params.vkid);
        userlist[''+req.params.vkid].balance += parseFloat(req.query.balance);
      }
      res.json({
        success: true
      });

    } else {
      if (config.debug) console.log(req.user.id + ' tried to access admin panel');
      res.redirect('/');
    }
  } else {
    res.redirect('/');
  }
});
app.get('/admin/updatechance/:vkid', function(req, res) {
  if (req.isAuthenticated()) {
    if (isAdmin(req.user.id)) {
      var vkid = req.user.id;
      var hash = sha(salt + ":" + vkid);
      if (req.params.vkid in userlist) {
        mysqlQueue.push('UPDATE users SET chance = ' + round(req.query.chance / 100, 2) + ' WHERE vkid = ' + req.params.vkid);
        userlist[''+req.params.vkid].chance = round(req.query.chance / 100, 2);
      }
      res.json({
        success: true
      });
    } else {
      if (config.debug) console.log(req.user.id + ' tried to access admin panel');
      res.redirect('/');
    }
  } else {
    res.redirect('/');
  }
});
app.get('/admin/case/:caseid', function(req, res) {
  var paramid = req.params.caseid;
  if (req.isAuthenticated()) {
    if (isAdmin(req.user.id)) {
      var casebox = getCaseById(paramid);
      if (null === casebox) {
        casebox = Object.assign({}, cases.defaultCase);
        casebox.id = Object.keys(cases.cases).length + 1;
        while (null !== getCaseById(casebox.id)) casebox.id++;
      }
      var vkid = req.user.id;
      var hash = sha(salt + ":" + vkid);
      res.render('admin/case', {
        title: render_title,
        user: (('user' in req && 'id' in req.user) ? getUser(req.user.id) : false),
        vkid: vkid,
        salt: hash,
        sockethost: sockethost,
        settings: cases,
        casebox: casebox
      });
    } else {
      if (config.debug) console.log(req.user.id + ' tried to access admin panel');
      res.redirect('/');
    }
  } else {
    res.redirect('/');
  }
});
app.get('/admin/del_case', function(req, res) {
  if (req.isAuthenticated()) {
    if (isAdmin(req.user.id)) {
      cases.cases.splice(getCaseKeyById(req.query.caseid), 1);
      savecases();
      res.json({
        success: true
      });
    } else {
      if (config.debug) console.log(req.user.id + ' tried to access admin panel');
      res.json({
        success: false
      });
    }
  } else {
    res.json({
      success: false
    });
  }
});
app.get('/admin/case_order', function(req, res) {
  if (req.isAuthenticated()) {
    if (isAdmin(req.user.id)) {
      var newOrder = [];
      for (var key in req.query.order) {
        newOrder.push(getCaseById(req.query.order[key]));
      }
      cases.cases = newOrder;
      savecases();
      res.json({
        success: true
      });
    } else {
      if (config.debug) console.log(req.user.id + ' tried to access admin panel');
      res.json({
        success: false
      });
    }
  } else {
    res.json({
      success: false
    });
  }
});
app.get('/admin/save_case', function(req, res) {
  if (req.isAuthenticated()) {
    if (isAdmin(req.user.id)) {
      var caseid = req.query.id;
      if (caseid == 'new' || !getCaseById(caseid)) {
        caseid = 0;
        while (getCaseById(caseid)) caseid++;
        if(config.debug) console.log(cases.cases.length);
        var newcase = Object.assign({}, cases.defaultCase, {
          id: caseid
        });
        cases.cases.push(newcase);
        if(config.debug) console.log(cases.cases.length, newcase);
      }
      var casebox = getCaseById(caseid);
      if (config.debug) console.log(caseid, casebox);
      casebox.id = req.query.id;
      casebox.name = req.query.name || cases.defaultCase.name;
      casebox.cat = req.query.cat || cases.defaultCase.cat;
      casebox.img = req.query.img || cases.defaultCase.img;
      casebox.price = parseFloat(req.query.price) || cases.defaultCase.price;
      casebox.description = req.query.description || cases.defaultCase.description;
      casebox.prizes = req.query.prizes || [];
      cases.cases[getCaseKeyById(caseid)] = casebox;
      if(config.debug) console.log(cases.cases[getCaseKeyById(caseid)], casebox)
      savecases();
      res.json({
        success: true
      });
    } else {
      if (config.debug) console.log(req.user.id + ' tried to access admin panel');
      res.json({
        success: false
      });
    }
  } else {
    res.json({
      success: false
    });
  }
});
app.get('/freekassa', function(req, res) {
  var input = {
    merchant_id: req.query.MERCHANT_ID || '',
    amount: parseFloat(req.query.AMOUNT) || 0,
    intid: req.query.initid || '',
    merchant_order_id: req.query.MERCHANT_ORDER_ID || '',
    p_email: req.query.P_EMAIL || '',
    p_phone: req.query.P_PHONE || '',
    cur_id: req.query.CUR_ID || '',
    sign: req.query.SIGN || '',
    us_d: parseInt(req.query.us_d) || 0
  };
  var sign = md5(config.merchant.id + ':' + input.amount + ':' + config.merchant.secret2 + ':' + input.merchant_order_id);
  if (sign.toLowerCase() !== input.sign.toLowerCase()) {
    return res.send('Invalid sign');
  }
  $curs = 1;
  // Берём транзакцию по переданному с FreeKassa ID
  var tr;
  if (tr = getTransaction(input.merchant_order_id)) {
    if (tr.status == 'waiting') {
      mysqlQueue.push('UPDATE transactions SET status=\'done\' WHERE id = ' + input.merchant_order_id);
      transactions[tr.___key].status = 'done';
      if (getUser(''+input.us_d)) {
        var usr = getUser(''+input.us_d);
        mysqlQueue.push('UPDATE users SET balance = balance + ' + input.amount + ' WHERE vkid = ' + input.us_d);
        userlist[''+input.us_d].balance += parseFloat(input.amount);
        sendbalance(input.us_d);
        if (usr.ref && usr.ref > 0) {
          var refer = usr.ref;
          if (refer in userlist && config.ref.ref.type == 'perc') {
            var refbu = input.amount * config.ref.ref.value; //REFer Balance Update
            mysqlQueue.push('UPDATE users SET balance = balance + ' + refbu + ' WHERE vkid =' + refer);
            mysqlQueue.push('INSERT INTO transactions (`type`,`status`,`amount`,`timestamp`,`vkid`) VALUES (\'ref\',\'done\',' + refbu + ',' + round(new Date / 1000) + ',' + refer + ')');
            userlist[''+refer].balance += refbu;
            sendbalance(refer);
			var tid = ((typeof transactions[transactions.length - 1] === 'undefined') ? 1 : (transactions[transactions.length - 1].id + 1));
            transactions.push({
              id: tid,
              type: 'ref',
              status: 'done',
              amount: refbu,
              timestamp: round(new Date / 1000),
              vkid: refer
            });
          }
        }
      }
    }
  }
  res.send('YES');
});
app.get('/withdraw', function(req, res) {
  var input = {
    b: parseFloat(req.query.b || 0),
    c: req.query.c || '',
    e: req.query.e || ''
  };
  var vkid = 1;
  var hash = 1;
  if (req.isAuthenticated()) {
    var vkid = req.user.id;
    var hash = sha(salt + ":" + vkid);
    if (isNaN(input.b) || input.b < 100 || input.b > 15000) return res.json({
      success: false,
      error: 'Недопустимая сумма'
    });
    if (input.c.length > 255) input.c = input.c.substr(0, 255);
    console.log(input.c);
    input.c = input.c.removequots();
    if (input.e != 'webmoney' && input.e != 'yandex' && input.e != 'qiwi') return res.json({
      success: false,
      error: 'Выберите платёжную систему'
    });
    var usr = getUser(vkid);
    if (usr.banned) return res.json({
      success: false,
      error: 'Вы были заблокированы'
    });
    if (usr.balance < input.b) return res.json({
      success: false,
      error: 'Недостаточно средств на вашем балансе'
    });
    mysqlQueue.push('UPDATE users SET balance = balance - ' + input.b + ' WHERE vkid = ' + vkid);
    userlist[''+vkid].balance -= parseFloat(input.b);
    mysqlQueue.push('INSERT INTO transactions (`type`,`status`,`amount`,`timestamp`,`vkid`) VALUES (\'withdraw\',\'waiting\',' + input.b + ',' + round(new Date / 1000) + ',' + vkid + ')');
    var tid = ((typeof transactions[transactions.length - 1] === 'undefined') ? 1 : (transactions[transactions.length - 1].id + 1));
    transactions.push({
      id: tid,
      type: 'withdraw',
      status: 'waiting',
      amount: input.b,
      timestamp: round(new Date / 1000),
      vkid: vkid
    });
    mysqlQueue.push('INSERT INTO withdraw (`status`,`amount`,`account`,`paysystem`,`time`,`vkid`,`tid`) VALUES (\'waiting\',' + input.b + ',\'' + input.c + '\',\'' + input.e + '\',' + round(new Date / 1000) + ',' + vkid + ',' + tid + ')');
    if (withdrawal == null) {
	    withdrawal = [];
    }
    var lastWithdrawalID = ((typeof withdrawal[withdrawal.length - 1] === 'undefined') ? 1 : (withdrawal[withdrawal.length - 1].id + 1));
    withdrawal.push({
      id: lastWithdrawalID,
      status: 'waiting',
      amount: input.b,
      account: input.c,
      paysystem: input.e,
      time: round(new Date / 1000),
      vkid: vkid,
      tid: tid
    });
    res.json({
      success: true
    });
  } else {
    res.json({
      success: false,
      error: 'Ошибка авторизации'
    });
  }
});

var http = require('http').Server(app);
var io = require('socket.io')(config.socket.port);

io.sockets.on('connection', function(socket) {

  stat_online++;
  io.emit('stats_update', {
    opened: stat_opened,
    online: stat_online,
    users: stat_users
  });

  socket.on('auth', function(data) {
    if (config.debug) console.log('auth');
    socket_connections[socket.id] = data.vkid;
    if (data.salt == sha(salt + ":" + data.vkid)) {
      if (config.debug) console.log('auth success');
      socket.emit('auth_success');
      sendbalance(data.vkid);
    } else {
      if (config.debug) console.log('auth fail');
      socket.emit('auth_fail');
    }
  });
  
  
	socket.on('buyTicket', function(data) {
		if (!checksalt(data.vkid, data.salt)) {
			if (config.debug) console.log('wrong salt');
				socket.emit('auth_fail');
			return;
		}
		
		query('SELECT * from users WHERE vkid="' + data.vkid + '"', function always(err, rows, fields) {
			if(rows.length >= 1) {	
    
				query('SELECT * from giveaway WHERE active=1', function always(err, rows2, fields) {
					if(rows2.length >= 1) {	
    
						if(rows[0].giveawayState == 0) {
    
							if(rows[0].balance >= rows2[0].ticketPrice) {
								query('UPDATE giveaway SET players=(players+1) WHERE active=1');
								query('UPDATE users set giveawayState=1 WHERE vkid="' + data.vkid + '"');
								query('UPDATE users set balance=(balance-' + rows2[0].ticketPrice + ') WHERE vkid="' + data.vkid + '"');
								userlist[''+data.vkid].balance -= parseFloat(rows2[0].ticketPrice);
								sendbalance(data.vkid);
								refreshGiveaways("updateGiveaway", "all");
			
								socket.emit('msg', { info : "Билет успешно куплен!", status : "success" });
    
								var time = Math.round(new Date().getTime()/1000);
    
								if((rows2[0].players+1) >= rows2[0].playersAll) {
									console.log("end Giveaway!");
									query('SELECT * from users WHERE giveawayState=1 ORDER BY rand() LIMIT 1', function always(err, rowsp, fields) {
										query('UPDATE users set balance=(balance+' + rows2[0].item_price + ') WHERE vkid="' + rowsp[0].vkid + '"');
										userlist[''+rowsp[0].vkid].balance += rows2[0].item_price;
										sendbalance(rowsp[0].vkid);
										
										query("UPDATE `giveaway` SET active=2 WHERE active=1");
    
										query("UPDATE `info` SET info_value='" + rowsp[0].username + "' WHERE `info_key`='ga_nickname'");
										query("UPDATE `info` SET info_value='" + rowsp[0].userimg + "' WHERE `info_key`='ga_ava'");
										
										//var gr = gaItems[getRandomInt(0, (gaItems.length-1))];
											
											var item = cases.cases[1].prizes[getRandomInt(1, 6)];
											var a1 = parseFloat(item.value) / 100 * 120;
											var b1 = a1 / 20;
											var c1 = a1 / b1;
											var time = Math.round(new Date().getTime()/1000);
											query("INSERT INTO `giveaway` SET item_name='" + item.name + "',item_img='" + item.img + "',item_price=" + item.value + ",players=0,playersAll=" + c1 + ",ticketPrice=" + b1 + ",active=1,start="+time);
											console.log("Full wipe succefully!");
											query('SELECT * from giveaway WHERE active=1', function always(err, rows, fields) {
												if(rows.length >= 1) {	
													setTimeout(function() {
														query('SELECT * from info WHERE `info_key`="ga_nickname" OR `info_key`="ga_ava"', function always(err, rows3, fields) {
															query('SELECT * from users WHERE `giveawayState`=1', function always(err, rowed, fields) {
																var itemName = rows[0].item_name;
																var dataTape = [];
																for(var o=0; o<rowed.length; o++) {
																	dataTape.push(rowed[o].userimg);
																}
																var data = { 
																	item_name : rows[0].item_name, 
																	item_price : rows[0].item_price, 
																	item_img : rows[0].item_img, 
																	players : rows[0].players,
																	playersAll : rows[0].playersAll,
																	ticketPrice : rows[0].ticketPrice,
																	lastAva : rows3[0].info_value,
																	lastName : rows3[1].info_value,
																	tape : dataTape,
																	timer : time
																};
																io.emit("updateGiveaway", data);
																isBuying = false;
    
    
																query("UPDATE `users` SET giveawayState=0");
															});
														});
													}, 500);
												}
											});
										
									});
								} else {
									isBuying = false;
								}
							} else {
								socket.emit('msg', { info : "Недостаточно денег!", status : "error" });
								isBuying = false;
							}
						} else {
							socket.emit('msg', { info : "Вы уже приобрели билет!", status : "error" });
							isBuying = false;
						}
					} else {
						socket.emit('msg', { info : "Розыгрыш уже закончен!", status : "error" });
						isBuying = false;
					}
				});
			} else {
				isBuying = false;
			}
		});
	})
	
	
  	// Розыгрыши
	function refreshGiveaways(state, state2) {
		query('SELECT * from giveaway WHERE active=1', function always(err, rows, fields) {
			if(rows.length >= 1) {	
				query('SELECT * from info WHERE `info_key`="ga_nickname" OR `info_key`="ga_ava"', function always(err, rows3, fields) {
					var time = Math.round(new Date().getTime()/1000);
					if(parseFloat(time) - 18000 <= parseFloat(rows[0].start)) {
						var itemName = rows[0].item_name;
						var data = { 
							item_name : rows[0].item_name, 
							item_price : rows[0].item_price, 
							item_img : rows[0].item_img, 
							item_type : rows[0].item_type, 
							players : rows[0].players,
							playersAll : rows[0].playersAll,
							ticketPrice : rows[0].ticketPrice,
							lastAva : rows3[0].info_value,
							lastName : rows3[1].info_value,
							timer : rows[0].start,
							refresh: 1
						};
						if(state2 == "all") {
							io.emit(state, data);
						} else {
							socket.emit(state, data);
						}
					} else {
						console.log("end Giveaway!");
						query('SELECT * from giveaway WHERE active=1', function always(err, laster, fields) {
							query("UPDATE `giveaway` SET active=2 WHERE active=1");
							
							//var gr = gaItems[getRandomInt(0, (gaItems.length-1))];
								var item = cases.cases[1].prizes[getRandomInt(1, 6)];
								var a1 = parseFloat(item.value) / 100 * 120;
								var b1 = a1 / 20;
								var c1 = a1 / b1;
								var time = Math.round(new Date().getTime()/1000);
								console.log(item);
								query("INSERT INTO `giveaway` SET item_name='" + item.name + "',item_img='" + item.img + "',item_price=" + item.value + ",players=0,playersAll=" + c1 + ",ticketPrice=" + b1 + ",active=1,start="+time);
								console.log("INSERT INTO `giveaway` SET item_name='" + item.name + "',item_img='" + item.img + "',item_price=" + item.value + ",players=0,playersAll=" + c1 + ",ticketPrice=" + b1 + ",active=1,start="+time);
								console.log("Full wipe succefully!");
								query('SELECT * from giveaway WHERE active=1', function always(err, rows, fields) {
									if(rows.length >= 1) {	
										setTimeout(function() {
											query('SELECT * from info WHERE `info_key`="ga_nickname" OR `info_key`="ga_ava"', function always(err, rows3, fields) {
												query('SELECT * from users WHERE `giveawayState`=1', function always(err, rowed, fields) {
													var itemName = rows[0].item_name;
													for(var o=0; o<rowed.length; o++) {
														query("UPDATE `users` SET balance=(balance+"+laster[0].ticketPrice+") WHERE vkid='"+rowed[o].vkid+"'");
														console.log("add "+laster[0].ticketPrice+" to " + rowed[o].vkid);
														userlist[''+rowed[o].vkid].balance -= parseFloat(laster[0].ticketPrice);
														sendbalance(rowed[o].vkid);
													}
													var data = { 
														item_name : rows[0].item_name, 
														item_price : rows[0].item_price, 
														item_img : rows[0].item_img, 
														players : rows[0].players,
														playersAll : rows[0].playersAll,
														ticketPrice : rows[0].ticketPrice,
														lastAva : rows3[0].info_value,
														lastName : rows3[1].info_value,
														timer : time
													};
													io.emit("updateGiveaway", data);
													isBuying = false;
													query("UPDATE `users` SET giveawayState=0");
												});
											});
										}, 500);
									}
								});
							
						});
					}
				});
			}
		});
	}

	socket.on("getGiveaways", function (data) {
		refreshGiveaways("currentGiveaway", "socket");
	});
  
  socket.on('opencase', function(data) {
    if (config.debug) console.log(data.vkid + " opening " + data.id);
    if (!checksalt(data.vkid, data.salt)) {
      if (config.debug) console.log('wrong salt');
      socket.emit('auth_fail');
      return;
    }
    var caseinfo = getCaseById(data.id) || false;
    if (!caseinfo) {
      socket.emit('err', {
        code: 0
      });
      if (config.debug) console.log('no such case ' + data.id);
      return;
    }
    if (config.debug) console.log('case: ' + JSON.stringify(caseinfo));
    if (config.debug) console.log('getting user info...');
    if (!(data.vkid in userlist)) return socket.emit('err', {
      code: 0
    });
    var res = getUser(data.vkid);
    var extra_chance = 0;
    var extra_price = 0;
    if (data.extrachance in config.extra) {
      extra_price = parseFloat(config.extra[data.extrachance].price);
      extra_chance = parseFloat(config.extra[data.extrachance].chance);
    }
    var caseprice = (parseFloat(caseinfo.price) + extra_price);
    if (res.banned) {
      socket.emit('err', {
        code: -1
      });
    } else if (res.balance >= caseprice) {
      var bal = res.balance;
      if (config.debug) console.log('CasePrice:', caseprice, 'Balance:', bal, 'Updating info');
      updatebalance(data.vkid, -caseprice);
      bal -= caseprice;
      sendbalance(data.vkid);
      if (config.debug) console.log('balance updated: ' + bal);
      var opening = opencase(data.id, res.chance, extra_chance, extra_price);
      if (config.debug) console.log('case opened');
      updatebalance(data.vkid, opening.prize.value);
      userlist[''+data.vkid].rolls++;
      userlist[''+data.vkid].won += parseFloat(opening.prize.value);
      bal += parseFloat(opening.prize.value);
      if (config.debug) console.log('balance updated: ' + bal);
      sendprize(data.vkid, opening.prize);
      setTimeout(function() {
        sendbalance(data.vkid);
        pushroll(data.vkid, opening.prize, data.id, opening.profit);
      }, 6500);
    } else {
      socket.emit('err', {
        code: 3
      });
    }
  });

  socket.on('disconnect', function() {
    stat_online--;
    delete socket_connections[socket.id];
  });
  
});


http.listen(80, '193.124.117.10', function() {
  console.log('HTTP Listener binded to 80');
});

function getRandomInt(min, max) {
	return Math.floor(Math.random() * (max - min + 1)) + min;
}