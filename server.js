
const bcrypt = require('bcrypt');
const _crypto = require('crypto');
const fs = require('fs');

const _ = require('lodash');
const express = require('express');
const bodyParser = require('body-parser');

const rsa = {
  encrypt: (text, publicKey) => {
    const buffer = Buffer.from(text);
    const encrypted = _crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString("base64");
  },
  decrypt: (encdata, privateKey) => {
    const buffer = Buffer.from(encdata, "base64");
    const decrypted = _crypto.privateDecrypt(privateKey, buffer);
    return decrypted.toString("utf8");
  },
  genKeyPair: () => {
    return _crypto.generateKeyPairSync('rsa', {
      modulusLength: 4096,  // the length of your key in bits
      publicKeyEncoding: {
        type: 'spki',       // recommended to be 'spki' by the Node.js docs
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',      // recommended to be 'pkcs8' by the Node.js docs
        format: 'pem'
      }
    });
  }
};

const aes = {
  encrypt: (text, masterkey) => {
    const iv = _crypto.randomBytes(16);
    const salt = _crypto.randomBytes(64);
    const key = _crypto.pbkdf2Sync(masterkey, salt, 2145, 32, 'sha512');
    const cipher = _crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
  },
  decrypt: (encdata, masterkey) => {
    const bData = Buffer.from(encdata, 'base64');
    const salt = bData.slice(0, 64);
    const iv = bData.slice(64, 80);
    const tag = bData.slice(80, 96);
    const text = bData.slice(96);
    const key = _crypto.pbkdf2Sync(masterkey, salt , 2145, 32, 'sha512');
    const decipher = _crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = decipher.update(text, 'binary', 'utf8') + decipher.final('utf8');
    return decrypted;
  }
};

class Server {
  
  constructor() {
    this.users = {};
    this.messages = {};
    this.writeState = this.writeState.bind(this);
    try {
      const rawState = fs.readFileSync('./state.json', 'utf8');
      const state = JSON.parse(rawState);
      this.users = state.users;
      this.messages = state.messages;
      console.log('State loaded !');
    } catch(e) {
      console.log('No state file yet');
    }
    setInterval(this.writeState, 2000);
  }

  writeState() {
    fs.writeFileSync('./state.json', JSON.stringify({
      users: this.users,
      messages: this.messages
    }, null, 2));
  }

  createUser(email, password, name) {
    const hash = bcrypt.hashSync(password, 10);
    this.users[email] = {
      email,
      name,
      password: hash
    };
  }

  login(email, password) {
    const user = this.users[email];
    if (user) {
      if (bcrypt.compareSync(password, user.password)) {
        return user;
      } else {
        return null;
      }
    } else {
      return null;
    }
  }

  storeKey(email, salt, publicKey, privateKey) {
    const user = this.users[email];
    user.salt = salt;
    user.publicKey = publicKey;
    user.privateKey = privateKey;
    this.users[email] = user;
  }

  sendMessage(email, message, sem) {
    const messagesTo = this.messages[message.to] || [];
    messagesTo.push(message);
    this.messages[message.to] = messagesTo;
    if (sem) {
      const messagesFrom = this.messages[email] || [];
      messagesFrom.push(sem);
      this.messages[email] = messagesFrom;
    }
  }

  loadMessages(email) {
    const messages = this.messages[email] || [];
    return messages;
  }

  getPublicKey(email) {
    const user = this.users[email];
    if (user) {
      if (user.publicKey) {
        return user.publicKey;
      }
    }
    return null;
  }

  state() {
    return {
      users: this.users,
      messages: this.messages
    };
  }
}

const app = express();
const port = process.env.PORT || 8080;
const server = new Server();
if (Object.keys(server.users).length === 0) {
  server.createUser('bob@foo.bar', 'password', 'Bobby Boby');
  server.createUser('alice@foo.bar', 'password', 'Ally Alice');
}

app.use(bodyParser.json());
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'POST, GET, PUT, DELETE, HEAD');
  res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, Accept');
  next();
});
app.use(express.static('dist'));
app.get('/api/state', (req, res) => {
  res.send(server.state());
});
app.get('/api/users', (req, res) => {
  res.send(Object.keys(server.users).map(k => server.users[k]).map(u => ({ email: u.email, name: u.name, publicKey: u.publicKey })));
});
app.post('/api/users/_login', (req, res) => {
  const user = server.login(req.body.email, req.body.password);
  if (user) {
    res.type('json').status(200).send(user);
  } else {
    res.type('json').status(500).send({ error: 'bad login' });
  }
});
app.post('/api/users/:email/key', (req, res) => {
  const email = req.params.email;
  server.storeKey(email, req.body.salt, req.body.publicKey, req.body.privateKey);
  res.send({ done: true });
});
app.post('/api/users/:email/messages', (req, res) => {
  const email = req.params.email;
  server.sendMessage(email, req.body.message, req.body.sem);
  res.send({ done: true });
});

app.get('/api/users/:email/messages', (req, res) => {
  const email = req.params.email;
  const messages = server.loadMessages(email);
  res.send(messages);
});
app.get('/api/users/:email/key', (req, res) => {
  const email = req.params.email;
  const publicKey = server.getPublicKey(email);
  res.send({ publicKey });
});
app.options('/*', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'POST, GET, PUT, DELETE, HEAD');
  res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, Accept');
  res.send('');
});
app.use((err, req, res, next) => {
  if (err) {
    console.log(err);
    res.status(500).send({ error: err.message })
  } else {
    try {
      res.set('Access-Control-Allow-Origin', '*');
      res.set('Access-Control-Allow-Methods', 'POST, GET, PUT, DELETE, HEAD');
      res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, Accept');
      next();
    } catch(e) {
      res.status(500).send({ error: e.message })
    }
  }
});
app.listen(port, () => {
  console.log(`e2ee listening on port ${port}!`);
});