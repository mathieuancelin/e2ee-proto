/*
"dependencies": {
  "bcrypt": "3.0.3",
}
*/
const bcrypt = require('bcrypt');
const _crypto = require('crypto');

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

  dump() {
    console.log('========== dump ===========');
    console.log('users', JSON.stringify(this.users, null, 2));
    console.log('messages', JSON.stringify(this.messages, null, 2));
    console.log('===========================');
  }
}

class Client {

  constructor(server) {
    this.server = server;
  }

  generateSalt() {
    return bcrypt.genSaltSync(10);
  }

  encryptPrivateKey(privateKey, salt, password) {
    const hash = bcrypt.hashSync(password, salt);
    return aes.encrypt(privateKey, hash);
  }

  decryptPrivateKey(encodedPrivateKey, salt, password) {
    const hash = bcrypt.hashSync(password, salt);
    return aes.decrypt(encodedPrivateKey, hash);
  }

  loadMessage() {
    this.messages = this.server.loadMessages(this.email);
  }

  login(email, password) {
    const res = this.server.login(email, password);
    if (res) {
      this.email = email;
      this.password = password;
      this.name = res.name
      if (!res.privateKey && !res.publicKey) {
        console.log('Generating keys ...');
        const pair = rsa.genKeyPair();
        this.privateKey = pair.privateKey;
        this.publicKey = pair.publicKey;
        this.salt = this.generateSalt();
        console.log('Sending keys to server');
        this.server.storeKey(
          this.email,
          aes.encrypt(this.salt, this.password),
          this.publicKey,
          this.encryptPrivateKey(this.privateKey, this.salt, this.password)
        );
        console.log('Logged in as ' + this.email);
        this.loadMessage();
      } else {
        this.salt = aes.decrypt(res.salt, this.password);
        this.privateKey = this.decryptPrivateKey(res.privateKey, this.salt, this.password);
        this.publicKey = res.publicKey;
        console.log('Logged in as ' + this.email);
        this.loadMessage();
      }
    } else {
      console.log('bad login :(');
      process.exit(1);
    }
  }

  encryptMessage(content, pubKey) {
    const messageKey = Date.now() + ''; // TODO: true random stuff;
    const encryptedContent = aes.encrypt(content, messageKey);
    const encryptedKey = rsa.encrypt(messageKey, pubKey || this.publicKey);
    return {
      key: encryptedKey,
      content: encryptedContent
    };
  }

  decryptMessage(message) {
    const key = rsa.decrypt(message.key, this.privateKey);
    const content = aes.decrypt(message.content, key);
    return content;
  }

  sendMessage(to, content) {
    const toPublicKey = this.server.getPublicKey(to);
    if (toPublicKey) {
      const encryptedMessage = this.encryptMessage(content, toPublicKey);
      encryptedMessage.from = this.email;
      encryptedMessage.to = to;
      encryptedMessage.at = Date.now();
      if (to === this.email) {
        this.server.sendMessage(this.email, encryptedMessage);
      } else {
        const selfEncryptedMessage = this.encryptMessage(content);
        selfEncryptedMessage.from = this.email;
        selfEncryptedMessage.to = to;
        selfEncryptedMessage.at = encryptedMessage.at;
        this.server.sendMessage(this.email, encryptedMessage, selfEncryptedMessage);
      }
    } else {
      console.log('No public key for user', to);
    }
  }

  displayMessages() {
    const messages = this.messages || [];
    const decryptedMessages = messages.map(message => {
      return `from: ${message.from}, to: ${message.to} => ${this.decryptMessage(message)}`;
    });
    console.log(JSON.stringify(decryptedMessages, null, 2));
  }

  close() {
    // console.log('closing client\n\n')
  }
}

const server = new Server();
server.createUser('bob@foo.bar', 'password', 'Bobby Boby');
server.createUser('alice@foo.bar', 'password', 'Ally Alice');

const bobClient = new Client(server);
const aliceClient = new Client(server);
bobClient.login('bob@foo.bar', 'password');
aliceClient.login('alice@foo.bar', 'password');
aliceClient.sendMessage('bob@foo.bar', 'Message 1 al');
aliceClient.close();

bobClient.sendMessage('alice@foo.bar', 'Message 1');
bobClient.sendMessage('alice@foo.bar', 'Message 2');
bobClient.sendMessage('alice@foo.bar', 'Message 3');
bobClient.close();

const client2 = new Client(server);
client2.login('bob@foo.bar', 'password');
client2.displayMessages();
client2.close();

const client3 = new Client(server);
client3.login('alice@foo.bar', 'password');
client3.displayMessages();
client3.close();

console.log('\n\n\n');
server.dump();

// console.log(rsa.genKeyPair());
