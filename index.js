const express = require('express');
const axios = require('axios');
const https = require('https');
const fs = require('fs');
const path = require('path');
const winston = require('winston');
const schedule = require('node-schedule');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const app = express();

const PORT = process.env.PORT || 3000; 
const PASSWORD = process.env.ADMIN_PASSWORD || 'admin';  // 管理密码

const SESSION_SECRET = Math.random().toString(36).slice(-16);
const HASHED_PASSWORD = bcrypt.hashSync(PASSWORD, 10);

app.use(express.json());
app.use(cookieParser());
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// 静态文件
app.use(express.static('public'));

// 登录接口
app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  if (bcrypt.compareSync(password, HASHED_PASSWORD)) {
      req.session.authenticated = true;
      res.json({ success: true });
  } else {
      res.status(401).json({ error: '密码错误' });
  }
});

// 认证中间件
const authenticate = (req, res, next) => {
  if (req.session.authenticated) {
      next();
  } else {
      res.status(401).json({ error: '未授权' });
  }
};

// initialization SQLite database
const db = new sqlite3.Database('./urls.db', (err) => {
  if (err) {
    console.error('cannot connect database:', err.message);
  } else {
    console.log('Already connect SQLite database');
    db.run(`CREATE TABLE IF NOT EXISTS urls (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      url TEXT UNIQUE,
      fail_count INTEGER DEFAULT 0,
      consecutive_fail_count INTEGER DEFAULT 0
    )`);
  }
});

const logDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({
      format: () => {
        return new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
      }
    }),
    winston.format.printf(({ timestamp, level, message }) => {
      return `[${timestamp}] ${level.toUpperCase()}: ${message}`;
    })
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(logDir, 'access.log'),
      level: 'info',
      maxsize: 1024 * 1024 * 10, // 10MB
      maxFiles: 5,
      tailable: true,
    }),
  ],
});

// delete logs every day 0:00
schedule.scheduleJob('0 0 * * *', () => {
  fs.readdir(logDir, (err, files) => {
    if (err) {
      logger.error('Unable to read log directory:', err.message);
      return;
    }
    
    files.forEach(file => {
      if (file.endsWith('.log')) {
        const filePath = path.join(logDir, file);
        fs.writeFile(filePath, '', err => {
          if (err) {
            logger.error(`Cleaning up log file ${file} faild:`, err.message);
          } else {
            logger.info(`log file ${file} has been deleted`);
          }
        });
      }
    });
  });
});

// get all url
app.get('/admin/urls', authenticate, (req, res) => {
  db.all('SELECT url FROM urls WHERE fail_count < 100', (err, rows) => {
    if (err) {
      logger.error('cannot url list:', err.message);
      return res
        .status(500)
        .json({ error: 'cannot url list', message: err.message });
    }
    const urls = rows.map((row) => `"${row.url}"`).join(',\n');
    res.set('Content-Type', 'text/plain');
    res.send(urls);
  });
});

// check log file
app.get('/admin/logs', authenticate, (req, res) => {
  const logFilePath = path.join(logDir, 'access.log');

  // check log file exists
  if (!fs.existsSync(logFilePath)) {
    return res.status(404).json({ error: 'log file not found' });
  }

  // read log file
  fs.readFile(logFilePath, 'utf8', (err, data) => {
    if (err) {
      logger.error('cannot read log file:', err.message);
      return res
        .status(500)
        .json({ error: 'cannot read log file', message: err.message });
    }

    const logs = data.split('\n').filter((line) => line.trim() !== '');

    if (logs.length === 0) {
      return res.status(200).json({ message: 'log file is empty' });
    }

    res.set('Content-Type', 'text/plain');
    res.send(logs.join('\n'));
  });
});

// delete log
app.delete('/admin/logs', authenticate, (req, res) => {
  const logFilePath = path.join(logDir, 'access.log');
  
  fs.writeFile(logFilePath, '', err => {
    if (err) {
      logger.error('清理日志文件失败:', err.message);
      return res.status(500).json({ error: '清理日志失败' });
    }
    logger.info('日志文件已清理');
    res.status(200).json({ message: '日志清理成功' });
  });
});

// add url
app.post('/add-url', (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'url cannot empty' });
  }

  db.get('SELECT url FROM urls WHERE url = ?', [url], (err, row) => {
    if (err) {
      logger.error('database search faild:', err.message);
      return res
        .status(500)
        .json({ error: 'database search faild', message: err.message });
    }
    if (row) {
      return res
        .status(200)
        .json({ message: 'url already exists，no need to add it again' });
    }

    db.run('INSERT INTO urls (url) VALUES (?)', [url], function (err) {
      if (err) {
        logger.error('cannot add url:', err.message);
        return res
          .status(500)
          .json({ error: 'cannot add url', message: err.message });
      }
      res
        .status(200)
        .json({ message: 'url add successfully', id: this.lastID });
    });
  });
});

// delete url
app.delete('/delete-url', (req, res) => {
  const { id, url } = req.body;

  if (!id && !url) {
    return res.status(400).json({ error: 'need id or url' });
  }

  let query;
  let params;
  if (id) {
    query = 'DELETE FROM urls WHERE id = ?';
    params = [id];
  } else {
    query = 'DELETE FROM urls WHERE url = ?';
    params = [url];
  }

  db.run(query, params, function (err) {
    if (err) {
      logger.error('cannot delete the url:', err.message);
      return res
        .status(500)
        .json({ error: 'cannot delete the url', message: err.message });
    }
    if (this.changes === 0) {
      return res.status(404).json({ message: 'cannot find the url' });
    }
    res.status(200).json({ message: 'url delelte successfully' });
  });
});

// get UTC+8 time
function getUTCTime() {
  return new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
}

// access url
async function accessurl(url) {
  try {
    const response = await axios.get(url, {
      httpsAgent: new https.Agent({
        rejectUnauthorized: false,
      }),
      timeout: 10000,
    });

    logger.info(
      `Success: ${url} | ${response.status}`
    );

    return { success: true, status: response.status };
  } catch (error) {
    logger.error(
      `Error: ${url} | error: ${
        error.response ? error.response.status : 'access faild'
      }`
    );

    return {
      success: false,
      status: error.response ? error.response.status : 'access faild',
    };
  }
}

// max url numbers
const MAX_CONCURRENT_REQUESTS = 100;
const BATCH_SIZE = 1000;

const processBatch = async (batch) => {
  const promises = batch.map((row) => {
    const { id, url, consecutive_fail_count } = row;
    return accessurl(url).then((result) => {
      if (result.success) {
        db.run('UPDATE urls SET consecutive_fail_count = 0 WHERE id = ?', [id]);
      } else {
        db.run(
          'UPDATE urls SET consecutive_fail_count = consecutive_fail_count + 1 WHERE id = ?',
          [id],
          function (err) {
            if (err) {
              logger.error('cannot update count:', err.message);
            } else if (consecutive_fail_count + 1 >= 100) {
              db.run('DELETE FROM urls WHERE id = ?', [id], function (err) {
                if (err) {
                  logger.error('cannot delete url:', err.message);
                } else {
                  logger.info(
                    `url delete successfully: ${url} [${getUTCTime()}]`
                  );
                }
              });
            }
          }
        );
      }
    });
  });

  await Promise.allSettled(promises.slice(0, MAX_CONCURRENT_REQUESTS));
};

setInterval(async () => {
  // logger.info('start access url...');
  db.all(
    'SELECT id, url, consecutive_fail_count FROM urls WHERE consecutive_fail_count < 100',
    async (err, rows) => {
      if (err) {
        logger.error('cannot get url list:', err.message);
        return;
      }

      // split the url
      for (let i = 0; i < rows.length; i += BATCH_SIZE) {
        const batch = rows.slice(i, i + BATCH_SIZE);
        await processBatch(batch);
      }
    }
  );
}, 2 * 60 * 1000);

// start server
app.listen(PORT, () => {
  console.log(`服务正在运行: http://localhost:${PORT}`);
  console.log(`管理密码是: ${PASSWORD}`);
});