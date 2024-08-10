const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const bodyParser = require('body-parser');
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const mysql = require('mysql');
const path = require('path');
const session = require('express-session');
const cron = require('node-cron');
const { exec } = require('child_process');
const moment = require('moment-timezone');
const crypto = require('crypto');

let activeSessions = {};

// 대한민국 서울 시간대로 현재 시간을 설정하는 함수
function getCurrentSeoulTime() {
    return moment().tz('Asia/Seoul').format('YYYY-MM-DD HH:mm:ss');
}

// 세션 미들웨어 설정
app.use(session({
    secret: 'your_secret_key', // 비밀 키는 보안상 강력한 값을 사용해야 합니다.
    resave: false, // 세션을 항상 저장할지 여부
    saveUninitialized: false, // 초기화되지 않은 세션도 저장할지 여부
    cookie: {
        secure: false, // HTTPS 사용 시 true로 설정
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 쿠키의 만료 시간 설정 (1일)
    }
}));

// 클라이언트가 서버에 연결되었을 때
io.on('connection', (socket) => {
    console.log('a user connected');

    socket.on('disconnect', () => {
        console.log('user disconnected');
    });

    socket.on('registerSession', (sessionId) => {
        activeSessions[sessionId] = socket;
    });
});

// 세션 만료 시 로그아웃 처리
app.use((req, res, next) => {
    if (req.session && req.session.user) {
        const connection = createConnection(dbConfig1);
        connection.query('SELECT session_id FROM bon_user WHERE ID = ?', [req.session.user.id], (err, results) => {
            if (err) {
                console.error(`Error fetching session_id: ${err}`);
                return next();
            }
            if (results.length > 0 && results[0].session_id !== req.sessionID) {
                req.session.destroy((err) => {
                    if (err) {
                        console.error('Error destroying session: ', err);
                    }
                    connection.end();
                    res.redirect('/'); // 세션 만료 시 리다이렉트
                });
            } else {
                connection.end();
                next();
            }
        });
    } else {
        next();
    }
});

// 새로운 세션 시작 함수
function startNewSession(req, res, user, connection) {
    const sessionId = req.sessionID;

    if (activeSessions[sessionId]) {
        activeSessions[sessionId].emit('forceLogout');
    }

    connection.query('UPDATE bon_user SET session_id = ? WHERE ID = ?', [sessionId, user.ID], (err) => {
        if (err) {
            console.error(`Error updating user session: ${err}`);
            connection.end();
            return res.status(500).send('Internal Server Error');
        }

        req.session.user = {
            id: user.ID,
            name: user.NAME,
            role: user.ROLE
        };

        // 사용자가 이전에 있던 페이지로 리다이렉트
        const redirectTo = req.session.returnTo || '/LOGIN';
        delete req.session.returnTo;

        connection.end();
        res.redirect(redirectTo);
    });
}

// 사용자가 특정 페이지를 방문했을 때 해당 페이지 정보를 세션에 저장
app.use((req, res, next) => {
    if (req.session && req.session.user) {
        req.session.lastPage = req.originalUrl; // 사용자가 마지막으로 방문한 페이지 저장
    }
    next();
});

// 세션을 유지하기 위한 간단한 API 라우트
app.get('/keep-session-alive', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }
    res.send('Session is refreshed');
});

// Body-parser 미들웨어 설정
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// 데이터베이스 연결 설정--------------------------------------------------------------------------------------------------------------------
const dbConfig1 = {
    host: 'svc.sel5.cloudtype.app',
    port: 31681,
    database: 'ts_server',
    user: 'root',
    password: 'rjscjf0739',
    charset: 'utf8mb4'
};

const dbConfig2 = {
    host: '175.125.92.248',
    database: 'db_ezs',
    user: 'incom_user',
    password: 'rlawjdtns00',
    charset: 'utf8mb4'
};

function createConnection(dbConfig) {
    return mysql.createConnection(dbConfig);
}

// 페이지 권한 체크
function checkRole(allowedRoles) {
    return function(req, res, next) {
        if (!req.session.user || !allowedRoles.includes(req.session.user.role)) {
            return res.redirect('/');
        }
        next();
    };
}

// 환경 변수에서 포트 번호를 읽어옴-----------------------------------------------------------------------------------------------------------------
const PORT = process.env.PORT || 31681;

// 서버 리스닝
server.listen(PORT, () => {
    console.log(`서버가 *:${PORT} 포트에서 실행 중입니다.`);
});

// 정적 파일 제공
app.use(express.static(path.join(__dirname, 'public')));

// 메인화면 라우트------------------------------------------------------------------------------------------------------------------------------------
app.get('/', function (req, res) {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 뷰 엔진 설정------------------------------------------------------------------------------------------------------------------------------------
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// 회원 가입 함수------------------------------------------------------------------------------------------------------------------------------------
function registerUser(name, id, password, phone, car, car_id, sasi, part) {
    const sql = `INSERT INTO bon_user (NAME, ID, PASSWORD, PHONE, CAR, CAR_ID, SASI, PART) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
    queryWithReconnect(dbConfig1, sql, [name, id, password, phone, car, car_id, sasi, part], (error) => {
        if (error) throw error;
        console.log("사용자 정보가 성공적으로 삽입되었습니다.");
    });
}

// 회원 가입 라우트
app.post('/signup', (req, res) => {
    const { NAME, ID, PASSWORD, PHONE, CAR, CAR_ID, SASI, PART } = req.body;

    const phoneRegex = /^\d{11}$/;
    if (!phoneRegex.test(PHONE)) {
        return res.status(400).send('<script>alert("잘못된 연락처입니다."); window.history.back();</script>');
    }

    const carRegex = /^[A-Za-z0-9가-힣]{9}$/;
    if (!carRegex.test(CAR)) {
        return res.status(400).send('<script>alert("잘못된 차량번호 입니다."); window.history.back();</script>');
    }

    const carIdRegex = /^[A-Za-z0-9]{8}$/;
    if (!carIdRegex.test(CAR_ID)) {
        return res.status(400).send('<script>alert("잘못된 차량아이디 입니다."); window.history.back();</script>');
    }

    queryWithReconnect(dbConfig1, 'SELECT * FROM bon_user WHERE PHONE = ?', [PHONE], (error, results) => {
        if (error) throw error;
        if (results.length > 0) {
            return res.status(400).send('<script>alert("이 연락처는 이미 등록되어 있습니다."); window.history.back();</script>');
        } else {
            queryWithReconnect(dbConfig1, 'SELECT * FROM bon_user WHERE ID = ?', [ID], (error, results) => {
                if (error) throw error;
                if (results.length > 0) {
                    return res.status(400).send('<script>alert("이 아이디는 이미 등록되어 있습니다."); window.history.back();</script>');
                } else {
                    registerUser(NAME, ID, PASSWORD, PHONE, CAR, CAR_ID, SASI, PART);
                    res.redirect('/');
                }
            });
        }
    });
});

// 로그인 및 세션 확인 라우트------------------------------------------------------------------------------------------------------------------------------------
app.post('/LOGIN', (req, res) => {
    const { username, password } = req.body;
    const connection = createConnection(dbConfig1);

    connection.query('SELECT * FROM bon_user WHERE ID = ?', [username], (err, results) => {
        if (err) {
            console.error(`Error fetching user data: ${err}`);
            connection.end();
            return res.status(500).send('Internal Server Error');
        }

        if (results.length > 0) {
            const user = results[0];

            if (password === user.PASSWORD) {
                if (user.session_id && user.session_id.trim() !== '') {
                    return res.status(200).send(`<script>if(confirm("로그인하시면 다른 PC로그인은 종료됩니다.")) { window.location.href = "/confirm-login?username=${username}&password=${password}"; } else { window.history.back(); }</script>`);
                } else {
                    req.session.user = {
                        id: user.ID,
                        name: user.NAME,
                        car: user.CAR,  
                        role: user.ROLE
                    };

                    console.log('세션에 저장된 사용자 정보:', req.session.user);

                    startNewSession(req, res, user, connection);
                }
            } else {
                console.log('비밀번호가 일치하지 않습니다.');
                connection.end();
                return res.status(400).send('<script>alert("잘못된 비밀번호입니다."); window.history.back();</script>');
            }
        } else {
            console.log('사용자가 존재하지 않습니다.');
            connection.end();
            return res.status(400).send('<script>alert("존재하지 않는 사용자입니다."); window.history.back();</script>');
        }
    });
});

app.get('/confirm-login', (req, res) => {
    const { username, password } = req.query;
    const connection = createConnection(dbConfig1);

    connection.query('SELECT * FROM bon_user WHERE ID = ?', [username], (err, results) => {
        if (err) {
            console.error(`Error fetching user data: ${err}`);
            connection.end();
            return res.status(500).send('Internal Server Error');
        }
        if (results.length > 0) {
            const user = results[0];
            if (password === user.PASSWORD) {
                // 기존 세션 종료
                connection.query('UPDATE bon_user SET session_id = NULL WHERE ID = ?', [username], (err) => {
                    if (err) {
                        console.error(`Error updating user session: ${err}`);
                        connection.end();
                        return res.status(500).send('Internal Server Error');
                    }
                    // 새로운 세션 시작
                    startNewSession(req, res, user, connection);
                });
            } else {
                console.log(`비밀번호가 일치하지 않습니다.`);
                connection.end();
                return res.status(400).send('<script>alert("잘못된 비밀번호입니다."); window.history.back();</script>');
            }
        } else {
            console.log(`사용자가 존재하지 않습니다.`);
            connection.end();
            return res.status(400).send('<script>alert("존재하지 않는 사용자입니다."); window.history.back();</script>');
        }
    });
});

// 로그인 후 리다이렉트 라우트
app.get('/LOGIN', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }

    const userId = req.session.user.id;
    const connection1 = createConnection(dbConfig1);
    connection1.connect();

    connection1.query('SELECT NAME, CAR, ROLE FROM bon_user WHERE ID = ?', [userId], (err, userResults) => {
        if (err) {
            console.error('사용자 데이터 가져오는 중 오류 발생: ', err);
            connection1.end();
            return res.status(500).send('내부 서버 오류');
        }

        if (userResults.length > 0) {
            const user = userResults[0];
            const car = user.CAR;
            const name = user.NAME;
            const role = user.ROLE;

            res.render('index_로그인후', {
                user: {
                    id: userId,
                    name: name,
                    car: car,
                    role: role
                },
                sessionID: req.sessionID
            });
        } else {
            connection1.end();
            return res.status(404).send('사용자를 찾을 수 없습니다');
        }
    });
});

// '/driver1' 라우트 설정-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
app.get('/driver1', (req, res) => {
    if (!req.session.user) {
        // 사용자가 로그인하지 않았으면 홈페이지로 리다이렉트
        return res.redirect('/');
    }

    // 로그인 후 이전 페이지 정보를 저장하기 위해 req.session.returnTo 설정
    if (!req.session.returnTo) {
        req.session.returnTo = '/driver1';
    }

    // 사용자가 로그인한 경우
    const userId = req.session.user.id;
    const connection1 = createConnection(dbConfig1);

    connection1.connect((err) => {
        if (err) {
            console.error('데이터베이스 연결 중 오류 발생: ', err);
            return res.status(500).send('내부 서버 오류');
        }

        connection1.query('SELECT NAME, CAR, ROLE FROM bon_user WHERE ID = ?', [userId], (err, userResults) => {
            if (err) {
                console.error('사용자 데이터 가져오는 중 오류 발생: ', err);
                connection1.end();
                return res.status(500).send('내부 서버 오류');
            }

            if (userResults.length > 0) {
                const user = userResults[0];
                const car = user.CAR;
                const name = user.NAME;
                const role = user.ROLE;

                // 사용자 정보를 템플릿에 전달하고, 운행시작 후 페이지 렌더링
                res.render('index_운행시작후', {
                    user: {
                        id: userId,
                        name: name,
                        car: car,
                        role: role
                    },
                    sessionID: req.sessionID // 세션 ID를 템플릿에 전달
                });
            } else {
                connection1.end();
                return res.status(404).send('사용자를 찾을 수 없습니다');
            }
            connection1.end();
        });
    });
});

// bon_carplayer 차량, 출근시간, 소속 업데이트
app.post('/start-driving', (req, res) => {
    const { userId } = req.body;
    const currentTime = getCurrentSeoulTime(); // 현재 시간을 대한민국 서울 시간으로 설정
    const connection = createConnection(dbConfig1);

    connection.connect((err) => {
        if (err) {
            console.error('데이터베이스 연결 중 오류 발생: ', err);
            return res.status(500).json({ success: false, message: '데이터베이스 연결 오류' });
        }

        connection.query('SELECT CAR, PART, NAME FROM bon_user WHERE ID = ?', [userId], (error, results) => {
            if (error || results.length === 0) {
                connection.end();
                return res.status(500).json({ success: false, message: '사용자 정보를 가져오는 중 오류가 발생했습니다.' });
            }

            const { CAR, PART, NAME } = results[0];

            // bon_carplayer 테이블에 인서트
            const insertQuery = 'INSERT INTO bon_carplayer (CAR, `ON`, PART, NAME) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE CAR=VALUES(CAR), `ON`=VALUES(`ON`), PART=VALUES(PART), NAME=VALUES(NAME)';
            connection.query(insertQuery, [CAR, currentTime, PART, NAME], (insertError) => {
                connection.end();
                if (insertError) {
                    return res.status(500).json({ success: false, message: '데이터베이스에 값을 삽입하는 중 오류가 발생했습니다.' });
                }

                res.json({ success: true });
            });
        });
    });
});

// 뒤로가기 버튼 - carplayer 행 삭제 후 /LOGIN으로 이동 그리고 bon_user 테이블 session_id 컬럼에 /LOGIN 세션 저장
app.post('/handle-back-button', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('Unauthorized');
    }

    const userId = req.session.user.id;
    const sessionId = req.sessionID;
    const connection = createConnection(dbConfig1);

    connection.query('SELECT CAR FROM bon_user WHERE ID = ?', [userId], (err, results) => {
        if (err) {
            console.error('Error fetching user data: ', err);
            connection.end();
            return res.status(500).send('Internal Server Error');
        }

        if (results.length > 0) {
            const car = results[0].CAR;

            // DELETE 쿼리 실행
            connection.query('DELETE FROM bon_carplayer WHERE CAR = ? AND `ON` IS NOT NULL AND `OFF` IS NULL', [car], (deleteErr) => {
                if (deleteErr) {
                    console.error('Error deleting data: ', deleteErr);
                    connection.end();
                    return res.status(500).send('Internal Server Error');
                }

                // session_id 업데이트 쿼리 실행
                connection.query('UPDATE bon_user SET session_id = ? WHERE ID = ?', [sessionId, userId], (updateErr) => {
                    if (updateErr) {
                        console.error('Error updating session_id: ', updateErr);
                        connection.end();
                        return res.status(500).send('Internal Server Error');
                    }

                    // 마지막 페이지로 리디렉션
                    req.session.returnTo = '/LOGIN';

                    connection.end();
                    res.json({ success: true, redirectTo: req.session.returnTo });
                });
            });
        } else {
            connection.end();
            res.status(404).send('User not found');
        }
    });
});

// 쿼리 재연결 함수
function queryWithReconnect(dbConfig, query, params, callback) {
    const connection = createConnection(dbConfig);

    connection.connect((err) => {
        if (err) {
            console.error('Error connecting to database: ', err);
            callback(err);
            return;
        }

        connection.query(query, params, (err, results) => {
            if (err) {
                console.error('Error executing query: ', err);
                connection.end();
                callback(err);
                return;
            }

            connection.end();
            callback(null, results);
        });
    });
}


// 신항버튼을 눌렀을때----------------------------------------------------------------------------------------------------
app.post('/start-driving-sin', (req, res) => {
    const userId = req.session.user.id;
    const location = '신항';
    const currentTime = getCurrentSeoulTime(); // 현재 시간을 대한민국 서울 시간으로 설정
    const connection = createConnection(dbConfig1);

    connection.connect((err) => {
        if (err) {
            console.error('데이터베이스 연결 중 오류 발생: ', err);
            return res.status(500).json({ success: false, message: '데이터베이스 연결 오류' });
        }

        connection.query('SELECT CAR, PART FROM bon_user WHERE ID = ?', [userId], (error, results) => {
            if (error || results.length === 0) {
                connection.end();
                return res.status(500).json({ success: false, message: '사용자 정보를 가져오는 중 오류가 발생했습니다.' });
            }

            const { CAR, PART } = results[0];

            // bon_carplayer 테이블에 인서트
            const insertQuery = 'INSERT INTO bon_carplayer (CAR, `ON`, PART) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE CAR=VALUES(CAR), `ON`=VALUES(`ON`), PART=VALUES(PART)';
            connection.query(insertQuery, [CAR, currentTime, PART], (insertError) => {
                if (insertError) {
                    connection.end();
                    return res.status(500).json({ success: false, message: '데이터베이스에 값을 삽입하는 중 오류가 발생했습니다.' });
                }

                // LOCATION 컬럼 업데이트
                const updateQuery = 'UPDATE bon_carplayer SET LOCATION = ? WHERE CAR = ?';
                connection.query(updateQuery, [location, CAR], (updateError) => {
                    connection.end();
                    if (updateError) {
                        return res.status(500).json({ success: false, message: '데이터베이스에 LOCATION 값을 업데이트하는 중 오류가 발생했습니다.' });
                    }

                    res.json({ success: true });
                });
            });
        });
    });
});

//신항, 북항에서 뒤로가기 버튼을 눌렀을때
app.post('/handle-back-button2-1', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('Unauthorized');
    }

    const userId = req.session.user.id;
    const sessionId = req.sessionID;
    const connection = createConnection(dbConfig1);

    connection.query('SELECT CAR FROM bon_user WHERE ID = ?', [userId], (err, results) => {
        if (err) {
            console.error('Error fetching user data: ', err);
            connection.end();
            return res.status(500).send('Internal Server Error');
        }

        if (results.length > 0) {
            const car = results[0].CAR;

            // DELETE 쿼리 실행
            connection.query('DELETE FROM bon_carplayer WHERE CAR = ? AND `ON` IS NOT NULL AND `OFF` IS NULL', [car], (deleteErr) => {
                if (deleteErr) {
                    console.error('Error deleting data: ', deleteErr);
                    connection.end();
                    return res.status(500).send('Internal Server Error');
                }

                // session_id 업데이트 쿼리 실행
                connection.query('UPDATE bon_user SET session_id = ? WHERE ID = ?', [sessionId, userId], (updateErr) => {
                    if (updateErr) {
                        console.error('Error updating session_id: ', updateErr);
                        connection.end();
                        return res.status(500).send('Internal Server Error');
                    }

                    // 마지막 페이지로 리디렉션
                    req.session.returnTo = '/driver1';

                    connection.end();
                    res.json({ success: true, redirectTo: req.session.returnTo });
                });
            });
        } else {
            connection.end();
            res.status(404).send('User not found');
        }
    });
});

// 북항버튼을 눌렀을때--------------------------------------------------------------------------------------------
app.post('/start-driving-buk', (req, res) => {
    const userId = req.session.user?.id;
    if (!userId) {
        return res.status(400).json({ success: false, message: '세션이 유효하지 않거나 사용자가 로그인되지 않았습니다.' });
    }

    const location = '북항';
    const currentTime = getCurrentSeoulTime();
    const connection = createConnection(dbConfig1);

    connection.connect((err) => {
        if (err) {
            console.error('데이터베이스 연결 중 오류 발생: ', err);
            return res.status(500).json({ success: false, message: '데이터베이스 연결 오류' });
        }

        connection.query('SELECT CAR, PART FROM bon_user WHERE ID = ?', [userId], (error, results) => {
            if (error || results.length === 0) {
                connection.end();
                return res.status(500).json({ success: false, message: '사용자 정보를 가져오는 중 오류가 발생했습니다.' });
            }

            const { CAR, PART } = results[0];
            const insertQuery = 'INSERT INTO bon_carplayer (CAR, `ON`, PART) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE CAR=VALUES(CAR), `ON`=VALUES(`ON`), PART=VALUES(PART)';
            connection.query(insertQuery, [CAR, currentTime, PART], (insertError) => {
                if (insertError) {
                    connection.end();
                    return res.status(500).json({ success: false, message: '데이터베이스에 값을 삽입하는 중 오류가 발생했습니다.' });
                }

                const updateQuery = 'UPDATE bon_carplayer SET LOCATION = ? WHERE CAR = ?';
                connection.query(updateQuery, [location, CAR], (updateError) => {
                    connection.end();
                    if (updateError) {
                        return res.status(500).json({ success: false, message: '데이터베이스에 LOCATION 값을 업데이트하는 중 오류가 발생했습니다.' });
                    }

                    res.json({ success: true });
                });
            });
        });
    });
});





// '/driver2-1' 라우트 설정(신항)-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
app.get('/driver2-1', (req, res) => {
    if (!req.session.user) {
        // 사용자가 로그인하지 않았으면 홈페이지로 리디렉트
        return res.redirect('/');
    }

    // 항상 req.session.returnTo를 /driver2-1로 설정
    req.session.returnTo = '/driver2-1';

    // 사용자가 로그인한 경우
    const userId = req.session.user.id;
    const connection1 = createConnection(dbConfig1);

    connection1.connect((err) => {
        if (err) {
            console.error('데이터베이스 연결 중 오류 발생: ', err);
            return res.status(500).send('내부 서버 오류');
        }

        connection1.query('SELECT NAME, CAR, ROLE FROM bon_user WHERE ID = ?', [userId], (err, userResults) => {
            if (err) {
                console.error('사용자 데이터 가져오는 중 오류 발생: ', err);
                connection1.end();
                return res.status(500).send('내부 서버 오류');
            }

            if (userResults.length > 0) {
                const user = userResults[0];
                const car = user.CAR;
                const name = user.NAME;
                const role = user.ROLE;

                // 사용자 정보를 템플릿에 전달하고, 신항 선택 후 페이지 렌더링
                res.render('index_신항선택후', {
                    user: {
                        id: userId,
                        name: name,
                        car: car,
                        role: role
                    },
                    sessionID: req.sessionID // 세션 ID를 템플릿에 전달
                });
            } else {
                connection1.end();
                return res.status(404).send('사용자를 찾을 수 없습니다');
            }
            connection1.end();
        });
    });
});

// '/driver2-2' 라우트 설정(북항)-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
app.get('/driver2-2', (req, res) => {
    if (!req.session.user) {
        // 사용자가 로그인하지 않았으면 홈페이지로 리다이렉트
        return res.redirect('/');
    }

    // 항상 req.session.returnTo를 /driver2-1로 설정
    req.session.returnTo = '/driver2-2';

    const userId = req.session.user.id;
    const connection1 = createConnection(dbConfig1);

    connection1.connect((err) => {
        if (err) {
            console.error('데이터베이스 연결 중 오류 발생:', err);
            return res.status(500).send('내부 서버 오류');
        }

        connection1.query('SELECT NAME, CAR, ROLE FROM bon_user WHERE ID = ?', [userId], (err, userResults) => {
            if (err) {
                console.error('사용자 데이터 가져오는 중 오류 발생:', err);
                connection1.end();
                return res.status(500).send('내부 서버 오류');
            }

            if (userResults.length > 0) {
                const user = userResults[0];
                const car = user.CAR;
                const name = user.NAME;
                const role = user.ROLE;

                res.render('index_북항선택후', {
                    user: {
                        id: userId,
                        name: name,
                        car: car,
                        role: role
                    },
                    sessionID: req.sessionID // 세션 ID를 템플릿에 전달
                });
            } else {
                connection1.end();
                return res.status(404).send('사용자를 찾을 수 없습니다');
            }
            connection1.end();
        });
    });
});

app.post('/update-location', (req, res) => {
    if (!req.session.user) {
        console.error('사용자 세션이 없습니다.');
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    const { location } = req.body;
    let car = req.session.user.car;

    // CAR 값이 세션에 없을 경우 데이터베이스에서 직접 조회
    if (!car) {
        console.error('세션에 CAR 값이 없습니다. 데이터베이스에서 값을 조회합니다.');
        const connection = createConnection(dbConfig1);

        connection.connect(err => {
            if (err) {
                console.error('데이터베이스 연결 오류:', err);
                return res.status(500).json({ success: false, message: '데이터베이스 연결 오류' });
            }

            connection.query('SELECT CAR FROM bon_user WHERE ID = ?', [req.session.user.id], (error, results) => {
                if (error || results.length === 0) {
                    connection.end();
                    console.error('사용자 정보를 가져오는 중 오류가 발생했습니다.');
                    return res.status(500).json({ success: false, message: '사용자 정보를 가져오는 중 오류가 발생했습니다.' });
                }

                car = results[0].CAR;
                if (!car) {
                    connection.end();
                    console.error('사용자의 CAR 정보를 찾을 수 없습니다.');
                    return res.status(400).json({ success: false, message: '사용자의 CAR 정보를 찾을 수 없습니다.' });
                }

                // 이후의 쿼리 실행
                updateLocation(car, location, res, connection);
            });
        });
    } else {
        // 세션에 CAR 값이 있는 경우 바로 위치 업데이트 진행
        const connection = createConnection(dbConfig1);
        connection.connect(err => {
            if (err) {
                console.error('데이터베이스 연결 오류:', err);
                return res.status(500).json({ success: false, message: '데이터베이스 연결 오류' });
            }
            updateLocation(car, location, res, connection);
        });
    }
});

function updateLocation(car, location, res, connection) {
    const query = 'UPDATE bon_carplayer SET CURRENT_LOCATION = ? WHERE CAR = ?';
    connection.query(query, [location, car], (error, results) => {
        connection.end();

        if (error) {
            console.error('위치 업데이트 중 오류 발생:', error);
            return res.status(500).json({ success: false, message: '위치 업데이트 중 오류 발생' });
        }

        if (results.affectedRows === 0) {
            console.error(`영향을 받은 행이 없습니다. CAR 값이 테이블에 존재하는지 확인하세요. CAR: ${car}`);
            return res.status(404).json({ success: false, message: '일치하는 CAR을 찾을 수 없습니다' });
        }

        console.log(`위치가 성공적으로 업데이트되었습니다. CAR: ${car}, Location: ${location}`);
        res.json({ success: true, message: '위치가 성공적으로 업데이트되었습니다.' });
    });
}



// '/driver3' 라우트 설정-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

app.get('/driver3', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }

    // 항상 req.session.returnTo를 /driver3로 설정
    req.session.returnTo = '/driver3';

    const userId = req.session.user.id;
    const connection = createConnection(dbConfig1);

    connection.query('SELECT CAR, SASI, session_id FROM bon_user WHERE ID = ?', [userId], (err, userResults) => {
        if (err || userResults.length === 0) {
            console.error('bon_user 데이터 조회 중 오류:', err);
            connection.end();
            return res.status(500).send('내부 서버 오류');
        }

        // 세션 유효성 확인
        if (userResults[0].session_id !== req.sessionID) {
            req.session.destroy(err => {
                if (err) console.error('세션 삭제 중 오류:', err);
                res.redirect('/');
            });
            return;
        }

        const { CAR, SASI } = userResults[0];
        req.session.car = CAR; // CAR 데이터 세션에 저장
        req.session.sasi = SASI; // SASI 데이터 세션에 저장
        handleCarAndSasi(CAR, SASI, userResults[0]);
    });

    function handleCarAndSasi(CAR, SASI, user) {
        connection.query('SELECT CURRENT_LOCATION FROM bon_carplayer WHERE CAR = ? AND LOCATION = "신항"', [CAR], (err, carResults) => {
            if (err || carResults.length === 0) {
                console.error('bon_carplayer 데이터 조회 중 오류:', err);
                connection.end();
                return res.status(500).send('내부 서버 오류');
            }

            const currentLocDigits = carResults[0].CURRENT_LOCATION.slice(-5); // 마지막 5자리
            processTotalValues(SASI, currentLocDigits, user);
        });
    }

    function processTotalValues(SASI, currentLocDigits, user) {
        connection.query('SELECT * FROM bon_planing_sin WHERE RESERVE IS NULL', (err, planResults) => {
            if (err) {
                console.error('bon_planing_sin 데이터 조회 중 오류:', err);
                connection.end();
                return res.status(500).send('내부 서버 오류');
            }

            let selectedRow = null;

            planResults.forEach(row => {
                const totalValueStr = String(row.TOTAL).split('.')[0]; // 소수점 제거 후 문자열로 변환
                const totalRightThree = totalValueStr.slice(-3); // 오른쪽에서 세 자리 숫자 추출
                const totalRightThreeNum = parseInt(totalRightThree, 10);
                const totalValue = parseInt(totalValueStr, 10); // 전체 TOTAL 값

                if (totalRightThreeNum >= 12 && totalRightThreeNum <= 110 && totalValue <= 400000) {
                    const sangHaPrefix = row.SANG_HA.split('-')[0];

                    if (sangHaPrefix && currentLocDigits !== sangHaPrefix) {
                        return;
                    }

                    if ((SASI === "콤바인샤시" && row.TOTAL % 1 <= 0.5) || 
                        (SASI === "라인샤시" && row.TOTAL % 1 === 0)) {
                        if (!selectedRow || parseFloat(row.TOTAL) > parseFloat(selectedRow.TOTAL)) {
                            selectedRow = row;
                        }
                    }
                }
            });

            if (selectedRow) {
                assignTotalValue(selectedRow, user);
            } else {
                req.session.assignedData = null;
                connection.end();
                res.render('index_배차', {
                    user: { id: user.id, car: user.CAR, role: user.ROLE },
                    sessionID: req.sessionID,
                    assignedTotal: null
                });
            }
        });
    }

    function assignTotalValue(row, user) {
        if (!row || !row.TOTAL) {
            console.error('유효하지 않은 데이터: TOTAL 값이 없습니다.', row);
            connection.end();
            return res.status(400).send('TOTAL value not set.');
        }

        const selectedSangHa = row.SANG_HA;

        connection.query('UPDATE bon_planing_sin SET RESERVE = "Y" WHERE TOTAL = ?', [row.TOTAL], (err) => {
            if (err) {
                console.error('RESERVE 업데이트 중 오류:', err);
                connection.end();
                return res.status(500).send('내부 서버 오류');
            }

            req.session.assignedData = {
                assignedTotal: row.TOTAL,
                currentData: {
                    SANG_HA: row.SANG_HA,
                    CON_NO: row.CON_NO,
                    CON_KU: row.CON_KU,
                    CON_KG: row.CON_KG,
                    B_KUM_IN: row.B_KUM_IN,
                    CON_TEMP: row.CON_TEMP,
                    CON_CLASS: row.CON_CLASS,
                    SASI: user.SASI
                }
            };

            connection.end();
            res.render('index_배차', {
                user: { id: user.id, car: user.CAR, role: user.ROLE },
                sessionID: req.sessionID,
                assignedTotal: row.TOTAL,
                currentData: req.session.assignedData.currentData
            });
        });
    }
});

app.get('/driver4', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }

    // 항상 req.session.returnTo를 /driver4로 설정
    req.session.returnTo = '/driver4';

    const nextData = req.session.nextData || {};
    
    res.render('index_배차2', {
        user: req.session.user,
        sessionID: req.sessionID,
        currentData: nextData
    });
});



// '/get-current-data' 라우트 설정
app.get('/get-current-data', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ message: '로그인이 필요합니다.' });
    }

    if (!req.session.assignedData) {
        return res.status(404).json({ message: '배차 데이터가 없습니다.' });
    }

    res.json(req.session.assignedData);
});

//다음배차
app.post('/calculate-next-dispatch', async (req, res) => {
    const connection = createConnection(dbConfig1); // 데이터베이스 연결 객체 생성
    try {
        const { currentTotal, SASI } = req.body;

        if (!currentTotal || !SASI) {
            return res.status(400).json({ message: 'currentTotal 또는 SASI 값이 누락되었습니다.' });
        }

        const integerTotal = Math.floor(currentTotal);
        const currentTotalString = integerTotal.toString();
        const currentTotalTrimmed = currentTotalString.slice(-3);

        console.log(`Received currentTotal: ${currentTotal}`);
        console.log(`Calculated currentTotalTrimmed: ${currentTotalTrimmed}`);

        const priorityRanges = {
            '052-058': ['072-078', '092-100', '102-110', '052-058', '012-019', '032-038'],
            '072-078': ['052-058', '092-100', '102-110', '072-078', '012-019', '032-038'],
            '092-100': ['102-110', '012-019', '092-100', '052-058', '032-038', '072-078'],
            '102-110': ['092-100', '052-058', '032-038', '102-110', '072-078', '012-019'],
            '012-019': ['032-038', '012-019', '092-100', '102-110', '052-058', '072-078'],
            '032-038': ['012-019', '032-038', '102-110', '092-100', '072-078', '052-058'],
        };

        let range = null;
        for (const [key, value] of Object.entries(priorityRanges)) {
            const [min, max] = key.split('-').map(Number);
            if (Number(currentTotalTrimmed) >= min && Number(currentTotalTrimmed) <= max) {
                range = value;
                break;
            }
        }

        if (!range) {
            connection.end();
            return res.status(400).json({ message: `유효하지 않은 currentTotalTrimmed 값: ${currentTotalTrimmed}` });
        }

        let selectedTotal = null;

        for (const priority of range) {
            const [min, max] = priority.split('-').map(Number);
        
            selectedTotal = await new Promise((resolve, reject) => {
                connection.query(`
                    SELECT * FROM bon_planing_sin 
                    WHERE CAST(SUBSTRING(TOTAL, -3) AS UNSIGNED) BETWEEN ? AND ? 
                      AND RESERVE IS NULL
                      AND ((? = "콤바인샤시" AND MOD(TOTAL, 1) <= 0.5)
                           OR (? = "라인샤시" AND MOD(TOTAL, 1) = 0))
                    ORDER BY TOTAL DESC
                    LIMIT 1
                `, [min, max, SASI, SASI], (err, result) => {
                    if (err) {
                        console.error('쿼리 실행 중 오류:', err);
                        return reject(err);
                    }
        
                    if (result.length > 0) {
                        resolve(result[0]);
                    } else {
                        resolve(null);
                    }
                });
            });
        
            if (selectedTotal) break; // 배차가 선택되면 반복문을 종료합니다.
        }

        if (selectedTotal) {
            connection.query(`UPDATE bon_planing_sin SET RESERVE = 'Y' WHERE TOTAL = ?`, [selectedTotal.TOTAL], (err) => {
                connection.end();
                if (err) {
                    console.error('RESERVE 업데이트 중 오류:', err);
                    return res.status(500).json({ success: false, message: 'RESERVE 업데이트 중 오류 발생' });
                }

                // 세션에 nextData 저장
                req.session.nextData = selectedTotal;

                res.json({ success: true, nextDispatch: selectedTotal });
            });
        } else {
            connection.end();
            res.status(404).json({ success: false, message: '적합한 배차를 찾을 수 없습니다.' });
        }

    } catch (error) {
        console.error(error);
        connection.end();
        res.status(500).json({ success: false, message: '서버 내부 오류' });
    }
});

app.post('/start-next-batch', (req, res) => {
    const { SANG_HA, CON_NO, CON_KU } = req.body;

    const connection = mysql.createConnection(dbConfig1); // 데이터베이스 연결 객체 생성

    connection.connect(err => {
        if (err) {
            console.error('데이터베이스 연결 오류:', err);
            return res.status(500).json({ success: false, message: '데이터베이스 연결 오류' });
        }

        // 특정 CON_NO에 해당하는 데이터를 조회하여 TOTAL 값 가져오기
        const query = 'SELECT TOTAL FROM bon_planing_sin WHERE CON_NO = ?';
        connection.query(query, [CON_NO], (error, results) => {
            if (error) {
                console.error('데이터베이스 조회 중 오류:', error);
                connection.end(); // 연결 종료
                return res.status(500).json({ success: false, message: '데이터베이스 오류' });
            }

            if (results.length === 0) {
                connection.end(); // 연결 종료
                return res.status(404).json({ success: false, message: '해당 CON_NO에 대한 데이터를 찾을 수 없습니다.' });
            }

            // 조회된 데이터에서 TOTAL 값을 가져와 세션에 저장
            const totalValue = results[0].TOTAL;

            req.session.assignedData = {
                ...req.session.assignedData,
                assignedTotal: totalValue
            };

            connection.end(); // 연결 종료
            res.json({ success: true, total: totalValue });
        });
    });
});


// 운행 종료를 눌렀을때 -------------------------------------------------------------------------------------------------------------------------------------
app.post('/end-driving', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send({ success: false, message: "로그인이 필요합니다." });
    }

    const userId = req.session.user.id;
    const connection1 = createConnection(dbConfig1);
    const currentTime = getCurrentSeoulTime(); // 현재 시간을 대한민국 서울 시간으로 설정
    const { CON_NO } = req.body; // 클라이언트에서 CON_NO 값을 받아옴

    connection1.connect((err) => {
        if (err) {
            console.error('데이터베이스 연결 중 오류 발생:', err);
            return res.status(500).send({ success: false, message: "내부 서버 오류" });
        }

        connection1.query('SELECT CAR FROM bon_user WHERE ID = ?', [userId], (err, userResults) => {
            if (err) {
                console.error('사용자 데이터 가져오는 중 오류 발생:', err);
                connection1.end();
                return res.status(500).send({ success: false, message: "내부 서버 오류" });
            }

            if (userResults.length > 0) {
                const userCar = userResults[0].CAR;

                connection1.query('SELECT * FROM bon_carplayer WHERE CAR = ?', [userCar], (err, carResults) => {
                    if (err) {
                        console.error('bon_carplyer 데이터 가져오는 중 오류 발생:', err);
                        connection1.end();
                        return res.status(500).send({ success: false, message: "내부 서버 오류" });
                    }

                    if (carResults.length > 0) {

                        connection1.query('UPDATE bon_carplayer SET OFF = ? WHERE CAR = ?', [currentTime, userCar], (err) => {
                            if (err) {
                                console.error('bon_carplayer 업데이트 중 오류 발생:', err);
                                connection1.end();
                                return res.status(500).send({ success: false, message: "내부 서버 오류" });
                            }

                            // RESERVE 값 제거 작업 추가
                            connection1.query('UPDATE bon_planing_sin SET RESERVE = NULL WHERE CON_NO = ?', [CON_NO], (err) => {
                                connection1.end();

                                if (err) {
                                    console.error('bon_planing_sin 업데이트 중 오류 발생:', err);
                                    return res.status(500).send({ success: false, message: "내부 서버 오류" });
                                }

                                return res.send({ success: true, message: "운행 종료 처리 완료" });
                            });
                        });
                    } else {
                        connection1.end();
                        return res.status(404).send({ success: false, message: "해당 차량을 찾을 수 없습니다." });
                    }
                });
            } else {
                connection1.end();
                return res.status(404).send({ success: false, message: "사용자를 찾을 수 없습니다." });
            }
        });
    });
});

