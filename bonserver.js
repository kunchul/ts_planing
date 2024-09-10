const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const bodyParser = require('body-parser');
const app = express();
const server = http.createServer(app);
const io = socketIo(server); 

const mysql = require('mysql');
const path = require('path');
const session = require('express-session');
const moment = require('moment-timezone');
const { v4: uuidv4 } = require('uuid');
const RedisStore = require('connect-redis').default;
const Redis = require('ioredis');


const redisClient = new Redis({
    host: 'svc.sel5.cloudtype.app', // Redis 서버의 호스트를 설정합니다.
    port: 31098,        // Redis 서버의 포트를 설정합니다.
    password: 'rjscjf0739', // Redis에 비밀번호가 설정된 경우 추가합니다.
});

// 대한민국 서울 시간대로 현재 시간을 설정하는 함수
function getCurrentSeoulTime() {
    return moment().tz('Asia/Seoul').format('YYYY-MM-DD HH:mm:ss');
}



function getCurrentSeoulTime2() {
    return moment().tz('Asia/Seoul').format('YYYY-MM-DD');
}

app.use(session({
    store: new RedisStore({ client: redisClient }), // Redis 클라이언트를 세션 스토어로 설정
    secret: 'your_secret_key', // 세션 암호화 키를 설정합니다.
    resave: false, // 세션이 변경되지 않아도 저장할지 여부를 설정합니다.
    saveUninitialized: false, // 초기화되지 않은 세션을 저장할지 여부를 설정합니다.
    rolling: true, // 사용자의 요청이 있을 때마다 세션 만료 시간을 갱신합니다.
    cookie: {
        secure: false, // HTTPS 환경에서만 쿠키가 전송되도록 설정 (HTTPS 사용 시 true로 변경)
        httpOnly: true, // 클라이언트 측에서 쿠키에 접근할 수 없도록 설정합니다.
        maxAge: 12 * 60 * 60 * 1000, // 쿠키의 만료 시간 (12시간으로 설정)
        sameSite: 'Lax' // 쿠키의 sameSite 속성을 설정합니다.
    }
}));



// 새로운 세션 시작 함수
function startNewSession(req, res, user, connection) {
    const sessionId = req.sessionID;

    // 동일 사용자 ID에 대한 기존 세션을 모두 무효화 (같은 세션 ID를 가진 다른 사용자의 세션 무효화)
    connection.query('UPDATE bon_user SET session_id = NULL WHERE ID = ? AND session_id != ?', [user.ID, sessionId], (err) => {
        if (err) {
            console.error('Error clearing old sessions:', err);
            connection.end();
            return res.status(500).send('Internal Server Error');
        }

        // 새로운 세션 ID를 DB에 저장
        connection.query('UPDATE bon_user SET session_id = ? WHERE ID = ?', [sessionId, user.ID], (err) => {
            if (err) {
                console.error('Error updating user session in database:', err);
                connection.end();
                return res.status(500).send('Internal Server Error');
            }

            req.session.user = {
                id: user.ID,
                name: user.NAME,
                role: user.ROLE,
                car: user.CAR
            };

            connection.end();
            res.redirect('/LOGIN');  // 로그인 후 이동할 페이지
        });
    });
}

// 세션 확인 미들웨어 (로그인 중인 세션을 검증하고 다른 세션을 무효화)
app.use((req, res, next) => {
    if (req.session && req.session.user) {

        const connection = mysql.createConnection(dbConfig1);
        const currentUserId = req.session.user.id;
        const currentSessionId = req.sessionID;

        connection.query('SELECT session_id FROM bon_user WHERE ID = ?', [currentUserId], (err, results) => {
            if (err) {
                console.error('Error checking session ID from database:', err);
                connection.end();
                return res.status(500).send('Internal Server Error');
            }

            const storedSessionId = results.length > 0 ? results[0].session_id : null;

            if (storedSessionId && storedSessionId !== currentSessionId) {
                req.session.destroy((err) => {
                    if (err) {
                        console.error('Error destroying session:', err);
                    }
                    connection.end();
                    res.redirect('/');  // 세션 무효화 시 리디렉션
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

const activeSessions = {};

io.on('connection', (socket) => {
    socket.on('registerSession', (sessionID) => {
        // 이미 동일한 사용자가 로그인한 세션이 있다면 해당 세션을 로그아웃 처리
        for (const id in activeSessions) {
            if (activeSessions[id].sessionID === sessionID) {
                activeSessions[id].socket.emit('forceLogout');
                delete activeSessions[id];
            }
        }

        // 현재 소켓을 세션 ID와 연결하여 activeSessions에 저장
        activeSessions[sessionID] = { socket: socket, sessionID: sessionID };

        socket.on('disconnect', () => {
            // 소켓이 연결 해제되면 activeSessions에서 제거
            delete activeSessions[sessionID];
        });
    });
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

function handleDisconnect(connection) {
    connection.on('error', function (err) {
        if (!err.fatal) {
            return;
        }

        if (err.code === 'PROTOCOL_CONNECTION_LOST') {
            console.error('Reconnecting lost connection: ', err.stack);
            // 재연결 시도
            connection = createConnection(connection.config); // 기존 설정을 사용해 새 연결
            handleDisconnect(connection); // 새 연결에 대해 재연결 로직 다시 설정
            connection.connect(function (error) {
                if (error) {
                    console.error('Error reconnecting: ', error.stack);
                } else {
                    console.log('Reconnected to the database.');
                }
            });
        } else {
            console.error('Unknown database error: ', err.stack);
        }
    });
}

function createConnection(dbConfig) {
    const connection = mysql.createConnection(dbConfig);
    handleDisconnect(connection); // 연결 생성 시 재연결 로직 설정
    return connection;
}

// 역할 검사를 위한 미들웨어 함수
function checkRoleForCarOrManager(req, res, next) {
    if (req.session.user && (req.session.user.role === 'car' || req.session.user.role === 'manager')) {
        next(); // 역할이 일치하면 다음 미들웨어로 진행
    } else {
        res.redirect('/'); // 일치하지 않으면 홈 페이지로 리다이렉트
    }
}

// 세션 확인 미들웨어
function sessionChecker(req, res, next) {
    if (req.session.user) {
        const connection = createConnection(dbConfig1);

        connection.query('SELECT session_id FROM bon_user WHERE ID = ?', [req.session.user.id], (err, results) => {
            if (err) {
                console.error('Error checking session ID from database:', err);
                connection.end();
                return res.status(500).send('Internal Server Error');
            }

            const storedSessionId = results.length > 0 ? results[0].session_id : null;

            // 세션 ID가 일치하지 않으면 현재 세션 무효화
            if (storedSessionId && storedSessionId !== req.sessionID) {
                req.session.destroy((err) => {
                    if (err) {
                        console.error('Error destroying session:', err);
                    }
                    connection.end();
                    res.redirect('/');  // 세션 무효화 시 리디렉션할 페이지
                });
            } else {
                connection.end();
                next();
            }
        });
    } else {
        next();
    }
}

app.use(sessionChecker);

// 세션 ID 전달 미들웨어
function sessionIDProvider(req, res, next) {
    res.locals.sessionID = req.sessionID;
    next();
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
    const connection = mysql.createConnection(dbConfig1);

    connection.query('SELECT * FROM bon_user WHERE ID = ?', [username], (err, results) => {
        if (err) {
            console.error('Error fetching user data:', err);
            connection.end();
            return res.status(500).send('Internal Server Error');
        }

        if (results.length > 0) {
            const user = results[0];

            if (password === user.PASSWORD) {
                req.session.regenerate((err) => {  // 새로운 세션 생성
                    if (err) {
                        console.error('Error regenerating session:', err);
                        connection.end();
                        return res.status(500).send('Internal Server Error');
                    }

                    // 사용자 정보를 세션에 저장
                    req.session.user = {
                        id: user.ID,
                        name: user.NAME,
                        role: user.ROLE
                    };

                    // 쿠키를 설정할 때 사용자 ID를 사용하여 저장
                    res.cookie('user_info', JSON.stringify({
                        id: user.ID,
                        name: user.NAME
                    }), { maxAge: 24 * 60 * 60 * 1000, httpOnly: true });

                    // 새로운 세션 ID를 데이터베이스에 저장
                    connection.query('UPDATE bon_user SET session_id = ? WHERE ID = ?', [req.sessionID, username], (err) => {
                        if (err) {
                            console.error('Error updating session ID:', err);
                            connection.end();
                            return res.status(500).send('Internal Server Error');
                        }

                        connection.end();
                        res.redirect('/LOGIN');  // 로그인 후 이동할 페이지
                    });
                });
            } else {
                connection.end();
                res.status(400).send('<script>alert("잘못된 비밀번호입니다."); window.location.href = "/";</script>');
            }
        } else {
            connection.end();
            res.status(400).send('<script>alert("존재하지 않는 사용자입니다."); window.location.href = "/";</script>');
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

    connection1.connect((err) => {
        if (err) {
            console.error('데이터베이스 연결 오류: ', err);
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
                req.session.user = {
                    id: userId,
                    name: user.NAME,
                    car: user.CAR,
                    role: user.ROLE
                };

                res.render('index_로그인후', {
                    user: req.session.user,
                    sessionID: req.sessionID
                });

                // 템플릿 렌더링 후 연결 종료
                connection1.end();

            } else {
                connection1.end();
                return res.status(404).send('사용자를 찾을 수 없습니다');
            }
        });
    });
});

// '/driver1' 라우트 설정-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
app.get('/driver1', sessionChecker, sessionIDProvider, checkRoleForCarOrManager, (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }

    if (!req.session.returnTo) {
        req.session.returnTo = '/driver1';
    }

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
            return res.status(500).json({ success: false, message: '데이터베이스 연결 오류', error: err });
        }

        connection.query('SELECT CAR, PART, NAME FROM bon_user WHERE ID = ?', [userId], (error, results) => {
            if (error) {
                console.error('사용자 정보를 가져오는 중 오류 발생: ', error);
                connection.end();
                return res.status(500).json({ success: false, message: '사용자 정보를 가져오는 중 오류가 발생했습니다.', error });
            }

            if (results.length === 0) {
                console.error('사용자 정보를 찾을 수 없음: ID = ', userId);
                connection.end();
                return res.status(404).json({ success: false, message: '사용자 정보를 찾을 수 없습니다.' });
            }

            const { CAR, PART, NAME } = results[0];

            // bon_carplayer 테이블에서 NAME이 일치하는지 확인
            connection.query('SELECT * FROM bon_carplayer WHERE NAME = ?', [NAME], (selectError, selectResults) => {
                if (selectError) {
                    console.error('bon_carplayer 조회 중 오류 발생: ', selectError);
                    connection.end();
                    return res.status(500).json({ success: false, message: 'bon_carplayer 조회 중 오류가 발생했습니다.', error: selectError });
                }

                if (selectResults.length > 0) {
                    // NAME이 일치하는 경우: OFF 컬럼을 삭제하고 나머지 값을 업데이트
                    connection.query(
                        'UPDATE bon_carplayer SET CAR = ?, `ON` = ?, PART = ?, OFF = NULL WHERE NAME = ?',
                        [CAR, currentTime, PART, NAME],
                        (updateError) => {
                            if (updateError) {
                                console.error('bon_carplayer 업데이트 중 오류 발생: ', updateError);
                                connection.end();
                                return res.status(500).json({ success: false, message: 'bon_carplayer 업데이트 중 오류가 발생했습니다.', error: updateError });
                            }

                            connection.end();
                            res.json({ success: true });
                        }
                    );
                } else {
                    // NAME이 일치하지 않는 경우: 새로운 레코드를 삽입
                    const insertQuery = 'INSERT INTO bon_carplayer (CAR, `ON`, PART, NAME) VALUES (?, ?, ?, ?)';
                    connection.query(insertQuery, [CAR, currentTime, PART, NAME], (insertError) => {
                        if (insertError) {
                            console.error('데이터베이스에 값을 삽입하는 중 오류 발생: ', insertError);
                            connection.end();
                            return res.status(500).json({ success: false, message: '데이터베이스에 값을 삽입하는 중 오류가 발생했습니다.', error: insertError });
                        }

                        connection.end();
                        res.json({ success: true });
                    });
                }
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

            // // DELETE 쿼리 실행
            // connection.query('DELETE FROM bon_carplayer WHERE CAR = ? AND `ON` IS NOT NULL AND `OFF` IS NULL', [car], (deleteErr) => {
            //     if (deleteErr) {
            //         console.error('Error deleting data: ', deleteErr);
            //         connection.end();
            //         return res.status(500).send('Internal Server Error');
            //     }

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
            // });
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

            const { CAR} = results[0];


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

            // // DELETE 쿼리 실행
            // connection.query('DELETE FROM bon_carplayer WHERE CAR = ? AND `ON` IS NOT NULL AND `OFF` IS NULL', [car], (deleteErr) => {
            //     if (deleteErr) {
            //         console.error('Error deleting data: ', deleteErr);
            //         connection.end();
            //         return res.status(500).send('Internal Server Error');
            //     }

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
                // });
            });
        } else {
            connection.end();
            res.status(404).send('User not found');
        }
    });
});

// 북항버튼을 눌렀을때--------------------------------------------------------------------------------------------
app.post('/start-driving-bok', (req, res) => {
    const userId = req.session.user.id;
    const location = '북항';
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

            const { CAR} = results[0];


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





// '/driver2-1' 라우트 설정(신항)-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
app.get('/driver2-1', sessionChecker, sessionIDProvider, checkRoleForCarOrManager, (req, res) => {
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
app.get('/driver2-2', sessionChecker, sessionIDProvider, checkRoleForCarOrManager, (req, res) => {
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

        connection1.query('SELECT NAME, CAR, ROLE, FROM bon_user WHERE ID = ?', [userId], (err, userResults) => {
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
app.get('/driver3', sessionChecker, sessionIDProvider, checkRoleForCarOrManager, (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }

    req.session.returnTo = '/driver1';

    const userId = req.session.user.id;
    const connection = createConnection(dbConfig1);

    // 재시도 로직 함수
    const updateWithRetry = async (connection, conNo, retries = 5) => {
        for (let attempt = 0; attempt < retries; attempt++) {
            try {
                await new Promise((resolve, reject) => {
                    connection.query(`UPDATE bon_planing_sin SET RESERVE = "Y" WHERE CON_NO = ?`, [conNo], (err) => {
                        if (err) {
                            if (err.code === 'ER_LOCK_WAIT_TIMEOUT') {
                                console.log(`Lock wait timeout exceeded. Retrying... (${attempt + 1}/${retries})`);
                                return reject('Timeout, retrying...');
                            }
                            return reject(err);
                        }
                        resolve();
                    });
                });
                return; // 성공 시 종료
            } catch (err) {
                if (attempt === retries - 1) {
                    throw err; // 최대 재시도 횟수 초과 시 오류 발생
                }
                await new Promise(resolve => setTimeout(resolve, 1000)); // 1초 대기 후 재시도
            }
        }
    };

    connection.query('SELECT CAR, SASI, NAME, ROLE, PHONE FROM bon_user WHERE ID = ?', [userId], (err, userResults) => {
        if (err || userResults.length === 0) {
            console.error('bon_user 데이터 조회 중 오류:', err);
            connection.end();
            return res.status(500).send('내부 서버 오류');
        }

        const { CAR, SASI, NAME, ROLE, PHONE } = userResults[0];

        // 사용자 정보를 세션에 저장
        req.session.car = CAR;
        req.session.sasi = SASI;
        req.session.user = {
            id: userId,
            name: NAME,
            role: ROLE
        };

        // bon_session 테이블에서 PHONE 값이 일치하는 레코드가 있는지 확인
        connection.query('SELECT * FROM bon_session WHERE PHONE = ?', [PHONE], (err, sessionResults) => {
            if (err) {
                console.error('bon_session 조회 중 오류:', err);
                connection.end();
                return res.status(500).send('내부 서버 오류');
            }

            if (sessionResults.length > 0) {
                // 일치하는 PHONE 값이 있을 때: bon_session 테이블의 데이터를 세션에 저장
                const sessionData = sessionResults[0];

                req.session.assignedData = {
                    assignedTotal: sessionData.TOTAL,
                    currentData: {
                        SANG_HA: sessionData.SANG_HA,
                        CON_NO: sessionData.CON_NO,
                        CON_KU: sessionData.CON_KU,
                        CON_KG: sessionData.CON_KG,
                        B_KUM_IN: sessionData.B_KUM_IN,
                        CON_TEMP: sessionData.CON_TEMP,
                        CON_CLASS: sessionData.CON_CLASS,
                        SASI: sessionData.SASI || SASI
                    }
                };

                // 세션 데이터로 클라이언트에 전송
                finalizeResponse();
            } else {
                // 일치하는 PHONE 값이 없을 때: 로직을 계속 진행
                handleCarAndSasi(CAR, SASI, userResults[0]);
            }
        });
    });

    function handleCarAndSasi(CAR, SASI, user) {
        connection.query('SELECT CURRENT_LOCATION FROM bon_carplayer WHERE CAR = ? AND LOCATION = "신항"', [CAR], (err, carResults) => {
            if (err || carResults.length === 0) {
                console.error('bon_carplayer 데이터 조회 중 오류:', err);
                connection.end();
                return res.status(500).send('내부 서버 오류');
            }

            const currentLocDigits = carResults[0].CURRENT_LOCATION;
            processTotalValues(SASI, currentLocDigits, user);
        });
    }

    function processTotalValues(SASI, currentLocDigits, user) {
        connection.query('SELECT * FROM bon_planing_sin WHERE RESERVE IS NULL AND (B_BANIP NOT IN ("HOLD", "CANCEL") OR B_BANIP IS NULL);', (err, planResults) => {
            if (err) {
                console.error('bon_planing_sin 데이터 조회 중 오류:', err);
                connection.end();
                return res.status(500).send('내부 서버 오류');
            }
    
            let selectedRow = null;  // 최종 선택된 행을 저장하는 변수
    
            // SANG_HA 접두사에 따른 우선순위 리스트 정의
            const sangHaPriorityMap = {
                DGTBC: ["DGTBC", "HJNPC", "PNCOC", "PNITC", "HPNTC", "BNCTC", "BCTHD"],
                HJNPC: ["HJNPC", "PNCOC", "DGTBC", "PNITC", "HPNTC", "BNCTC", "BCTHD"],
                PNCOC: ["PNCOC", "HJNPC", "PNITC", "DGTBC", "HPNTC", "BNCTC", "BCTHD"],
                PNITC: ["PNITC", "PNCOC", "HPNTC", "HJNPC", "DGTBC", "BNCTC", "BCTHD"],
                HPNTC: ["HPNTC", "BNCTC", "PNITC", "BCTHD", "PNCOC", "HJNPC", "DGTBC"],
                BNCTC: ["BNCTC", "HPNTC", "BCTHD", "PNITC", "PNCOC", "HJNPC", "DGTBC"],
                BCTHD: ["BCTHD", "BNCTC", "HPNTC", "PNITC", "PNCOC", "HJNPC", "DGTBC"]
            };
    
            // currentLocDigits에 맞는 우선순위 리스트 가져오기
            const priorityList = sangHaPriorityMap[currentLocDigits] || [];
    
            // 차량 조건에 맞는 데이터를 찾기 위한 반복문
            for (let i = 0; i < priorityList.length; i++) {
                const prefix = priorityList[i];  // 현재 우선순위 접두사
    
                // planResults에서 우선순위 접두사와 일치하는 데이터를 찾음
                planResults.some(row => {
                    const totalValueStr = String(row.TOTAL).split('.')[0];
                    const totalRightThree = totalValueStr.slice(-3);
                    const totalRightThreeNum = parseInt(totalRightThree, 10);
                    const totalValue = parseInt(totalValueStr, 10);
    
                    // TOTAL 값 조건 필터링
                    if (totalRightThreeNum >= 12 && totalRightThreeNum <= 110 && totalValue <= 400000) {
                        const sangHaPrefix = row.SANG_HA.split('(')[0].split('-')[0];
    
                        // 현재 우선순위 접두사(prefix)와 일치하는 경우
                        if (sangHaPrefix === prefix) {
                            // SASI 조건에 맞는지 확인
                            if ((SASI === "콤바인샤시" && row.TOTAL % 1 <= 0.5) || 
                                (SASI === "라인샤시" && row.TOTAL % 1 === 0)) {
                                
                                // 최종 선택된 행을 저장하고 루프 종료
                                selectedRow = row;
                                return true;  // 일치하는 데이터를 찾았으므로 반복문 종료
                            }
                        }
                    }
                    return false;  // 일치하는 데이터가 없으면 계속 탐색
                });
    
                // 일치하는 데이터를 찾았으면 더 이상 우선순위를 탐색하지 않음
                if (selectedRow) {
                    break;
                }
            }
    
            // 선택된 데이터 처리
            if (selectedRow) {
                assignTotalValue(selectedRow, user);
            } else {
                req.session.assignedData = null;
                connection.end();
                res.redirect('/driver1');  // /driver1로 리다이렉트
            }
        });
    }
    
    function assignTotalValue(row, user) {
        if (!row || !row.B_IDX) {
            console.error('유효하지 않은 데이터: B_IDX 값이 없습니다.', row);
            connection.end();
            return res.status(400).send('B_IDX value not set.');
        }
    
        const selectedSangHa = row.SANG_HA;
        
    
        // bon_session 테이블에 데이터 삽입
        connection.query(
            `INSERT INTO bon_session (NAME, CAR, PHONE, SANG_HA, CON_NO, CON_KU, CON_KG, B_KUM_IN, CON_TEMP, CON_CLASS, TOTAL, SASI, DATA_INS)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
            [user.NAME, user.CAR, user.PHONE, row.SANG_HA, row.CON_NO, row.CON_KU, row.CON_KG, row.B_KUM_IN, row.CON_TEMP, row.CON_CLASS, row.TOTAL, user.SASI],
            (err) => {
                if (err) {
                    console.error('bon_session 데이터 삽입 중 오류:', err);
                    connection.end();
                    return res.status(500).send('내부 서버 오류');
                }
    
                // 삽입 후 bon_planing_sin 테이블의 RESERVE 값을 재시도 로직을 통해 업데이트
                updateWithRetry(connection, row.CON_NO)
                    .then(() => {
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
    
                        finalizeResponse();
                    })
                    .catch((err) => {
                        console.error('bon_planing_sin 업데이트 중 오류:', err);
                        connection.end();
                        return res.status(500).send('내부 서버 오류');
                    });
            }
        );
    }
    
    function finalizeResponse() {
        res.render('index_배차', {
            user: { id: req.session.user.id, car: req.session.car, role: req.session.user.role },
            sessionID: req.sessionID,
            assignedTotal: req.session.assignedData.assignedTotal,
            currentData: req.session.assignedData.currentData
        });
        connection.end();
    }
});




// 요구사항 1과 2: 데이터 전송 API
const connection1 = mysql.createConnection(dbConfig1);
const connection2 = mysql.createConnection(dbConfig2);

connection1.connect(err => {
    if (err) {
        console.error('dbConfig1 연결 오류:', err);
        return;
    }
    console.log('dbConfig1 연결 성공');
});

connection2.connect(err => {
    if (err) {
        console.error('dbConfig2 연결 오류:', err);
        return;
    }
    console.log('dbConfig2 연결 성공');
});

// 요구사항 1과 2: 데이터 전송 API
app.post('/api/send-data', (req, res) => {
    const { conNo } = req.body;
    const userId = req.session.user.id; // 현재 세션의 사용자 ID

    // 요청 시마다 새로운 연결을 생성
    const connection1 = mysql.createConnection(dbConfig1);
    const connection2 = mysql.createConnection(dbConfig2);

    connection1.query('SELECT B_IDX FROM bon_planing_sin WHERE CON_NO = ?', [conNo], (err, planingSinResult) => {
        if (err) {
            console.error('bon_planing_sin 조회 중 오류 발생:', err);
            connection1.end(); // 연결 해제
            return res.status(500).json({ success: false, message: '내부 서버 오류' });
        }

        if (planingSinResult.length === 0) {
            connection1.end(); // 연결 해제
            return res.status(404).json({ success: false, message: '데이터를 찾을 수 없습니다.' });
        }

        const B_IDX = planingSinResult[0].B_IDX;

        connection1.query('SELECT CAR, NAME, PART, CAR_ID FROM bon_user WHERE ID = ?', [userId], (err, userResult) => {
            if (err) {
                console.error('bon_user 조회 중 오류 발생:', err);
                connection1.end(); // 연결 해제
                return res.status(500).json({ success: false, message: '내부 서버 오류' });
            }

            if (userResult.length === 0) {
                connection1.end(); // 연결 해제
                return res.status(404).json({ success: false, message: '사용자 정보를 찾을 수 없습니다.' });
            }

            const { CAR, NAME, PART, CAR_ID } = userResult[0];
            const currentDate = getCurrentSeoulTime2();

            connection2.query('SELECT C_IDX FROM t_cust_bae WHERE CONVERT(CAST(C_NAME2 AS BINARY) USING utf8mb4) = CONVERT(CAST(? AS BINARY) USING utf8mb4) AND C_DEL = "N"', [PART], (err, custBaeResult) => {
                if (err) {
                    console.error('t_cust 조회 중 오류 발생:', err);
                    connection1.end(); // 연결 해제
                    connection2.end(); // 연결 해제
                    return res.status(500).json({ success: false, message: '내부 서버 오류' });
                }

                if (custBaeResult.length === 0) {
                    connection1.end(); // 연결 해제
                    connection2.end(); // 연결 해제
                    return res.status(404).json({ success: false, message: '고객 정보를 찾을 수 없습니다.' });
                }

                const C_IDX = custBaeResult[0].C_IDX;

                connection2.query('SELECT COUNT(*) AS count FROM t_baecha WHERE B_IDX = ?', [B_IDX], (err, existsResult) => {
                    if (err) {
                        console.error('t_baecha 존재 확인 중 오류 발생:', err);
                        connection1.end(); // 연결 해제
                        connection2.end(); // 연결 해제
                        return res.status(500).json({ success: false, message: '내부 서버 오류' });
                    }

                    const recordExists = existsResult[0].count > 0;

                    if (recordExists) {
                        const updateBaecha = `
                            UPDATE t_baecha
                            SET 
                                B_DATE = CONVERT(CAST(? AS BINARY) USING utf8mb4),
                                B_CAR = CONVERT(CAST(? AS BINARY) USING utf8mb4),
                                B_DRIVER = CONVERT(CAST(? AS BINARY) USING utf8mb4),
                                B_CAR_ID = CONVERT(CAST(? AS BINARY) USING utf8mb4),
                                C_IDX_IN = CONVERT(CAST(? AS BINARY) USING utf8mb4)
                            WHERE B_IDX = ? AND B_DEL = "N";
                        `;
                        connection2.query(updateBaecha, [currentDate, CAR, NAME, CAR_ID, C_IDX, B_IDX], (err, result) => {
                            if (err) {
                                console.error('t_baecha 업데이트 중 오류 발생:', err);
                                connection1.end(); // 연결 해제
                                connection2.end(); // 연결 해제
                                return res.status(500).json({ success: false, message: '내부 서버 오류' });
                            }

                            const insertTTBaecha = `
                                INSERT INTO tt_baecha (B_IDX, C_IDX_BON, B_DIV_LOC, CON_NO, B_CAR_ID, DATE_INS, B_DIV_WORK)
                                VALUES (?, '1', CONVERT(CAST('운송6팀(본선)' AS BINARY) USING utf8mb4), ?, ?, ?, 'TS');
                            `;
                            connection2.query(insertTTBaecha, [B_IDX, conNo, CAR_ID, currentDate], (err, result) => {
                                connection1.end(); // 연결 해제
                                connection2.end(); // 연결 해제
                                if (err) {
                                    console.error('tt_baecha 삽입 중 오류 발생:', err);
                                    return res.status(500).json({ success: false, message: '내부 서버 오류' });
                                }

                                return res.json({ success: true, message: '데이터 업데이트 및 삽입 완료' });
                            });
                        });
                    } else {
                        connection1.end(); // 연결 해제
                        connection2.end(); // 연결 해제
                        return res.status(404).json({ success: false, message: '해당 B_IDX 레코드가 존재하지 않습니다.' });
                    }
                });
            });
        });
    });
});




app.post('/set-return-to', (req, res) => {
    if (req.session) {
        req.session.returnTo = req.body.returnTo;
        res.status(200).send({ success: true });
    } else {
        res.status(400).send({ success: false, message: '세션이 유효하지 않습니다.' });
    }
});




// bon_log 인설트
app.post('/api/insert-log', (req, res) => {
    if (!req.session.user) {
        console.log('세션에 사용자 정보가 없습니다.');
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const userId = req.session.user.id;
    const { conNo, sangHa } = req.body;
    const connection = createConnection(dbConfig1);

    connection.query('SELECT CAR FROM bon_user WHERE ID = ?', [userId], (error, results) => {
        if (error) {
            console.error('사용자 조회 오류:', error);
            connection.end();
            return res.status(500).json({ success: false, message: 'Database query error', error });
        }

        if (results.length > 0) {
            const carNumber = results[0].CAR;
            const time = getCurrentSeoulTime();

            // 먼저 CON_NO가 이미 존재하는지 확인
            connection.query('SELECT * FROM bon_log WHERE CON_NO = ?', [conNo], (selectError, selectResults) => {
                if (selectError) {
                    console.error('로그 조회 오류:', selectError);
                    connection.end();
                    return res.status(500).json({ success: false, message: 'Select log error', error: selectError });
                }

                if (selectResults.length > 0) {
                    // CON_NO가 이미 존재하면 업데이트
                    connection.query(
                        'UPDATE bon_log SET CAR = ?, SANG_HA = ?, TIME = ? WHERE CON_NO = ?',
                        [carNumber, sangHa, time, conNo],
                        (updateError) => {
                            connection.end();
                            if (updateError) {
                                console.error('로그 업데이트 오류:', updateError);
                                return res.status(500).json({ success: false, message: 'Update log error', error: updateError });
                            }
                            res.json({ success: true });
                        }
                    );
                } else {
                    // CON_NO가 존재하지 않으면 삽입
                    connection.query(
                        'INSERT INTO bon_log (CAR, CON_NO, SANG_HA, TIME) VALUES (?, ?, ?, ?)',
                        [carNumber, conNo, sangHa, time],
                        (insertError) => {
                            connection.end();
                            if (insertError) {
                                console.error('로그 삽입 오류:', insertError);
                                return res.status(500).json({ success: false, message: 'Insert log error', error: insertError });
                            }
                            res.json({ success: true });
                        }
                    );
                }
            });
        } else {
            console.error('사용자 없음: ', userId);
            connection.end();
            res.status(404).json({ success: false, message: 'User not found' });
        }
    });
});

// SANG_WORK 업데이트
app.post('/api/update-sang-work', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const { conNo, status } = req.body;
    const connection = createConnection(dbConfig1);

    connection.query('UPDATE bon_log SET SANG_WORK = ? WHERE CON_NO = ?', [status, conNo], (error, results) => {
        connection.end();
        if (error) {
            return res.status(500).json({ success: false, message: 'Update SANG_WORK error' });
        }
        res.json({ success: true });
    });
});

// HA_WORK 업데이트
app.post('/api/update-ha-work', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const { conNo, status } = req.body;
    const userId = req.session.user.id;
    const connection = createConnection(dbConfig1);

    // 현재 로그인한 유저의 PHONE 값을 가져오기
    connection.query('SELECT PHONE FROM bon_user WHERE ID = ?', [userId], (err, userResults) => {
        if (err || userResults.length === 0) {
            console.error('유저 정보 조회 중 오류:', err);
            connection.end();
            return res.status(500).json({ success: false, message: '유저 정보를 가져올 수 없습니다.' });
        }

        const userPhone = userResults[0].PHONE;

        // bon_session 테이블에서 PHONE 값이 일치하는 행 삭제
        connection.query('DELETE FROM bon_session WHERE PHONE = ?', [userPhone], (deleteSessionError, deleteSessionResults) => {
            if (deleteSessionError) {
                console.error('bon_session 삭제 중 오류:', deleteSessionError);
                connection.end();
                return res.status(500).json({ success: false, message: 'bon_session 삭제 오류' });
            }

            // bon_log 테이블의 HA_WORK 업데이트
            connection.query('UPDATE bon_log SET HA_WORK = ? WHERE CON_NO = ?', [status, conNo], (error, results) => {
                if (error) {
                    console.error('HA_WORK 업데이트 중 오류:', error);
                    connection.end();
                    return res.status(500).json({ success: false, message: 'HA_WORK 업데이트 오류' });
                }

                // bon_planing_sin 테이블에서 CON_NO에 해당하는 행 삭제
                connection.query('DELETE FROM bon_planing_sin WHERE CON_NO = ?', [conNo], (deleteError, deleteResults) => {
                    connection.end(); // 쿼리 실행 후 연결 종료

                    if (deleteError) {
                        console.error('bon_planing_sin 삭제 중 오류:', deleteError);
                        return res.status(500).json({ success: false, message: 'bon_planing_sin 삭제 오류' });
                    }

                    res.json({ success: true, message: '업데이트 및 삭제 완료' });
                });
            });
        });
    });
});

app.post('/api/delete-log', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const { conNo } = req.body;
    const connection = createConnection(dbConfig1);

    connection.query('DELETE FROM bon_log WHERE CON_NO = ?', [conNo], (error, results) => {
        connection.end();
        if (error) {
            return res.status(500).json({ success: false, message: 'Delete log error' });
        }
        res.json({ success: true });
    });
});

app.post('/api/update-current-location', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const userId = req.session.user.id;
    const { newLocation, newcunt } = req.body; // 클라이언트에서 새로운 위치 데이터와 컨테이너 번호 받기
    const connection = createConnection(dbConfig1);

    // bon_user 테이블에서 CAR 값 가져오기
    connection.query('SELECT CAR FROM bon_user WHERE ID = ?', [userId], (error, results) => {
        if (error) {
            console.error('사용자 데이터 조회 오류:', error);
            connection.end();
            return res.status(500).json({ success: false, message: 'Database query error', error });
        }

        if (results.length > 0) {
            const car = results[0].CAR;

            // newLocation과 newcunt 값을 결합
            const combinedLocation = `${newcunt} : ${newLocation}`;

            // bon_carplayer 테이블의 CURRENT_LOCATION 업데이트
            connection.query('UPDATE bon_carplayer SET CURRENT_LOCATION = ? WHERE CAR = ? AND OFF IS NULL', 
            [combinedLocation, car], (updateError, updateResults) => {
                connection.end();
                if (updateError) {
                    console.error('CURRENT_LOCATION 업데이트 오류:', updateError);
                    return res.status(500).json({ success: false, message: 'Update CURRENT_LOCATION error', error: updateError });
                }

                res.json({ success: true, message: 'CURRENT_LOCATION 업데이트 완료' });
            });
        } else {
            connection.end();
            res.status(404).json({ success: false, message: '일치하는 사용자를 찾을 수 없습니다.' });
        }
    });
});

//driver4 라우터------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------



app.get('/driver4', sessionChecker, sessionIDProvider, checkRoleForCarOrManager, (req, res) => {
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

    // 재시도 로직 함수
    const updateWithRetry = async (connection, bIdx, retries = 5) => {
        for (let attempt = 0; attempt < retries; attempt++) {
            try {
                await new Promise((resolve, reject) => {
                    connection.query(`UPDATE bon_planing_sin SET RESERVE = "Y" WHERE B_IDX = ?`, [bIdx], (err) => {
                        if (err) {
                            if (err.code === 'ER_LOCK_WAIT_TIMEOUT') {
                                console.log(`Lock wait timeout exceeded. Retrying... (${attempt + 1}/${retries})`);
                                return reject('Timeout, retrying...');
                            }
                            return reject(err);
                        }
                        resolve();
                    });
                });
                return; // 성공적으로 업데이트되면 종료
            } catch (err) {
                if (attempt === retries - 1) {
                    throw err; // 최대 재시도 횟수 초과 시 오류 발생
                }
                await new Promise(resolve => setTimeout(resolve, 1000)); // 1초 대기 후 재시도
            }
        }
    };

    try {
        const userId = req.session.user.id;

        // 현재 로그인한 유저의 PHONE 값과 SASI 값을 가져오기
        const { userPhone, userSasi } = await new Promise((resolve, reject) => {
            connection.query('SELECT PHONE, CAST(SASI AS CHAR CHARACTER SET utf8mb4) AS SASI FROM bon_user WHERE ID = ?', [userId], (err, results) => {
                if (err || results.length === 0) {
                    console.error('유저 정보 조회 중 오류:', err);
                    return reject(err || new Error('유저 정보를 가져올 수 없습니다.'));
                }
                resolve({
                    userPhone: results[0].PHONE,
                    userSasi: results[0].SASI
                });
            });
        });

        // bon_session 테이블에서 PHONE 값이 일치하는 레코드의 TOTAL 값을 가져오기
        const sessionTotal = await new Promise((resolve, reject) => {
            connection.query('SELECT TOTAL FROM bon_session WHERE PHONE = ?', [userPhone], (err, results) => {
                if (err) {
                    console.error('TOTAL 조회 중 오류:', err);
                    return reject(err);
                }
                resolve(results.length > 0 ? results[0].TOTAL : null);
            });
        });

        // sessionTotal 값을 무조건 currentTotal로 사용
        let currentTotal = sessionTotal;

        if (!currentTotal || !userSasi) {
            return res.status(400).json({ message: 'currentTotal 또는 SASI 값이 누락되었습니다.' });
        }

        const integerTotal = Math.floor(currentTotal); // 소수점 이하를 제거한 값
        const currentTotalString = integerTotal.toString(); // 문자열로 변환
        const currentTotalTrimmed = currentTotalString.slice(-3); // 마지막 세 자리 추출

        console.log(`Received currentTotal: ${currentTotal}`);
        console.log(`Calculated currentTotalTrimmed: ${currentTotalTrimmed}`);

        // 우선순위 필터링 범위 정의
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
            return res.status(400).json({ message: `유효하지 않은 currentTotalTrimmed 값: ${currentTotalTrimmed}` });
        }

        let selectedTotal = null;

        // 각 우선순위 범위에 따라 필터링하여 선택
        for (const priority of range) {
            const [min, max] = priority.split('-').map(Number);
        
            const possibleTotals = await new Promise((resolve, reject) => {
                connection.query(`
                    (
                        SELECT * 
                        FROM bon_planing_sin 
                        WHERE CAST(SUBSTRING(CAST(TOTAL AS UNSIGNED), -3) AS UNSIGNED) BETWEEN ? AND ?
                        AND RESERVE IS NULL
                        AND B_BANIP = '1ST'
                        AND (
                            (? = '라인샤시' AND MOD(CAST(TOTAL AS DECIMAL(10,1)), 1) = 0)  -- 라인샤시는 소수점이 없어야 함
                            OR
                            (? = '콤바인샤시')  -- 콤바인샤시는 소수점이 있어도 되고 없어도 됨
                        )
                        ORDER BY CAST(TOTAL AS DECIMAL(10, 1)) DESC
                        LIMIT 1
                    )
                    UNION
                    (
                        SELECT * 
                        FROM bon_planing_sin 
                        WHERE CAST(SUBSTRING(CAST(TOTAL AS UNSIGNED), -3) AS UNSIGNED) BETWEEN ? AND ?
                        AND RESERVE IS NULL
                        AND (B_BANIP NOT IN ("HOLD", "CANCEL") OR B_BANIP IS NULL)
                        AND (
                            (? = '라인샤시' AND MOD(CAST(TOTAL AS DECIMAL(10,1)), 1) = 0)  
                            OR
                            (? = '콤바인샤시')
                        )
                        ORDER BY CAST(TOTAL AS DECIMAL(10, 1)) DESC
                        LIMIT 1
                    )
                    LIMIT 1;
                `, [min, max, userSasi, userSasi, min, max, userSasi, userSasi], (err, results) => {
                    if (err) {
                        console.error('쿼리 실행 중 오류:', err);
                        return reject(err);
                    }
                    // 쿼리 결과를 resolve로 전달
                    resolve(results);
                });
            });
        
            // 쿼리 외부에서 조건을 적용하여 필터링
            possibleTotals.forEach(row => {
                const totalValueStr = String(row.TOTAL).split('.')[0]; // TOTAL의 정수 부분 추출
                const totalRightThree = totalValueStr.slice(-3); // TOTAL 값의 마지막 세 자리 추출
                const totalRightThreeNum = parseInt(totalRightThree, 10); // 마지막 세 자리를 정수로 변환
                const totalValue = parseInt(totalValueStr, 10); // TOTAL 값의 정수 부분을 정수로 변환
        
                console.log(`Processing row: TOTAL=${row.TOTAL}, totalRightThreeNum=${totalRightThreeNum}, totalValue=${totalValue}`);
        
                // 특정 조건에 따른 선택 로직
                if (totalRightThreeNum >= 12 && totalRightThreeNum <= 110 && totalValue <= 400000) {
                    console.log(`Match found: TOTAL=${row.TOTAL}`);
                    selectedTotal = row; // 조건을 만족하는 경우 selectedTotal에 값을 저장
                }
            });
        
            if (selectedTotal) {
                break; // 조건에 맞는 배차가 선택되면 반복문 종료
            }
        }
        
        if (selectedTotal) {
            // 재시도 로직을 적용한 업데이트 함수 사용
            await updateWithRetry(connection, selectedTotal.B_IDX);

            const { B_IDX } = selectedTotal;

            // B_IDX 값을 이용해 bon_planing_sin에서 CON_NO 값을 추출
            const extractedConNo = await new Promise((resolve, reject) => {
                connection.query(`SELECT CON_NO FROM bon_planing_sin WHERE B_IDX = ?`, [B_IDX], (err, results) => {
                    if (err) {
                        console.error('CON_NO 추출 중 오류:', err);
                        return reject(err);
                    }
                    if (results.length === 0) {
                        return reject(new Error('해당 B_IDX에 대한 CON_NO를 찾을 수 없습니다.'));
                    }
                    resolve(results[0].CON_NO);
                });
            });

            const carResult = await new Promise((resolve, reject) => {
                connection.query('SELECT CAR FROM bon_user WHERE ID = ?', [req.session.user.id], (err, results) => {
                    if (err || results.length === 0) {
                        console.error('CAR 조회 중 오류:', err);
                        return reject(err);
                    }
                    resolve(results[0].CAR);
                });
            });

            const currentTime = getCurrentSeoulTime();

            // 먼저 CON_NO가 이미 존재하는지 확인
            const existingLog = await new Promise((resolve, reject) => {
                connection.query('SELECT * FROM bon_log WHERE CON_NO = ?', [extractedConNo], (selectError, selectResults) => {
                    if (selectError) {
                        console.error('로그 조회 오류:', selectError);
                        return reject(selectError);
                    }
                    resolve(selectResults.length > 0);
                });
            });

            if (existingLog) {
                // CON_NO가 이미 존재하면 업데이트
                await new Promise((resolve, reject) => {
                    connection.query(
                        'UPDATE bon_log SET CAR = ?, SANG_HA = ?, TIME = ? WHERE CON_NO = ?',
                        [carResult, selectedTotal.SANG_HA, currentTime, extractedConNo],
                        (updateError) => {
                            if (updateError) {
                                console.error('로그 업데이트 오류:', updateError);
                                return reject(updateError);
                            }
                            resolve();
                        }
                    );
                });
            } else {
                // CON_NO가 존재하지 않으면 삽입
                await new Promise((resolve, reject) => {
                    connection.query(
                        'INSERT INTO bon_log (CAR, CON_NO, SANG_HA, TIME) VALUES (?, ?, ?, ?)',
                        [carResult, extractedConNo, selectedTotal.SANG_HA, currentTime],
                        (insertError) => {
                            if (insertError) {
                                console.error('로그 삽입 오류:', insertError);
                                return reject(insertError);
                            }
                            resolve();
                        }
                    );
                });
            }

            // 세션에 nextData 저장
            req.session.nextData = selectedTotal;

            res.json({ success: true, nextDispatch: selectedTotal });
        } else {
            res.status(404).json({ success: false, message: '적합한 배차를 찾을 수 없습니다.' });
        }

    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: '서버 내부 오류' });
    } finally {
        connection.end(); // 모든 처리가 끝난 후에 연결을 종료합니다.
    }
});

app.post('/start-next-batch', (req, res) => {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ message: '사용자 세션이 없습니다.' });
    }

    if (!req.session.nextData) {
        return res.status(400).json({ message: 'nextData가 세션에 없습니다.' });
    }
    const { SANG_HA, CON_NO, CON_KU, CON_KG, B_KUM_IN, CON_TEMP, CON_CLASS, TOTAL, SASI } = req.session.nextData;
    const userId = req.session.user.id;
    const connection = createConnection(dbConfig1); // 데이터베이스 연결 객체 생성

    connection.connect(err => {
        if (err) {
            console.error('데이터베이스 연결 오류:', err);
            return res.status(500).json({ success: false, message: '데이터베이스 연결 오류' });
        }

        // 현재 로그인한 유저의 PHONE, NAME, CAR 값을 가져오기
        connection.query('SELECT PHONE, NAME, CAR FROM bon_user WHERE ID = ?', [userId], (err, userResults) => {
            if (err || userResults.length === 0) {
                console.error('유저 정보 조회 중 오류:', err);
                connection.end();
                return res.status(500).json({ success: false, message: '유저 정보를 가져올 수 없습니다.' });
            }

            const { PHONE: userPhone, NAME: userName, CAR: userCar } = userResults[0];

            // bon_session 테이블에서 PHONE 값이 일치하는 레코드가 있는지 확인
            connection.query('SELECT * FROM bon_session WHERE PHONE = ?', [userPhone], (err, sessionResults) => {
                if (err) {
                    console.error('bon_session 조회 중 오류:', err);
                    connection.end();
                    return res.status(500).json({ success: false, message: '데이터베이스 조회 오류' });
                }

                if (sessionResults.length > 0) {
                    // PHONE 값이 일치하는 레코드가 있으면 업데이트
                    connection.query(`
                        UPDATE bon_session 
                        SET NAME = ?, CAR = ?, SANG_HA = ?, CON_NO = ?, CON_KU = ?, CON_KG = ?, B_KUM_IN = ?, CON_TEMP = ?, CON_CLASS = ?, TOTAL = ?, SASI = ?, DATA_INS = ?
                        WHERE PHONE = ?`,
                        [userName, userCar, SANG_HA, CON_NO, CON_KU, CON_KG, B_KUM_IN, CON_TEMP, CON_CLASS, TOTAL, SASI, getCurrentSeoulTime(), userPhone],
                        (err, updateResults) => {
                            connection.end();
                            if (err) {
                                console.error('bon_session 업데이트 중 오류:', err);
                                return res.status(500).json({ success: false, message: '데이터 업데이트 오류' });
                            }

                            // currentTotal 값을 클라이언트에 반환
                            res.json({ success: true, message: 'bon_session이 성공적으로 업데이트되었습니다.', currentTotal: TOTAL });
                        }
                    );
                } else {
                    // PHONE 값이 일치하는 레코드가 없으면 새 레코드를 삽입
                    connection.query(`
                        INSERT INTO bon_session (NAME, CAR, PHONE, SANG_HA, CON_NO, CON_KU, CON_KG, B_KUM_IN, CON_TEMP, CON_CLASS, TOTAL, SASI, DATA_INS) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                        [userName, userCar, userPhone, SANG_HA, CON_NO, CON_KU, CON_KG, B_KUM_IN, CON_TEMP, CON_CLASS, TOTAL, SASI, getCurrentSeoulTime()],
                        (err, insertResults) => {
                            connection.end();
                            if (err) {
                                console.error('bon_session 삽입 중 오류:', err);
                                return res.status(500).json({ success: false, message: '데이터 삽입 오류' });
                            }

                            // currentTotal 값을 클라이언트에 반환
                            res.json({ success: true, message: 'bon_session이 성공적으로 삽입되었습니다.', currentTotal: TOTAL });
                        }
                    );
                }
            });
        });
    });
});

// 운행 종료를 눌렀을때 -------------------------------------------------------------------------------------------------------------------------------------
function createConnection(config) {
    return mysql.createConnection(config);
}



app.post('/end-driving', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send({ success: false, message: "로그인이 필요합니다." });
    }

    const userId = req.session.user.id;
    const { CON_NO } = req.body;

    const connection1 = createConnection(dbConfig1);
    const connection2 = createConnection(dbConfig2);
    const currentTime = getCurrentSeoulTime();

    connection1.connect((err) => {
        if (err) {
            console.error('dbConfig1 데이터베이스 연결 중 오류 발생:', err);
            return res.status(500).send({ success: false, message: "내부 서버 오류" });
        }

        connection1.query('SELECT CAR, PHONE FROM bon_user WHERE ID = ?', [userId], (err, userResults) => {
            if (err) {
                console.error('사용자 데이터 가져오는 중 오류 발생:', err);
                connection1.end();
                return res.status(500).send({ success: false, message: "내부 서버 오류" });
            }

            if (userResults.length > 0) {
                const userCar = userResults[0].CAR;
                const userPhone = userResults[0].PHONE;

                connection1.query('SELECT * FROM bon_carplayer WHERE CAR = ?', [userCar], (err, carResults) => {
                    if (err) {
                        console.error('bon_carplayer 데이터 가져오는 중 오류 발생:', err);
                        connection1.end();
                        return res.status(500).send({ success: false, message: "내부 서버 오류" });
                    }

                    if (carResults.length > 0) {
                        connection1.query('UPDATE bon_carplayer SET OFF = ? WHERE CAR = ? AND OFF IS NULL', [currentTime, userCar], (err) => {
                            if (err) {
                                console.error('bon_carplayer 업데이트 중 오류 발생:', err);
                                connection1.end();
                                return res.status(500).send({ success: false, message: "내부 서버 오류" });
                            }

                            // RESERVE 값 제거 작업
                            connection1.query('UPDATE bon_planing_sin SET RESERVE = NULL WHERE CON_NO = ?', [CON_NO], (err) => {
                                if (err) {
                                    console.error('bon_planing_sin 업데이트 중 오류 발생:', err);
                                    connection1.end();
                                    return res.status(500).send({ success: false, message: "내부 서버 오류" });
                                }

                                // bon_planing_sin에서 B_IDX 가져오기
                                connection1.query('SELECT B_IDX FROM bon_planing_sin WHERE CON_NO = ?', [CON_NO], (err, planingSinResult) => {
                                    if (err) {
                                        console.error('bon_planing_sin에서 B_IDX 가져오는 중 오류 발생:', err);
                                        connection1.end();
                                        return res.status(500).send({ success: false, message: "내부 서버 오류" });
                                    }

                                    if (planingSinResult.length > 0) {
                                        const B_IDX = planingSinResult[0].B_IDX;

                                        // t_baecha에서 해당 B_IDX의 특정 컬럼을 NULL로 업데이트
                                        connection2.connect((err) => {
                                            if (err) {
                                                console.error('dbConfig2 데이터베이스 연결 중 오류 발생:', err);
                                                connection1.end();
                                                return res.status(500).send({ success: false, message: "내부 서버 오류" });
                                            }

                                            const query = `
                                                UPDATE t_baecha 
                                                SET B_CAR = NULL, B_DRIVER = NULL, B_CAR_ID = NULL, C_IDX_IN = NULL, B_DATE = NULL 
                                                WHERE B_IDX = ? AND B_DIV_WORK = ?`;

                                            connection2.query(query, [B_IDX, 'TS'], (err, result) => {
                                                if (err) {
                                                    console.error('t_baecha 업데이트 중 오류 발생:', err);
                                                    connection1.end();
                                                    connection2.end();
                                                    return res.status(500).send({ success: false, message: "내부 서버 오류" });
                                                }

                                                // bon_session에서 PHONE 값이 일치하는 행 삭제
                                                connection1.query('DELETE FROM bon_session WHERE PHONE = ?', [userPhone], (err) => {
                                                    connection1.end();
                                                    connection2.end();

                                                    if (err) {
                                                        console.error('bon_session에서 PHONE 값 삭제 중 오류 발생:', err);
                                                        return res.status(500).send({ success: false, message: "내부 서버 오류" });
                                                    }

                                                    return res.send({ success: true, message: "운행 종료 처리 완료 및 세션 데이터 삭제 완료" });
                                                });
                                            });
                                        });
                                    } else {
                                        connection1.end();
                                        return res.status(404).send({ success: false, message: "해당 데이터를 찾을 수 없습니다." });
                                    }
                                });
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



// 내정보 페이지--------------------------------------------------------------------------------------------------------------------------------------------------------------------
app.get('/my', checkRoleForCarOrManager, (req, res) => {
    if (!req.session.user || !req.session.user.id) {
        return res.redirect('/');
    }

    const userId = req.session.user.id;
    const connection1 = createConnection(dbConfig1);

    connection1.connect((err) => {
        if (err) {
            console.error('데이터베이스 연결 중 오류 발생: ', err);
            return res.status(500).send('내부 서버 오류');
        }

        // bon_user 테이블에서 사용자 정보와 역할을 조회
        connection1.query('SELECT ID, NAME, ROLE FROM bon_user WHERE ID = ?', [userId], (err, userResults) => {
            if (err) {
                console.error('사용자 데이터 가져오는 중 오류 발생: ', err);
                connection1.end();
                return res.status(500).send('내부 서버 오류');
            }

            if (userResults.length > 0) {
                const user = userResults[0];
                req.session.user = {
                    id: user.ID,
                    name: user.NAME,
                    role: user.ROLE // 세션에 ROLE 정보 저장
                };

                // 사용자 정보를 템플릿에 전달하고, my 페이지 렌더링
                res.render('index_내정보', {
                    user: req.session.user,
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



// 사용자 정보 가져오기 API
app.get('/api/my-info', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('로그인이 필요합니다.');
    }

    const userId = req.session.user.id;
    const query = 'SELECT NAME, PASSWORD, PHONE, CAR, CAR_ID, SASI, PART FROM bon_user WHERE ID = ?';
    queryWithReconnect(dbConfig1, query, [userId], (error, results) => {
        if (error) {
            return res.status(500).send('데이터베이스 오류');
        }
        if (results.length === 0) {
            return res.status(404).send('사용자를 찾을 수 없습니다.');
        }
        res.json(results[0]);
    });
});

// 사용자 정보 업데이트 API
app.post('/update-user', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('로그인이 필요합니다.');
    }

    const userId = req.session.user.id;
    const { name, password, phone, car, car_id, SASI, part } = req.body;

    const updateQuery = `
        UPDATE bon_user 
        SET NAME = ?, PASSWORD = ?, PHONE = ?, CAR = ?, CAR_ID = ?, SASI = ?, PART = ?
        WHERE ID = ?
    `;
    const updateValues = [name, password, phone, car, car_id, SASI, part, userId];

    queryWithReconnect(dbConfig1, updateQuery, updateValues, (error, results) => {
        if (error) {
            return res.status(500).send('데이터베이스 업데이트 오류');
        }
        res.json({ message: '정보가 업데이트되었습니다.' });
    });
});


///////차량 출퇴근 페이지----------------------------------------------------------------------------------------------------------------------------------------------------------


app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.get('/car', (req, res) => {
    // 사용자 세션이 없거나, 사용자의 역할이 'manager'가 아니면 리디렉션
    if (!req.session.user || !['manager'].includes(req.session.user.role)) {
        return res.redirect('/');
    }

    const query = `
        SELECT * 
        FROM bon_carplayer 
        ORDER BY 
            \`OFF\` IS NOT NULL, 
            \`ON\` ASC           
    `;

    queryWithReconnect(dbConfig1, query, [], (error, results) => {
        if (error) {
            console.error('데이터베이스 쿼리 오류:', error);
            return res.status(500).send('데이터베이스 쿼리 오류가 발생했습니다.');
        }

        // 세션 ID와 함께 데이터 및 사용자 정보를 템플릿에 전달
        res.render('index_본선출퇴근', { 
            data: results, 
            user: req.session.user,
            sessionID: req.sessionID  // 세션 ID 전달
        });
    });
});

app.post('/delete-container', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('인증이 필요합니다.');
    }

    const containerIds = req.body.containerIds;
    if (!containerIds || containerIds.length === 0) {
        return res.status(400).send('삭제할 운행자가 지정되지 않았습니다.');
    }

    const placeholders = containerIds.map(() => '?').join(',');
    const sqlQuery = `DELETE FROM bon_carplayer WHERE NAME IN (${placeholders})`;

    queryWithReconnect(dbConfig1, sqlQuery, containerIds, (error, results) => {
        if (error) {
            console.error('데이터베이스 쿼리 오류:', error);
            return res.status(500).send('데이터베이스 쿼리 오류가 발생했습니다.');
        }

        res.send({ message: `${results.affectedRows}개의 행이 삭제되었습니다.` });
    });
});

///////차량 출퇴근 페이지----------------------------------------------------------------------------------------------------------------------------------------------------------


app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.get('/car', (req, res) => {
    if (!req.session.user || !['manager'].includes(req.session.user.role)) {
        return res.redirect('/');
    }

    queryWithReconnect(dbConfig1, 'SELECT * FROM bon_carplayer', [], (error, results) => {
        if (error) {
            console.error('데이터베이스 쿼리 오류:', error);
            return res.status(500).send('데이터베이스 쿼리 오류가 발생했습니다.');
        }

        res.render('index_본선출퇴근', { data: results, user: req.session.user });
    });
});

app.post('/delete-container', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('인증이 필요합니다.');
    }

    const containerIds = req.body.containerIds;
    if (!containerIds || containerIds.length === 0) {
        return res.status(400).send('삭제할 운행자가 지정되지 않았습니다.');
    }

    const placeholders = containerIds.map(() => '?').join(',');
    const sqlQuery = `DELETE FROM bon_carplayer WHERE NAME IN (${placeholders})`;

    queryWithReconnect(dbConfig1, sqlQuery, containerIds, (error, results) => {
        if (error) {
            console.error('데이터베이스 쿼리 오류:', error);
            return res.status(500).send('데이터베이스 쿼리 오류가 발생했습니다.');
        }

        res.send({ message: `${results.affectedRows}개의 행이 삭제되었습니다.` });
    });
});


///////본선로그 페이지----------------------------------------------------------------------------------------------------------------------------------------------------------


app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.get('/tslog', (req, res) => {
    // 사용자가 로그인하지 않았거나, 사용자의 역할이 'manager'가 아니라면 리디렉션
    if (!req.session.user || !['manager'].includes(req.session.user.role)) {
        return res.redirect('/');
    }

    const query = `
        SELECT * 
        FROM bon_log 
        ORDER BY TIME ASC 
    `;

    queryWithReconnect(dbConfig1, query, [], (error, results) => {
        if (error) {
            console.error('데이터베이스 쿼리 오류:', error);
            return res.status(500).send('데이터베이스 쿼리 오류가 발생했습니다.');
        }

        // 세션 ID와 함께 데이터 및 사용자 정보를 템플릿에 전달
        res.render('index_본선로그', { 
            data: results, 
            user: req.session.user,
            sessionID: req.sessionID  // 세션 ID 전달
        });
    });
});


// 배차취소
app.post('/delete-order', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('로그인이 필요합니다.');
    }

    const containerIds = req.body.containerIds;
    if (!containerIds || containerIds.length === 0) {
        return res.status(400).send('컨테이너 번호를 입력하세요.');
    }

    const placeholders = containerIds.map(() => '?').join(',');
    const sqlUpdateQuery = `UPDATE bon_planing_sin SET RESERVE = NULL WHERE CON_NO IN (${placeholders})`;
    const sqlDeleteQuery = `DELETE FROM bon_log WHERE CON_NO IN (${placeholders})`;
    const sqlSelectBIdxQuery = `SELECT B_IDX FROM bon_planing_sin WHERE CON_NO IN (${placeholders})`;
    const sqlDeleteSessionQuery = `DELETE FROM bon_session WHERE CON_NO IN (${placeholders})`;

    const connection = createConnection(dbConfig1);
    const connection2 = createConnection(dbConfig2);

    let resultsMessage = [];

    // bon_planing_sin 테이블 업데이트
    connection.query(sqlUpdateQuery, containerIds, (updateError, updateResults) => {
        if (updateError) {
            console.error('bon_planing_sin 업데이트 중 오류:', updateError);
            resultsMessage.push('bon_planing_sin 업데이트 실패');
        } else {
            resultsMessage.push(`${updateResults.affectedRows}개의 행이 bon_planing_sin에서 업데이트되었습니다.`);
        }

        // bon_log 테이블 삭제
        connection.query(sqlDeleteQuery, containerIds, (deleteError, deleteResults) => {
            if (deleteError) {
                console.error('bon_log 삭제 중 오류:', deleteError);
                resultsMessage.push('bon_log 삭제 실패');
            } else {
                resultsMessage.push(`${deleteResults.affectedRows}개의 행이 bon_log에서 삭제되었습니다.`);
            }

            // B_IDX 조회
            connection.query(sqlSelectBIdxQuery, containerIds, (selectError, selectResults) => {
                if (selectError) {
                    console.error('B_IDX 조회 중 오류:', selectError);
                    resultsMessage.push('B_IDX 조회 실패');
                } else if (selectResults.length > 0) {
                    const bIdxValues = selectResults.map(row => row.B_IDX);
                    const bIdxPlaceholders = bIdxValues.map(() => '?').join(',');
                    const sqlUpdateTbaechaQuery = `
                        UPDATE t_baecha 
                        SET B_DATE = NULL, B_CAR = NULL, B_DRIVER = NULL, B_CAR_ID = NULL, C_IDX_IN = NULL 
                        WHERE B_IDX IN (${bIdxPlaceholders}) AND B_DEL != 'Y'
                    `;

                    // t_baecha 테이블 업데이트
                    connection2.query(sqlUpdateTbaechaQuery, bIdxValues, (updateTbaechaError, updateTbaechaResults) => {
                        if (updateTbaechaError) {
                            console.error('t_baecha 업데이트 중 오류:', updateTbaechaError);
                            resultsMessage.push('t_baecha 업데이트 실패');
                        } else {
                            resultsMessage.push(`${updateTbaechaResults.affectedRows}개의 행이 t_baecha에서 업데이트되었습니다.`);
                        }

                        // bon_session 삭제
                        connection.query(sqlDeleteSessionQuery, containerIds, (deleteSessionError, deleteSessionResults) => {
                            if (deleteSessionError) {
                                console.error('bon_session 삭제 중 오류:', deleteSessionError);
                                resultsMessage.push('bon_session 삭제 실패');
                            } else {
                                resultsMessage.push(`${deleteSessionResults.affectedRows}개의 행이 bon_session에서 삭제되었습니다.`);
                            }

                            connection.end();
                            connection2.end();
                            res.send({ message: resultsMessage });
                        });
                    });
                } else {
                    // B_IDX가 없는 경우 bon_session 삭제
                    connection.query(sqlDeleteSessionQuery, containerIds, (deleteSessionError, deleteSessionResults) => {
                        if (deleteSessionError) {
                            console.error('bon_session 삭제 중 오류:', deleteSessionError);
                            resultsMessage.push('bon_session 삭제 실패');
                        } else {
                            resultsMessage.push(`${deleteSessionResults.affectedRows}개의 행이 bon_session에서 삭제되었습니다.`);
                        }

                        connection.end();
                        res.send({ message: resultsMessage });
                    });
                }
            });
        });
    });
});

// 반입확인
app.post('/delete-container2', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('인증이 필요합니다.');
    }

    const containerIds = req.body.containerIds;
    if (!containerIds || containerIds.length === 0) {
        return res.status(400).send('삭제할 컨테이너 번호를 확인하세요.');
    }

    // 쿼리의 플레이스홀더 문자열 생성
    const placeholders = containerIds.map(() => '?').join(',');

    const sqlDeleteLog = `DELETE FROM bon_log WHERE CON_NO IN (${placeholders})`;
    const sqlDeletePlanning = `DELETE FROM bon_planing_sin WHERE CON_NO IN (${placeholders})`;
    const sqlDeleteSession = `DELETE FROM bon_session WHERE CON_NO IN (${placeholders})`;

    const connection = createConnection(dbConfig1); // MySQL 연결 생성

    // 결과 메시지를 저장할 배열
    let resultsMessage = [];

    // bon_log 테이블에서 삭제
    connection.query(sqlDeleteLog, containerIds, (error, results) => {
        if (error) {
            console.error('bon_log 삭제 중 오류:', error);
            resultsMessage.push('bon_log 삭제 실패');
        } else {
            resultsMessage.push(`${results.affectedRows}개의 행이 bon_log에서 삭제되었습니다.`);
        }

        // bon_planing_sin 테이블에서 삭제
        connection.query(sqlDeletePlanning, containerIds, (deleteError, deleteResults) => {
            if (deleteError) {
                console.error('bon_planing_sin 삭제 중 오류:', deleteError);
                resultsMessage.push('bon_planing_sin 삭제 실패');
            } else {
                resultsMessage.push(`${deleteResults.affectedRows}개의 행이 bon_planing_sin에서 삭제되었습니다.`);
            }

            // bon_session 테이블에서 삭제
            connection.query(sqlDeleteSession, containerIds, (deleteSessionError, deleteSessionResults) => {
                if (deleteSessionError) {
                    console.error('bon_session 삭제 중 오류 발생:', deleteSessionError);
                    resultsMessage.push('bon_session 삭제 실패');
                } else {
                    resultsMessage.push(`${deleteSessionResults.affectedRows}개의 행이 bon_session에서 삭제되었습니다.`);
                }

                // 모든 작업이 완료되면 결과 메시지 전송
                connection.end(); // 연결 종료
                res.send({ message: resultsMessage });
            });
        });
    });
});



// 본선오더 페이지----------------------------------------------------------------------------

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.get('/tsorder', (req, res) => {
    // 사용자 세션이 없거나, 사용자의 역할이 'manager'가 아니면 리디렉션
    if (!req.session.user || !['manager'].includes(req.session.user.role)) {
        return res.redirect('/');
    }

    const query = `
        SELECT * 
        FROM bon_planing_sin 
        ORDER BY 
            CASE WHEN RESERVE IS NOT NULL THEN 0 ELSE 1 END, 
            M_DATE2 ASC
    `;

    queryWithReconnect(dbConfig1, query, [], (error, results) => {
        if (error) {
            console.error('데이터베이스 쿼리 오류:', error);
            return res.status(500).send('데이터베이스 쿼리 오류가 발생했습니다.');
        }

        // 세션 ID와 함께 데이터 및 사용자 정보를 템플릿에 전달
        res.render('index_본선플래닝오더', { 
            data: results, 
            user: req.session.user,
            sessionID: req.sessionID  // 세션 ID 전달
        });
    });
});

app.post('/delete-tsorder', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('인증이 필요합니다.');
    }

    const containerIds = req.body.containerIds;
    if (!containerIds || containerIds.length === 0) {
        return res.status(400).send('삭제할 컨테이너 번호를 확인하세요.');
    }

    // 쿼리의 플레이스홀더 문자열 생성
    const placeholders = containerIds.map(() => '?').join(',');

    // 1단계: bon_planing_sin 테이블에서 B_IDX와 CON_NO 추출
    const sqlSelectQuery = `SELECT B_IDX, CON_NO FROM bon_planing_sin WHERE CON_NO IN (${placeholders})`;

    queryWithReconnect(dbConfig1, sqlSelectQuery, containerIds, (selectError, selectResults) => {
        if (selectError) {
            console.error('데이터베이스 조회 쿼리 오류:', selectError);
            return res.status(500).send('데이터베이스 조회 쿼리 오류가 발생했습니다.');
        }

        if (selectResults.length === 0) {
            return res.status(404).send('해당 조건에 맞는 데이터가 없습니다.');
        }

        // 추출된 B_IDX와 CON_NO 값들
        const bIdxValues = selectResults.map(row => row.B_IDX);
        const conNoValues = selectResults.map(row => row.CON_NO);

        const bIdxPlaceholders = bIdxValues.map(() => '?').join(',');

        // 2단계: t_baecha 테이블에서 B_IDX가 일치하고 B_DATE가 NULL인 열의 B_DEL을 'Y'로 업데이트
        const sqlUpdateBaecha = `
            UPDATE t_baecha 
            SET B_DEL = 'Y' 
            WHERE B_IDX IN (${bIdxPlaceholders}) 
            AND B_DATE IS NULL
        `;

        queryWithReconnect(dbConfig2, sqlUpdateBaecha, bIdxValues, (updateBaechaError, updateBaechaResults) => {
            if (updateBaechaError) {
                console.error('t_baecha 테이블 업데이트 쿼리 오류:', updateBaechaError);
                return res.status(500).send('t_baecha 테이블 업데이트 중 오류가 발생했습니다.');
            }

            // 3단계: bon_planing_sin 테이블에서 B_IDX와 일치하는 행 삭제
            const sqlDeletePlanning = `DELETE FROM bon_planing_sin WHERE B_IDX IN (${bIdxPlaceholders})`;

            queryWithReconnect(dbConfig1, sqlDeletePlanning, bIdxValues, (deletePlanningError, deletePlanningResults) => {
                if (deletePlanningError) {
                    console.error('bon_planing_sin 테이블 삭제 쿼리 오류:', deletePlanningError);
                    return res.status(500).send('bon_planing_sin 테이블 삭제 중 오류가 발생했습니다.');
                }

                // 4단계: 2단계에서 업데이트된 CON_NO를 이용해 bon_log 테이블에서 일치하는 행 삭제
                const conNoPlaceholders = conNoValues.map(() => '?').join(',');
                const sqlDeleteLog = `DELETE FROM bon_log WHERE CON_NO IN (${conNoPlaceholders})`;

                queryWithReconnect(dbConfig1, sqlDeleteLog, conNoValues, (deleteLogError, deleteLogResults) => {
                    if (deleteLogError) {
                        console.error('bon_log 테이블 삭제 쿼리 오류:', deleteLogError);
                        return res.status(500).send('bon_log 테이블 삭제 중 오류가 발생했습니다.');
                    }

                    res.send({
                        message: `작업 완료: ${updateBaechaResults.affectedRows}개의 행이 t_baecha에서 업데이트되었고, ${deletePlanningResults.affectedRows}개의 행이 bon_planing_sin에서 삭제되었으며, ${deleteLogResults.affectedRows}개의 행이 bon_log에서 삭제되었습니다.`
                    });
                });
            });
        });
    });
});

///////관리자 페이지----------------------------------------------------------------------------------------------------------------------------------------------------------

app.set('view engine', 'ejs');  
app.set('views', path.join(__dirname, 'views'))  

// 관리자 페이지 라우트
app.get('/manager', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'manager') {
        return res.redirect('/');
    }

    // 만약 results 변수가 필요한 경우, 빈 배열을 기본값으로 설정하거나,
    // 실제 데이터베이스 쿼리 결과로 이 부분을 대체할 수 있습니다.
    const results = [];  // 빈 배열 또는 기본값

    res.render('index_관리자', { 
        data: results, 
        user: req.session.user,
        sessionID: req.sessionID 
    });
});

app.post('/api/search-user', (req, res) => {
    const { id } = req.body;
    queryWithReconnect(dbConfig1, 'SELECT * FROM bon_user WHERE ID = ?', [id], (error, results) => {
        if (error) return res.status(500).send('Database query error');
        if (results.length > 0) {
            res.json(results[0]);
        } else {
            res.status(404).send('User not found');
        }
    });
});

app.post('/api/update-user', (req, res) => {
    const { id, password, phone, car, carId, SASI, part, role } = req.body;
    const updateFields = {};
    if (password) updateFields.PASSWORD = password;
    if (phone) updateFields.PHONE = phone;
    if (car) updateFields.CAR = car;
    if (carId) updateFields.CAR_ID = carId;
    if (SASI) updateFields.SASI = SASI;
    if (part) updateFields.PART = part;
    if (role) updateFields.ROLE = role;

    const sql = 'UPDATE bon_user SET ? WHERE ID = ?';
    queryWithReconnect(dbConfig1, sql, [updateFields, id], (error, results) => {
        if (error) return res.status(500).send('Database update error');
        res.send('User updated');
    });
});

app.get('/api/unassigned-accounts', (req, res) => {
    queryWithReconnect(dbConfig1, 'SELECT ID, CAR, PHONE FROM bon_user WHERE ROLE IS NULL OR ROLE = "차단"', [], (error, results) => {
        if (error) return res.status(500).send('Database query error');
        res.json(results);
    });
});

app.get('/api/user-list', (req, res) => {
    queryWithReconnect(dbConfig1, 'SELECT ID, PHONE, CAR, CAR_ID, SASI, PART, ROLE FROM bon_user', [], (error, results) => {
        if (error) {
            console.error('Database query error:', error); // 오류 로그 출력
            return res.status(500).send('Database query error');
        }
        res.json(results);
    });
});

app.post('/api/search-by-car', (req, res) => {
    const { car } = req.body;
    queryWithReconnect(dbConfig1, 'SELECT ID, PHONE, CAR, CAR_ID, PART, SASI, ROLE FROM bon_user WHERE CAR = ?', [car], (error, results) => {
        if (error) {
            console.error('Database query error:', error); // 오류 로그 출력
            return res.status(500).send('Database query error');
        }
        res.json(results);
    });
});

