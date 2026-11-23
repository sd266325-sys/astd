# 올스타 타워 디펜스 HQ 서버

외부 패키지 없이 Node.js(16 이상)만으로 동작합니다.

## 실행
    cd tower-defense-server
    node server.js          # 또는 npm start
브라우저에서 http://localhost:3000 접속.

## 환경변수
- PORT: 포트 (기본 3000)
- DATA_FILE: 계정/세이브 파일 경로 (기본 ./data.json)
- TRUST_PROXY=1: nginx 등 리버스 프록시 뒤에서 실제 IP를 쓰려면 설정

## API
- POST /api/auth  {name, pw, init} → 로그인, 없으면 자동 가입 → {token, data}
- GET  /api/load  (Authorization: Bearer 토큰) → {data}
- POST /api/save  (Authorization: Bearer 토큰) {data} → {ok}

## 참고
- 비밀번호는 scrypt로 해시 저장, 로그인 토큰은 30일 유지, IP당 10분에 실패 10회 초과 시 잠금
- 게임 로직은 브라우저에서 돌아가므로 세이브는 클라이언트가 보낸 값을 그대로 저장합니다 (치트 방지 없음)
- data.json을 백업해 두세요. HTTPS가 필요하면 nginx/Caddy 등으로 프록시하세요
