# DND-AutoMod (Red-DiscordBot v3)

특정 유저(1173942304927645786)를 직접 멘션하는 메시지를 AutoMod로 자동 차단하는 Cog입니다.  
`<@ID>` / `<@!ID>` 형태의 **직접 멘션만** 차단하며, `@everyone` / `@here` / 역할 멘션은 차단하지 않습니다.

## 설치/로드
```
[p]load dnd_automod
```

## 명령어
### 기본 사용자 명령 (allowlist 포함자만)
- `[p]dnd`  
  DND 토글(ON/OFF).
- `[p]dnd on`  
  DND 강제 ON.
- `[p]dnd off`  
  DND 강제 OFF(룰은 비활성화만 하고 삭제하지 않음).
- `[p]dnd status`  
  현재 상태(ON/OFF), 룰 ID, 룰 활성 상태, 마지막 변경 시각 표시.

### 관리 명령 (봇 오너 + 지정 사용자ID만)
- `[p]dnd allow add <user>`  
  컨트롤러 허용 목록에 추가(최대 20명).
- `[p]dnd allow remove <user>`  
  컨트롤러 허용 목록에서 제거(기본 사용자 제거 가능, 목록이 비면 자동 복구).
- `[p]dnd allow list`  
  허용 컨트롤러 목록 표시.
- `[p]dnd allow reset`  
  허용 컨트롤러 목록을 기본값으로 초기화.

### 예외 기능 (기본 OFF, 관리자 전용)
- `[p]dnd setexempt enable` / `[p]dnd setexempt disable`  
  예외 기능 ON/OFF.
- `[p]dnd setexempt channel add/remove/list <channel>`  
  예외 채널 관리.
- `[p]dnd setexempt role add/remove/list <role>`  
  예외 역할 관리.

## 동작 요약
- DND ON 시 AutoMod 룰을 생성/정합성 보정 후 활성화합니다.
- DND OFF 시 AutoMod 룰을 비활성화합니다(삭제는 하지 않음).
- 설정/상태는 길드 단위로 저장되며, 재시작 후에도 유지됩니다.

## 권한/요구사항
- 봇 권한: **Manage Guild(서버 관리)** 필요
- Red-DiscordBot v3.x / Python 3.10+

