# FreeGSM - Rustify
FreeGSM을 Rust로 재작성한 버전입니다.
자세한 설명은 [main 브랜치의 README](https://github.com/wwwcomcomcomcom/FreeGSM)를 참고하세요.

## macOS

macOS에서는 WinDivert 대신 `pf` 임시 앵커를 사용합니다. TCP/UDP DNS(:53)는 로컬
DoH 프록시로 리다이렉트하고, TCP/443은 로컬 TLS 릴레이로 보내 SNI fragmentation을
적용합니다. UDP/443은 QUIC/HTTP-3 우회를 막고 TCP fallback을 유도하기 위해
차단합니다.

```bash
cargo build --release
sudo ./target/release/FreeGSM
```

- `sudo`가 필요합니다. `/dev/pf`의 `DIOCNATLOOK`으로 리다이렉트 전 목적지를 복구합니다.
- 종료 시 `pf` 앵커를 비워 일반 DNS로 돌아갑니다.
