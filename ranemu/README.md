# ranemu — 실 5G 코어 시험검증용 기지국/단말 에뮬레이터

5G-Advanced / 6G feature(RedCap, NTN 등)를 **기지국 단에서** 구현하고, **실제 패킷**으로
5G 코어에 주입해 코어측에서 수집·측정할 수 있게 하는 에뮬레이터입니다.

```
┌──────────────── ranemu ────────────────┐            ┌──── 실 5G 코어 ────┐
│  UE 에뮬레이터 (NAS 5GS, 다중 단말)     │    N2      │  AMF               │
│      ↕                                  │  NGAP/SCTP │   ↕                │
│  gNB 에뮬레이터 ── feature 플러그인 ────┼───────────►│  SMF               │
│   RedCap/NTN/URLLC/XR/NES/LTM/SBFD/6G   │            │   ↕                │
│      ↕ 무선 물리모델 → 쉐이퍼            │    N3      │  UPF ── N6 ──► DN  │
│  사용자평면 (GTP-U)                     ├───────────►│                    │
└─────────────────────────────────────────┘            └────────────────────┘
              │                                                 │
              │ 정답 manifest (IMSI↔TEID↔UE IP↔프로파일)         │ SPAN 미러
              └──────────────► 자동 대조 ◄──────── dpi_engine / ngap_agent
```

## 왜 만들었나

`~/5ga_solution` 의 기존 파이프라인은 미러에서 본 것을 **관측**합니다. 그런데 그 측정이
맞는지 확인할 기준이 없었습니다. ranemu 는 반대편에서 **정답을 알고 주입**하므로,
"주입한 것 == 측정한 것" 을 자동으로 대조할 수 있습니다.

동시에, 5G-A/6G feature 를 코어가 제대로 처리하는지 시험할 수 있습니다. RedCap 단말의
낮은 UE-AMBR, NTN 위성의 480ms 지연에서의 NAS 타이머, 슬라이스 분리 등입니다.

## 빠른 시작

```bash
cd ~/5ga_solution

# 1) 전 계층 자체검증 (네트워크 장비 불필요, ~1분)
python3 -m ranemu.cli selftest -v

# 2) 스텁 코어로 전 경로 검증 (실코어 없이 등록→세션→트래픽 전부)
python3 -m ranemu.cli e2e

# 3) 지원 feature 확인
python3 -m ranemu.cli features

# 4) 실코어 시험 — 먼저 설정을 채우고 미리보기
cp ranemu/configs/real-core-mixed.yaml my.yaml
$EDITOR my.yaml                      # TODO 표시된 항목(AMF 주소/PLMN/SIM 키/IMSI)
python3 -m ranemu.cli plan -c my.yaml    # 무엇을 얼마나 주입할지 미통신 미리보기
python3 -m ranemu.cli run  -c my.yaml    # 실제 주입 + 코어측 캡처 + 자동 대조
```

## 지원 feature (18종)

| 분류 | feature | 릴리즈 | 기지국이 반영하는 것 |
|---|---|---|---|
| 서비스 | `embb` | Rel-15 | 100MHz TDD, 4×2 MIMO, 256QAM (기준선) |
| | `urllc` | Rel-15/16/17 | 5QI 82, mini-slot·60kHz SCS, 1e-6 손실 |
| | `mmtc` | Rel-15 | 5MHz·QPSK, eDRX 655초, 산발 전송 |
| | `xr` | Rel-18 | 5QI 87, 프레임 주기(60/90/120fps) 버스트 |
| | `positioning` | Rel-16/17/18 | PRS 자원 오버헤드 + 주기 측정보고 |
| 단말능력 | **`redcap`** | Rel-17 / eRedCap Rel-18 | 20MHz(5MHz), 1Rx·1레이어·64QAM, HD-FDD, eDRX |
| 배치 | **`ntn`** | Rel-17/18 | GEO/MEO/LEO/HAPS 궤도별 전파지연·도플러·셀전환 |
| RAN 거동 | `nes` | Rel-18 | 셀 DTX/DRX, 공간요소 적응 |
| 이동성 | `ltm` | Rel-18 | L1/L2 트리거 핸드오버(단절 30~50ms → 0~10ms) |
| PHY | `sbfd` | Rel-18/19 | 서브밴드 풀듀플렉스(UL 대폭↑, DL 소폭↓) |
| | `mimo_evo` | Rel-18 | 8Tx UL, 최대 8레이어, CJT |
| | `ca` | Rel-15+ | 반송파 집성 |
| 코어연동 | `slicing` | Rel-15+ | S-NSSAI 지정 + 슬라이스별 AMBR |
| 6G 후보 | `isac` | Rel-19 연구 | 통합 센싱·통신(센싱 자원 점유 + 보고) |
| | `ai_ran` | Rel-18/19 | AI 기반 CSI 압축 → 실효 SINR 이득 |
| | `ambient_iot` | Rel-19 | 무배터리 초저전력(32바이트 초산발) |
| | `upper_mid_band` | 6G 후보 | FR3 7~24GHz 광대역 + 대규모 MIMO |
| | `sub_thz` | 6G 후보 | 100GHz+, 1.6GHz 대역폭 |

feature 는 조합할 수 있습니다(예: `[redcap, ntn]` = 위성 IoT 단말).

## feature 가 코어에 보이는 두 경로

feature 는 RAN 의 성질이므로 코어는 두 가지로만 관측합니다. ranemu 는 둘 다 만듭니다.

1. **시그널링** — NGAP/NAS IE 가 달라집니다.
   RedCap → 낮은 UE-AMBR, 축소된 UE 무선능력, mo-Data 확립사유.
   NTN → NAS 타이머 연장, 위성 셀 표시.
   URLLC → 5QI 82~85, 낮은 ARP.

2. **거동** — 사용자평면 트래픽의 물리적 성질이 달라집니다.
   `radio.py` 가 TS 38.306 피크율과 TR 38.901 링크버짓으로 속도/지연/손실을 산출하고,
   `shaper.py` 가 그것을 실제 GTP-U 송신 시각과 패킷 폐기로 바꿉니다.

## 구조

| 파일 | 역할 |
|---|---|
| `crypto/` | MILENAGE(TS 35.206), 5G 키계층(TS 33.501), NAS 보안(NEA/NIA) |
| `nas/nas5gs.py` | NAS 5GS 메시지 인코더/디코더 (TS 24.501) |
| `ngap/aper.py` | ASN.1 ALIGNED PER 프리미티브 (X.691) |
| `ngap/messages.py` | NGAP 메시지 (TS 38.413) |
| `ngap/verify.py` | **tshark 를 독립 오라클로 쓰는 인코딩 검증** |
| `transport/sctp.py` | N2 SCTP (PPID 60, pysctp 불필요) |
| `transport/gtpu.py` | N3 GTP-U (PDU Session Container/QFI 포함) |
| `radio.py` | 무선 물리모델 (TS 38.306 / TR 38.901 / TS 38.214) |
| `features/` | 5G-A·6G feature 플러그인 레지스트리 |
| `shaper.py` | 토큰버킷·지연선·손실·단절 |
| `traffic.py` | 트래픽 패턴 생성기 |
| `ue.py` | 단말 NAS 상태머신 |
| `gnb.py` | 기지국 오케스트레이터(단일 이벤트 루프) |
| `core/stub.py` | 오프라인 검증용 최소 코어(AMF/SMF/UPF) |
| `capture.py` | 기존 `network_agent`/`dpi_engine`/`ngap_agent` 연동 |
| `manifest.py` | 정답 대비 측정 대조 |

## 코어측 수집과의 연동

`capture.py` 는 기존 파이프라인을 **다시 구현하지 않고 가져다 씁니다**. 그래야 ranemu 가
주입한 트래픽이 평소 측정과 같은 자로 재어집니다.

```
network_agent.start_measurement_capture()   → N3(GTP-U) + N2(NGAP) pcap
network_agent.analyze_measurement()         → dpi_engine(처리량) + ngap_agent(IMSI/TEID)
manifest.compare()                          → 주입값 대비 오차(%) + PASS/FAIL
```

대조는 IMSI → UE IP → TEID 순으로 매칭하는데, 이 순서 자체가 `ngap_agent` 의 N2 신원추출
정확도를 검증합니다(IMSI 로 매칭되면 신원추출이 동작한 것).

## 검증 방식

이 코드는 다음으로 검증되어 있습니다.

- **표준 테스트벡터**: MILENAGE 는 TS 35.207 Test Set 1 의 8개 출력 전부 대조.
- **독립 오라클(tshark)**: NGAP/GTP-U 인코딩을 Wireshark 디섹터로 파싱해 대조.
  자체 왕복 테스트는 같은 오해를 공유하므로 이런 오류를 못 잡습니다. 실제로 이 방식으로
  `UserLocationInformation` CHOICE 에 확장비트를 넣으면 안 된다는 점(넣으면 코어가 EUTRA
  위치정보로 오독), `AssociatedQosFlowItem` 의 OPTIONAL 이 3개라는 점을 찾아 고쳤습니다.
- **전 경로 E2E**: 스텁 코어 상대로 NGSetup → 5G-AKA → NAS 보안 → 등록 → PDU 세션 →
  GTP-U 트래픽까지 8개 항목 판정.
- **주입 대비 실측**: 쉐이퍼가 의도한 속도를 실제로 내는지 매 실행마다 확인.

```
python3 -m ranemu.cli selftest -v      # 15개 스위트
```

## 알려진 제약

- **NAS 보안 알고리즘은 NEA0/NEA2, NIA0/NIA2 만 구현**했습니다. SNOW3G(NEA1/NIA1)와
  ZUC(NEA3/NIA3)는 표준 테스트벡터 없이 구현하면 "원인 불명의 Security mode reject" 를
  만들므로 넣지 않았습니다. 단말이 광고하지 않은 알고리즘은 코어가 선택할 수 없으므로
  (TS 33.501 §6.7.2) 정상 코어에서는 문제가 없습니다. 필요하면 `crypto/snow3g.py` 를
  추가하고 `nas_sec._ENC/_INT` 에 등록하면 자동으로 광고 대상이 됩니다.
- **SUCI 은닉은 null scheme(profile 0)만** 지원합니다. 코어가 profile A/B 를 강제하면
  등록이 실패합니다.
- **AS(무선) 보안은 키 유도까지만** 합니다. 실제 RF 구간이 없어 RRC/PDCP 암호화는
  적용하지 않습니다(코어는 이를 보지 못하므로 시험에 영향 없음).
- **사용자평면은 UDP** 입니다. 따라서 `dpi_engine` 의 ACK 기반 DL 복원은 동작하지 않고
  패킷 기반 측정이 쓰입니다. 캡처가 완전하면 오히려 더 정확합니다.
- **1 GbE 미러 포화**: 총 주입량이 ~950 Mbps 를 넘으면 캡처 손실이 생깁니다.
  `plan` 명령이 미리 경고합니다.
- `n3_local_port: 2152` 는 1024 미만이라 root 권한이 필요합니다. 없으면 높은 포트를
  쓰되, 코어가 그 포트로 하향을 보낼 수 있어야 합니다.

## 실코어 연동 시 증상별 원인

| 증상 | 원인 |
|---|---|
| `NGSetupFailure` | PLMN/TAC/슬라이스가 코어 설정과 불일치 |
| `RegistrationReject` | IMSI 가 UDM 에 없음, 또는 SUCI scheme 불허 |
| `AUTN MAC 불일치` (에뮬레이터가 보고) | K/OPc/AMF 필드 불일치 |
| `코어가 미광고 알고리즘 선택` | 코어가 SNOW3G/ZUC 만 허용 |
| PDU 세션 거절 | DNN/S-NSSAI 미허용, UPF 미가용 |
| 등록은 되는데 트래픽 0 | N3 광고 주소(`n3_advertise_addr`)가 코어에서 도달 불가 |
