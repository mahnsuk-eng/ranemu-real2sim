#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu — 실 5G 코어 시험검증용 RAN(기지국)/단말 에뮬레이터.

목적
====
`~/5ga_solution` 의 코어측 수집·측정 파이프라인(network_agent / dpi_engine / ngap_agent)은
"와이어에 흐르는 것을 수동으로 관측"한다. 그러나 시험검증을 하려면 **무엇을 흘렸는지(정답)** 를
아는 쪽이 필요하다. ranemu 는 그 반대편, 즉 **부하를 만들어 실코어에 주입하는 쪽**이다.

    ┌──────────── ranemu (이 패키지) ───────────┐        ┌──── 실 5G 코어 ────┐
    │  UE 에뮬레이터 (NAS 5GS, 다중단말)         │  N2    │  AMF               │
    │      ↕                                     │ NGAP/  │   ↕                │
    │  gNB 에뮬레이터 ── feature 플러그인 ───────┼─SCTP──►│  SMF               │
    │      (RedCap/NTN/URLLC/XR/NES/LTM/6G…)     │        │   ↕                │
    │      ↕ 무선 물리모델 → 쉐이퍼               │  N3    │  UPF ── N6 ──► DN  │
    │  사용자평면 (GTP-U)                        ├─GTP-U─►│                    │
    └────────────────────────────────────────────┘        └────────────────────┘
                     │                                              │
                     │ 정답 manifest(IMSI↔TEID↔UE IP↔프로파일)      │ SPAN 미러
                     └──────────────► 대조 ◄────────── dpi_engine / ngap_agent

설계 원칙
=========
1. **실 패킷**: 시뮬레이션 로그가 아니라 진짜 NGAP/SCTP·GTP-U/UDP 패킷을 코어로 보낸다.
   따라서 기존 미러 캡처·DPI 측정 경로가 아무 변경 없이 그대로 동작한다.
2. **기지국이 feature 를 소유**: 5G-Advanced / 6G feature(RedCap, NTN, …)는 코어가 아니라
   RAN 의 성질이다. feature 플러그인은 두 갈래로 효과를 낸다.
     (a) 시그널링: NGAP/NAS IE(슬라이스, RRC establishment cause, UE capability, TAC …)
     (b) 거동: 무선 물리모델(TS 38.306 피크율·링크버짓 SINR)이 산출한 rate/delay/jitter/loss 를
         사용자평면 쉐이퍼에 적용 → 코어가 실제로 그 특성의 트래픽을 본다.
3. **정답 보존**: 모든 주입 파라미터는 manifest 로 남겨 측정 결과와 자동 대조한다.
4. **오프라인 검증 가능**: 실코어가 없어도 `--core stub` 으로 내장 AMF/UPF 스텁을 띄워
   전체 경로를 자체 검증한다.

주요 진입점
===========
    python3 -m ranemu.cli selftest              # 전 계층 자체검증(코어 불필요)
    python3 -m ranemu.cli run -c configs/xxx.yaml
    python3 -m ranemu.cli features              # 지원 feature 목록
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
