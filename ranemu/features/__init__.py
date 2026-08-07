#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ranemu.features — 기지국이 제공하는 5G-Advanced / 6G feature 레지스트리."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from ..radio import RadioProfile, LinkBudget, compute_link
from .base import (
    Feature, FeatureContext, SignalingHints, TrafficHints,
    register, get, all_features, unknown_features, check_conflicts, apply_features,
)
from . import catalog  # noqa: F401  — import 시점에 모든 feature 가 등록된다

__all__ = [
    "Feature", "FeatureContext", "SignalingHints", "TrafficHints",
    "register", "get", "all_features", "unknown_features", "check_conflicts",
    "apply_features", "build_profile", "describe_all", "selftest",
]


def build_profile(feature_names: Iterable[str], *, ue_index: int = 0,
                  params: Optional[Dict[str, Dict[str, Any]]] = None,
                  base_profile: Optional[RadioProfile] = None,
                  rng: Any = None) -> Dict[str, Any]:
    """feature 목록을 적용해 (RadioProfile, SignalingHints, TrafficHints, LinkBudget) 생성.

    feature 를 하나도 주지 않으면 eMBB 기본 프로파일을 쓴다.
    """
    names = list(feature_names or [])
    if not names:
        names = ["embb"]
    elif not any(get(n).order <= -10 for n in names if n in all_features()):
        # 베이스 서비스 프로파일이 없으면 eMBB 를 깔아준다
        names = ["embb"] + names

    profile = base_profile or RadioProfile()
    sig = SignalingHints()
    traf = TrafficHints()
    applied: List[str] = []
    per_feature_params = params or {}

    ordered = sorted((get(n) for n in dict.fromkeys(names)), key=lambda f: (f.order, f.name))
    for feat in ordered:
        ctx = FeatureContext(profile=profile, signaling=sig, traffic=traf,
                             ue_index=ue_index, rng=rng,
                             params=per_feature_params.get(feat.name, {}) or {})
        feat.apply(ctx)
        applied.append(feat.name)

    link = compute_link(profile)
    return {"profile": profile, "signaling": sig, "traffic": traf,
            "link": link, "applied": applied}


def describe_all() -> List[Dict[str, Any]]:
    """CLI/문서용 feature 카탈로그."""
    return [f.describe() for f in
            sorted(all_features().values(), key=lambda f: (f.category, f.name))]


def selftest(verbose: bool = False) -> bool:
    ok = True
    feats = all_features()
    if len(feats) < 15:
        ok = False
        print(f"  [FEATURES] 등록 수가 적음: {len(feats)}")
    elif verbose:
        print(f"  [FEATURES] {len(feats)}개 등록: {', '.join(sorted(feats))}")

    # (1) 기본(eMBB)
    base = build_profile([])
    if base["link"].dl_mbps <= 0:
        ok = False
        print("  [FEATURES] 기본 프로파일 처리량 0")

    # (2) RedCap: eMBB 보다 훨씬 느리고, 규격상 20MHz 상한이어야 함
    rc = build_profile(["redcap"])
    if rc["profile"].bandwidth_mhz != 20.0:
        ok = False
        print(f"  [FEATURES] RedCap 대역폭 {rc['profile'].bandwidth_mhz} != 20MHz")
    if rc["profile"].dl_layers != 1:
        ok = False
        print("  [FEATURES] RedCap 이 1레이어가 아님")
    if not rc["signaling"].redcap:
        ok = False
        print("  [FEATURES] RedCap 시그널링 표시 누락")
    if not (rc["link"].dl_mbps < base["link"].dl_mbps / 5):
        ok = False
        print(f"  [FEATURES] RedCap DL({rc['link'].dl_mbps:.1f}) 이 "
              f"eMBB({base['link'].dl_mbps:.1f}) 대비 충분히 낮지 않음")
    elif verbose:
        print(f"  [FEATURES] RedCap DL {rc['link'].dl_mbps:.1f} Mbps "
              f"(eMBB {base['link'].dl_mbps:.0f} Mbps) OK")

    # (3) eRedCap(Rel-18) 은 Rel-17 보다 더 낮아야 함
    rc18 = build_profile(["redcap"], params={"redcap": {"variant": "rel18"}})
    if not (rc18["link"].dl_mbps < rc["link"].dl_mbps):
        ok = False
        print("  [FEATURES] eRedCap(Rel-18) 이 Rel-17 보다 낮지 않음")
    elif verbose:
        print(f"  [FEATURES] eRedCap DL {rc18['link'].dl_mbps:.1f} Mbps < "
              f"RedCap {rc['link'].dl_mbps:.1f} Mbps OK")

    # (4) NTN 궤도별 전파지연 서열: GEO > MEO > LEO > HAPS
    rtts = {}
    for orbit in ("geo", "meo", "leo", "haps"):
        r = build_profile(["ntn"], params={"ntn": {"orbit": orbit}})
        rtts[orbit] = r["link"].rtt_ms
        if not r["signaling"].ntn or r["signaling"].ntn_orbit != orbit:
            ok = False
            print(f"  [FEATURES] NTN {orbit} 시그널링 표시 누락")
    if not (rtts["geo"] > rtts["meo"] > rtts["leo"] > rtts["haps"]):
        ok = False
        print(f"  [FEATURES] NTN RTT 서열 위반: {rtts}")
    elif verbose:
        print("  [FEATURES] NTN RTT geo={geo:.0f} meo={meo:.0f} leo={leo:.0f} "
              "haps={haps:.1f} ms OK".format(**rtts))
    # GEO 왕복은 470~560ms 범위여야 한다(위성 규격 상식)
    if not (400 < rtts["geo"] < 700):
        ok = False
        print(f"  [FEATURES] GEO RTT 가 비현실적: {rtts['geo']:.0f} ms")

    # (5) NAS 타이머 연장이 NTN 에서 적용되는지
    if build_profile(["ntn"])["signaling"].nas_timer_scale <= 1.0:
        ok = False
        print("  [FEATURES] NTN NAS 타이머 연장 미적용")

    # (6) URLLC: 낮은 지연 + 낮은 손실 + 지연크리티컬 5QI
    u = build_profile(["urllc"])
    if not (u["link"].owd_ms < base["link"].owd_ms and u["link"].loss_rate < base["link"].loss_rate):
        ok = False
        print("  [FEATURES] URLLC 가 기본보다 낮은 지연/손실이 아님")
    if u["signaling"].five_qi not in (82, 83, 84, 85):
        ok = False
        print(f"  [FEATURES] URLLC 5QI 이상: {u['signaling'].five_qi}")
    elif verbose:
        print(f"  [FEATURES] URLLC OWD {u['link'].owd_ms:.2f}ms, "
              f"5QI {u['signaling'].five_qi} OK")

    # (7) XR: 프레임 주기 버스트
    xr = build_profile(["xr"], params={"xr": {"fps": 90}})
    if xr["traffic"].pattern != "burst" or abs(xr["traffic"].period_ms - 1000 / 90) > 0.01:
        ok = False
        print("  [FEATURES] XR 프레임 주기 오류")
    if xr["signaling"].five_qi not in (87, 88, 89, 90):
        ok = False
        print(f"  [FEATURES] XR 5QI 이상: {xr['signaling'].five_qi}")
    elif verbose:
        print(f"  [FEATURES] XR 90fps period={xr['traffic'].period_ms:.2f}ms, "
              f"burst={xr['traffic'].burst_packets}pkt OK")

    # (8) NES: 가용시간 축소 → 처리량 감소
    nes = build_profile(["nes"])
    if not (nes["link"].dl_mbps < base["link"].dl_mbps):
        ok = False
        print("  [FEATURES] NES 가 처리량을 낮추지 않음")

    # (9) mMTC: 매우 낮은 상한
    m = build_profile(["mmtc"])
    if m["link"].dl_mbps > 1.0 + 1e-9:
        ok = False
        print(f"  [FEATURES] mMTC DL 상한 초과: {m['link'].dl_mbps}")

    # (10) 조합: RedCap + NTN (위성 IoT) — 둘 다 반영되어야 함
    combo = build_profile(["redcap", "ntn"], params={"ntn": {"orbit": "leo"}})
    if not (combo["signaling"].redcap and combo["signaling"].ntn):
        ok = False
        print("  [FEATURES] redcap+ntn 조합에서 표시 누락")
    if combo["link"].rtt_ms < 10:
        ok = False
        print("  [FEATURES] redcap+ntn 조합에 NTN 지연이 반영되지 않음")
    elif verbose:
        print(f"  [FEATURES] redcap+ntn(LEO): DL {combo['link'].dl_mbps:.1f} Mbps, "
              f"RTT {combo['link'].rtt_ms:.0f} ms OK")

    # (11) 충돌 검출
    if not check_conflicts(["embb", "urllc"]):
        ok = False
        print("  [FEATURES] 충돌(embb+urllc) 미검출")
    if check_conflicts(["redcap", "ntn"]):
        ok = False
        print("  [FEATURES] 정상 조합(redcap+ntn)을 충돌로 오판")

    # (12) 미지 feature 검출
    if unknown_features(["redcap", "nosuch"]) != {"nosuch"}:
        ok = False
        print("  [FEATURES] 미지 feature 검출 실패")

    # (13) 파라미터 덮어쓰기
    wide = build_profile(["redcap"], params={"redcap": {"bandwidth_mhz": 40.0}})
    if wide["profile"].bandwidth_mhz != 40.0:
        ok = False
        print("  [FEATURES] feature 파라미터 덮어쓰기 실패")

    # (14) 모든 feature 가 단독으로 예외 없이 적용되고, 양방향 모두 0 이 아니어야 한다
    #      (한 방향이 0 이면 그 단말은 시험에서 아무것도 측정하지 못한다)
    for name in feats:
        try:
            r = build_profile([name])
            if r["link"].dl_mbps < 0 or r["link"].ul_mbps < 0:
                ok = False
                print(f"  [FEATURES] {name}: 음수 처리량")
            if r["link"].dl_mbps <= 0 or r["link"].ul_mbps <= 0:
                ok = False
                print(f"  [FEATURES] {name}: 한 방향 처리량이 0 "
                      f"(DL {r['link'].dl_mbps}, UL {r['link'].ul_mbps})")
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"  [FEATURES] {name} 단독 적용 실패: {e}")

    # (14b) 실제로 쓰이는 조합들도 양방향이 살아 있어야 한다.
    #       특히 redcap(반이중) + ntn(FDD) 은 듀플렉스 가정이 충돌하는 조합이라
    #       슬롯비가 한쪽으로 쏠려 UL 이 0 이 되기 쉽다(실제로 발생했던 결함).
    combos = [
        (["redcap", "ntn"], {"ntn": {"orbit": "leo"}}),
        (["redcap", "ntn"], {"ntn": {"orbit": "geo"}}),
        (["redcap", "nes"], {}),
        (["ntn", "ltm"], {"ntn": {"orbit": "leo"}}),
        (["urllc", "slicing"], {}),
        (["xr", "mimo_evo"], {}),
        (["mmtc", "ntn"], {"ntn": {"orbit": "geo"}}),
        (["embb", "sbfd", "ai_ran"], {}),
        (["ambient_iot", "ntn"], {"ntn": {"orbit": "leo"}}),
        (["positioning", "isac", "redcap"], {}),
    ]
    for names, params in combos:
        try:
            r = build_profile(names, params=params)
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"  [FEATURES] 조합 {names} 적용 실패: {e}")
            continue
        lb = r["link"]
        if lb.dl_mbps <= 0 or lb.ul_mbps <= 0:
            ok = False
            print(f"  [FEATURES] 조합 {'+'.join(names)}: 한 방향 처리량 0 "
                  f"(DL {lb.dl_mbps:.3f}, UL {lb.ul_mbps:.3f}, "
                  f"duplex={r['profile'].duplex}, half={r['profile'].half_duplex}, "
                  f"slot={r['profile'].dl_slot_ratio})")
    if verbose:
        print(f"  [FEATURES] 단독 {len(feats)}종 + 조합 {len(combos)}종 양방향 처리량 OK")

    # (15) 6G 후보: SBFD 는 UL 을 늘려야 함
    sb = build_profile(["sbfd"])
    if not (sb["link"].ul_mbps > base["link"].ul_mbps):
        ok = False
        print("  [FEATURES] SBFD UL 증가 없음")
    elif verbose:
        print(f"  [FEATURES] SBFD UL {base['link'].ul_mbps:.0f} → "
              f"{sb['link'].ul_mbps:.0f} Mbps OK")
    return ok


if __name__ == "__main__":
    print("FEATURES selftest:", "PASS" if selftest(verbose=True) else "FAIL")
