#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.cli — 명령행 진입점.

    python3 -m ranemu.cli selftest              # 전 계층 자체검증(네트워크 불필요)
    python3 -m ranemu.cli e2e                   # 스텁 코어로 전 경로 검증
    python3 -m ranemu.cli features              # 지원 feature 목록
    python3 -m ranemu.cli plan -c cfg.yaml      # 무엇을 주입할지 미리보기(무통신)
    python3 -m ranemu.cli run  -c cfg.yaml      # 실코어에 주입(+캡처+대조)
    python3 -m ranemu.cli compare --manifest m.json --measurement r.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from . import __version__
from .util import get_logger, human_bps

log = get_logger("ranemu.cli")


# ═════════════════════════════════════════════════════════════════════════════
def cmd_selftest(args: argparse.Namespace) -> int:
    """모든 계층의 자체검증을 순서대로 실행."""
    from . import config as config_mod
    from . import crypto as crypto_mod
    from . import features as features_mod
    from . import manifest as manifest_mod
    from . import radio as radio_mod
    from . import shaper as shaper_mod
    from . import traffic as traffic_mod
    from . import capture as capture_mod
    from . import calibrate as calibrate_mod
    from . import estimator as estimator_mod
    from . import impair as impair_mod
    from . import pcapio as pcapio_mod
    from .core import stub as stub_mod
    from .nas import nas5gs
    from .ngap import aper, verify as ngap_verify
    from .transport import gtpu, sctp
    from . import ue as ue_mod

    v = args.verbose
    suites = [
        ("crypto (MILENAGE/KDF/NAS보안)", lambda: crypto_mod.selftest(v)),
        ("radio (TS 38.306 물리모델)", lambda: radio_mod.selftest(v)),
        ("features (5G-A/6G)", lambda: features_mod.selftest(v)),
        ("config", lambda: config_mod.selftest(v)),
        ("nas (TS 24.501 코덱)", lambda: nas5gs.selftest(v)),
        ("ngap/aper (X.691)", lambda: aper.selftest(v)),
        ("ngap/verify (tshark 대조)", lambda: ngap_verify.selftest(v)),
        ("transport/sctp", lambda: sctp.selftest(v)),
        ("transport/gtpu", lambda: gtpu.selftest(v)),
        ("shaper", lambda: shaper_mod.selftest(v)),
        ("traffic", lambda: traffic_mod.selftest(v)),
        ("ue (NAS 상태머신)", lambda: ue_mod.selftest(v)),
        ("manifest (정답 대조)", lambda: manifest_mod.selftest(v)),
        ("capture (기존 파이프라인 연동)", lambda: capture_mod.selftest(v)),
        ("pcapio (정답 캡처 기록)", lambda: pcapio_mod.selftest(v)),
        ("impair (캡처 손상 모델)", lambda: impair_mod.selftest(v)),
        ("estimator (손실 보정)", lambda: estimator_mod.selftest(v)),
        ("calibrate (교정 파이프라인)", lambda: calibrate_mod.selftest(v)),
        ("core/stub (UE 주소 할당)", lambda: stub_mod.selftest(v)),
    ]
    try:
        from .paper import lf_bridge as lf_mod
        suites.append(("paper/lf_bridge (오차 전파)", lambda: lf_mod.selftest(v)))
        from .paper import lf_field as lff_mod
        suites.append(("paper/lf_field (실측 부하계수)", lambda: lff_mod.selftest(v)))
    except ImportError as e:                     # noqa: BLE001
        print(f"(lf_bridge 없음 — 건너뜀: {e})")
    # 시나리오 계층 — 선택 설치. 없어도 기존 19종은 그대로 돈다.
    try:
        from .scenario import (catalog as scn_catalog, kpi as scn_kpi,
                               model as scn_model, reflector as scn_reflector,
                               runner as scn_runner, stamp as scn_stamp,
                               stats as scn_stats, verdict as scn_verdict)
        suites += [
            ("scenario/stats (신뢰도 통계)", lambda: scn_stats.selftest(v)),
            ("scenario/stamp (인밴드 계측)", lambda: scn_stamp.selftest(v)),
            ("scenario/kpi (3GPP 추정기)", lambda: scn_kpi.selftest(v)),
            ("scenario/verdict (4치 판정)", lambda: scn_verdict.selftest(v)),
            ("scenario/model (시나리오 스키마)", lambda: scn_model.selftest(v)),
            ("scenario/catalog (요구값 전사)", lambda: scn_catalog.selftest(v)),
            ("scenario/reflector (T2 회신자)", lambda: scn_reflector.selftest(v)),
            ("scenario/runner (컴파일·훅)", lambda: scn_runner.selftest(v)),
        ]
    except ImportError as e:                     # noqa: BLE001
        print(f"(시나리오 계층 없음 — 건너뜀: {e})")

    if not args.skip_e2e:
        from . import e2e as e2e_mod
        suites.append(("e2e (스텁 코어 전 경로)", lambda: e2e_mod.selftest(v, args.duration)))

    results: List[tuple] = []
    for name, fn in suites:
        print(f"\n── {name} " + "─" * max(0, 60 - len(name)))
        try:
            ok = bool(fn())
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"  예외: {type(e).__name__}: {e}")
            if v:
                import traceback
                traceback.print_exc()
        results.append((name, ok))
        print(f"   → {'PASS' if ok else 'FAIL'}")

    print("\n" + "═" * 72)
    n_ok = sum(1 for _n, o in results if o)
    for name, ok in results:
        print(f" {'PASS' if ok else 'FAIL'}  {name}")
    print("═" * 72)
    print(f" 합계 {n_ok}/{len(results)} 통과")
    return 0 if n_ok == len(results) else 1


def cmd_e2e(args: argparse.Namespace) -> int:
    from . import e2e as e2e_mod
    ok = e2e_mod.selftest(verbose=True, duration=args.duration)
    print("\nE2E:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def cmd_features(args: argparse.Namespace) -> int:
    from . import features as features_mod
    items = features_mod.describe_all()
    if args.json:
        print(json.dumps(items, ensure_ascii=False, indent=2))
        return 0
    by_cat: Dict[str, List[Dict[str, Any]]] = {}
    for f in items:
        by_cat.setdefault(f["category"], []).append(f)
    print(f"ranemu {__version__} — 지원 feature {len(items)}종\n")
    for cat in sorted(by_cat):
        print(f"[{cat}]")
        for f in by_cat[cat]:
            print(f"  {f['name']:<16} {f['title']}  ({f['release']})")
            print(f"  {'':<16} {f['summary']}")
            if f.get("knobs"):
                knobs = ", ".join(f"{k}={vv}" for k, vv in f["knobs"].items())
                print(f"  {'':<16} 조정: {knobs}")
            if f.get("conflicts"):
                print(f"  {'':<16} 충돌: {', '.join(f['conflicts'])}")
        print()
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    """설정을 읽어 '무엇을 주입하게 되는지' 를 통신 없이 계산해 보여준다."""
    from . import config as config_mod
    from . import features as features_mod
    cfg = config_mod.load(args.config)
    errs = cfg.validate()
    if errs:
        print("설정 문제:")
        for e in errs:
            print(f"  - {e}")
        if not args.force:
            return 2

    print(f"\n시험 '{cfg.name}' — 코어 {cfg.core.kind} {cfg.core.amf_addr}:{cfg.core.amf_port}")
    print(f"gNB {cfg.gnb.name}  PLMN {cfg.gnb.mcc}/{cfg.gnb.mnc}  "
          f"gNB-ID {cfg.gnb.gnb_id}  TAC {cfg.gnb.tac}  NCI 0x{cfg.gnb.nr_cell_identity():09x}")
    print(f"지속 {cfg.traffic.duration}s, 목적지 {cfg.traffic.dest_addr}:{cfg.traffic.dest_port}\n")

    def _mbps(v: float) -> str:
        """작은 값이 0.0 으로 보여 오해를 부르지 않도록 자릿수를 조절."""
        if v >= 10:
            return f"{v:.1f}"
        if v >= 0.1:
            return f"{v:.2f}"
        if v > 0:
            return f"{v:.3f}"
        return "0"

    hdr = (f"{'그룹':<12}{'대수':>4}  {'feature':<24}{'DL(Mbps)':>10}{'UL(Mbps)':>10}"
           f"{'RTT(ms)':>9}{'SINR':>7}  패턴")
    print(hdr); print("─" * len(hdr))
    total_ul = total_dl = 0.0
    for g in cfg.ue_groups:
        built = features_mod.build_profile(g.features, params=g.feature_params)
        link, traf = built["link"], built["traffic"]
        pattern = g.traffic or traf.pattern
        ul = min(link.ul_mbps, traf.offered_ul_mbps or link.ul_mbps,
                 built["signaling"].ue_ambr_ul / 1e6)
        dl = min(link.dl_mbps, traf.offered_dl_mbps or link.dl_mbps,
                 built["signaling"].ue_ambr_dl / 1e6)
        if pattern == "fullbuffer":
            ul = min(link.ul_mbps, built["signaling"].ue_ambr_ul / 1e6)
            dl = min(link.dl_mbps, built["signaling"].ue_ambr_dl / 1e6)
        total_ul += ul * g.count
        total_dl += dl * g.count
        print(f"{g.name:<12}{g.count:>4}  {'+'.join(built['applied']):<24}"
              f"{_mbps(dl):>10}{_mbps(ul):>10}"
              f"{link.rtt_ms:>9.1f}{link.sinr_db:>7.1f}  {pattern}")
    print("─" * len(hdr))
    print(f"{'합계':<12}{cfg.total_ues():>4}  {'':<24}"
          f"{_mbps(total_dl):>10}{_mbps(total_ul):>10}")
    print(f"\n예상 총 주입량: UL {human_bps(total_ul*1e6)}, DL {human_bps(total_dl*1e6)}")
    if total_ul > 900 or total_dl > 900:
        print("주의: 1 GbE 미러 포화(~950 Mbps) 구간입니다 — 캡처 손실이 생길 수 있습니다.")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """실코어에 주입한다. 필요하면 코어측 캡처와 대조까지 수행."""
    from . import capture as capture_mod
    from . import config as config_mod
    from . import manifest as manifest_mod
    from .gnb import Gnb

    cfg = config_mod.load(args.config)
    if args.duration:
        cfg.traffic.duration = args.duration
    errs = cfg.validate()
    if errs:
        print("설정 문제:")
        for e in errs:
            print(f"  - {e}")
        if not args.force:
            print("\n무시하고 진행하려면 --force")
            return 2

    out_dir = args.out or cfg.out_dir
    os.makedirs(out_dir, exist_ok=True)

    sess = None
    if cfg.capture.enabled and not args.no_capture:
        sess = capture_mod.start(cfg.capture.out_dir, cfg.name,
                                 snaplen=cfg.capture.snaplen)
        if not sess.ok:
            print(f"경고: 코어측 캡처를 시작하지 못했습니다 — {sess.error}")

    gnb = Gnb(cfg)
    try:
        result = gnb.run()
    finally:
        gnb.close()

    cap_info: Dict[str, Any] = {}
    if sess is not None and sess.ok:
        cap_info = capture_mod.stop(sess)
        result["capture"] = cap_info

    mpath = manifest_mod.write(result, out_dir, name=cfg.name)
    s = result["summary"]
    st = result["stats"]
    print("\n" + "═" * 72)
    print(f" 시험 '{cfg.name}' 종료 — {'실패: ' + result['failed'] if result.get('failed') else '정상'}")
    print("═" * 72)
    print(f" 단말 {s['ue_total']}대 → 등록 {s['ue_registered']}, 활성 {s['ue_active']}, "
          f"실패 {s['ue_failed']}")
    if s["failures"]:
        for f in s["failures"]:
            print(f"   실패사유: {f}")
    print(f" 주입량 UL {st['ul_packets']}패킷 {st['ul_mbps']} Mbps / "
          f"DL {st['dl_packets']}패킷 {st['dl_mbps']} Mbps ({st['duration_s']}s)")
    print(f" 정답 manifest: {mpath}")

    if cap_info.get("n3_bytes"):
        print(f" 코어측 캡처: N3 {cap_info['n3_bytes']/1e6:.1f} MB, "
              f"N2 {cap_info['n2_bytes']/1e3:.1f} kB")
        if cfg.capture.auto_analyze:
            print(" 코어측 분석 중...")
            meas = capture_mod.analyze(cap_info["n3_pcap"], cap_info["n2_pcap"])
            if not meas.get("ok"):
                print(f" 분석 실패: {meas.get('error')}")
            else:
                cmp_res = manifest_mod.compare(result, meas)
                print()
                print(manifest_mod.render_text(cmp_res))
                with open(os.path.join(out_dir, f"{cfg.name}.compare.json"), "w",
                          encoding="utf-8") as fh:
                    json.dump({"comparison": cmp_res, "measurement": meas}, fh,
                              ensure_ascii=False, indent=2, default=str)
                return 0 if cmp_res["summary"]["verdict"] == "PASS" else 1
    elif cfg.capture.enabled:
        print(" 코어측 캡처 산출물이 비어 있습니다(권한/인터페이스 확인).")

    return 0 if not result.get("failed") and s["ue_active"] > 0 else 1


def cmd_calibrate(args: argparse.Namespace) -> int:
    """정답 캡처에 알려진 손상을 주입해 프로브 오차와 보정 성능을 측정한다."""
    from . import calibrate as cal
    from .impair import ImpairmentConfig

    if not os.path.exists(args.truth_pcap):
        print(f"정답 pcap 없음: {args.truth_pcap}\n"
              f"capture.truth_pcap=true 로 run 을 먼저 수행하십시오.")
        return 2

    if args.conditions == "default":
        conds = cal.default_conditions(seed=args.seed)
    elif args.conditions == "loss":
        conds = [("clean", ImpairmentConfig(seed=args.seed))]
        conds += [(f"loss{p}", ImpairmentConfig(loss_rate=p / 100.0, seed=args.seed))
                  for p in (5, 10, 20, 30, 40, 50, 60)]
    else:                                       # saturation
        conds = [("clean", ImpairmentConfig(seed=args.seed))]
        conds += [(f"sat{c}", ImpairmentConfig(capacity_mbps=float(c), seed=args.seed))
                  for c in (950, 900, 700, 500, 300, 150)]

    pts = cal.sweep(args.truth_pcap, conds, workdir=args.workdir,
                    link_mbps=args.link_mbps, run_probe=not args.no_probe)
    print()
    print(cal.render_table(pts))
    s = cal.summarize(pts)
    print("\n요약:")
    for k, val in s.items():
        print(f"  {k}: {val}")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"summary": s, "points": [p.as_dict() for p in pts]}, fh,
                      ensure_ascii=False, indent=2)
        print(f"\n저장: {args.out}")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    from . import capture as capture_mod
    from . import manifest as manifest_mod
    mf = manifest_mod.load(args.manifest)
    if args.measurement:
        with open(args.measurement, "r", encoding="utf-8") as fh:
            meas = json.load(fh)
        if "ues" not in meas and "measurement" in meas:
            meas = meas["measurement"]
    elif args.n3_pcap:
        meas = capture_mod.analyze(args.n3_pcap, args.n2_pcap or "")
    else:
        print("--measurement 또는 --n3-pcap 중 하나가 필요합니다")
        return 2
    cmp_res = manifest_mod.compare(mf, meas,
                                   throughput_tolerance_pct=args.tolerance)
    print(manifest_mod.render_text(cmp_res))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(cmp_res, fh, ensure_ascii=False, indent=2, default=str)
        print(f"\n결과 저장: {args.out}")
    return 0 if cmp_res["summary"]["verdict"] == "PASS" else 1


# ═════════════════════════════════════════════════════════════════════════════
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ranemu",
        description="실 5G 코어 시험검증용 기지국/단말 에뮬레이터 "
                    "(5G-Advanced/6G feature 포함)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("--version", action="version", version=f"ranemu {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("selftest", help="전 계층 자체검증(네트워크 불필요)")
    s.add_argument("-v", "--verbose", action="store_true")
    s.add_argument("--skip-e2e", action="store_true", help="스텁 코어 E2E 생략")
    s.add_argument("--duration", type=float, default=4.0, help="E2E 트래픽 지속(초)")
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("e2e", help="스텁 코어로 전 경로 검증")
    s.add_argument("--duration", type=float, default=5.0)
    s.set_defaults(func=cmd_e2e)

    s = sub.add_parser("features", help="지원하는 5G-A/6G feature 목록")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_features)

    s = sub.add_parser("plan", help="설정대로 무엇을 주입할지 미리보기(무통신)")
    s.add_argument("-c", "--config", required=True)
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_plan)

    s = sub.add_parser("run", help="실코어에 주입(+코어측 캡처/대조)")
    s.add_argument("-c", "--config", required=True)
    s.add_argument("-o", "--out", help="결과 출력 디렉터리")
    s.add_argument("--duration", type=float, help="트래픽 지속(초) 덮어쓰기")
    s.add_argument("--no-capture", action="store_true", help="코어측 캡처 생략")
    s.add_argument("--force", action="store_true", help="설정 경고 무시")
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("compare", help="정답 manifest 와 코어측 측정 대조")
    s.add_argument("--manifest", required=True)
    s.add_argument("--measurement", help="analyze_measurement 결과 JSON")
    s.add_argument("--n3-pcap", help="직접 분석할 N3 pcap")
    s.add_argument("--n2-pcap", help="직접 분석할 N2 pcap")
    s.add_argument("--tolerance", type=float, default=25.0, help="처리량 허용오차 %%")
    s.add_argument("-o", "--out", help="대조 결과 JSON 경로")
    s.set_defaults(func=cmd_compare)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("\n중단됨")
        return 130
    except FileNotFoundError as e:
        print(f"파일 없음: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
