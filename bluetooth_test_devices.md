# 블루투스 보안 테스트용 사무기기 구매 목록 (20개) — 키보드/마우스 전용

BlueToolkit exploit 43개 (BR/EDR 39개, BLE 2개, 크로스트랜스포트 1개) 대상 테스트를 위한 기기 목록입니다.

> **중요:** BlueToolkit exploit의 대다수(39/43)가 **BR/EDR (Bluetooth Classic)** 을 대상으로 합니다.
> 최신 Logitech Logi Bolt 제품군은 **BLE 전용**이므로 BR/EDR exploit 테스트가 불가합니다.
> BR/EDR 테스트를 위해 BT 3.0 Classic 기기 및 Rapoo 듀얼모드(BT 3.0 + BT 4.0) 기기를 반드시 포함해야 합니다.

## 구매 목록

| # | 카테고리 | 제품명 | BT 버전 | BR/EDR | BLE | 주요 BT 프로파일 | 테스트 가능 Exploit 그룹 | 구매 링크 (한국) |
|---|---------|--------|---------|--------|-----|-----------------|------------------------|-----------------|
| 1 | 키보드 | 로지텍 K380 멀티디바이스 BT 키보드 | BT 3.0 | O | X | HID (Classic) | Braktooth, BlueBorne, SSP/페어링, Legacy Pairing | [쿠팡](https://www.coupang.com/np/search?q=%EB%A1%9C%EC%A7%80%ED%85%8D+K380) |
| 2 | 키보드+마우스 세트 | Rapoo 9300M 멀티모드 무선 키보드+마우스 | BT 3.0 + BT 4.0 | O | O | HID (Classic + BLE) | Braktooth, BlueBorne, KNOB BLE, BLUR, 페어링 검사 | [다나와](https://prod.danawa.com/info/?pcode=27571730) |
| 3 | 키보드 | 삼성 Smart Keyboard Trio 500 | BT 5.0 | X | O | HID (BLE) | KNOB BLE, Recon BLE, 페어링 검사 | [쿠팡](https://www.coupang.com/np/search?q=%EC%82%BC%EC%84%B1+%ED%8A%B8%EB%A6%AC%EC%98%A4+500+%ED%82%A4%EB%B3%B4%EB%93%9C) |
| 4 | 키보드 | 로지텍 MX Keys S 무선 키보드 | BT 5.0 | X | O | HID (BLE) | KNOB BLE, Recon BLE, SSP 검사 | [쿠팡](https://www.coupang.com/np/search?q=%EB%A1%9C%EC%A7%80%ED%85%8D+MX+Keys+S) |
| 5 | 키보드 | 로지텍 K580 슬림 멀티디바이스 키보드 | BLE | X | O | HID (BLE) | KNOB BLE, Recon BLE, 페어링 검사 | [쿠팡](https://www.coupang.com/np/search?q=%EB%A1%9C%EC%A7%80%ED%85%8D+K580) |
| 6 | 키보드 | 로지텍 ERGO K860 인체공학 키보드 | BT 5.0 | X | O | HID (BLE) | KNOB BLE, Recon BLE, 페어링 검사 | [쿠팡](https://www.coupang.com/np/search?q=%EB%A1%9C%EC%A7%80%ED%85%8D+ERGO+K860) |
| 7 | 키보드 | 로지텍 Pebble Keys 2 K380s | BT 5.1 | X | O | HID (BLE) | KNOB BLE, Recon BLE, 페어링 검사 | [쿠팡](https://www.coupang.com/np/search?q=%EB%A1%9C%EC%A7%80%ED%85%8D+K380s) |
| 8 | 키보드 | Microsoft Designer Compact Keyboard | BT 5.0 | X | O | HID (BLE) | KNOB BLE, Recon BLE, 페어링 검사 | [다나와](https://search.danawa.com/dsearch.php?query=%EB%A7%88%EC%9D%B4%ED%81%AC%EB%A1%9C%EC%86%8C%ED%94%84%ED%8A%B8+%EB%94%94%EC%9E%90%EC%9D%B4%EB%84%88+%EC%BB%B4%ED%8C%A9%ED%8A%B8+%ED%82%A4%EB%B3%B4%EB%93%9C) |
| 9 | 키보드 | Microsoft Bluetooth Keyboard | BT 5.0 | X | O | HID (BLE) | KNOB BLE, Recon BLE, 페어링 검사 | [다나와](https://prod.danawa.com/info/?pcode=10503801) |
| 10 | 키보드+마우스 세트 | 로지텍 Pebble 2 Combo (K380s + M350s) | BT 5.1 | X | O | HID (BLE) | KNOB BLE, Recon BLE, 페어링 검사 | [쿠팡](https://www.coupang.com/np/search?q=%EB%A1%9C%EC%A7%80%ED%85%8D+Pebble+2+Combo) |
| 11 | 마우스 | 로지텍 M750 Signature 무선 마우스 | BLE | X | O | HID (BLE) | KNOB BLE, Recon BLE, 페어링 검사 | [쿠팡](https://www.coupang.com/np/search?q=%EB%A1%9C%EC%A7%80%ED%85%8D+M750) |
| 12 | 마우스 | 로지텍 MX Master 3S 무선 마우스 | BLE | X | O | HID (BLE) | KNOB BLE, Recon BLE, SSP/SC 검사 | [쿠팡](https://www.coupang.com/np/search?q=%EB%A1%9C%EC%A7%80%ED%85%8D+MX+Master+3S) |
| 13 | 마우스 | 로지텍 Lift Vertical 인체공학 마우스 | BLE | X | O | HID (BLE) | KNOB BLE, Recon BLE, Method Confusion | [쿠팡](https://www.coupang.com/np/search?q=%EB%A1%9C%EC%A7%80%ED%85%8D+Lift+Vertical+%EB%A7%88%EC%9A%B0%EC%8A%A4) |
| 14 | 마우스 | 로지텍 Pebble Mouse 2 M350s | BT 5.1 | X | O | HID (BLE) | KNOB BLE, Recon BLE, 페어링 검사 | [쿠팡](https://www.coupang.com/np/search?q=%EB%A1%9C%EC%A7%80%ED%85%8D+M350s) |
| 15 | 마우스 | 로지텍 MX Anywhere 3S 무선 마우스 | BLE | X | O | HID (BLE) | KNOB BLE, Recon BLE, 페어링 검사 | [쿠팡](https://www.coupang.com/np/search?q=%EB%A1%9C%EC%A7%80%ED%85%8D+MX+Anywhere+3S) |
| 16 | 마우스 | Microsoft Bluetooth Mouse | BT 5.0 | X | O | HID (BLE) | KNOB BLE, Recon BLE, 페어링 검사 | [쿠팡](https://www.coupang.com/np/search?q=%EB%A7%88%EC%9D%B4%ED%81%AC%EB%A1%9C%EC%86%8C%ED%94%84%ED%8A%B8+%EB%B8%94%EB%A3%A8%ED%88%AC%EC%8A%A4+%EB%A7%88%EC%9A%B0%EC%8A%A4) |
| 17 | 마우스 | Microsoft Bluetooth Ergonomic Mouse | BT 5.0 | X | O | HID (BLE) | KNOB BLE, Recon BLE, 페어링 검사 | [쿠팡](https://www.coupang.com/np/search?q=%EB%A7%88%EC%9D%B4%ED%81%AC%EB%A1%9C%EC%86%8C%ED%94%84%ED%8A%B8+%EC%9D%B8%EC%B2%B4%EA%B3%B5%ED%95%99+%EB%B8%94%EB%A3%A8%ED%88%AC%EC%8A%A4+%EB%A7%88%EC%9A%B0%EC%8A%A4) |
| 18 | 마우스 | 로지텍 M650 Signature 무선 마우스 | BLE | X | O | HID (BLE) | KNOB BLE, Recon BLE, 페어링 검사 | [쿠팡](https://www.coupang.com/np/search?q=%EB%A1%9C%EC%A7%80%ED%85%8D+M650) |
| 19 | 마우스 | 로지텍 M550 무선 마우스 | BLE | X | O | HID (BLE) | KNOB BLE, Recon BLE, 페어링 검사 | [쿠팡](https://www.coupang.com/np/search?q=%EB%A1%9C%EC%A7%80%ED%85%8D+M550) |
| 20 | 키보드 | 로지텍 K650 Signature 무선 키보드 | BLE | X | O | HID (BLE) | KNOB BLE, Recon BLE, 페어링 검사 | [쿠팡](https://www.coupang.com/np/search?q=%EB%A1%9C%EC%A7%80%ED%85%8D+K650) |

## BR/EDR vs BLE 테스트 커버리지 요약

| 연결 유형 | 기기 # | 테스트 가능 Exploit 수 | 비고 |
|-----------|--------|----------------------|------|
| **BR/EDR Classic** (BT 3.0) | #1 | 39개 (전체 BR/EDR exploit) | Braktooth, BlueBorne, Bleeding Tooth, 페어링 취약점 전체 |
| **듀얼모드** (BR/EDR + BLE) | #2 | 39 + 2개 (BR/EDR + BLE 모두) | BLUR 크로스트랜스포트 테스트 가능, 가장 넓은 커버리지 |
| **BLE 전용** | #3-#20 | 2개 (KNOB BLE, Recon BLE) | BR/EDR exploit 테스트 불가 |

## Exploit 그룹별 커버리지

| 테스트 영역 | 커버 기기 # | 비고 |
|------------|-----------|------|
| Braktooth (LMP/L2CAP DoS, ESP32 필요) | 1, 2 | BR/EDR 지원 기기만 가능 |
| BlueBorne (SDP/L2CAP) | 1, 2 | BR/EDR 지원 기기만 가능 |
| Bleeding Tooth (Linux BT 스택 대상) | 1, 2 | BR/EDR 기기, Linux 호스트 테스트 |
| KNOB BLE | 2-20 | BLE 지원 기기 전체 |
| Recon (SC/SSP/BLUR 검사) | 전체 | 프로파일 정보 수집 |
| 페어링 취약점 (SSP, NiNo, Method Confusion, Legacy) | 전체 | IO Capability 다양성 확보 |
| BLUR (크로스트랜스포트) | 2 | BR/EDR + BLE 듀얼모드 기기만 가능 |

## 추가 참고사항

- **Braktooth exploit 실행에는 ESP32 보드** (별도 구매 필요)가 공격 측 하드웨어로 필요합니다
- **InternalBlue exploit에는 Nexus 5** (중고)가 필요하지만 사무용품이 아니므로 목록에서 제외했습니다
- **로지텍 K480은 2025년 초 단종**되어 신품 구매가 불가하므로 목록에서 제외했습니다
- **Rapoo 8200M, 8100M은 한국 내 정식 유통처를 찾기 어려워** 목록에서 제외했습니다
- **Rapoo MT760은 쿠팡에서 품절** 상태이므로 목록에서 제외했습니다
- **Rapoo 9300M은 쿠팡에서는 미판매**이나, [다나와](https://prod.danawa.com/info/?pcode=27571730) / [영재컴퓨터](https://www.youngjaecomputer.com/shop/item.php?it_id=5676621756) 등에서 구매 가능합니다 (~39,650원)
- **최신 로지텍 Logi Bolt 제품군 (MX Keys S, MX Master 3S, Lift, K580 등)은 BLE 전용**으로, BR/EDR exploit (Braktooth, BlueBorne 등) 테스트에 사용할 수 없습니다
- **BR/EDR 테스트 기기가 #1, #2로 제한적**입니다 — 현재 시판 중인 키보드/마우스 중 BR/EDR Classic을 지원하는 제품이 극히 드뭅니다
- 칩셋 다양성: Broadcom (로지텍), Qualcomm (삼성), Realtek (Rapoo), Nordic (Microsoft) 등 주요 칩셋 커버
