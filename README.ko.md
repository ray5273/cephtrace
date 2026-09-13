# PR #192 측정 가이드 (내일 할 일)

대상 PR: https://github.com/taodd/cephtrace/pull/192 (Draft)

목표는 PR 본문의 `TODO(ray5273)` 칸 세 곳을 채우는 것입니다.

1. **Environment**: 측정 환경 한 줄
2. **Validation**: main에서는 출력이 멈추고, PR 브랜치에서는 계속 나온다는 재현 결과
3. **Performance**: `bpf_stats` ns/hit 표와 클라이언트 IOPS

`run.sh all` 한 번이면 세 가지가 모두 `work/results/pr-sections.md`에 markdown으로 정리됩니다. 전체 소요 시간은 빌드를 빼고 약 20분입니다.

> ⚠️ **반드시 테스트 클러스터에서 하세요.** 전용 풀에 쓰기 부하(`rados bench`)가 들어가고, `pr192-*` object를 만들었다 지웁니다. 추적 중에는 OSD에 tracer 오버헤드도 걸립니다.

---

## 0. 준비물 체크리스트

측정할 **OSD가 떠 있는 Linux 호스트** 한 대에서 모두 진행합니다.

- [ ] root 권한 (`sudo -i`)
- [ ] 커널 5.8 이상 (`uname -r`). `bpf_stats` 때문에 필요합니다.
- [ ] 이 호스트에서 `ceph -s`가 동작함 (`/etc/ceph/ceph.conf`와 keyring이 있어야 함)
- [ ] `python3 -c 'import rados'`가 에러 없이 끝남
- [ ] 빌드 도구: `git make clang g++`와 개발 라이브러리
- [ ] 이 호스트에서 GitHub 접근 가능. 막혀 있으면 [부록 A](#부록-a-github-접근이-막힌-경우) 참고.

패키지 설치:

```bash
# Ubuntu/Debian
apt-get install -y git make clang g++ libelf-dev libc6-dev libdw-dev libssl-dev \
                   python3-rados ceph-common
# RHEL/Rocky
dnf install -y git make clang gcc-c++ elfutils-libelf-devel glibc-devel \
               elfutils-devel openssl-devel python3-rados ceph-common
```

cephadm 클러스터에서 OSD 호스트에 `ceph.conf`나 keyring이 없다면, **admin 노드에서** 아래를 실행해 OSD 호스트로 복사합니다.

```bash
ceph config generate-minimal-conf > ceph.conf
ceph auth get client.admin > ceph.client.admin.keyring
# 두 파일을 OSD 호스트의 /etc/ceph/ 로 복사
```

---

## 1. 스크립트를 회사 호스트로 옮기기

내 fork의 별도 브랜치 `pr192-bench`에 올려두었습니다. 이 브랜치는 PR 브랜치와 이력이 연결되지 않은 독립 브랜치라 PR #192에는 들어가지 않습니다.

```bash
# OSD 호스트에서
git clone -b pr192-bench --single-branch https://github.com/ray5273/cephtrace.git ~/bench-pr192
cd ~/bench-pr192
./run.sh          # 사용법이 출력되면 정상
```

호스트에서 GitHub 접근이 안 되면 Mac에서 scp로 복사합니다.

```bash
# Mac에서
scp -r ~/workspace/cephtrace-fix-osdtrace-hang-ops-map-exhaustion/bench-pr192 <user>@<osd-host>:~/
# OSD 호스트에서
cd ~/bench-pr192 && chmod +x run.sh pr192.py
```

> 이 브랜치에서 스크립트를 고쳐도 PR에는 영향이 없습니다. 측정 결과(`work/`)는 `.gitignore`로 제외되어 있습니다.

---

## 2. 테스트 풀 만들기

```bash
ceph osd pool create pr192test 32
ceph osd pool application enable pr192test rados
```

이미 쓰는 테스트 풀이 있으면 그걸 써도 됩니다. 이 풀 이름을 아래 `POOL=`에 넣습니다.

---

## 3. 추적할 OSD 정하기 (`OSDTRACE_ARGS`)

부하가 들어가는 object는 여러 PG로 흩어지고, **추적 중인 OSD가 primary인 op만** 출력에 잡힙니다. 그래서 **이 호스트의 OSD를 전부 추적**하는 게 좋습니다.

```bash
ceph osd ls-tree $(hostname -s)     # 이 호스트의 OSD id 목록
pgrep -a ceph-osd                   # OSD 프로세스 확인
```

| OSD 배포 방식 | 설정 |
| :--- | :--- |
| 패키지 설치 (호스트에 `ceph-osd` 바이너리가 있음) | 비워둠. 호스트의 OSD를 자동으로 추적합니다. |
| cephadm / 컨테이너 | `OSDTRACE_ARGS="--id 0,1,2,3"` (위에서 본 id를 모두) |
| 특정 프로세스만 | `OSDTRACE_ARGS="-p 1234,5678"` |

---

## 4. 실행

root 셸에서 진행합니다. `sudo POOL=... ./run.sh`는 sudoers 설정에 따라 거부될 수 있으니, `sudo -i`로 들어가거나 `sudo env POOL=...` 형태를 쓰세요.

### 방법 1: 한 번에 모두

```bash
sudo -i
cd ~<user>/bench-pr192
POOL=pr192test OSDTRACE_ARGS="--id 0,1,2,3" ./run.sh all 2>&1 | tee run.log
```

### 방법 2: 단계별 (권장. 중간 결과를 확인하면서 진행)

```bash
export POOL=pr192test
export OSDTRACE_ARGS="--id 0,1,2,3"     # 패키지 설치 OSD면 이 줄 생략

./run.sh build     # ① 빌드 (몇 분)
./run.sh env       # ② 환경 기록 (몇 초)
./run.sh stall     # ③ 멈춤 재현 (약 7분)
./run.sh perf      # ④ 성능 측정 (약 7분)
./run.sh report    # ⑤ PR용 markdown 출력
```

### 각 단계에서 확인할 것

**① build**
- 끝부분에 `PR diff against its base:`가 나오고, 변경 파일이 `src/osdtrace.bpf.c` 하나뿐인지 확인합니다.
- `work/bin/osdtrace-main`, `work/bin/osdtrace-pr` 두 파일이 생겼는지 봅니다.

**② env**: 출력된 `ceph_osd_version`, `osds_total`, `osds_local`, `deploy`, `nproc` 값이 실제와 맞는지 봅니다.

**③ stall**: main → PR 순서로 각각 이렇게 진행됩니다.

```
[..] stall/main: starting osdtrace
[..] osdtrace attached (pid ...)
[..] stall/main: baseline 20s (canary only)
[..] stall/main: missing-object flood 120s x 16 procs
[..] stall/main: flood stopped, watching 40s
{ ...summary.json... }
```

- `WARNING: no op rows during baseline`이 뜨면 → [문제 해결](#문제-해결) 1번
- **기대 결과**

  | 항목 | main | PR |
  | :--- | :--- | :--- |
  | `"ops_map_type"` | `"HASH"` | `"LRU_HASH"` |
  | `"stall"` | 값이 있음 (멈춘 시점) | `null` |
  | `"rows_per_sec_after_flood"` | `0` | 0보다 큼 |
  | `"ops_entries_max"` | 8192 근처 | 8192 근처 |

**④ perf**
- `Average IOPS: ...` 줄이 5번 나옵니다. tracer 없이 1번, main 2번, PR 2번입니다.
- 시작할 때 `bpf_stats`를 켜고, 끝나면 원래 값으로 되돌립니다.

**⑤ report**: 화면에 markdown이 출력되고 `work/results/pr-sections.md`에 저장됩니다.

---

## 5. 결과 확인과 해석

```bash
cat work/results/pr-sections.md
cat work/results/stall-main/summary.json
cat work/results/stall-pr/summary.json
```

결과 폴더 구조:

```
work/results/
├── env.txt, commits.txt, ceph-versions.json   # 환경
├── stall-main/, stall-pr/
│   ├── timeline.csv     # 매초: 출력 줄 수, ops 맵 엔트리 수, flood/canary 누적 op 수
│   ├── events.txt       # 구간 시작/끝 시각
│   ├── summary.json     # 판정 결과
│   ├── flood.log        # 없는 object stat 총 개수와 초당 개수
│   └── osdtrace.out / osdtrace.err
├── perf/
│   ├── notracer/bench.log
│   └── main-r1/, pr-r1/, main-r2/, pr-r2/   # before.json, after.json, bench.log
└── pr-sections.md       # PR에 붙일 markdown
```

### 해석 가이드

- **main에서 `stall`이 `null`인 경우** (재현 실패)
  - `ops_entries_max`가 8192에 못 미쳤다면: 누수 속도가 느렸거나 flood가 추적 중인 OSD에 잘 안 갔습니다. → [문제 해결](#문제-해결) 2번
  - `ops_entries_max`가 8192인데도 출력이 계속 나왔다면: 예상과 다른 결과이니 그대로 가져와 주세요. PR 주장을 다시 봐야 합니다.
- **PR에서 `rows_per_sec_flood`가 baseline보다 눈에 띄게 낮은 경우**: LRU가 진행 중인 op까지 evict해서 일부 줄이 빠진 것일 수 있습니다. PR에 적어둔 트레이드오프이니 숨기지 말고 수치 그대로 적습니다.
- **perf의 Δ가 크게 나빠진 경우** (예: +20% 이상): Ready for review로 바꾸기 전에 같이 봅시다.
- 라운드 간 편차가 크면 `ROUNDS=4`로 다시 돌립니다.

---

## 6. 결과 가져오기

```bash
cd ~<user>/bench-pr192
tar czf pr192-results.tgz -C work results run.log 2>/dev/null || tar czf pr192-results.tgz -C work results
```

`pr192-results.tgz`를 Mac으로 가져오면 됩니다. 최소한 `pr-sections.md`와 `stall-*/summary.json` 두 개만 있어도 됩니다.

---

## 7. PR 업데이트

결과를 Claude에게 주고 "PR #192 본문 TODO 채워줘"라고 하면 됩니다. 직접 하려면:

1. `pr-sections.md` 내용을 PR 본문의 `### Validation`, `### Performance` 섹션에 붙입니다.
2. `<!-- TODO(ray5273) ... -->` 주석과 빈 표를 지웁니다.
3. 결과가 괜찮으면 Draft를 해제합니다: PR 페이지에서 **Ready for review** 클릭, 또는 `gh pr ready 192 --repo taodd/cephtrace`

---

## 8. 정리

```bash
# 테스트 풀 삭제 (mon_allow_pool_delete가 필요할 수 있음)
ceph config set mon mon_allow_pool_delete true
ceph osd pool rm pr192test pr192test --yes-i-really-really-mean-it
ceph config set mon mon_allow_pool_delete false

# 빌드 폴더 삭제
rm -rf ~<user>/bench-pr192/work/src ~<user>/bench-pr192/work/wt-*
```

canary object(`pr192-canary-*`)는 `stall` 단계 끝에 자동으로 지워집니다. 중간에 끊겼다면 풀을 삭제하면 같이 정리됩니다.

---

## 문제 해결

**1. `WARNING: no op rows during baseline`**
- 부하가 추적하지 않는 OSD로만 갔을 가능성이 높습니다. `OSDTRACE_ARGS`에 이 호스트의 OSD를 모두 넣으세요.
- 그래도 안 되면 `work/results/stall-main/osdtrace.err`를 확인합니다. DWARF 관련 에러가 있으면 3번으로 갑니다.

**2. main이 멈추지 않음** (`ops_entries_max`가 8192 미만)
- 부하를 늘립니다: `FLOOD_PROCS=32 FLOOD_SECS=300 ./run.sh stall`
- `flood.log`의 `rate_per_sec`가 너무 낮으면(수백 이하) 클라이언트 쪽이 병목입니다. 프로세스 수를 늘리세요.

**3. `osdtrace exited during startup` 또는 `did not attach`**
- `osdtrace.err` 끝부분을 봅니다.
- `none of the ... are traceable with this osdtrace's embedded DWARF data`가 나오면, 이 Ceph 버전의 DWARF가 osdtrace에 내장되어 있지 않은 것입니다. DWARF JSON을 따로 만들어 넘겨야 합니다.
  ```bash
  work/bin/osdtrace-pr -p <osd pid> -j osd-dwarf.json      # 한 번만
  OSDTRACE_ARGS="-p <pid1,pid2> -i $PWD/osd-dwarf.json --skip-version-check" ./run.sh stall
  ```
- 시작이 느린 환경이면 `ATTACH_TIMEOUT=600`으로 늘립니다.

**4. `another osdtrace/radostrace is running`**
- 이전 실행이 남아 있는 것입니다. `pkill -INT -x osdtrace`로 정리한 뒤 다시 실행합니다.

**5. `kernel lacks kernel.bpf_stats_enabled`**
- 커널이 5.8 미만입니다. perf 단계는 건너뛰고 stall 결과만 가져오세요.

**6. python 쪽 에러** (`ops map not found`, `unsupported arch`, `OSError` 등)
- 이 스크립트에서 가장 검증이 덜 된 부분입니다(Mac에서 실행 불가). 에러 메시지 전체와 `uname -m`, `uname -r`를 가져와 주세요.

---

## 부록 A. GitHub 접근이 막힌 경우

인터넷이 되는 Linux 머신에서 `./run.sh build`를 먼저 돌립니다. 생긴 `work/bin/osdtrace-main`, `work/bin/osdtrace-pr`를 회사 호스트로 복사한 뒤 이렇게 지정합니다.

```bash
MAIN_BIN=/path/osdtrace-main PR_BIN=/path/osdtrace-pr POOL=pr192test ./run.sh stall
```

이 경우 `commits.txt`가 비므로, 리포트의 커밋 해시는 직접 채워 넣습니다(main=`5d999ab`, PR=`6fb8d71`). 빌드한 머신과 측정 호스트의 glibc 버전이 다르면 실행이 안 될 수 있으니, 같은 OS 버전에서 빌드하세요.

## 부록 B. 조정 가능한 설정

| 변수 | 기본값 | 의미 |
| :--- | :--- | :--- |
| `BASELINE_SECS` | 20 | flood 전 기준선 구간 |
| `FLOOD_SECS` | 120 | 없는 object stat을 보내는 시간 |
| `POST_SECS` | 40 | flood를 멈춘 뒤 관찰하는 시간 |
| `FLOOD_PROCS` | 16 | flood 프로세스 수 |
| `STALL_WINDOW` | 20 | 이 시간(초) 동안 출력이 0줄이면 "멈춤"으로 판정 |
| `CANARY_OBJECTS` | 64 | 정상 op용 object 수 |
| `BENCH_SECS` / `BENCH_BS` / `BENCH_THREADS` | 30 / 4096 / 16 | `rados bench` 설정 (다른 PR들과 같은 값) |
| `ROUNDS` | 2 | main/PR 번갈아 반복하는 횟수 |
| `COOLDOWN` | 30 | 측정 사이 휴지 시간(초) |
| `ATTACH_TIMEOUT` | 180 | osdtrace attach 대기 시간(초) |
| `CEPH_CONF` / `CEPH_NAME` | `/etc/ceph/ceph.conf` / `client.admin` | ceph 접속 설정 |
