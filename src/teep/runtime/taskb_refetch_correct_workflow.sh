#!/usr/bin/env bash
# taskb_refetch_correct_workflow.sh - Task 5 (Plan B validity fix). BAN v1.
#
# VAN DE (xac nhan qua measurement/experiment/audit_log_validity.py, chay tren
# TOAN BO 556 repo da fetch): taskb_fetch_and_grep.sh chon "run completed gan
# nhat CUA CA REPO" (GET /repos/{repo}/actions/runs) - KHONG loc theo workflow
# file. 45.9% repo (255/556) bi anh huong:
#   - 24.5% (136): log thu duoc KHONG co bang chung Harden-Runner nao ca (sai
#     workflow hoan toan - vd bat trung "Copilot Code Review", "dependency-review",
#     "npm_and_yarn ... Update #xxxx" cua Dependabot).
#   - 16.9% (94): bat DUNG job co Harden-Runner nhung la job CAU HINH audit-mode,
#     trong khi repo do THAT SU CO san >=1 workflow file khac cau hinh block-mode
#     (xac nhan qua data/policies_ci.jsonl - khong phai "repo nay chi co audit").
#   - 4.5% (25): bat dung job block-mode nhung Harden-Runner tu fallback ve
#     audit luc runtime (do loi fetch policy cache) - CAN xem lai xem co
#     nen fetch lai run KHAC cua CUNG workflow file nay hay khong (co the run
#     khac cua chinh workflow nay khong bi fallback).
#
# FIX GOC: GitHub co API rieng loc THEO 1 WORKFLOW FILE CU THE thay vi toan bo
# repo:
#   GET /repos/{repo}/actions/workflows/{file_name}/runs?per_page=5&status=completed
# measurement/experiment/build_refetch_targets.py da doi chieu voi
# data/policies_ci.jsonl va xac dinh DUNG ten file (vd "ci.yml") co job
# egress_policy=block cho tung repo trong danh sach can fetch lai, ghi vao
# measurement/experiment/refetch_targets.json (ca 288/255 repo can sua deu co
# it nhat 1 candidate file - khong co repo nao "khong sua duoc").
#
# LOGIC (giu nguyen phan da kiem chung tu taskb_fetch_and_grep.sh v3: strip \r
# token, -L theo redirect, pre-flight token, kiem /jobs THAT cho tung run loc
# job "skipped", -o zip + unzip -l kiem hop le) - CHI DOI nguon danh sach run:
#
#   for repo in refetch_targets.json:
#     for file_name in candidate_files (uu tien file nhieu job block nhat):
#       GET /actions/workflows/{file_name}/runs?per_page=5&status=completed
#       -> duyet run moi nhat truoc, GET /jobs THAT, chon run dau tien co
#          >=1 job khac "skipped"
#       neu tim duoc -> tai log, DUNG (khong thu candidate_files tiep theo)
#       neu KHONG tim duoc trong ca 5 va 100 run gan nhat cua file nay -> thu
#          candidate_files[i+1]
#     neu het candidate_files ma van khong tim duoc run hop le -> ghi
#       error_type=no_valid_run_in_any_block_workflow_file
#
# LUU Y BAT BUOC: sandbox nay (Cowork) KHONG goi duoc api.github.com (bi chan
# mang - xem memory "Sandbox blocks GitHub API"). Script nay PHAI chay tren
# may CUA BAO (co gh auth login that), giong het taskb_fetch_and_grep.sh.
#
# GHI DE: log cu trong measurement/taskb_run_data/logs/<repo>/ SE BI GHI DE
# (extracted/, logs.zip, runs_p5.json...) cho repo nao fetch lai thanh cong -
# ban goc van con nguyen trong taskb_run_data/taskb_step1_results.csv (khong
# bi xoa) nhung thu muc extracted/ tren dia se la BAN MOI. Neu muon giu ca 2
# de doi chieu, doi TARGETS_LOGS_DIR ben duoi truoc khi chay.
#
# CHAY (khuyen nghi --sample truoc):
#   bash measurement/taskb_refetch_correct_workflow.sh --sample 8
#   bash measurement/taskb_refetch_correct_workflow.sh --repos "CarlAllenn/edtf,Azure/karpenter-provider-azure"
#   bash measurement/taskb_refetch_correct_workflow.sh            # het 288 repo trong refetch_targets.json
#
# YEU CAU: gh CLI (da `gh auth login`), curl, jq, unzip. Chay TU thu muc goc
# repo (giong taskb_fetch_and_grep.sh).
set -uo pipefail

# Data lives outside the repo (see src/teep/paths.py). TEEP_DATA overrides.
ROOT_DIR="${TEEP_DATA:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)/teep_data}"
cd "$ROOT_DIR" || exit 1

TARGETS_JSON="measurement/experiment/refetch_targets.json"
OUT_DIR="measurement/taskb_run_data"
LOGS_DIR="$OUT_DIR/logs"
RESULTS_CSV="$OUT_DIR/taskb_refetch_results.csv"
DEBUG_LOG="$OUT_DIR/taskb_refetch_debug_raw_responses.log"

REPOS_ARG=""
SAMPLE_N=""
while [ $# -gt 0 ]; do
  case "$1" in
    --repos) REPOS_ARG="$2"; shift 2 ;;
    --sample) SAMPLE_N="$2"; shift 2 ;;
    *) echo "Tham so khong hieu: $1"; exit 1 ;;
  esac
done

[ -f "$TARGETS_JSON" ] || { echo "Thieu $TARGETS_JSON - chay: python3 measurement/experiment/build_refetch_targets.py truoc."; exit 1; }
mkdir -p "$LOGS_DIR"
: > "$DEBUG_LOG"

for cmd in gh jq curl unzip; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Thieu lenh '$cmd'. Cai roi chay lai."; exit 1; }
done
gh auth status >/dev/null 2>&1 || { echo "Chua dang nhap gh. Chay: gh auth login"; exit 1; }

TOKEN=$(gh auth token | tr -d '\r')

echo "=== Pre-flight: kiem TOKEN dung duoc voi API khong (GET /user) ==="
preflight_status=$(curl -s -o /tmp/taskb_refetch_preflight.json -w "%{http_code}" \
  -H "Authorization: token $TOKEN" https://api.github.com/user)
echo "  HTTP $preflight_status"
if [ "$preflight_status" != "200" ]; then
  echo "  !! DUNG NGAY: token khong dung duoc (HTTP $preflight_status). Kiem gh auth status."
  cat /tmp/taskb_refetch_preflight.json
  exit 1
fi
echo "  OK - dang xac thuc la: $(jq -r '.login' /tmp/taskb_refetch_preflight.json)"
echo ""

if [ -n "$REPOS_ARG" ]; then
  REPOS=$(echo "$REPOS_ARG" | tr ',' '\n')
  echo "=== CHE DO TEST: chi chay ${REPOS_ARG} ==="
elif [ -n "$SAMPLE_N" ]; then
  REPOS=$(jq -r "keys[:${SAMPLE_N}][]" "$TARGETS_JSON")
  echo "=== CHE DO SAMPLE: $SAMPLE_N repo dau tien trong $TARGETS_JSON ==="
else
  REPOS=$(jq -r 'keys[]' "$TARGETS_JSON")
  echo "=== CHE DO DAY DU: toan bo $(echo "$REPOS" | grep -c '.') repo trong $TARGETS_JSON ==="
  echo "!! Khuyen nghi: chi chay che do nay SAU KHI --sample nho da cho ket qua hop ly !!"
fi
REPOS=$(printf '%s' "$REPOS" | tr -d '\r')
N=$(echo "$REPOS" | grep -c '.' || true)
echo "Se thu fetch lai $N repo."
echo ""

echo "repo,reason,candidate_file_used,candidate_file_index,run_id,run_created_at,n_jobs,log_http_status,zip_ok,n_step_files,error_type" > "$RESULTS_CSV"

MAX_CANDIDATES_PER_PAGE=20
n_fixed=0

i=0
while IFS= read -r repo; do
  [ -z "$repo" ] && continue
  i=$((i + 1))
  echo ""
  echo "[$i/$N] $repo"

  # BUG da xac nhan tu chay that (--sample 8, 2026-09-10): jq ban Windows ghi
  # CRLF ra stdout - "$(...)"/mapfile chi cat \n cuoi dong, KHONG cat \r dung
  # truoc no, nen "reason" va TUNG PHAN TU cua candidate_files deu dinh \r o
  # cuoi (vd "cargo-deny.yml\r"). \r lot vao URL lam curl khong parse duoc ->
  # HTTP 000 o MOI request, khong lien quan gi den token/auth. Day CHINH LA
  # bug \r-corruption da tung gap va sua cho bien REPOS (xem comment lich su
  # trong taskb_fetch_and_grep.sh) nhung lan nay sot 2 diem doc jq moi nay -
  # sua bang `tr -d '\r'` NGAY KHI doc ra, ap dung ca 2 diem.
  reason=$(jq -r --arg r "$repo" '.[$r].reason' "$TARGETS_JSON" | tr -d '\r')
  mapfile -t candidate_files < <(jq -r --arg r "$repo" '.[$r].candidate_files[]' "$TARGETS_JSON" | tr -d '\r')
  echo "  ly do fetch lai: $reason | candidate_files: ${candidate_files[*]}"

  safe_repo=$(echo "$repo" | tr '/' '__')
  repo_dir="$LOGS_DIR/$safe_repo"
  mkdir -p "$repo_dir"

  # THEM (2026-09-10): cho phep chay lai TOAN BO refetch_targets.json nhieu
  # lan ma khong ton cong/quota lam lai repo DA fetch thanh cong tu lan chay
  # truoc - kiem thang tren dia (co file .txt that trong extracted/), khong
  # dua vao CSV ket qua (co the tu 1 lan chay khac, de sot). Neu da co roi,
  # bo qua repo nay, sang repo tiep theo ngay.
  if [ -d "$repo_dir/extracted" ] && find "$repo_dir/extracted" -name '*.txt' -print -quit 2>/dev/null | grep -q .; then
    echo "  (da co log that tu truoc, bo qua - xoa thu muc extracted/ neu muon ep fetch lai)"
    sleep 0.1
    continue
  fi

  found=false
  cand_idx=0
  for wf_file in "${candidate_files[@]}"; do
    cand_idx=$((cand_idx + 1))
    echo "  -- thu candidate_file #$cand_idx: $wf_file"

    for per_page in 5 100; do
      runs_body_file="$repo_dir/refetch_runs_${wf_file//\//_}_p${per_page}.json"
      runs_http=$(curl -s -L -o "$runs_body_file" -w "%{http_code}" \
        -H "Authorization: token $TOKEN" \
        "https://api.github.com/repos/$repo/actions/workflows/$wf_file/runs?per_page=${per_page}&status=completed")

      if [ "$runs_http" != "200" ]; then
        echo "     workflows/$wf_file/runs (per_page=$per_page) HTTP $runs_http"
        { echo "== $repo wf=$wf_file p=$per_page HTTP $runs_http =="; cat "$runs_body_file"; echo; } >> "$DEBUG_LOG"
        continue
      fi

      n_completed=$(jq '[.workflow_runs[] | select(.status=="completed")] | length' "$runs_body_file" 2>/dev/null | tr -d '\r')
      [ -z "$n_completed" ] && n_completed=0
      [ "$n_completed" = "0" ] && continue

      chosen_run_id="" chosen_created="" chosen_n_jobs=""
      tried=0
      # tr -d '\r' o day CUNG BAT BUOC voi cung ly do nhu tren - $cid dung
      # truc tiep trong URL ben duoi, \r con sot lai se lam HTTP 000 lap lai.
      while IFS= read -r cid; do
        [ -z "$cid" ] && continue
        tried=$((tried + 1))
        [ "$tried" -gt "$MAX_CANDIDATES_PER_PAGE" ] && break
        jf="$repo_dir/refetch_jobs_${cid}.json"
        jhttp=$(curl -s -L -o "$jf" -w "%{http_code}" -H "Authorization: token $TOKEN" \
          "https://api.github.com/repos/$repo/actions/runs/$cid/jobs?per_page=100")
        [ "$jhttp" != "200" ] && continue
        n_real_jobs=$(jq -r '[.jobs[] | select(.conclusion != "skipped" and .conclusion != null)] | length' "$jf" 2>/dev/null | tr -d '\r')
        if [ -n "$n_real_jobs" ] && [ "$n_real_jobs" != "0" ]; then
          chosen_run_id="$cid"
          chosen_created=$(jq -r --arg id "$cid" '.workflow_runs[]? | select((.id|tostring)==$id) | .created_at' "$runs_body_file" | head -1 | tr -d '\r')
          chosen_n_jobs=$(jq -r '.total_count // (.jobs|length)' "$jf" | tr -d '\r')
          echo "     run $cid: $n_real_jobs job thuc su chay -> CHON."
          break
        fi
      done <<< "$(jq -r '[.workflow_runs[] | select(.status=="completed")] | sort_by(.created_at) | reverse | .[].id' "$runs_body_file" | tr -d '\r')"

      if [ -n "$chosen_run_id" ]; then
        zip_path="$repo_dir/logs.zip"
        log_http_status=$(curl -s -L -H "Authorization: token $TOKEN" -w "%{http_code}" -o "$zip_path" \
          "https://api.github.com/repos/$repo/actions/runs/$chosen_run_id/logs")
        zip_ok=false n_step_files=0 error_type="ok"
        if [ "$log_http_status" = "200" ] && unzip -l "$zip_path" >/dev/null 2>&1; then
          zip_ok=true
          n_step_files=$(unzip -l "$zip_path" 2>/dev/null | grep -c '\.txt$' || true)
          rm -rf "$repo_dir/extracted"
          unzip -o -q "$zip_path" -d "$repo_dir/extracted"
          echo "     log 200 OK, $n_step_files file .txt -> DA GHI DE $repo_dir/extracted"
          n_fixed=$((n_fixed + 1))
        else
          error_type="log_http${log_http_status}_or_invalid_zip"
          echo "     log HTTP $log_http_status hoac zip khong hop le"
        fi
        echo "$repo,$reason,$wf_file,$cand_idx,$chosen_run_id,$chosen_created,$chosen_n_jobs,$log_http_status,$zip_ok,$n_step_files,$error_type" >> "$RESULTS_CSV"
        found=true
        break 2
      fi
    done
    echo "     khong tim duoc run hop le cho $wf_file (ca per_page=5 va 100), thu candidate tiep theo."
  done

  if [ "$found" = false ]; then
    echo "  !! KHONG fetch lai duoc (het candidate_files, khong run nao hop le)."
    echo "$repo,$reason,,,,,,,,,no_valid_run_in_any_block_workflow_file" >> "$RESULTS_CSV"
  fi

  sleep 1
done <<< "$REPOS"

echo ""
echo "=================================================================="
echo "Fetch lai thanh cong: $n_fixed / $N repo"
echo "Ket qua chi tiet: $RESULTS_CSV"
echo ""
echo "BUOC TIEP THEO SAU KHI CHAY XONG TREN MAY CUA BAO:"
echo "  1. uv run python measurement/extract_rlog_v2.py   (build lai R_exec voi log da sua)"
echo "  2. uv run python measurement/experiment/audit_log_validity.py   (kiem lai ty le con lai)"
echo "  3. uv run python measurement/experiment/evaluate_s1_vs_rexec.py  (do lai Precision/Recall/F1)"
