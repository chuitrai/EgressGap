#!/usr/bin/env bash
# taskb_fetch_and_grep.sh - Task B, Buoc 1+2. BAN v3.
#
# LICH SU: v2 sua bug "608/609 khong co completed run" (xem
# measurement/taskb_actions_log_feasibility_notes.md muc 7). v3 (2026-09-06)
# sua tiep 3 phat hien tu vong test n=11/n=50 that (xem muc 8-9 cua note):
#   1. -L (follow redirect) THEM vao ca 2 request liet-ke-run (truoc chi co o
#      request tai log) - sua loi 301 tren repo bi doi ten/chuyen chu so huu
#      (vd CarlAllenn/edtf -> GitHub redirect sang /repositories/{id}/...).
#   2. THEM buoc goi /actions/runs/{id}/jobs TRUOC khi thu tai log, de tach
#      rieng "no_jobs" (run chua bao gio thuc thi job nao - HOP LE, khong phai
#      loi; xac nhan thuc nghiem qua gh api tay cho prowler-cloud/prowler va
#      open-edge-platform/geti-instant-learn, ca hai deu tra dung
#      {"total_count":0,"jobs":[]}) khoi "no_log" (job DA chay nhung log van
#      404 - BI AN, can dieu tra rieng, KHONG duoc gop chung).
#   3. THEM cot workflow_name, n_jobs, job_ids, log_source vao CSV de moi dong
#      ket qua truy nguyen duoc ve DUNG 1 run cu the - vi script CHU DICH chon
#      "run completed gan nhat" moi lan chay nen KHONG deterministic tren repo
#      dang hoat dong (chay lai ngay mai co the ra run_id khac - day la THIET
#      KE DUNG, khong phai loi can "sua" thanh luon chon 1 run co dinh).
#   4. Doi cach ghi dong CSV sang ham csv_row() dung mang bash thay vi noi
#      chuoi tay dem dau phay (tranh lap lai kieu bug da gap voi \r-corruption).
#
# BAN v2 - sua sau khi audit ket qua "608/609 khong co completed run" (xem
# measurement/taskb_actions_log_feasibility_notes.md muc 7 "Audit 608/609" de
# doc toan bo qua trinh dieu tra).
#
# NGUYEN NHAN DA XAC NHAN QUA DOC CODE (khong phai doan): ban v1 goi
# `curl -s ... /actions/runs?per_page=5` NHUNG KHONG kiem tra ma HTTP cua chinh
# request nay (chi kiem HTTP cho request tai log o buoc sau). Neu request nay
# that bai (401 sai token, 403 rate-limit, hoac loi khac) thi bien $runs_json
# se la 1 JSON LOI (vd {"message":"Bad credentials",...}) - KHONG co field
# .workflow_runs. Vi jq dung `.workflow_runs[]?` (dau `?` nuot loi khi field
# khong ton tai), pipeline tra ve RONG MA KHONG BAO LOI GI CA -> script ket
# luan nham "khong co completed run" trong khi that ra REQUEST DA THAT BAI TU
# DAU. Day la nguyen nhan CHAC CHAN (doc thay tu code), khong phai gia thuyet.
#
# CHUA XAC NHAN duoc TU sandbox nay (mang bi chan, xem muc dau file note) VI
# SAO chinh request do that bai - cac gia thuyet can Bao tu kiem (script nay
# co san cong cu de kiem, xem --diagnose ben duoi):
#   (a) $(gh auth token) tren Git Bash/Windows co the dinh \r cuoi chuoi (loi
#       dong CRLF quen thuoc cua Windows) -> header Authorization bi hong ->
#       MOI request curl deu 401, dong loat, khop voi ty le gan 100% that bai.
#   (b) scope token khong du actions:read (gh auth status van "OK" nhung API
#       Actions rieng co the tra 403/404 khac).
#   (c) rate limit da can kiet TRUOC KHI vao vong lap 609 repo (vd do 1 lan
#       chay thu truoc do da dung het quota).
#   (d) auth scheme "token" (cu) thay vi "Bearer" (moi) khong tuong thich voi
#       loai token dang dung (fine-grained PAT dung Bearer, classic PAT ca
#       hai deu duoc theo doc GitHub).
#
# BAN v2 nay THEM (khong doi logic cot loi da dung: chon run status=="completed",
# curl -L cho log download, lenh grep giu nguyen):
#   1. Pre-flight: goi GET /user MOT LAN truoc vong lap - neu khac 200, DUNG
#      NGAY va bao loi auth ro rang, khong lang phi 609 lan lap lai cung 1 loi.
#   2. Tach rieng HTTP status cua request /actions/runs (truoc day khong co).
#   3. Khi /actions/runs that bai (khac 200), IN RA raw body loi + ghi
#      error_type rieng (api_runs_list_httpNNN) - KHONG gop vao "no_completed_run".
#   4. Khi /actions/runs tra 200 nhung 0 run "completed" trong per_page=5, TU
#      DONG thu lai voi per_page=100 truoc khi ket luan "genuinely khong co
#      completed run gan day" (test gia thuyet "5 run la qua it").
#   5. --repos "a/b,c/d" hoac --sample N de test tren vai repo TRUOC, khong
#      bat buoc chay het danh sach trong taskb_selected_repos.json.
#   6. In rate limit truoc/sau + so request thuc te da dung (khong gia dinh
#      "1 repo = 1 request").
#   7. CSV ket qua co them cot rieng cho tung failure mode (xem header).
#
# CHAY (khuyen nghi: luon --sample nho truoc, KHONG chay het ngay)
#   bash measurement/taskb_fetch_and_grep.sh --repos backstage/backstage,eclipse-jkube/ci
#   bash measurement/taskb_fetch_and_grep.sh --sample 8
#   bash measurement/taskb_fetch_and_grep.sh            # het danh sach - CHI sau khi sample OK
#
# YEU CAU: gh CLI (da `gh auth login`), curl, jq, unzip.
set -uo pipefail   # KHONG dung -e: 1 repo loi khong duoc lam dung ca vong lap

# Data lives outside the repo (see src/teep/paths.py). TEEP_DATA overrides.
ROOT_DIR="${TEEP_DATA:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)/teep_data}"
cd "$ROOT_DIR" || exit 1

SELECTED_JSON="measurement/taskb_selected_repos.json"
OUT_DIR="measurement/taskb_run_data"
LOGS_DIR="$OUT_DIR/logs"
RESULTS_CSV="$OUT_DIR/taskb_step1_results.csv"
URLS_JSON="$OUT_DIR/taskb_step2_urls.json"
DEBUG_LOG="$OUT_DIR/taskb_debug_raw_responses.log"

# --- doc tham so dong lenh ---
REPOS_ARG=""
SAMPLE_N=""
while [ $# -gt 0 ]; do
  case "$1" in
    --repos) REPOS_ARG="$2"; shift 2 ;;
    --sample) SAMPLE_N="$2"; shift 2 ;;
    *) echo "Tham so khong hieu: $1"; exit 1 ;;
  esac
done

mkdir -p "$LOGS_DIR"
: > "$DEBUG_LOG"

for cmd in gh jq curl unzip; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Thieu lenh '$cmd'. Cai roi chay lai."; exit 1; }
done
if command -v uv >/dev/null 2>&1; then PY="uv run python"
elif command -v python3 >/dev/null 2>&1; then PY="python3"
elif command -v python >/dev/null 2>&1; then PY="python"
else echo "Thieu python/uv. Cai roi chay lai."; exit 1
fi
gh auth status >/dev/null 2>&1 || { echo "Chua dang nhap gh. Chay: gh auth login"; exit 1; }

TOKEN=$(gh auth token)

# --- 0. KIEM TRA TOKEN CO BI HONG DINH DANG KHONG (gia thuyet a) ---
echo "=== Kiem tra bien TOKEN (gia thuyet CRLF tren Windows/Git Bash) ==="
token_len=$(printf '%s' "$TOKEN" | wc -c)
echo "  Do dai TOKEN (khong tinh newline cuoi): $token_len ky tu"
if printf '%s' "$TOKEN" | grep -q $'\r'; then
  echo "  !! PHAT HIEN: TOKEN co ky tu \\r (carriage return) - DAY LA BUG."
  echo "     Header Authorization se bi hong tren MOI request. Sua bang:"
  echo '       TOKEN=$(gh auth token | tr -d "\r")'
  echo "     roi chay lai script (da tu dong xu ly ben duoi, chi canh bao de ban biet nguyen nhan)."
  TOKEN=$(printf '%s' "$TOKEN" | tr -d '\r')
else
  echo "  Khong thay \\r trong TOKEN - gia thuyet CRLF (a) KHONG phai nguyen nhan (it nhat o buoc nay)."
fi
echo ""

# --- 1. RATE LIMIT TRUOC ---
echo "=== Rate limit TRUOC khi bat dau ==="
rl_before=$(curl -s -H "Authorization: token $TOKEN" https://api.github.com/rate_limit)
echo "$rl_before" | jq '.rate' 2>/dev/null || echo "$rl_before"
remaining_before=$(echo "$rl_before" | jq -r '.rate.remaining // "?"' 2>/dev/null)
echo ""

# --- 2. PRE-FLIGHT: TOKEN CO DUNG DUOC KHONG (dung 1 request re nhat: GET /user) ---
echo "=== Pre-flight: kiem TOKEN dung duoc voi API khong (GET /user) ==="
preflight_status=$(curl -s -o /tmp/taskb_preflight_body.json -w "%{http_code}" \
  -H "Authorization: token $TOKEN" https://api.github.com/user)
echo "  HTTP $preflight_status"
if [ "$preflight_status" != "200" ]; then
  echo "  !! DUNG NGAY: token khong dung duoc voi API (HTTP $preflight_status), khong chay"
  echo "     vong lap repo nua vi se lap lai DUNG 1 loi nay 609 lan. Body loi:"
  cat /tmp/taskb_preflight_body.json | tee -a "$DEBUG_LOG"
  echo ""
  echo "  Thu voi scheme 'Bearer' thay vi 'token' (mot so loai token yeu cau Bearer):"
  alt_status=$(curl -s -o /tmp/taskb_preflight_body2.json -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" https://api.github.com/user)
  echo "  HTTP $alt_status (voi Bearer)"
  cat /tmp/taskb_preflight_body2.json
  echo ""
  echo "  Kiem tra: gh auth status ; gh auth token | cat -A | tail -c 50   (xem co ^M/\\r cuoi khong)"
  exit 1
fi
gh_user=$(jq -r '.login // "?"' /tmp/taskb_preflight_body.json)
echo "  OK - dang xac thuc la: $gh_user"
echo ""

# --- 3. Xac dinh danh sach repo se chay (--repos / --sample / het danh sach) ---
[ -f "$SELECTED_JSON" ] || { echo "Thieu $SELECTED_JSON - chay taskb_select_repos.py truoc."; exit 1; }
if [ -n "$REPOS_ARG" ]; then
  REPOS=$(echo "$REPOS_ARG" | tr ',' '\n')
  echo "=== CHE DO TEST: chi chay ${REPOS_ARG} ==="
elif [ -n "$SAMPLE_N" ]; then
  REPOS=$(jq -r ".selected[:${SAMPLE_N}][].repo" "$SELECTED_JSON")
  echo "=== CHE DO SAMPLE: $SAMPLE_N repo dau tien trong danh sach ==="
else
  REPOS=$(jq -r '.selected[].repo' "$SELECTED_JSON")
  echo "=== CHE DO DAY DU: toan bo repo trong $SELECTED_JSON ==="
  echo "!! Khuyen nghi: chi chay che do nay SAU KHI --sample nho da cho ket qua hop ly !!"
fi

# !!! FIX CHINH cho bug 608/609 (da xac nhan bang byte-level tren file that cua
# ban chay truoc: repo "clidey/whodb\r" - ky tu \r bam vao CUOI ten repo o MOI
# dong TRU dong CUOI CUNG). Nguyen nhan: `jq` (ban Windows native) ghi CRLF ra
# stdout; `$(...)` chi cat newline o CUOI TOAN BO chuoi capture, KHONG cat \r
# nam giua cac dong -> moi $repo doc duoc trong vong lap deu dinh \r phia sau,
# lam URL goi API sai ten repo -> API tra loi/khong tim thay -> bi hieu nham la
# "khong co completed run". Fix: loai bo TOAN BO \r ngay khi co REPOS, truoc khi
# dua vao vong lap - khong sua o tung diem doc rieng le (de sot).
REPOS=$(printf '%s' "$REPOS" | tr -d '\r')

N=$(echo "$REPOS" | grep -c '.' || true)
echo "Se thu $N repo."
echo ""

echo "=== Xac nhan lai tieu chi 'public' cho $N repo se chay (diem 6 yeu cau audit) ==="
while IFS= read -r r; do
  [ -z "$r" ] && continue
  priv=$(gh repo view "$r" --json isPrivate --jq '.isPrivate' 2>>"$DEBUG_LOG")
  if [ "$priv" = "true" ]; then
    echo "  !! CANH BAO: $r la PRIVATE - loai truoc khi dung ket qua."
  elif [ "$priv" != "false" ]; then
    echo "  !! $r : gh repo view THAT BAI (khong ro private/public) - xem $DEBUG_LOG"
  fi
done <<< "$REPOS"
echo "(khong thay dong nao o tren = tat ca public va gh repo view goi duoc)"
echo ""

# CSV header v3 - them workflow_name, n_jobs, job_ids, log_source (yeu cau
# truy nguyen: moi ket qua Task B phai gan duoc voi dung 1 GitHub Actions run
# cu the, khong chi 1 repo chung chung - vi script CO CHU DICH chon "run
# completed gan nhat" moi lan chay, nen 2 lan chay CACH NHAU 1 NGAY tren cung
# 1 repo dang hoat dong co the ra 2 run_id KHAC NHAU - day la thiet ke DUNG
# (Task B can bang chung runtime MOI NHAT), khong phai loi can sua thanh
# "luon chon cung 1 run". Cot moi giup biet CHINH XAC run nao da dung cho
# tung dong ket qua, khong can doan.
echo "repo,runs_list_http_status,n_runs_seen,n_completed_seen,per_page_used,run_id,run_created_at,run_age_days,workflow_name,run_conclusion,n_jobs,job_ids,log_source,log_http_status,zip_ok,n_step_files,n_urls,error_type" > "$RESULTS_CSV"
echo "{}" > "$URLS_JSON"

# Ghi 1 dong CSV bang MANG (array) thay vi noi chuoi tay dem dau phay - da
# tung dinh bug do dem dau phay sai/mat dong bo cot 1 lan trong du an nay
# (xem lich su \r-corruption o tren), nen KHONG lap lai kieu do voi cot moi.
# So luong tham so truyen vao PHAI dung 18 (dung header o tren) - kiem bang
# `bash -n` va 1 lan chay --repos that sau khi sua.
csv_row() {
  local IFS=,
  printf '%s\n' "$*" >> "$RESULTS_CSV"
}

n_ok=0
n_with_3plus_urls=0
declare -A error_counts

i=0
while IFS= read -r repo; do
  [ -z "$repo" ] && continue
  i=$((i + 1))
  echo ""
  echo "[$i/$N] $repo"
  safe_repo=$(echo "$repo" | tr '/' '__')
  repo_dir="$LOGS_DIR/$safe_repo"
  mkdir -p "$repo_dir"

  run_id="" run_created="" run_conclusion="" error_type=""
  log_http_status="" zip_ok=false n_step_files=0 n_urls=0
  per_page_used=5
  workflow_name="" n_jobs="" job_ids="" log_source=""
  n_runs_seen=0 n_completed_seen=0

  # --- Buoc 1a: lay danh sach run, KIEM TRA HTTP STATUS RIENG (fix chinh) ---
  runs_body_file="$repo_dir/runs_p5.json"
  # -L BAT BUOC: repo bi doi ten/chuyen owner sau khi crawl se khien GitHub tra
  # 301 toi /repositories/{id}/... (xac nhan qua CarlAllenn/edtf - curl khong
  # -L thi dung lai o 301, khong bao gio thay duoc noi dung that). Ban truoc
  # thieu -L o CA HAI request runs-list (per_page=5 va per_page=100 ben duoi).
  runs_http=$(curl -s -L -o "$runs_body_file" -w "%{http_code}" \
    -H "Authorization: token $TOKEN" \
    "https://api.github.com/repos/$repo/actions/runs?per_page=5")

  if [ "$runs_http" != "200" ]; then
    echo "  !! /actions/runs tra HTTP $runs_http (KHONG PHAI 'khong co completed run')."
    echo "     Body loi (ghi vao $DEBUG_LOG):"
    { echo "== $repo (runs list) HTTP $runs_http =="; cat "$runs_body_file"; echo; } >> "$DEBUG_LOG"
    head -c 200 "$runs_body_file"; echo ""
    # tien to "download_error_" de taskb_compare.py xep vao nhom "download_error"
    # (loi tang goi API/mang, KHONG phai "repo khong co Actions") khi gom bao cao
    error_type="download_error_api_runs_list_http${runs_http}"
    csv_row "$repo" "$runs_http" 0 0 5 "" "" "" "" "" "" "" "" "" false 0 0 "$error_type"
    error_counts[$error_type]=$(( ${error_counts[$error_type]:-0} + 1 ))
    sleep 1
    continue
  fi

  n_runs_seen=$(jq '.workflow_runs | length' "$runs_body_file" 2>/dev/null || echo 0)
  n_completed_seen=$(jq '[.workflow_runs[] | select(.status=="completed")] | length' "$runs_body_file" 2>/dev/null || echo 0)

  # --- Buoc 1a-bis (SUA LAI HOAN TOAN sau khi Bao phat hien tu sample n=50
  # that: prowler-cloud/prowler co the co CA 5 run "completed" gan nhat DEU
  # la action_required/n_jobs=0 - vd repo nhan nhieu PR tu fork can duyet thu
  # cong truoc khi chay. Uu tien "conclusion success/failure" o ban truoc
  # KHONG DU, vi no chi chon 1 run DUY NHAT roi dung lai neu run do co
  # n_jobs=0 - se bo qua mat 1 run CU HON van co the co job that. Logic dung:
  # DUYET TUNG run "completed" tu moi nhat, GOI /jobs THAT cho tung run, chon
  # run DAU TIEN co n_jobs>0; chi bo qua han (khong dung repo nay) neu THU HET
  # moi candidate (ca p5 lan p100 khi can) ma khong run nao co job. ---
  #
  #   candidate runs (moi nhat truoc)
  #         v
  #   status=="completed" ?
  #         v
  #   GET /jobs that su cho TUNG run
  #         v
  #   n_jobs > 0 ?  --NO--> bo run nay, thu run TIEP THEO trong danh sach
  #         |
  #        YES
  #         v
  #   dung run nay, tai log
  #
  MAX_CANDIDATES_PER_PAGE=20   # chan tren de khong dot request neu 1 repo co
                                # rat nhieu run lien tiep deu n_jobs=0 (hiem)
  chosen_run_id="" chosen_created="" chosen_conclusion="" chosen_workflow=""
  chosen_n_jobs="" chosen_job_ids=""
  declare -A checked_run_ids

  try_candidates() {
    # $1 = file JSON runs (p5 hoac p100) de duyet candidate + tra cuu metadata
    local body_file="$1"
    local cid tried=0
    while IFS= read -r cid; do
      [ -z "$cid" ] && continue
      [ -n "${checked_run_ids[$cid]:-}" ] && continue   # da kiem o vong truoc, khong goi lai
      tried=$((tried + 1))
      [ "$tried" -gt "$MAX_CANDIDATES_PER_PAGE" ] && { echo "    (da thu $MAX_CANDIDATES_PER_PAGE candidate, dung tim tiep de gioi han request)"; return 1; }
      checked_run_ids[$cid]=1
      local jf="$repo_dir/jobs_${cid}.json" jhttp nj jids n_real_jobs
      jhttp=$(curl -s -L -o "$jf" -w "%{http_code}" -H "Authorization: token $TOKEN" \
        "https://api.github.com/repos/$repo/actions/runs/$cid/jobs?per_page=100")
      if [ "$jhttp" != "200" ]; then
        echo "    run $cid: /jobs tra HTTP $jhttp - khong biet n_jobs, BO QUA (thu run tiep theo)."
        { echo "== $repo run=$cid (jobs) HTTP $jhttp =="; cat "$jf"; echo; } >> "$DEBUG_LOG"
        continue
      fi
      nj=$(jq -r '.total_count // (.jobs | length)' "$jf" 2>/dev/null)
      # MOI (phat hien tu sample n=50 that voi ban v4): "total_count>0" KHONG
      # DU - 1 job co the TON TAI trong danh sach nhung conclusion="skipped"
      # (dieu kien `if:` cua job do sai nen KHONG thuc thi buoc nao that su).
      # 3/3 case "log 200 nhung zip khong hop le" trong sample n=50 THAT deu
      # co run_conclusion=skipped - manh moi manh: job "skipped" ton tai
      # trong /jobs (nj>0) nhung khong sinh log that, GitHub tra ve file
      # khong phai zip hop le dung. Kiem THEM: co it nhat 1 job voi conclusion
      # KHAC "skipped" va KHAC null khong (tuc la co job THAT SU chay, du
      # thanh cong/that bai/huy giua chung - cancelled/timed_out van co log
      # tung phan, chi rieng skipped la chua he chay buoc nao).
      n_real_jobs=$(jq -r '[.jobs[] | select(.conclusion != "skipped" and .conclusion != null)] | length' "$jf" 2>/dev/null)
      if [ -n "$nj" ] && [ "$nj" != "0" ] && [ -n "$n_real_jobs" ] && [ "$n_real_jobs" != "0" ]; then
        jids=$(jq -r '[.jobs[].id] | .[:5] | join(";")' "$jf" 2>/dev/null)
        chosen_run_id="$cid"
        chosen_n_jobs="$nj"
        chosen_job_ids="$jids"
        chosen_created=$(jq -r --arg id "$cid" '.workflow_runs[]? | select((.id|tostring)==$id) | .created_at' "$body_file" | head -1)
        chosen_conclusion=$(jq -r --arg id "$cid" '.workflow_runs[]? | select((.id|tostring)==$id) | .conclusion' "$body_file" | head -1)
        chosen_workflow=$(jq -r --arg id "$cid" '.workflow_runs[]? | select((.id|tostring)==$id) | .name' "$body_file" | head -1 | tr ',' ';')
        echo "    run $cid: n_jobs=$nj (co $n_real_jobs job KHAC skipped) -> CHON run nay."
        return 0
      elif [ -n "$nj" ] && [ "$nj" != "0" ]; then
        echo "    run $cid: n_jobs=$nj NHUNG tat ca deu conclusion=skipped (chua he chay buoc nao)"
        echo "       -> BO QUA (day chinh la nguyen nhan '200 nhung zip khong hop le' phat hien"
        echo "       tu sample that - xem note muc 11), thu run tiep theo."
      else
        echo "    run $cid: n_jobs=0 -> BO QUA (chua tung thuc thi), thu run tiep theo."
      fi
    done <<< "$(jq -r '[.workflow_runs[] | select(.status=="completed")] | sort_by(.created_at) | reverse | .[].id' "$body_file")"
    return 1
  }

  per_page_used=5
  if [ "$n_completed_seen" -gt 0 ]; then
    try_candidates "$runs_body_file" || true
  fi

  if [ -z "$chosen_run_id" ]; then
    # Chua tim duoc run co job trong $per_page=5 (hoac 0 run completed trong
    # do) - thu lai voi per_page=100 (kiem ca gia thuyet "5 run la qua it" LAN
    # gia thuyet moi "toan bo run gan day deu action_required/n_jobs=0").
    per_page_used=100
    runs_body_file100="$repo_dir/runs_p100.json"
    runs_http100=$(curl -s -L -o "$runs_body_file100" -w "%{http_code}" \
      -H "Authorization: token $TOKEN" \
      "https://api.github.com/repos/$repo/actions/runs?per_page=100")
    if [ "$runs_http100" = "200" ]; then
      n_runs_seen=$(jq '.workflow_runs | length' "$runs_body_file100")
      n_completed_seen=$(jq '[.workflow_runs[] | select(.status=="completed")] | length' "$runs_body_file100")
      runs_body_file="$runs_body_file100"
      if [ "$n_completed_seen" -gt 0 ]; then
        try_candidates "$runs_body_file100" || true
      fi
      [ -n "$chosen_run_id" ] && echo "  (per_page=5 khong tim duoc run co job, per_page=100 THI CO)"
    fi
  fi

  if [ -z "$chosen_run_id" ]; then
    if [ "$n_completed_seen" -eq 0 ]; then
      echo "  API tra 200, thay $n_runs_seen run (per_page=$per_page_used), 0 run 'completed' -> GENUINELY khong co."
      error_type="no_run_genuine"
    else
      echo "  Da thu TAT CA candidate 'completed' co duoc (toi da $MAX_CANDIDATES_PER_PAGE moi trang) -"
      echo "     KHONG run nao co job (n_jobs>0). Repo nay that su chua co bang chung runtime nao dung duoc."
      error_type="no_jobs_run_never_executed"
    fi
    csv_row "$repo" 200 "$n_runs_seen" "$n_completed_seen" "$per_page_used" "" "" "" "" "" "" "" "" "" false 0 0 "$error_type"
    error_counts[$error_type]=$(( ${error_counts[$error_type]:-0} + 1 ))
    sleep 1
    continue
  fi

  run_id="$chosen_run_id"
  run_created="$chosen_created"
  run_conclusion="$chosen_conclusion"
  workflow_name="$chosen_workflow"
  n_jobs="$chosen_n_jobs"
  job_ids="$chosen_job_ids"

  # tuoi run (ngay) - de KHONG bao gio phai doan "co phai het han 90 ngay
  # khong" nua, tinh luon o day va ghi vao CSV (yeu cau: 404 tren run <90 ngay
  # KHONG duoc goi la "het han" - phai co so lieu ro rang di kem)
  run_age_days=""
  if [ -n "$run_created" ] && [ "$run_created" != "null" ]; then
    run_epoch=$(date -d "$run_created" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$run_created" +%s 2>/dev/null)
    now_epoch=$(date +%s)
    [ -n "$run_epoch" ] && run_age_days=$(( (now_epoch - run_epoch) / 86400 ))
  fi
  echo "  run_id=$run_id  created=$run_created (${run_age_days:-?} ngay truoc)  conclusion=$run_conclusion  workflow=$workflow_name  n_jobs=$n_jobs  (n_runs_seen=$n_runs_seen, n_completed=$n_completed_seen, per_page=$per_page_used)"

  # --- Buoc 1b: thu tai log ---
  zip_path="$repo_dir/logs.zip"
  log_source="GET /repos/$repo/actions/runs/$run_id/logs"
  log_http_status=$(curl -s -L -H "Authorization: token $TOKEN" \
    -w "%{http_code}" -o "$zip_path" \
    "https://api.github.com/repos/$repo/actions/runs/$run_id/logs")

  case "$log_http_status" in
    200)
      if unzip -l "$zip_path" >/dev/null 2>&1; then
        zip_ok=true
        n_step_files=$(unzip -l "$zip_path" 2>/dev/null | grep -c '\.txt$' || true)
        error_type="ok"
        echo "  log 200 OK - $n_step_files file .txt trong zip"
      else
        error_type="log_200_but_invalid_zip"
        echo "  log 200 nhung KHONG phai zip hop le - xem $zip_path"
      fi
      ;;
    404)
      # LUU Y (tu doc GitHub Community Discussion #186838): endpoint nay AN
      # loi permission thanh 404 thay vi 403 de khong lo thong tin - "404" o
      # day co the la "het han that" HOAC "thieu quyen" HOAC ly do khac (settings
      # retention rieng cua repo, log da bi xoa tay, to chuc han che truy cap) -
      # GitHub an 403 thanh 404 o endpoint nay nen KHONG phan biet duoc chi tu
      # ma HTTP. TUYET DOI KHONG duoc ghi "het han" khi run_age_days < 90 - da
      # bat gap thuc te: prowler-cloud/prowler va open-edge-platform/
      # geti-instant-learn tra 404 voi run tao 1 NGAY TRUOC, chung minh "het
      # han 90 ngay" SAI cho 2 case nay. Neu run con moi (< 90 ngay) van 404,
      # error_type rieng de KHONG lan vao thong ke "het han" chung.
      # Da kiem /jobs O TREN roi (n_jobs=0 da bi loai truoc, khong toi duoc day
      # nua) - nen neu roi vao day tuc n_jobs>0 (job THAT SU da chay) HOAC
      # jobs_http != 200 (khong biet chac). Phai tach 2 truong hop nay, KHONG
      # con dung chung 1 nhan "co the het han/thieu quyen" nhu ban cu nua.
      if [ "$jobs_http" = "200" ] && [ -n "$n_jobs" ] && [ "$n_jobs" != "0" ]; then
        error_type="no_log_despite_jobs_ran_SUSPICIOUS"
        echo "  log 404 NHUNG n_jobs=$n_jobs (job DA THAT SU chay, xac nhan qua /jobs) -> day la"
        echo "     truong hop KHO HIEU HON nhieu so voi truoc: khong con la 'co the run chua"
        echo "     thuc thi'. Nghi van con lai: retention rieng ngan hon cua repo, log bi xoa"
        echo "     tay, to chuc han che truy cap rieng endpoint /logs. CAN dieu tra tay tiep."
      elif [ -n "$run_age_days" ] && [ "$run_age_days" -lt 90 ]; then
        error_type="log_404_unavailable_run_under_90d_SUSPICIOUS"
        echo "  log 404, run moi $run_age_days ngay (<90), jobs_http=$jobs_http (khong xac dinh"
        echo "     duoc n_jobs) -> KHONG PHAI het han theo dinh nghia thong thuong. Xem note muc"
        echo "     7-8-9 de dieu tra tiep (co the /jobs cung loi cung nguyen nhan voi /logs)."
      else
        error_type="log_404_unavailable"
        echo "  log 404 - co the het han (run $run_age_days ngay truoc, gan/qua nguong 90) HOAC thieu quyen"
        echo "     (GitHub an 403 thanh 404 o endpoint nay - khong phan biet duoc chi tu ma HTTP)."
      fi
      ;;
    403)
      error_type="log_403_permission"
      echo "  log 403 - THIEU QUYEN ro rang. Kiem scope: gh auth status."
      ;;
    *)
      error_type="log_http${log_http_status}"
      echo "  log HTTP $log_http_status - khong ro, xem $zip_path thu cong."
      ;;
  esac

  if [ "$zip_ok" = true ]; then
    rm -rf "$repo_dir/extracted"
    unzip -o -q "$zip_path" -d "$repo_dir/extracted"
    grep -ohrE 'https?://[a-zA-Z0-9._-]+' "$repo_dir/extracted" 2>/dev/null \
      | sed -E 's#https?://##' | sort | uniq -c | sort -rn > "$repo_dir/urls.txt"
    n_urls=$(grep -c '[0-9]' "$repo_dir/urls.txt" 2>/dev/null || echo 0)
    echo "  -> $n_urls domain phan biet. Xem $repo_dir/urls.txt"
    [ "$n_urls" -ge 3 ] && n_with_3plus_urls=$((n_with_3plus_urls + 1))
    n_ok=$((n_ok + 1))
    if [ "$n_urls" -eq 0 ]; then
      error_type="ok_but_0_urls_in_grep"
    fi
  fi

  error_counts[$error_type]=$(( ${error_counts[$error_type]:-0} + 1 ))
  csv_row "$repo" 200 "$n_runs_seen" "$n_completed_seen" "$per_page_used" "$run_id" "$run_created" "$run_age_days" "$workflow_name" "$run_conclusion" "$n_jobs" "$job_ids" "$log_source" "$log_http_status" "$zip_ok" "$n_step_files" "$n_urls" "$error_type"

  $PY - "$URLS_JSON" "$repo" "$repo_dir/urls.txt" <<'PYEOF'
import json, sys
out_path, repo, urls_path = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(out_path, encoding="utf-8"))
entries = []
try:
    with open(urls_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                entries.append({"domain": parts[1], "count": int(parts[0])})
except FileNotFoundError:
    pass
d[repo] = entries
json.dump(d, open(out_path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
PYEOF

  sleep 1
done <<< "$REPOS"

echo ""
echo "=================================================================="
echo "RATE LIMIT SAU"
echo "=================================================================="
rl_after=$(curl -s -H "Authorization: token $TOKEN" https://api.github.com/rate_limit)
echo "$rl_after" | jq '.rate' 2>/dev/null || echo "$rl_after"
remaining_after=$(echo "$rl_after" | jq -r '.rate.remaining // "?"' 2>/dev/null)
if [ "$remaining_before" != "?" ] && [ "$remaining_after" != "?" ]; then
  consumed=$((remaining_before - remaining_after))
  echo "Da dung: $consumed request cho $N repo (~$(awk "BEGIN{printf \"%.1f\", $consumed/$N}") request/repo)"
fi

echo ""
echo "=================================================================="
echo "TOM TAT BUOC 1-2 (theo error_type - KHONG gop chung thanh 1 so 'skip')"
echo "=================================================================="
for et in "${!error_counts[@]}"; do
  echo "  $et : ${error_counts[$et]}"
done
echo ""
echo "Tai duoc log thanh cong (zip hop le) : $n_ok / $N"
echo "Co >=3 domain phan biet trong log     : $n_with_3plus_urls / $N"
echo ""
echo "File ket qua:"
echo "  $RESULTS_CSV       (moi repo 1 dong, co error_type rieng)"
echo "  $URLS_JSON         (R_log tung repo, dung cho Buoc 3)"
echo "  $DEBUG_LOG         (raw body loi cua cac request that bai, neu co)"
echo ""
echo "Buoc tiep theo: uv run python measurement/taskb_compare.py"
