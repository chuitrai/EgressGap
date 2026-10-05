import os
import time
import json
import re
import requests
import sys
import io

# Cấu hình UTF-8 cho stdout trên Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

def load_env_file(env_path=".env"):
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    os.environ[key.strip()] = val.strip()

load_env_file(".env")
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()

def get_headers():
    return {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "GitHub-Feasibility-Measurer"
    }

def check_token():
    if not GITHUB_TOKEN or GITHUB_TOKEN == "YOUR_GITHUB_PAT_HERE":
        print("[!] CẢNH BÁO: Chưa điền GITHUB_TOKEN trong file .env!")
        print("    Vui lòng cập nhật token vào file .env để bắt đầu đo đạc.")
        return False
    return True

def handle_rate_limit(response):
    if response.status_code in (403, 429):
        reset_time = int(response.headers.get("X-RateLimit-Reset", time.time() + 60))
        sleep_time = max(reset_time - int(time.time()), 1) + 2
        print(f"[!] Chạm giới hạn Rate Limit. Tạm nghỉ {sleep_time} giây...")
        time.sleep(sleep_time)
        return True
    return False

# ==========================================
# ĐO ĐẠC THỐNG KÊ 3 TẦNG (FEASIBILITY MEASUREMENT)
# ==========================================

def count_query_total(query_string):
    """Đếm tổng số kết quả trả về từ GitHub Code Search API"""
    base_url = "https://api.github.com/search/code"
    params = {"q": query_string, "per_page": 1, "page": 1}
    
    while True:
        response = requests.get(base_url, headers=get_headers(), params=params)
        if handle_rate_limit(response):
            continue
        if response.status_code == 200:
            return response.json().get("total_count", 0)
        else:
            print(f"[X] Lỗi query '{query_string}': {response.status_code} - {response.text}")
            return 0

def fetch_sample_workflows(query_string, sample_limit=50):
    """Lấy danh sách mẫu file workflow từ query"""
    base_url = "https://api.github.com/search/code"
    items_list = []
    page = 1
    per_page = min(100, sample_limit)
    
    while len(items_list) < sample_limit:
        params = {"q": query_string, "per_page": per_page, "page": page}
        response = requests.get(base_url, headers=get_headers(), params=params)
        if handle_rate_limit(response):
            continue
        if response.status_code != 200:
            break
            
        data = response.json()
        items = data.get("items", [])
        if not items:
            break
            
        for item in items:
            html_url = item.get("html_url", "")
            raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            items_list.append({
                "repo": item["repository"]["full_name"],
                "path": item["path"],
                "raw_url": raw_url
            })
            if len(items_list) >= sample_limit:
                break
                
        if len(items) < per_page:
            break
        page += 1
        time.sleep(2)
        
    return items_list

def analyze_sample_allowlist(sample_files):
    """Đánh giá chi tiết mẫu để xác định Tầng 2 (Allowlist không rỗng)"""
    matched_tier2 = []
    audit_mode_count = 0
    empty_allowlist_count = 0
    valid_allowlist_count = 0
    
    for idx, item in enumerate(sample_files, 1):
        raw_url = item["raw_url"]
        try:
            resp = requests.get(raw_url, headers=get_headers(), timeout=5)
            if resp.status_code == 200:
                content = resp.text
                
                # Kiểm tra mode
                if "egress-policy: audit" in content:
                    audit_mode_count += 1
                
                # Regex bóc tách allowed-endpoints
                match = re.search(r'allowed-endpoints:\s*(.*?)(?=\n\s*[a-zA-Z0-9_-]+:|\Z)', content, re.DOTALL)
                domains = []
                if match:
                    raw_text = match.group(1)
                    cleaned_text = re.sub(r'[,>|"\']', ' ', raw_text)
                    domains = [d.strip() for d in cleaned_text.split() if d.strip()]
                    
                if domains:
                    valid_allowlist_count += 1
                    matched_tier2.append({
                        "repo": item["repo"],
                        "path": item["path"],
                        "domains": domains,
                        "domain_count": len(domains)
                    })
                else:
                    empty_allowlist_count += 1
        except Exception as e:
            print(f"  [X] Lỗi đọc mẫu {item['repo']}: {e}")
        time.sleep(0.5)
        
    return {
        "valid_allowlist_count": valid_allowlist_count,
        "empty_allowlist_count": empty_allowlist_count,
        "audit_mode_count": audit_mode_count,
        "matched_tier2_samples": matched_tier2
    }

def run_feasibility_measurement():
    print("=" * 60)
    print("  BẮT ĐẦU ĐO ĐẠC KHẢ THI (FEASIBILITY MEASUREMENT STUDY)")
    print("=" * 60)
    
    # 1. Tầng 0: Mention harden-runner
    q_tier0 = '"step-security/harden-runner" path:.github/workflows extension:yml'
    print("[1/3] Đang đếm Tầng 0 (Mention harden-runner)...")
    count_tier0 = count_query_total(q_tier0)
    print(f"  ==> Tầng 0 (Tổng số repo dùng harden-runner): {count_tier0:,} workflows")
    
    # 2. Tầng 1: egress-policy: block
    q_tier1 = '"step-security/harden-runner" "egress-policy: block" path:.github/workflows extension:yml'
    print("\n[2/3] Đang đếm Tầng 1 (egress-policy: block)...")
    count_tier1 = count_query_total(q_tier1)
    print(f"  ==> Tầng 1 (Số workflow bật Block Mode): {count_tier1:,} workflows")
    
    # 3. Tầng 2: egress-policy: block + allowed-endpoints
    q_tier2 = '"step-security/harden-runner" "egress-policy: block" "allowed-endpoints" path:.github/workflows extension:yml'
    print("\n[3/3] Đang đếm Tầng 2 (Block Mode + allowed-endpoints)...")
    count_tier2_query = count_query_total(q_tier2)
    print(f"  ==> Tầng 2 Search API (Chứa từ khóa allowed-endpoints): {count_tier2_query:,} workflows")
    
    # Lấy mẫu 50 file từ Tầng 1 để kiểm tra tỉ lệ thực tế (Sampling)
    SAMPLE_SIZE = 50
    print(f"\n[*] Đang lấy ngẫu nhiên mẫu {SAMPLE_SIZE} workflows từ Tầng 1 để kiểm tra allowlist...")
    sample_items = fetch_sample_workflows(q_tier1, sample_limit=SAMPLE_SIZE)
    analysis = analyze_sample_allowlist(sample_items)
    
    # Tính toán tỉ lệ
    pct_t1_t0 = (count_tier1 / count_tier0 * 100) if count_tier0 > 0 else 0
    pct_t2_t0 = (count_tier2_query / count_tier0 * 100) if count_tier0 > 0 else 0
    
    sample_valid = analysis["valid_allowlist_count"]
    sample_total = len(sample_items)
    sample_valid_ratio = (sample_valid / sample_total) if sample_total > 0 else 0
    
    estimated_corpus_size = int(count_tier1 * sample_valid_ratio)
    
    report = {
        "tier_0_total_harden_runner": count_tier0,
        "tier_1_block_mode": count_tier1,
        "tier_2_query_count": count_tier2_query,
        "conversion_rates": {
            "tier1_over_tier0_pct": f"{pct_t1_t0:.2f}%",
            "tier2_over_tier0_pct": f"{pct_t2_t0:.2f}%",
            "sample_valid_ratio_in_block_mode": f"{sample_valid_ratio * 100:.2f}%"
        },
        "estimated_valid_corpus_size": estimated_corpus_size,
        "sample_analysis_detail": {
            "sample_size": sample_total,
            "valid_allowlist": sample_valid,
            "empty_or_no_allowlist": analysis["empty_allowlist_count"],
            "audit_mode_in_sample": analysis["audit_mode_count"]
        }
    }
    
    # Ghi báo cáo ra file JSON
    output_file = "feasibility_report.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
        
    print("\n" + "=" * 60)
    print("  KẾT QUẢ ĐO ĐẠC VÀ ƯỚC LƯỢNG CORPUS THỰC TẾ")
    print("=" * 60)
    print(f" • Tầng 0 (Tổng harden-runner)        : {count_tier0:,} repos")
    print(f" • Tầng 1 (Chế độ Block mode)         : {count_tier1:,} repos ({pct_t1_t0:.1f}% tổng số)")
    print(f" • Tầng 2 (Có Allowlist cấu hình)     : {count_tier2_query:,} repos ({pct_t2_t0:.1f}% tổng số)")
    print(f" • Tỉ lệ mẫu thực sự có Allowlist    : {sample_valid}/{sample_total} ({sample_valid_ratio*100:.1f}%)")
    print(f" 👉 CORPUS DÙNG ĐƯỢC ƯỚC TÍNH (TẦNG 2) : ~{estimated_corpus_size:,} WORKFLOWS")
    print(f"\n[✓] Đã lưu báo cáo chi tiết vào '{output_file}'.")

if __name__ == "__main__":
    if check_token():
        run_feasibility_measurement()
