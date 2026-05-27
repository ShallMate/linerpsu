#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${ROOT}/bazel-bin/examples/linerpsu/ourpsu"
OUT_DIR="${LINERPSU_OUT_DIR:-${ROOT}/examples/linerpsu/results/psu_net_$(date +%Y%m%d_%H%M%S)}"
SUMMARY="${OUT_DIR}/summary.csv"
LOGNS="${LINERPSU_LOGNS:-8 10 12 14 16 18 20 22}"
SCENARIOS="${LINERPSU_SCENARIOS:-lan wan}"
CASE_TIMEOUT="${LINERPSU_CASE_TIMEOUT:-0}"
BUILD_FIRST="${LINERPSU_BUILD_FIRST:-1}"
SILENT_OT_CODE="${LINERPSU_SILENT_OT_CODE:-Tungsten}"
LAN_GMW_TRIPLE_BATCH="${LINERPSU_LAN_GMW_TRIPLE_BATCH:-262144}"
WAN_GMW_MAX_TRIPLE_BATCHES="${LINERPSU_WAN_GMW_MAX_TRIPLE_BATCHES:-16}"
WAN_GMW_MAX_BATCH_BYTES="${LINERPSU_WAN_GMW_MAX_BATCH_BYTES:-268435456}"

mkdir -p "${OUT_DIR}"

if [[ "${BUILD_FIRST}" != "0" ]]; then
  bazel build //examples/linerpsu:ourpsu
fi

printf 'scenario,rate,rtt_ms,oneway_delay,logn,ns,nr,cuckoolen,status,offline_s,online_s,total_s,offline_comm_bytes,online_comm_bytes,total_comm_bytes,total_comm_mb,result_size,console_log\n' > "${SUMMARY}"

scenario_params() {
  case "$1" in
    lan)
      printf 'lan_10gbps_0p02ms 10gbit 10us 0.02\n'
      ;;
    wan)
      printf 'wan_100mbps_80ms 100mbit 40ms 80\n'
      ;;
    *)
      echo "unknown scenario: $1" >&2
      return 1
      ;;
  esac
}

extract_value() {
  local line="$1"
  local key="$2"
  tr ',' '\n' <<< "${line}" | awk -F= -v k="${key}" '$1 == k {print $2; exit}'
}

run_case() {
  local scenario="$1"
  local rate="$2"
  local delay="$3"
  local rtt_ms="$4"
  local logn="$5"
  local log_file="${OUT_DIR}/${scenario}_logn${logn}.log"
  local gmw_triple_batch=""
  local gmw_max_batches=""
  local gmw_max_batch_bytes=""

  case "${scenario}" in
    lan_*)
      gmw_triple_batch="${LAN_GMW_TRIPLE_BATCH}"
      ;;
    wan_*)
      gmw_max_batches="${WAN_GMW_MAX_TRIPLE_BATCHES}"
      gmw_max_batch_bytes="${WAN_GMW_MAX_BATCH_BYTES}"
      ;;
  esac

  echo "[linerpsu] scenario=${scenario} logn=${logn} rate=${rate} rtt=${rtt_ms}ms"
  set +e
  if [[ "${CASE_TIMEOUT}" == "0" ]]; then
    unshare --user --map-root-user --net env \
      RATE="${rate}" DELAY="${delay}" ROOT="${ROOT}" BIN="${BIN}" LOGN="${logn}" \
      SILENT_OT_CODE="${SILENT_OT_CODE}" \
      GMW_TRIPLE_BATCH="${gmw_triple_batch}" \
      GMW_MAX_BATCHES="${gmw_max_batches}" \
      GMW_MAX_BATCH_BYTES="${gmw_max_batch_bytes}" \
      bash -lc '
        set -euo pipefail
        ip link set lo up
        tc qdisc replace dev lo root netem rate "${RATE}" delay "${DELAY}"
        cd "${ROOT}"
        if [[ -n "${GMW_TRIPLE_BATCH}" ]]; then
          export PSU_PEQT_GMW_TRIPLE_BATCH="${GMW_TRIPLE_BATCH}"
        fi
        if [[ -n "${GMW_MAX_BATCHES}" ]]; then
          export PSU_PEQT_GMW_MAX_TRIPLE_BATCHES="${GMW_MAX_BATCHES}"
        fi
        if [[ -n "${GMW_MAX_BATCH_BYTES}" ]]; then
          export PSU_PEQT_GMW_MAX_BATCH_BYTES="${GMW_MAX_BATCH_BYTES}"
        fi
        OMP_NUM_THREADS=1 \
        PSU_PEQT_GMW_THREADS=1 \
        PSU_PEQT_PARALLEL_BATCHES=1 \
        LINERPSU_RESULT_LINE=1 \
        LINERPSU_LOGN="${LOGN}" \
        LINERPSU_SILENT_OT_CODE="${SILENT_OT_CODE}" \
        "${BIN}"
      ' > "${log_file}" 2>&1
  else
    timeout "${CASE_TIMEOUT}" unshare --user --map-root-user --net env \
      RATE="${rate}" DELAY="${delay}" ROOT="${ROOT}" BIN="${BIN}" LOGN="${logn}" \
      SILENT_OT_CODE="${SILENT_OT_CODE}" \
      GMW_TRIPLE_BATCH="${gmw_triple_batch}" \
      GMW_MAX_BATCHES="${gmw_max_batches}" \
      GMW_MAX_BATCH_BYTES="${gmw_max_batch_bytes}" \
      bash -lc '
        set -euo pipefail
        ip link set lo up
        tc qdisc replace dev lo root netem rate "${RATE}" delay "${DELAY}"
        cd "${ROOT}"
        if [[ -n "${GMW_TRIPLE_BATCH}" ]]; then
          export PSU_PEQT_GMW_TRIPLE_BATCH="${GMW_TRIPLE_BATCH}"
        fi
        if [[ -n "${GMW_MAX_BATCHES}" ]]; then
          export PSU_PEQT_GMW_MAX_TRIPLE_BATCHES="${GMW_MAX_BATCHES}"
        fi
        if [[ -n "${GMW_MAX_BATCH_BYTES}" ]]; then
          export PSU_PEQT_GMW_MAX_BATCH_BYTES="${GMW_MAX_BATCH_BYTES}"
        fi
        OMP_NUM_THREADS=1 \
        PSU_PEQT_GMW_THREADS=1 \
        PSU_PEQT_PARALLEL_BATCHES=1 \
        LINERPSU_RESULT_LINE=1 \
        LINERPSU_LOGN="${LOGN}" \
        LINERPSU_SILENT_OT_CODE="${SILENT_OT_CODE}" \
        "${BIN}"
      ' > "${log_file}" 2>&1
  fi
  local status_code=$?
  set -e

  local result_line
  result_line="$(grep 'LINERPSU_RESULT' "${log_file}" | tail -n 1 || true)"
  local status="ok"
  if [[ ${status_code} -ne 0 || -z "${result_line}" ]]; then
    status="fail_${status_code}"
  fi

  local ns="" nr="" cuckoolen="" offline_s="" online_s="" total_s=""
  local offline_comm="" online_comm="" total_comm="" total_comm_mb="" result_size=""
  if [[ -n "${result_line}" ]]; then
    ns="$(extract_value "${result_line}" ns)"
    nr="$(extract_value "${result_line}" nr)"
    cuckoolen="$(extract_value "${result_line}" cuckoolen)"
    offline_s="$(extract_value "${result_line}" offline_s)"
    online_s="$(extract_value "${result_line}" online_s)"
    total_s="$(extract_value "${result_line}" total_s)"
    offline_comm="$(extract_value "${result_line}" offline_comm_bytes)"
    online_comm="$(extract_value "${result_line}" online_comm_bytes)"
    total_comm="$(extract_value "${result_line}" total_comm_bytes)"
    result_size="$(extract_value "${result_line}" result_size)"
    total_comm_mb="$(awk -v b="${total_comm}" 'BEGIN {printf "%.6f", b / 1048576.0}')"
  fi

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "${scenario}" "${rate}" "${rtt_ms}" "${delay}" "${logn}" \
    "${ns}" "${nr}" "${cuckoolen}" "${status}" \
    "${offline_s}" "${online_s}" "${total_s}" \
    "${offline_comm}" "${online_comm}" "${total_comm}" "${total_comm_mb}" \
    "${result_size}" "${log_file}" >> "${SUMMARY}"

  if [[ "${status}" != "ok" ]]; then
    echo "[linerpsu] failed scenario=${scenario} logn=${logn}, see ${log_file}" >&2
  fi
}

for scenario_key in ${SCENARIOS}; do
  read -r scenario rate delay rtt_ms < <(scenario_params "${scenario_key}")
  for logn in ${LOGNS}; do
    run_case "${scenario}" "${rate}" "${delay}" "${rtt_ms}" "${logn}"
  done
done

echo "[linerpsu] summary: ${SUMMARY}"
